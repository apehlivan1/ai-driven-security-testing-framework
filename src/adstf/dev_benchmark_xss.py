from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

from adstf.browser import BrowserExecutor
from adstf.config import load_target_config
from adstf.contracts import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
    VerificationOutcome,
)
from adstf.discovery import (
    CandidateRanking,
    ReflectedInputCandidate,
    candidate_ranking_to_attributes,
    discover_reflected_input_candidates,
    rank_reflected_input_candidates,
)
from adstf.discovery import DETERMINISTIC_RANKING_RULESET_VERSION as RANKING_RULESET_VERSION
from adstf.execution import HttpExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.llm_ranking import (
    CommandModelClient,
    FakeModelClient,
    LLMRankingResult,
    ModelClient,
    rank_candidates_with_model,
    ranking_result_artifact,
)
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "reflected-dev-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


@dataclass(frozen=True)
class ScenarioSpec:
    scenario_id: str
    seed_paths: list[str]
    test_budget: int


@dataclass(frozen=True)
class RankingRunSpec:
    ranking_source: str
    trial_number: int
    model_client: ModelClient | None = None
    model_settings: dict | None = None


def run_development_benchmark_reflected_xss(
    config_path: Path,
    output_root: Path,
    headless: bool = True,
    ranking_mode: str = "deterministic",
    llm_trials: int = 1,
    model_client: ModelClient | None = None,
    model_settings: dict | None = None,
) -> Path:
    target = load_target_config(config_path)
    run_id = f"dev-benchmark-xss-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    modules = mvp_modules()

    smoke_action = _http_smoke_action(run_id, target.base_url)
    store.save_action_request(smoke_action)
    smoke_result, smoke_evidence = HttpExecutor(safety).execute(smoke_action)
    for evidence in smoke_evidence:
        store.save_evidence(evidence)
    store.save_action_result(smoke_result)
    if smoke_result.status != ActionStatus.EXECUTED:
        store.save_report(render_placeholder_report(target, []))
        raise RuntimeError("Development benchmark is not reachable. Start the local server first.")

    all_findings: list[FindingRecord] = []
    scenario_summaries: list[dict] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(base_url=target.base_url)
        try:
            page = context.new_page()
            for ranking_run in _ranking_run_specs(
                ranking_mode,
                llm_trials,
                model_client,
                model_settings,
            ):
                for scenario in _scenario_specs(target):
                    summary, findings = _run_scenario(
                        scenario=scenario,
                        ranking_run=ranking_run,
                        page=page,
                        target=target,
                        safety=safety,
                        store=store,
                        modules=modules,
                        smoke_evidence=smoke_evidence,
                    )
                    scenario_summaries.append(summary)
                    all_findings.extend(findings)
        finally:
            context.close()
            browser.close()

    store.save_report(render_placeholder_report(target, all_findings, placeholder=False))
    evaluation = evaluate_run_against_ground_truth(
        store.run_dir,
        _ground_truth_path(target),
    )
    store.save_artifact_text(
        "benchmark-evaluation.json",
        json.dumps(to_json_value(evaluation), indent=2, sort_keys=True) + "\n",
    )
    store.save_artifact_text(
        "scenario-run-summary.json",
        json.dumps(to_json_value(scenario_summaries), indent=2, sort_keys=True) + "\n",
    )
    return store.run_dir


def evaluate_run_against_ground_truth(run_dir: Path, ground_truth_path: Path) -> dict:
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    cases_by_scenario = {
        scenario["scenario_id"]: {
            (case["action_path"], case["parameter_name"]): case
            for case in scenario["cases"]
        }
        for scenario in truth["scenarios"]
    }
    candidate_records = [
        record
        for record in _json_records(run_dir / "evidence")
        if record["evidence_type"] == EvidenceType.ATTACK_SURFACE_CANDIDATE.value
    ]
    run_keys = sorted(
        {
            (
                record["attributes"].get("ranking_source", "deterministic"),
                int(record["attributes"].get("trial_number", 1)),
            )
            for record in candidate_records
        }
    )
    ranking_runs = [
        _evaluate_ranking_run(
            run_dir,
            truth,
            cases_by_scenario,
            ranking_source,
            trial_number,
        )
        for ranking_source, trial_number in run_keys
    ]
    deterministic = next((run for run in ranking_runs if run["ranking_source"] == "deterministic"), None)
    return {
        "benchmark_id": truth["benchmark_id"],
        "ground_truth_used_phase": "post_run_evaluation_only",
        "ranking_ruleset_version": truth.get("ranking_ruleset_version", RANKING_RULESET_VERSION),
        "scenario_count": len(truth["scenarios"]),
        "ranking_runs": ranking_runs,
        "deterministic_baseline": deterministic,
        "llm_trials": [run for run in ranking_runs if run["ranking_source"] == "llm"],
    }


def _evaluate_ranking_run(
    run_dir: Path,
    truth: dict,
    cases_by_scenario: dict[str, dict[tuple[str, str], dict]],
    ranking_source: str,
    trial_number: int,
) -> dict:
    scenario_results = [
        _evaluate_scenario(
            run_dir,
            scenario["scenario_id"],
            cases_by_scenario[scenario["scenario_id"]],
            ranking_source,
            trial_number,
        )
        for scenario in truth["scenarios"]
    ]
    vulnerable_results = [
        result for result in scenario_results if result["vulnerable_candidate_count"] > 0
    ]
    no_vulnerability_results = [
        result for result in scenario_results if result["vulnerable_candidate_count"] == 0
    ]
    clean_results = [
        result
        for result in scenario_results
        if ranking_source != "llm"
        or (not result["model_validation_errors"] and not result["model_provider_failed"])
    ]
    clean_vulnerable_results = [
        result for result in clean_results if result["vulnerable_candidate_count"] > 0
    ]
    first_result = next((result for result in scenario_results if result["model_identifier"]), None)
    return {
        "ranking_source": ranking_source,
        "trial_number": trial_number,
        "model_identifier": first_result["model_identifier"] if first_result else None,
        "provider": first_result["provider"] if first_result else None,
        "prompt_version": first_result["prompt_version"] if first_result else None,
        "scenario_count": len(scenario_results),
        "top_1_accuracy": _mean(
            1.0 if result["top_rank_is_vulnerable"] else 0.0
            for result in vulnerable_results
        ),
        "top_k_recall": _mean(result["top_k_recall"] for result in vulnerable_results),
        "mean_reciprocal_rank": _mean(result["reciprocal_rank"] for result in vulnerable_results),
        "valid_metric_scenario_count": len(clean_results),
        "valid_top_1_accuracy": _mean(
            1.0 if result["top_rank_is_vulnerable"] else 0.0
            for result in clean_vulnerable_results
        ),
        "valid_top_k_recall": _mean(result["top_k_recall"] for result in clean_vulnerable_results),
        "valid_mean_reciprocal_rank": _mean(
            result["reciprocal_rank"] for result in clean_vulnerable_results
        ),
        "no_vulnerability_scenario_count": len(no_vulnerability_results),
        "no_vulnerability_false_positive_count": sum(
            1 for result in no_vulnerability_results if result["verified_finding_count"] > 0
        ),
        "validation_error_count": sum(
            len(result["model_validation_errors"]) for result in scenario_results
        ),
        "provider_failure_count": sum(
            1 for result in scenario_results if result["model_provider_failed"]
        ),
        "fallback_used_count": sum(
            1
            for result in scenario_results
            if result["ranking_source"] == "llm"
            and (result["model_validation_errors"] or result["model_provider_failed"])
        ),
        "valid_model_output_count": sum(
            1
            for result in scenario_results
            if result["ranking_source"] != "llm"
            or (not result["model_validation_errors"] and not result["model_provider_failed"])
        ),
        "scenario_results": scenario_results,
    }


def _run_scenario(
    *,
    scenario: ScenarioSpec,
    ranking_run: RankingRunSpec,
    page,
    target: TargetConfig,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    modules: dict,
    smoke_evidence: list[EvidenceRecord],
) -> tuple[dict, list[FindingRecord]]:
    seed_observations: list[tuple[ActionRequest, ActionResult, EvidenceRecord]] = []
    candidates: list[ReflectedInputCandidate] = []
    for index, seed_url in enumerate(_seed_urls(target, scenario), start=1):
        seed_action = _seed_action(store.run_id, scenario.scenario_id, seed_url, index)
        store.save_action_request(seed_action)
        seed_result, seed_evidence, discovered = _discover_candidates(page, safety, store, seed_action)
        store.save_evidence(seed_evidence)
        store.save_action_result(seed_result)
        seed_observations.append((seed_action, seed_result, seed_evidence))
        candidates.extend(discovered)

    rankings, llm_artifact_ref, llm_result = _build_rankings(
        candidates=candidates,
        safety=safety,
        store=store,
        scenario=scenario,
        ranking_run=ranking_run,
    )
    if not rankings:
        raise RuntimeError(f"No simple GET reflected-input candidates were discovered for {scenario.scenario_id}.")
    candidate_evidence = _candidate_evidence_records(
        store.run_id,
        scenario.scenario_id,
        ranking_run.ranking_source,
        ranking_run.trial_number,
        scenario.test_budget,
        rankings,
        seed_observations,
        llm_artifact_ref,
        llm_result,
    )
    for evidence in candidate_evidence:
        store.save_evidence(evidence)

    tested_findings: list[FindingRecord] = []
    tested_candidates: list[dict] = []
    verified_finding: FindingRecord | None = None
    for ranking in rankings[: scenario.test_budget]:
        tested_candidates.append(
            {
                "rank": ranking.rank,
                "candidate_id": ranking.candidate.candidate_id,
                "score": ranking.score,
            }
        )
        verified = _test_candidate(
            scenario=scenario,
            ranking_run=ranking_run,
            ranking=ranking,
            page=page,
            safety=safety,
            store=store,
            modules=modules,
            smoke_evidence=smoke_evidence,
            seed_observations=seed_observations,
            candidate_evidence=candidate_evidence,
        )
        tested_findings.append(verified)
        if verified.state == FindingState.VERIFIED:
            verified_finding = verified
            break

    return (
        {
            "scenario_id": scenario.scenario_id,
            "ranking_source": ranking_run.ranking_source,
            "trial_number": ranking_run.trial_number,
            "ranking_ruleset_version": RANKING_RULESET_VERSION,
            "model_identifier": llm_result.model_identifier if llm_result else None,
            "llm_artifact": llm_artifact_ref,
            "candidate_count": len(rankings),
            "test_budget": scenario.test_budget,
            "tested_candidate_count": len(tested_candidates),
            "verified_finding_id": verified_finding.finding_id if verified_finding else None,
            "tested_candidates": tested_candidates,
        },
        tested_findings,
    )


def _test_candidate(
    *,
    scenario: ScenarioSpec,
    ranking_run: RankingRunSpec,
    ranking: CandidateRanking,
    page,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    modules: dict,
    smoke_evidence: list[EvidenceRecord],
    seed_observations: list[tuple[ActionRequest, ActionResult, EvidenceRecord]],
    candidate_evidence: list[EvidenceRecord],
) -> FindingRecord:
    candidate = ranking.candidate
    run_label = f"{ranking_run.ranking_source}-trial-{ranking_run.trial_number}"
    marker = f"adstf_xss_{store.run_id.replace('-', '_')}_{scenario.scenario_id}_{run_label}_{ranking.rank}"
    control_marker = f"adstf_control_{store.run_id.replace('-', '_')}_{scenario.scenario_id}_{run_label}_{ranking.rank}"
    artifact_stem = f"{scenario.scenario_id}-{run_label}-candidate-{ranking.rank}"
    xss_url = candidate.url_with_value(f"<script>window.__adstfXssMarker='{marker}'</script>")
    control_url = candidate.url_with_value(control_marker)

    xss_action = _browser_action(
        store.run_id,
        scenario.scenario_id,
        xss_url,
        marker,
        f"{artifact_stem}-execution",
        "Submit safe marker payload to ranked reflected-input candidate.",
    )
    control_action = _browser_action(
        store.run_id,
        scenario.scenario_id,
        control_url,
        None,
        f"{artifact_stem}-control",
        "Submit benign control marker to ranked reflected-input candidate.",
    )
    store.save_action_request(xss_action)
    store.save_action_request(control_action)

    browser_executor = BrowserExecutor(safety, store)
    xss_result, xss_evidence = browser_executor.observe(xss_action, page)
    control_result, control_observation_evidence = browser_executor.observe(control_action, page)
    store.save_evidence(xss_evidence)
    store.save_evidence(control_observation_evidence)
    store.save_action_result(xss_result)
    store.save_action_result(control_result)
    if xss_result.status != ActionStatus.EXECUTED or control_result.status != ActionStatus.EXECUTED:
        raise RuntimeError("Browser observation failed or was blocked by safety boundary.")

    control_evidence = _control_evidence(
        store.run_id,
        control_url,
        control_action,
        control_observation_evidence,
        control_marker,
        scenario.scenario_id,
        ranking_run.ranking_source,
        ranking_run.trial_number,
    )
    verification_note = _evidence(
        run_id=store.run_id,
        evidence_type=EvidenceType.VERIFICATION_NOTE,
        target_ref=xss_url,
        summary="Reflected-XSS verification used safe JavaScript marker assignment only.",
        related_action_ids=[xss_action.action_id, control_action.action_id],
        attributes={
            "payload_family": "safe_marker_assignment",
            "ground_truth_used": False,
            "scenario_id": scenario.scenario_id,
            "ranking_source": ranking_run.ranking_source,
            "trial_number": ranking_run.trial_number,
            "candidate_rank": ranking.rank,
        },
    )
    store.save_evidence(control_evidence)
    store.save_evidence(verification_note)

    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=store.run_id,
        module_id="xss.reflected",
        title=f"Reflected XSS candidate observed in development benchmark {scenario.scenario_id}",
        category=modules["xss.reflected"].category,
        affected_target=candidate.url_with_value(""),
        state=FindingState.SUSPECTED,
        hypothesis=(
            "The ranked reflected-input candidate may execute script supplied through "
            f"the {candidate.parameter_name} parameter."
        ),
        created_by="dev_benchmark_xss",
        supporting_evidence_refs=[
            smoke_evidence[0].evidence_id,
            *[seed_evidence.evidence_id for _, _, seed_evidence in seed_observations],
            *[evidence.evidence_id for evidence in candidate_evidence],
            xss_evidence.evidence_id,
            control_observation_evidence.evidence_id,
            control_evidence.evidence_id,
            verification_note.evidence_id,
        ],
        report_fields={
            "scenario_id": scenario.scenario_id,
            "ranking_source": ranking_run.ranking_source,
            "trial_number": ranking_run.trial_number,
            "parameter": candidate.parameter_name,
            "candidate_id": candidate.candidate_id,
            "candidate_rank": ranking.rank,
            "candidate_score": ranking.score,
            "candidate_rationale": ranking.rationale,
            "ranking_ruleset_version": RANKING_RULESET_VERSION,
            "payload_marker": marker,
            "control_marker": control_marker,
            "execution_artifact": xss_evidence.data_ref,
            "control_artifact": control_evidence.data_ref,
        },
        severity="medium",
        confidence="verified_by_browser_marker",
    )
    store.save_finding(finding)

    requested = request_verification(finding)
    store.save_finding(requested)
    verifier_result = FindingVerifier(modules).verify(
        requested,
        [
            *smoke_evidence,
            *[seed_evidence for _, _, seed_evidence in seed_observations],
            *candidate_evidence,
            xss_evidence,
            control_observation_evidence,
            control_evidence,
            verification_note,
        ],
    )
    store.save_verifier_result(verifier_result)
    verified = apply_verifier_result(requested, verifier_result)
    store.save_finding(verified)
    return verified


def _evaluate_scenario(
    run_dir: Path,
    scenario_id: str,
    cases: dict[tuple[str, str], dict],
    ranking_source: str,
    trial_number: int,
) -> dict:
    ranked_candidates = sorted(
        [
            record
            for record in _json_records(run_dir / "evidence")
            if record["evidence_type"] == EvidenceType.ATTACK_SURFACE_CANDIDATE.value
            and record["attributes"].get("scenario_id") == scenario_id
            and record["attributes"].get("ranking_source", "deterministic") == ranking_source
            and int(record["attributes"].get("trial_number", 1)) == trial_number
        ],
        key=lambda record: record["attributes"]["rank"],
    )
    evaluated_candidates = [_evaluate_candidate(record, cases) for record in ranked_candidates]
    first_vulnerable = next(
        (candidate for candidate in evaluated_candidates if candidate["ground_truth_vulnerable"]),
        None,
    )
    findings = [
        finding
        for finding in _json_records(run_dir / "findings")
        if finding["report_fields"].get("scenario_id") == scenario_id
        and finding["report_fields"].get("ranking_source", "deterministic") == ranking_source
        and int(finding["report_fields"].get("trial_number", 1)) == trial_number
    ]
    verified_findings = [
        finding for finding in findings if finding["state"] == FindingState.VERIFIED.value
    ]
    tested_ranks = sorted(finding["report_fields"]["candidate_rank"] for finding in findings)
    test_budget = (
        ranked_candidates[0]["attributes"].get("test_budget", 0)
        if ranked_candidates
        else 0
    )
    top_k = min(int(test_budget), len(evaluated_candidates))
    top_k_recall = bool(
        first_vulnerable and first_vulnerable["rank"] <= top_k
    )
    return {
        "scenario_id": scenario_id,
        "ranking_source": ranking_source,
        "trial_number": trial_number,
        "ranking_ruleset_version": RANKING_RULESET_VERSION,
        "model_identifier": (
            ranked_candidates[0]["attributes"].get("model_identifier")
            if ranked_candidates
            else None
        ),
        "provider": (
            ranked_candidates[0]["attributes"].get("provider")
            if ranked_candidates
            else None
        ),
        "prompt_version": (
            ranked_candidates[0]["attributes"].get("prompt_version")
            if ranked_candidates
            else None
        ),
        "model_validation_errors": (
            ranked_candidates[0]["attributes"].get("model_validation_errors", [])
            if ranked_candidates
            else []
        ),
        "model_provider_failed": bool(
            ranked_candidates
            and ranked_candidates[0]["attributes"].get("model_provider_failed", False)
        ),
        "candidate_count": len(evaluated_candidates),
        "vulnerable_candidate_count": sum(
            1 for candidate in evaluated_candidates if candidate["ground_truth_vulnerable"]
        ),
        "top_rank_is_vulnerable": bool(
            evaluated_candidates and evaluated_candidates[0]["ground_truth_vulnerable"]
        ),
        "top_k": top_k,
        "top_k_recall": 1.0 if top_k_recall else 0.0,
        "reciprocal_rank": (1.0 / first_vulnerable["rank"]) if first_vulnerable else 0.0,
        "candidates_tested_before_verification": (
            min(finding["report_fields"]["candidate_rank"] for finding in verified_findings)
            if verified_findings
            else None
        ),
        "candidate_test_count": len(tested_ranks),
        "verified_finding_count": len(verified_findings),
        "no_vulnerability_behavior": (
            "no_verified_findings"
            if not first_vulnerable and not verified_findings
            else "verified_without_ground_truth_vulnerability"
            if not first_vulnerable and verified_findings
            else "not_applicable"
        ),
        "ranked_candidates": evaluated_candidates,
    }


def _evaluate_candidate(record: dict, cases: dict[tuple[str, str], dict]) -> dict:
    attributes = record["attributes"]
    action_path = urlparse(attributes["action_url"]).path
    key = (action_path, attributes["parameter_name"])
    case = cases.get(key)
    return {
        "rank": attributes["rank"],
        "score": attributes["score"],
        "selected": attributes["selected"],
        "candidate_id": attributes["candidate_id"],
        "action_path": action_path,
        "parameter_name": attributes["parameter_name"],
        "ground_truth_known": case is not None,
        "ground_truth_vulnerable": bool(case and case["vulnerable"]),
    }


def _http_smoke_action(run_id: str, base_url: str) -> ActionRequest:
    url = urljoin(f"{base_url.rstrip('/')}/", "/health")
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_xss",
        module_id="xss.reflected",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=url,
        scope_context={},
        parameters={"method": "GET", "url": url},
        preconditions=["development_benchmark_running_locally"],
        safety_class=SafetyClass.LOW,
        rationale="Confirm the local development benchmark is reachable.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def _scenario_specs(target: TargetConfig) -> list[ScenarioSpec]:
    configured = target.metadata.get("scenarios")
    if isinstance(configured, list) and configured:
        return [
            ScenarioSpec(
                scenario_id=str(item["id"]),
                seed_paths=[str(path) for path in item["seed_paths"]],
                test_budget=int(item.get("test_budget", target.max_actions)),
            )
            for item in configured
        ]
    paths = target.metadata.get("reflected_xss_seed_paths", ["/start"])
    if not isinstance(paths, list) or not paths:
        raise ValueError("Development benchmark target requires reflected_xss_seed_paths")
    return [
        ScenarioSpec(
            scenario_id="case-a",
            seed_paths=[str(path) for path in paths],
            test_budget=target.max_actions,
        )
    ]


def _ranking_run_specs(
    ranking_mode: str,
    llm_trials: int,
    model_client: ModelClient | None,
    model_settings: dict | None,
) -> list[RankingRunSpec]:
    if ranking_mode not in {"deterministic", "llm", "both"}:
        raise ValueError("ranking_mode must be one of: deterministic, llm, both")
    specs: list[RankingRunSpec] = []
    if ranking_mode in {"deterministic", "both"}:
        specs.append(RankingRunSpec("deterministic", 1))
    if ranking_mode in {"llm", "both"}:
        client = model_client or FakeModelClient()
        for trial_number in range(1, llm_trials + 1):
            specs.append(
                RankingRunSpec(
                    "llm",
                    trial_number,
                    client,
                    model_settings or {"temperature": 0.0},
                )
            )
    return specs


def _seed_urls(target: TargetConfig, scenario: ScenarioSpec) -> list[str]:
    return [
        path
        if str(path).startswith(("http://", "https://"))
        else urljoin(f"{target.base_url.rstrip('/')}/", str(path))
        for path in scenario.seed_paths
    ]


def _seed_action(run_id: str, scenario_id: str, seed_url: str, index: int) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_xss",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=seed_url,
        scope_context={"scenario_id": scenario_id},
        parameters={
            "url": seed_url,
            "artifact_prefix": f"{scenario_id}-seed-{index}",
            "summary": "Development benchmark seed page observed for reflected-input discovery.",
        },
        preconditions=["development_benchmark_running_locally"],
        safety_class=SafetyClass.LOW,
        rationale="Observe configured seed page and extract simple reflected-input candidates.",
        expected_evidence=[EvidenceType.BROWSER_OBSERVATION, EvidenceType.ATTACK_SURFACE_CANDIDATE],
    )


def _discover_candidates(
    page,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    seed_action: ActionRequest,
) -> tuple[ActionResult, EvidenceRecord, list[ReflectedInputCandidate]]:
    result, seed_evidence = BrowserExecutor(safety, store).observe(seed_action, page)
    if result.status != ActionStatus.EXECUTED:
        raise RuntimeError("Seed page observation failed or was blocked by safety boundary.")
    html_path = store.run_dir / seed_evidence.attributes["html_artifact"]
    candidates = discover_reflected_input_candidates(
        seed_evidence.attributes["final_url"],
        html_path.read_text(encoding="utf-8"),
    )
    return result, seed_evidence, candidates


def _rank_candidates(
    candidates: list[ReflectedInputCandidate],
    safety: SafetyBoundary,
) -> list[CandidateRanking]:
    rankings = rank_reflected_input_candidates(
        candidates,
        lambda candidate: safety.evaluate_url(candidate.action_url).approved,
    )
    if rankings and not safety.evaluate_url(rankings[0].candidate.action_url).approved:
        raise RuntimeError("No in-scope reflected-input candidate is available.")
    return rankings


def _build_rankings(
    *,
    candidates: list[ReflectedInputCandidate],
    safety: SafetyBoundary,
    store: RunArtifactStore,
    scenario: ScenarioSpec,
    ranking_run: RankingRunSpec,
) -> tuple[list[CandidateRanking], str | None, LLMRankingResult | None]:
    if ranking_run.ranking_source == "deterministic":
        return _rank_candidates(candidates, safety), None, None
    if ranking_run.model_client is None:
        raise ValueError("LLM ranking run requires a model client")
    result = rank_candidates_with_model(
        candidates=candidates,
        scenario_id=scenario.scenario_id,
        trial_number=ranking_run.trial_number,
        model_client=ranking_run.model_client,
        settings=ranking_run.model_settings,
    )
    artifact = store.save_artifact_text(
        f"llm/{scenario.scenario_id}-trial-{ranking_run.trial_number}-ranking.json",
        json.dumps(to_json_value(ranking_result_artifact(result)), indent=2, sort_keys=True) + "\n",
    )
    by_id = {candidate.candidate_id: candidate for candidate in candidates}
    rankings = [
        CandidateRanking(
            candidate=by_id[candidate_id],
            rank=index + 1,
            score=0,
            rationale=[result.rationales.get(candidate_id, ""), *result.validation_errors],
            selected=index == 0,
        )
        for index, candidate_id in enumerate(result.ordered_candidate_ids)
        if candidate_id in by_id
    ]
    return rankings, str(artifact.relative_to(store.run_dir)), result


def _candidate_evidence_records(
    run_id: str,
    scenario_id: str,
    ranking_source: str,
    trial_number: int,
    test_budget: int,
    rankings: list[CandidateRanking],
    seed_observations: list[tuple[ActionRequest, ActionResult, EvidenceRecord]],
    llm_artifact_ref: str | None,
    llm_result: LLMRankingResult | None,
) -> list[EvidenceRecord]:
    related_action_ids = [seed_action.action_id for seed_action, _, _ in seed_observations]
    return [
        _evidence(
            run_id=run_id,
            evidence_type=EvidenceType.ATTACK_SURFACE_CANDIDATE,
            target_ref=ranking.candidate.action_url,
            summary="Discovered and ranked development benchmark reflected-input candidate.",
            related_action_ids=related_action_ids,
            attributes={
                "scenario_id": scenario_id,
                "ranking_source": ranking_source,
                "trial_number": trial_number,
                "ranking_ruleset_version": RANKING_RULESET_VERSION,
                "test_budget": test_budget,
                "llm_artifact": llm_artifact_ref,
                "model_identifier": llm_result.model_identifier if llm_result else None,
                "provider": llm_result.provider if llm_result else None,
                "latency_ms": llm_result.latency_ms if llm_result else None,
                "prompt_version": llm_result.prompt_version if llm_result else None,
                "usage": llm_result.usage if llm_result else None,
                "cost": llm_result.cost if llm_result else None,
                "model_validation_errors": llm_result.validation_errors if llm_result else [],
                "model_provider_failed": llm_result.provider_failed if llm_result else False,
                "all_candidate_count": len(rankings),
                **candidate_ranking_to_attributes(ranking),
            },
        )
        for ranking in rankings
    ]


def _browser_action(
    run_id: str,
    scenario_id: str,
    url: str,
    expected_marker: str | None,
    artifact_prefix: str,
    rationale: str,
) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_xss",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=url,
        scope_context={"scenario_id": scenario_id},
        parameters={
            "url": url,
            "marker_variable": "__adstfXssMarker",
            "expected_marker": expected_marker,
            "artifact_prefix": artifact_prefix,
            "summary": "Browser observed selected development benchmark candidate.",
        },
        preconditions=["development_benchmark_running_locally"],
        safety_class=SafetyClass.LOW,
        rationale=rationale,
        expected_evidence=[EvidenceType.BROWSER_OBSERVATION],
    )


def _control_evidence(
    run_id: str,
    control_url: str,
    control_action: ActionRequest,
    control_observation_evidence: EvidenceRecord,
    control_marker: str,
    scenario_id: str,
    ranking_source: str,
    trial_number: int,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dev_benchmark_xss",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=control_url,
        created_at=datetime.now(UTC).isoformat(),
        summary="Benign control marker did not set the browser execution marker.",
        data_ref=control_observation_evidence.data_ref,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[control_action.action_id],
        attributes={
            "scenario_id": scenario_id,
            "ranking_source": ranking_source,
            "trial_number": trial_number,
            "is_control_case": True,
            "control_case_passed": control_observation_evidence.attributes["execution_marker_observed"] is False,
            "execution_marker_observed": control_observation_evidence.attributes["execution_marker_observed"],
            "control_marker": control_marker,
            "control_observation_evidence": control_observation_evidence.evidence_id,
            "html_artifact": control_observation_evidence.attributes["html_artifact"],
            "screenshot_artifact": control_observation_evidence.attributes["screenshot_artifact"],
        },
    )


def _ground_truth_path(target: TargetConfig) -> Path:
    configured = Path(str(target.metadata["ground_truth_path"]))
    return configured if configured.is_absolute() else REPO_ROOT / configured


def _evidence(
    *,
    run_id: str,
    evidence_type: EvidenceType,
    target_ref: str,
    summary: str,
    related_action_ids: list[str],
    attributes: dict,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dev_benchmark_xss",
        evidence_type=evidence_type,
        target_ref=target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary=summary,
        data_ref=None,
        redaction_status=RedactionStatus.REDACTED,
        related_action_ids=related_action_ids,
        attributes=attributes,
    )


def _json_records(directory: Path) -> list[dict]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in directory.glob("*.json")]


def _mean(values) -> float | None:
    items = list(values)
    return sum(items) / len(items) if items else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local reflected-input development benchmark integration."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--headed", action="store_true", help="Run Chromium with a visible window.")
    parser.add_argument(
        "--ranking-mode",
        choices=["deterministic", "llm", "both"],
        default="deterministic",
        help="Choose deterministic baseline, bounded LLM ranking, or both.",
    )
    parser.add_argument("--trials", type=int, default=1, help="Number of LLM ranking trials.")
    parser.add_argument(
        "--llm-client",
        choices=["fake", "command"],
        default="fake",
        help="Provider-neutral model client for bounded ranking.",
    )
    parser.add_argument(
        "--fake-llm-strategy",
        default="as_listed",
        choices=[
            "as_listed",
            "reverse",
            "duplicate_first",
            "omit_last",
            "unknown_first",
            "malformed",
            "timeout",
            "provider_failure",
        ],
    )
    parser.add_argument(
        "--llm-command",
        nargs=argparse.REMAINDER,
        help="Command model client. Receives JSON on stdin and writes model response to stdout.",
    )
    args = parser.parse_args()
    model_client: ModelClient | None = None
    if args.ranking_mode in {"llm", "both"}:
        if args.llm_client == "command":
            if not args.llm_command:
                parser.error("--llm-command is required when --llm-client command is used")
            model_client = CommandModelClient(args.llm_command)
        else:
            model_client = FakeModelClient(strategy=args.fake_llm_strategy)
    try:
        run_dir = run_development_benchmark_reflected_xss(
            args.config,
            args.output_root,
            headless=not args.headed,
            ranking_mode=args.ranking_mode,
            llm_trials=args.trials,
            model_client=model_client,
            model_settings={"temperature": 0.0},
        )
    except Exception as exc:
        print(f"Development benchmark reflected-XSS integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Development benchmark reflected-XSS artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
