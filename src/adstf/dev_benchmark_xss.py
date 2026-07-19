from __future__ import annotations

import argparse
import json
import sys
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
from adstf.execution import HttpExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "reflected-dev-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


def run_development_benchmark_reflected_xss(
    config_path: Path,
    output_root: Path,
    headless: bool = True,
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

    marker = f"adstf_xss_{run_id.replace('-', '_')}"
    control_marker = f"adstf_control_{run_id.replace('-', '_')}"
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(base_url=target.base_url)
        try:
            page = context.new_page()
            seed_observations: list[tuple[ActionRequest, ActionResult, EvidenceRecord]] = []
            candidates: list[ReflectedInputCandidate] = []
            for index, seed_url in enumerate(_seed_urls(target), start=1):
                seed_action = _seed_action(run_id, seed_url, index)
                store.save_action_request(seed_action)
                seed_result, seed_evidence, discovered = _discover_candidates(
                    page,
                    safety,
                    store,
                    seed_action,
                )
                store.save_evidence(seed_evidence)
                store.save_action_result(seed_result)
                seed_observations.append((seed_action, seed_result, seed_evidence))
                candidates.extend(discovered)

            rankings = _rank_candidates(candidates, safety)
            if not rankings:
                raise RuntimeError("No simple GET reflected-input candidates were discovered.")
            candidate_evidence = _candidate_evidence_records(run_id, rankings, seed_observations)
            for evidence in candidate_evidence:
                store.save_evidence(evidence)

            selected_ranking = rankings[0]
            candidate = selected_ranking.candidate
            xss_url = candidate.url_with_value(
                f"<script>window.__adstfXssMarker='{marker}'</script>"
            )
            control_url = candidate.url_with_value(control_marker)
            xss_action = _browser_action(
                run_id,
                xss_url,
                marker,
                "dev-xss-execution",
                "Submit safe marker payload to selected reflected-input candidate.",
            )
            control_action = _browser_action(
                run_id,
                control_url,
                None,
                "dev-xss-control",
                "Submit benign control marker to selected reflected-input candidate.",
            )
            store.save_action_request(xss_action)
            store.save_action_request(control_action)

            browser_executor = BrowserExecutor(safety, store)
            xss_result, xss_evidence = browser_executor.observe(xss_action, page)
            control_result, control_observation_evidence = browser_executor.observe(control_action, page)
        finally:
            context.close()
            browser.close()

    store.save_evidence(xss_evidence)
    store.save_evidence(control_observation_evidence)
    store.save_action_result(xss_result)
    store.save_action_result(control_result)
    if xss_result.status != ActionStatus.EXECUTED or control_result.status != ActionStatus.EXECUTED:
        store.save_report(render_placeholder_report(target, []))
        raise RuntimeError("Browser observation failed or was blocked by safety boundary.")

    control_evidence = _control_evidence(
        run_id,
        control_url,
        control_action,
        control_observation_evidence,
        control_marker,
    )
    verification_note = _evidence(
        run_id=run_id,
        evidence_type=EvidenceType.VERIFICATION_NOTE,
        target_ref=xss_url,
        summary="Reflected-XSS verification used safe JavaScript marker assignment only.",
        related_action_ids=[xss_action.action_id, control_action.action_id],
        attributes={"payload_family": "safe_marker_assignment", "ground_truth_used": False},
    )
    store.save_evidence(control_evidence)
    store.save_evidence(verification_note)

    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=run_id,
        module_id="xss.reflected",
        title="Reflected XSS executes in development benchmark browser context",
        category=modules["xss.reflected"].category,
        affected_target=candidate.url_with_value(""),
        state=FindingState.SUSPECTED,
        hypothesis=(
            "The selected reflected-input candidate executes script supplied through "
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
            "parameter": candidate.parameter_name,
            "candidate_id": candidate.candidate_id,
            "candidate_rank": selected_ranking.rank,
            "candidate_score": selected_ranking.score,
            "candidate_rationale": selected_ranking.rationale,
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
    store.save_report(render_placeholder_report(target, [verified], placeholder=False))

    evaluation = evaluate_run_against_ground_truth(
        store.run_dir,
        _ground_truth_path(target),
    )
    store.save_artifact_text(
        "benchmark-evaluation.json",
        json.dumps(to_json_value(evaluation), indent=2, sort_keys=True) + "\n",
    )

    if verifier_result.outcome != VerificationOutcome.VERIFIED:
        raise RuntimeError(
            "Development benchmark reflected-XSS verification did not produce a verified finding. "
            f"Outcome was {verifier_result.outcome.value}."
        )
    return store.run_dir


def evaluate_run_against_ground_truth(run_dir: Path, ground_truth_path: Path) -> dict:
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    cases = {
        (case["action_path"], case["parameter_name"]): case
        for case in truth["cases"]
    }
    candidate_records = []
    for path in (run_dir / "evidence").glob("*.json"):
        record = json.loads(path.read_text(encoding="utf-8"))
        if record["evidence_type"] == EvidenceType.ATTACK_SURFACE_CANDIDATE.value:
            candidate_records.append(record)
    ranked_candidates = sorted(candidate_records, key=lambda record: record["attributes"]["rank"])
    evaluated_candidates = [
        _evaluate_candidate(record, cases)
        for record in ranked_candidates
    ]
    selected = next(
        (candidate for candidate in evaluated_candidates if candidate["selected"]),
        None,
    )
    findings = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (run_dir / "findings").glob("*.json")
    ]
    return {
        "benchmark_id": truth["benchmark_id"],
        "ground_truth_used_phase": "post_run_evaluation_only",
        "candidate_count": len(evaluated_candidates),
        "vulnerable_candidate_count": sum(1 for candidate in evaluated_candidates if candidate["ground_truth_vulnerable"]),
        "top_rank_is_vulnerable": bool(selected and selected["ground_truth_vulnerable"]),
        "selected_candidate": selected,
        "ranked_candidates": evaluated_candidates,
        "verified_finding_count": sum(1 for finding in findings if finding["state"] == FindingState.VERIFIED.value),
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


def _seed_urls(target: TargetConfig) -> list[str]:
    paths = target.metadata.get("reflected_xss_seed_paths", ["/start"])
    if not isinstance(paths, list) or not paths:
        raise ValueError("Development benchmark target requires reflected_xss_seed_paths")
    return [
        path
        if str(path).startswith(("http://", "https://"))
        else urljoin(f"{target.base_url.rstrip('/')}/", str(path))
        for path in paths
    ]


def _seed_action(run_id: str, seed_url: str, index: int) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_xss",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=seed_url,
        scope_context={},
        parameters={
            "url": seed_url,
            "artifact_prefix": f"dev-seed-{index}",
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


def _candidate_evidence_records(
    run_id: str,
    rankings: list[CandidateRanking],
    seed_observations: list[tuple[ActionRequest, ActionResult, EvidenceRecord]],
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
                "all_candidate_count": len(rankings),
                **candidate_ranking_to_attributes(ranking),
            },
        )
        for ranking in rankings
    ]


def _browser_action(
    run_id: str,
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
        scope_context={},
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local reflected-input development benchmark integration."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--headed", action="store_true", help="Run Chromium with a visible window.")
    args = parser.parse_args()
    try:
        run_dir = run_development_benchmark_reflected_xss(
            args.config,
            args.output_root,
            headless=not args.headed,
        )
    except Exception as exc:
        print(f"Development benchmark reflected-XSS integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Development benchmark reflected-XSS artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
