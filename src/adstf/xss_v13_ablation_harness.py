from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from playwright.sync_api import sync_playwright

from adstf.config import load_target_config
from adstf.contracts import (
    ActionRequest,
    ActionStatus,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
)
from adstf.discovery import (
    CandidateRanking,
    ReflectedInputCandidate,
    candidate_ranking_to_attributes,
    rank_reflected_input_candidates,
)
from adstf.dev_benchmark_xss import _test_candidate
from adstf.execution import HttpExecutor
from adstf.lifecycle import new_id
from adstf.llm_ranking import CommandModelClient, FakeModelClient, LLMRankingResult, ModelClient, rank_candidates_with_model, ranking_result_artifact
from adstf.local_runtime import MODEL_ARTIFACTS, MODEL_ROOT, RUNTIME_ROOT, LlamaCppCliClient, sha256_file as runtime_sha256_file
from adstf.local_runtime_output_boundary import transport_settings
from adstf.local_runtime_readiness import readiness_json_schema
from adstf.metrics import NOT_APPLICABLE, NOT_AVAILABLE, derive_measurements
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.xss_v13_protocol_prep import (
    ARM_IDS,
    CANDIDATE_SNAPSHOT_VERSION,
    LOCAL_CONTINGENCY_MODEL_ID,
    LOCAL_PRIMARY_MODEL_ID,
    PROPRIETARY_MODEL_IDENTIFIER,
    snapshot_contains_forbidden_data,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
HARNESS_VERSION = "xss-v13-ablation-harness-v1"
HARNESS_READINESS_VERSION = "xss-v13-ablation-harness-readiness-v1"
PROTOCOL_TAG = "evaluation-protocol-v1.3"
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.3.md"
TARGET_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "xss-v13-local.json"
SNAPSHOT_PACKAGE_DIR = REPO_ROOT / "results" / "xss-v13-protocol-prep"
SNAPSHOT_DIR = SNAPSHOT_PACKAGE_DIR / "candidate-snapshots"
SNAPSHOT_CHECKSUMS_PATH = SNAPSHOT_PACKAGE_DIR / "checksums.sha256"
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "xss-v13-ablation-harness-readiness"
DEFAULT_AMENDMENT_READINESS_DIR = REPO_ROOT / "results" / "xss-v13-1-amendment-readiness"
FINAL_PACKAGE_DIR = REPO_ROOT / "results" / "xss-v13-ablation-v1.3"
LLAMA_COMPLETION_EXE = RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"
DETERMINISTIC_TRIALS = 1
LLM_TRIALS = 5
FROZEN_TEST_BUDGET = 4
FROZEN_TOP_K_DEFINITION = "top_k = min(test_budget, discovered_candidate_count)"

PROTOCOL_CRITICAL_HASHES = {
    "docs/metrics-definition-v1.3.md": "b089cceb5eddb5400c4eb9d6661226873222d1c372e9230345c7709fb8e411ca",
    "src/adstf/llm_ranking.py": "7f39e73faf024eec0c7bf03e995e63572ad4ccc9c8f895f44bd6ae9a1de89e25",
    "src/adstf/openai_ranking_wrapper.py": "78db929df3ab691cbaa36fdae5a799c68e3dc8f6850b8e1edc0fe4b9f7a3f0df",
    "src/adstf/local_runtime.py": "f663557b94396bc22b7931a40f3981e2c91effb283fa92f91ec571e201210986",
    "src/adstf/local_runtime_output_boundary.py": "d875c00ecea5629d488582343976e0c25c7a85ca95e3297d1382fe4a1ace865c",
    "examples/benchmarks/xss-v13-manifest.json": "afc598b4e8abf050b6fa8ef49998950ea7c3ccde1029d3155b92aa3a6758365b",
    "examples/targets/xss-v13-local.json": "f48ab88eead31af322f8edf7af0e4bf17f67a4475e3450bebeb0f80aeaafbe82",
    "results/local-runtime-output-boundary-v1.3/transport-settings.json": "36c8dfa71b26b655226abec9dbf1a8188f5f915e4accbea672a7e0f86afacfa7",
    "results/local-runtime-provisioning-v1.3/model-metadata/qwen2_5_7b_instruct_gguf_q4_k_m.json": "6c9d90954bf1ceb5933c002fa306dd2455a83e74c642675d463a36f4bb075b6e",
    "results/local-model-calibration-bakeoff-v1.3/selection-decision.json": "c049479d0ea5a375661d91eb28713c448e82bba9403e985a2f85c078674b5a5c",
}

PROTECTED_OUTPUT_DIRS = {
    (REPO_ROOT / "results" / "heldout-evaluation-v1.2-canonical").resolve(),
    (REPO_ROOT / "results" / "heldout-evaluation-v1.2-analysis").resolve(),
    (REPO_ROOT / "results" / "xss-v13-protocol-prep").resolve(),
    (REPO_ROOT / "results" / "xss-v13-structural-validation").resolve(),
    (REPO_ROOT / "results" / "local-model-calibration-bakeoff-v1.3").resolve(),
}
GROUND_TRUTH_PATH = REPO_ROOT / "examples" / "benchmarks" / "xss-v13-ground-truth.json"
PROVIDER_CONNECTIVITY_SCENARIO_ID = "provider-connectivity-readiness-v1.3.1"
AMENDMENT_READINESS_VERSION = "xss-v13-1-amendment-readiness-v1"


class HarnessReadinessError(RuntimeError):
    pass


def build_execution_schedule(snapshots: list[dict[str, Any]]) -> list[dict[str, Any]]:
    schedule: list[dict[str, Any]] = []
    index = 1
    for arm_id in ARM_IDS:
        trials = DETERMINISTIC_TRIALS if arm_id == "deterministic_structural" else LLM_TRIALS
        for trial_number in range(1, trials + 1):
            for snapshot in snapshots:
                schedule.append(
                    {
                        "schedule_index": index,
                        "arm_id": arm_id,
                        "scenario_id": snapshot["scenario_id"],
                        "trial_number": trial_number,
                        "candidate_snapshot_sha256": sha256_json(snapshot["candidate_input"]),
                        "candidate_count": snapshot["candidate_count"],
                        "test_budget": snapshot["test_budget"],
                        "top_k": snapshot["top_k"],
                        "status": "planned_not_executed",
                    }
                )
                index += 1
    return schedule


def load_frozen_snapshots(snapshot_dir: Path = SNAPSHOT_DIR) -> list[dict[str, Any]]:
    snapshots = []
    for path in sorted(snapshot_dir.glob("x13-*.json")):
        snapshots.append(json.loads(path.read_text(encoding="utf-8")))
    return snapshots


def preflight_check(
    *,
    measured_execution: bool,
    output_dir: Path,
    env: Mapping[str, str | None] | None = None,
    allow_existing_readiness_output: bool = False,
) -> dict[str, Any]:
    if env is None:
        env = os.environ
    checks: list[dict[str, Any]] = []
    errors: list[str] = []

    _check("git_tag_ancestor", git_tag_is_ancestor(), checks, errors)
    _check("protocol_file_present", PROTOCOL_PATH.exists(), checks, errors)
    _check_hashes(checks, errors)
    snapshots = load_frozen_snapshots()
    snapshot_validation = validate_snapshot_package(snapshots)
    _check("snapshot_count_24", snapshot_validation["scenario_count"] == 24, checks, errors)
    _check("snapshot_checksums_valid", snapshot_validation["checksums_valid"], checks, errors)
    _check("snapshots_ground_truth_free", not snapshot_validation["snapshots_contain_ground_truth"], checks, errors)
    _check("snapshots_do_not_load_ground_truth_semantics", snapshot_validation["ground_truth_semantics_loaded"] is False, checks, errors)
    _check_qwen_artifacts(checks, errors)
    _check_output_dir(output_dir, checks, errors, allow_existing_readiness_output=allow_existing_readiness_output)

    openai_key_present = bool(env.get("OPENAI_API_KEY"))
    openai_model = env.get("OPENAI_RANKING_MODEL")
    send_temperature = str(env.get("OPENAI_SEND_TEMPERATURE") or "").lower()
    temperature_ok = send_temperature in {"", "0", "false", "no"}
    _check("openai_send_temperature_unset_or_false", temperature_ok, checks, errors)
    if measured_execution:
        _check("openai_api_key_present", openai_key_present, checks, errors)
        _check("openai_model_exact", openai_model == PROPRIETARY_MODEL_IDENTIFIER, checks, errors)
    else:
        checks.append(
            {
                "check": "openai_api_key_present_for_future_measured_execution",
                "passed": openai_key_present,
                "required_for_dry_run": False,
                "secret_value_recorded": False,
            }
        )
        checks.append(
            {
                "check": "openai_model_exact_for_future_measured_execution",
                "passed": openai_model == PROPRIETARY_MODEL_IDENTIFIER,
                "required_for_dry_run": False,
                "expected": PROPRIETARY_MODEL_IDENTIFIER,
                "actual": openai_model or NOT_AVAILABLE,
            }
        )

    return {
        "schema_version": f"{HARNESS_VERSION}-preflight",
        "measured_execution": measured_execution,
        "valid": not errors,
        "errors": errors,
        "checks": checks,
        "snapshot_validation": snapshot_validation,
        "openai_model_identifier_resolved": openai_model or NOT_AVAILABLE,
        "openai_api_key_present": openai_key_present,
        "openai_secret_recorded": False,
        "ground_truth_loaded": False,
    }


def validate_snapshot_package(snapshots: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    if len(snapshots) != 24:
        errors.append("expected exactly 24 snapshots")
    scenario_ids = [snapshot.get("scenario_id") for snapshot in snapshots]
    if scenario_ids != [f"x13-{index:03d}" for index in range(1, 25)]:
        errors.append("snapshot scenario IDs are not the frozen x13-001..x13-024 sequence")
    budget_values = sorted({snapshot.get("test_budget") for snapshot in snapshots})
    if budget_values != [FROZEN_TEST_BUDGET]:
        errors.append(f"snapshot budgets differ from frozen budget {FROZEN_TEST_BUDGET}")
    for snapshot in snapshots:
        if snapshot.get("schema_version") != CANDIDATE_SNAPSHOT_VERSION:
            errors.append(f"{snapshot.get('scenario_id')} has unexpected snapshot schema version")
        if snapshot.get("top_k") != min(int(snapshot.get("test_budget", 0)), int(snapshot.get("candidate_count", 0))):
            errors.append(f"{snapshot.get('scenario_id')} has unexpected top_k")
        if snapshot_contains_forbidden_data(snapshot):
            errors.append(f"{snapshot.get('scenario_id')} contains ground-truth-like fields")

    checksum_errors = validate_checksum_file(SNAPSHOT_CHECKSUMS_PATH)
    errors.extend(checksum_errors)
    return {
        "scenario_count": len(snapshots),
        "scenario_ids": scenario_ids,
        "candidate_count_distribution": dict(Counter(str(snapshot.get("candidate_count")) for snapshot in snapshots)),
        "budget_values": budget_values,
        "top_k_definition": FROZEN_TOP_K_DEFINITION,
        "checksums_valid": not checksum_errors,
        "checksum_errors": checksum_errors,
        "snapshots_contain_ground_truth": any(snapshot_contains_forbidden_data(snapshot) for snapshot in snapshots),
        "ground_truth_semantics_loaded": False,
        "errors": errors,
        "valid": not errors,
    }


def create_proprietary_gpt_client(env: Mapping[str, str | None] | None = None) -> ModelClient:
    if env is None:
        env = os.environ
    if env.get("OPENAI_RANKING_MODEL") != PROPRIETARY_MODEL_IDENTIFIER:
        raise HarnessReadinessError("OPENAI_RANKING_MODEL must resolve to the frozen proprietary model identifier")
    return CommandModelClient(["python", "-m", "adstf.openai_ranking_wrapper"], model_identifier=PROPRIETARY_MODEL_IDENTIFIER, timeout_seconds=60)


def create_local_qwen_client(schema_path: Path) -> LlamaCppCliClient:
    model = _local_model_artifact(LOCAL_PRIMARY_MODEL_ID)
    model_path = MODEL_ROOT / model.candidate_id / model.primary_model_filename
    if not model_path.exists():
        raise HarnessReadinessError("frozen Qwen model artifact is missing")
    return LlamaCppCliClient(
        executable=LLAMA_COMPLETION_EXE,
        model_path=model_path,
        model_identifier="Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M",
        timeout_seconds=300,
        context_size_tokens=4096,
        max_output_tokens=768,
        temperature=0.0,
        top_p=1.0,
        seed=42,
        threads=8,
        json_schema_path=schema_path,
    )


def provider_connectivity_readiness(
    *,
    model_client: ModelClient | None = None,
    env: Mapping[str, str | None] | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    live_provider_call_executed = model_client is None
    if model_client is None:
        model_client = create_proprietary_gpt_client(env)
    candidates = _provider_readiness_candidates()
    result = rank_candidates_with_model(
        candidates=candidates,
        scenario_id=PROVIDER_CONNECTIVITY_SCENARIO_ID,
        trial_number=0,
        model_client=model_client,
        settings={
            "temperature_parameter": "omitted",
            "provider_default_temperature_used": True,
            "max_output_tokens": 1200,
            "non_scored_readiness": True,
        },
    )
    report = {
        "schema_version": "xss-v13-1-provider-connectivity-readiness-v1",
        "status": "non_scored_provider_connectivity_readiness",
        "execution_mode": "live_provider_connectivity" if live_provider_call_executed else "fake_offline_validation",
        "live_provider_call_executed": live_provider_call_executed,
        "held_out_scenario_used": False,
        "scored_observation_created": False,
        "scenario_id": PROVIDER_CONNECTIVITY_SCENARIO_ID,
        "model_identifier": result.model_identifier,
        "prompt_version": result.prompt_version,
        "provider": result.provider,
        "provider_failed": result.provider_failed,
        "validation_errors": result.validation_errors,
        "raw_response_present": result.raw_response is not None,
        "usage_present": result.usage is not None,
        "cost_present": result.cost is not None,
        "latency_ms": result.latency_ms if result.latency_ms is not None else NOT_AVAILABLE,
        "candidate_count": len(candidates),
        "parsed_candidate_count": len(result.ordered_candidate_ids),
        "valid": result.is_valid,
        "artifact": ranking_result_artifact(result),
    }
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        _write_json(output_dir / "provider-connectivity-readiness.json", report)
    return report


def build_amendment_readiness_package(output_dir: Path = DEFAULT_AMENDMENT_READINESS_DIR) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    provider_readiness = provider_connectivity_readiness(
        model_client=FakeModelClient(model_identifier=PROPRIETARY_MODEL_IDENTIFIER),
    )
    timestamp_validation = timestamp_metric_dry_validation()
    validation = {
        "schema_version": f"{AMENDMENT_READINESS_VERSION}-validation",
        "valid": provider_readiness["valid"] and timestamp_validation["valid"],
        "provider_readiness_live_call_executed": False,
        "scored_experiment_executed": False,
        "browser_verification_executed": False,
        "local_qwen_inference_executed": False,
        "ground_truth_loaded": False,
        "errors": [
            *([] if provider_readiness["valid"] else ["fake provider readiness failed"]),
            *timestamp_validation["errors"],
        ],
    }
    manifest = {
        "schema_version": AMENDMENT_READINESS_VERSION,
        "status": "draft_amendment_readiness_only_no_scored_execution",
        "created_at": datetime.now(UTC).isoformat(),
        "base_protocol_tag": PROTOCOL_TAG,
        "draft_protocol": "docs/evaluation-protocol-v1.3.1.md",
        "provider_connectivity_readiness": "provider-connectivity-readiness.json",
        "timestamp_metric_dry_validation": "timestamp-metric-dry-validation.json",
        "validation_report": "validation-report.json",
    }
    _write_json(output_dir / "manifest.json", manifest)
    _write_json(output_dir / "provider-connectivity-readiness.json", provider_readiness)
    _write_json(output_dir / "timestamp-metric-dry-validation.json", timestamp_validation)
    _write_json(output_dir / "validation-report.json", validation)
    _write_text(output_dir / "report.md", render_amendment_readiness_report(validation, provider_readiness, timestamp_validation))
    _write_text(output_dir / "thesis-readiness-table.md", render_amendment_readiness_table(validation, provider_readiness, timestamp_validation))
    checksum_paths = [path for path in sorted(output_dir.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    _write_text(output_dir / "checksums.sha256", render_checksums(checksum_paths))
    return {
        "manifest": manifest,
        "provider_readiness": provider_readiness,
        "timestamp_validation": timestamp_validation,
        "validation": validation,
    }


def timestamp_metric_dry_validation() -> dict[str, Any]:
    measurements = derive_measurements(
        action_requests=[
            {
                "action_id": "action-1",
                "action_type": "observe_browser",
                "scope_context": {"candidate_id": "candidate-a"},
                "parameters": {},
            }
        ],
        action_results=[
            {
                "action_id": "action-1",
                "status": "executed",
                "started_at": "2026-08-08T10:00:00+00:00",
                "completed_at": "2026-08-08T10:00:02+00:00",
                "normalized_observations": {"browser_navigation_count": 1, "candidate_id": "candidate-a"},
            }
        ],
        findings=[
            {
                "state": "verified",
                "report_fields": {"verification_completed_at": "2026-08-08T10:00:03+00:00"},
            }
        ],
        verifier_results=[{"outcome": "verified", "completed_at": "2026-08-08T10:00:03+00:00"}],
        candidate_based=True,
    )
    first = measurements["first_verified_finding"]
    expected = {
        "timestamp": "2026-08-08T10:00:03+00:00",
        "time_to_first_verified_finding_ms": 3000,
        "requests_to_first_verified_finding": 1,
        "candidates_tested_before_first_verification": 1,
    }
    errors = [
        key
        for key, expected_value in expected.items()
        if first.get(key) != expected_value
    ]
    return {
        "schema_version": "xss-v13-1-timestamp-metric-dry-validation-v1",
        "valid": not errors,
        "errors": errors,
        "clock_source": "timezone-aware UTC datetime captured by the deterministic verifier at completion",
        "timestamp_field": "FindingRecord.report_fields.verification_completed_at",
        "file_time_reconstruction_used": False,
        "measurements": measurements,
        "expected_first_verified_finding": expected,
    }


def run_measured_xss_v13_ablation(
    *,
    output_root: Path = FINAL_PACKAGE_DIR,
    headless: bool = True,
    env: Mapping[str, str | None] | None = None,
) -> Path:
    preflight = preflight_check(measured_execution=True, output_dir=output_root, env=env)
    if not preflight["valid"]:
        raise HarnessReadinessError("measured execution preflight failed: " + "; ".join(preflight["errors"]))
    target = load_target_config(TARGET_CONFIG_PATH)
    snapshots = load_frozen_snapshots()
    run_id = f"xss-v13-ablation-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)
    store.save_artifact_text(
        "preflight-report.json",
        json.dumps(to_json_value(preflight), indent=2, sort_keys=True) + "\n",
    )

    safety = SafetyBoundary(target)
    smoke_action = _health_action(store.run_id, target)
    store.save_action_request(smoke_action)
    smoke_result, smoke_evidence = HttpExecutor(safety).execute(smoke_action)
    for evidence in smoke_evidence:
        store.save_evidence(evidence)
    store.save_action_result(smoke_result)
    if smoke_result.status != ActionStatus.EXECUTED:
        store.save_report(render_placeholder_report(target, []))
        raise HarnessReadinessError("v1.3 XSS benchmark target is not reachable or was blocked by safety preflight")

    clients = {
        "proprietary_gpt": create_proprietary_gpt_client(env),
    }
    model_settings = {
        "proprietary_gpt": {
            "temperature_parameter": "omitted",
            "provider_default_temperature_used": True,
        },
    }

    all_findings: list[FindingRecord] = []
    scenario_summaries: list[dict[str, Any]] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(base_url=target.base_url)
        try:
            page = context.new_page()
            for schedule_item in build_execution_schedule(snapshots):
                snapshot = next(item for item in snapshots if item["scenario_id"] == schedule_item["scenario_id"])
                rankings, llm_ref, llm_result = _rank_snapshot_for_arm(
                    snapshot=snapshot,
                    arm_id=schedule_item["arm_id"],
                    trial_number=int(schedule_item["trial_number"]),
                    target=target,
                    safety=safety,
                    store=store,
                    model_client=clients.get(schedule_item["arm_id"]),
                    model_settings=model_settings.get(schedule_item["arm_id"]),
                )
                if not rankings:
                    scenario_summaries.append(_skipped_scenario_summary(schedule_item, "no_ranked_candidates"))
                    continue
                candidate_evidence = _snapshot_candidate_evidence_records(
                    store.run_id,
                    snapshot,
                    schedule_item["arm_id"],
                    int(schedule_item["trial_number"]),
                    rankings,
                    llm_ref,
                    llm_result,
                )
                for evidence in candidate_evidence:
                    store.save_evidence(evidence)

                tested_findings: list[FindingRecord] = []
                tested_candidates: list[dict[str, Any]] = []
                verified_finding: FindingRecord | None = None
                for ranking in rankings[: FROZEN_TEST_BUDGET]:
                    tested_candidates.append(
                        {
                            "rank": ranking.rank,
                            "candidate_id": ranking.candidate.candidate_id,
                            "score": ranking.score,
                        }
                    )
                    finding = _test_candidate(
                        scenario=_scenario_spec_from_snapshot(snapshot),
                        ranking_run=_ranking_run_spec(schedule_item),
                        ranking=ranking,
                        page=page,
                        safety=safety,
                        store=store,
                        modules=mvp_modules(),
                        smoke_evidence=smoke_evidence,
                        seed_observations=[],
                        candidate_evidence=candidate_evidence,
                    )
                    tested_findings.append(finding)
                    if finding.state == FindingState.VERIFIED:
                        verified_finding = finding
                        break
                all_findings.extend(tested_findings)
                scenario_summaries.append(
                    {
                        "scenario_id": snapshot["scenario_id"],
                        "arm_id": schedule_item["arm_id"],
                        "trial_number": schedule_item["trial_number"],
                        "candidate_count": len(rankings),
                        "test_budget": FROZEN_TEST_BUDGET,
                        "top_k": min(FROZEN_TEST_BUDGET, len(rankings)),
                        "tested_candidate_count": len(tested_candidates),
                        "verified_finding_id": verified_finding.finding_id if verified_finding else None,
                        "tested_candidates": tested_candidates,
                    }
                )
        finally:
            context.close()
            browser.close()

    store.save_artifact_text(
        "scenario-run-summary.json",
        json.dumps(to_json_value(scenario_summaries), indent=2, sort_keys=True) + "\n",
    )
    canonical = build_canonical_package_from_run(store.run_dir, output_root / "canonical")
    store.save_artifact_text(
        "canonical-summary.json",
        json.dumps(to_json_value(canonical), indent=2, sort_keys=True) + "\n",
    )
    store.save_report(_render_measured_report(target, all_findings, canonical))
    return store.run_dir


def _rank_snapshot_for_arm(
    *,
    snapshot: dict[str, Any],
    arm_id: str,
    trial_number: int,
    target: TargetConfig,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    model_client: ModelClient | None,
    model_settings: dict[str, Any] | None,
) -> tuple[list[CandidateRanking], str | None, LLMRankingResult | None]:
    candidates = snapshot_to_candidates(snapshot, target.base_url)
    if arm_id == "deterministic_structural":
        return (
            rank_reflected_input_candidates(
                candidates,
                lambda candidate: safety.evaluate_url(candidate.action_url).approved,
            ),
            None,
            None,
        )
    if arm_id not in {"proprietary_gpt", "local_qwen"}:
        raise HarnessReadinessError(f"unknown frozen arm id: {arm_id}")
    if arm_id == "local_qwen":
        schema_path = write_scenario_schema(
            snapshot,
            store.run_dir / "artifacts" / "schemas" / f"{snapshot['scenario_id']}-trial-{trial_number}.schema.json",
        )
        model_client = create_local_qwen_client(schema_path)
        model_settings = local_qwen_settings_for_schema(schema_path)
    if model_client is None:
        raise HarnessReadinessError(f"missing model client for {arm_id}")
    result = rank_candidates_with_model(
        candidates=candidates,
        scenario_id=snapshot["scenario_id"],
        trial_number=trial_number,
        model_client=model_client,
        settings=model_settings or {},
    )
    artifact = store.save_artifact_text(
        f"ranking/{arm_id}/{snapshot['scenario_id']}-trial-{trial_number}.json",
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


def build_canonical_package_from_run(run_dir: Path, output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=False)
    case_rows = _case_rows_from_run(run_dir)
    ground_truth = json.loads(GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    scored = score_post_run_cases(case_rows, ground_truth)
    measurements = derive_measurements_from_artifact_rows(run_dir, scored["rows"])
    manifest = {
        "schema_version": "xss-v13-ablation-canonical-package-v1",
        "protocol_tag": PROTOCOL_TAG,
        "source_run_dir": display_path(run_dir),
        "ground_truth_used_phase": "post_run_scoring_only",
        "scenario_count": 24,
        "arm_ids": list(ARM_IDS),
        "case_row_count": len(scored["rows"]),
    }
    _write_json(output_dir / "manifest.json", manifest)
    _write_json(output_dir / "normalized" / "case-results.json", scored)
    _write_csv(output_dir / "normalized" / "case-results.csv", scored["rows"])
    _write_json(output_dir / "normalized" / "measurement-summary.json", measurements)
    _write_text(output_dir / "report.md", _render_canonical_report(manifest, scored, measurements))
    _write_text(output_dir / "tables" / "thesis-tables.md", "# XSS v1.3 Ablation Results\n\nGenerated after measured execution only.\n")
    _write_text(output_dir / "tables" / "thesis-tables.tex", "% Generated after measured execution only.\n")
    _write_json(output_dir / "figures" / "source-data.json", {"case_results": scored["rows"]})
    checksum_paths = [path for path in sorted(output_dir.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    _write_text(output_dir / "checksums.sha256", render_checksums(checksum_paths))
    return manifest


def derive_measurements_from_artifact_rows(run_dir: Path, case_rows: list[dict[str, Any]]) -> dict[str, Any]:
    model_artifact_paths = sorted((run_dir / "artifacts" / "ranking").glob("*/*.json"))
    return derive_measurements(
        action_requests=_json_records(run_dir / "actions"),
        action_results=_json_records(run_dir / "results"),
        evidence_records=_json_records(run_dir / "evidence"),
        findings=_json_records(run_dir / "findings"),
        verifier_results=_json_records(run_dir / "verification"),
        model_artifacts=[json.loads(path.read_text(encoding="utf-8")) for path in model_artifact_paths],
        case_rows=case_rows,
        arm_type="framework",
        candidate_based=True,
    )


def _case_rows_from_run(run_dir: Path) -> list[dict[str, Any]]:
    findings = _json_records(run_dir / "findings")
    rows: list[dict[str, Any]] = []
    for finding in findings:
        fields = finding.get("report_fields") or {}
        candidate_id = fields.get("candidate_id")
        if not candidate_id:
            continue
        rows.append(
            {
                "scenario_id": fields.get("scenario_id"),
                "arm_id": fields.get("ranking_source"),
                "trial_number": fields.get("trial_number"),
                "candidate_id": candidate_id,
                "action_path": _path_from_target(finding.get("affected_target")),
                "parameter_name": fields.get("parameter"),
                "verified": finding.get("state") == FindingState.VERIFIED.value,
                "finding_id": finding.get("finding_id"),
            }
        )
    return rows


def _snapshot_candidate_evidence_records(
    run_id: str,
    snapshot: dict[str, Any],
    arm_id: str,
    trial_number: int,
    rankings: list[CandidateRanking],
    llm_artifact_ref: str | None,
    llm_result: LLMRankingResult | None,
) -> list[EvidenceRecord]:
    return [
        EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=run_id,
            source="xss_v13_ablation_harness",
            evidence_type=EvidenceType.ATTACK_SURFACE_CANDIDATE,
            target_ref=ranking.candidate.action_url,
            created_at=datetime.now(UTC).isoformat(),
            summary="Frozen v1.3 candidate snapshot ranked for the ablation study.",
            data_ref=None,
            redaction_status=RedactionStatus.REDACTED,
            related_action_ids=[],
            attributes={
                "scenario_id": snapshot["scenario_id"],
                "ranking_source": arm_id,
                "trial_number": trial_number,
                "ranking_ruleset_version": "deterministic-structural-v1" if arm_id == "deterministic_structural" else None,
                "test_budget": FROZEN_TEST_BUDGET,
                "top_k": min(FROZEN_TEST_BUDGET, len(rankings)),
                "candidate_snapshot_sha256": sha256_json(snapshot["candidate_input"]),
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


def _health_action(run_id: str, target: TargetConfig) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="xss_v13_ablation_harness",
        module_id=None,
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=target.base_url,
        scope_context={"purpose": "local_v13_health_check"},
        parameters={"method": "GET", "url": target.base_url, "allow_redirects": False},
        preconditions=["local_xss_v13_benchmark_running"],
        safety_class=SafetyClass.LOW,
        rationale="Confirm the frozen local v1.3 XSS target is reachable before measured execution.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def _scenario_spec_from_snapshot(snapshot: dict[str, Any]):
    from adstf.dev_benchmark_xss import ScenarioSpec

    return ScenarioSpec(
        scenario_id=snapshot["scenario_id"],
        seed_paths=[],
        test_budget=FROZEN_TEST_BUDGET,
    )


def _ranking_run_spec(schedule_item: dict[str, Any]):
    from adstf.dev_benchmark_xss import RankingRunSpec

    return RankingRunSpec(
        ranking_source=schedule_item["arm_id"],
        trial_number=int(schedule_item["trial_number"]),
    )


def _skipped_scenario_summary(schedule_item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "scenario_id": schedule_item["scenario_id"],
        "arm_id": schedule_item["arm_id"],
        "trial_number": schedule_item["trial_number"],
        "status": "skipped",
        "reason": reason,
    }


def _render_measured_report(target: TargetConfig, findings: list[FindingRecord], canonical: dict[str, Any]) -> str:
    verified = sum(1 for finding in findings if finding.state == FindingState.VERIFIED)
    return (
        f"# {target.name} XSS v1.3 Ablation Run\n\n"
        f"- Protocol tag: `{PROTOCOL_TAG}`\n"
        f"- Verifier-confirmed findings: `{verified}`\n"
        f"- Canonical package: `{canonical.get('source_run_dir')}`\n"
        "- Ground truth phase: `post_run_scoring_only`\n"
    )


def _render_canonical_report(manifest: dict[str, Any], scored: dict[str, Any], measurements: dict[str, Any]) -> str:
    counts = Counter(row["classification"] for row in scored["rows"])
    return (
        "# XSS v1.3 Ablation Canonical Package\n\n"
        f"- Protocol tag: `{manifest['protocol_tag']}`\n"
        f"- Source run: `{manifest['source_run_dir']}`\n"
        f"- Case rows: `{manifest['case_row_count']}`\n"
        f"- TP: `{counts.get('TP', 0)}`\n"
        f"- FP: `{counts.get('FP', 0)}`\n"
        f"- FN: `{counts.get('FN', 0)}`\n"
        f"- TN: `{counts.get('TN', 0)}`\n"
        f"- Action requests: `{measurements['action_counts']['requested']}`\n"
        "- Scanner alerts are not part of this XSS ablation package.\n"
    )


def _json_records(directory: Path) -> list[dict[str, Any]]:
    if not directory.exists():
        return []
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.json"))]


def _path_from_target(target_ref: str | None) -> str:
    if not target_ref:
        return ""
    from urllib.parse import urlparse

    return urlparse(target_ref).path


def _provider_readiness_candidates() -> list[ReflectedInputCandidate]:
    base_url = "http://127.0.0.1/provider-connectivity-readiness-v1.3.1"
    return [
        ReflectedInputCandidate(
            candidate_id="provider-readiness:candidate-a",
            page_url=f"{base_url}/page-a",
            action_url=f"{base_url}/action-a",
            method="GET",
            parameter_name="alpha",
            source="synthetic_readiness",
            input_type="text",
            editable_input_count=1,
            required_input_count=0,
            parameter_count=1,
        ),
        ReflectedInputCandidate(
            candidate_id="provider-readiness:candidate-b",
            page_url=f"{base_url}/page-b",
            action_url=f"{base_url}/action-b",
            method="GET",
            parameter_name="beta",
            source="synthetic_readiness",
            input_type="text",
            editable_input_count=1,
            required_input_count=0,
            parameter_count=1,
        ),
    ]


def render_amendment_readiness_report(
    validation: dict[str, Any],
    provider_readiness: dict[str, Any],
    timestamp_validation: dict[str, Any],
) -> str:
    return (
        "# XSS v1.3.1 Amendment Readiness\n\n"
        "Status: draft amendment readiness only. No scored experiment, live provider call, "
        "local-model inference, browser verification, or ground-truth scoring was executed.\n\n"
        f"- Validation valid: `{validation['valid']}`\n"
        f"- Fake provider readiness valid: `{provider_readiness['valid']}`\n"
        f"- Timestamp metric dry validation valid: `{timestamp_validation['valid']}`\n"
        f"- Timestamp source: `{timestamp_validation['timestamp_field']}`\n"
        f"- File-time reconstruction used: `{timestamp_validation['file_time_reconstruction_used']}`\n"
        f"- Scored experiment executed: `{validation['scored_experiment_executed']}`\n"
    )


def render_amendment_readiness_table(
    validation: dict[str, Any],
    provider_readiness: dict[str, Any],
    timestamp_validation: dict[str, Any],
) -> str:
    return (
        "# XSS v1.3.1 Amendment Readiness Table\n\n"
        "| Check | Result |\n"
        "| --- | --- |\n"
        f"| Overall validation | `{validation['valid']}` |\n"
        f"| Provider readiness mechanism | `{provider_readiness['valid']}` |\n"
        f"| Timestamp metric fixture | `{timestamp_validation['valid']}` |\n"
        f"| Live provider call executed | `{validation['provider_readiness_live_call_executed']}` |\n"
        f"| Scored experiment executed | `{validation['scored_experiment_executed']}` |\n"
    )


def deterministic_rank_snapshot(snapshot: dict[str, Any], base_url: str) -> list[str]:
    candidates = snapshot_to_candidates(snapshot, base_url)
    ranked = rank_reflected_input_candidates(candidates, lambda _candidate: True)
    return [item.candidate.candidate_id for item in ranked]


def snapshot_to_candidates(snapshot: dict[str, Any], base_url: str) -> list[ReflectedInputCandidate]:
    return [
        ReflectedInputCandidate(
            candidate_id=item["candidate_id"],
            page_url=f"{base_url.rstrip('/')}{item['action_path']}",
            action_url=f"{base_url.rstrip('/')}{item['action_path']}",
            method=item["method"],
            parameter_name=item["parameter_name"],
            source=item["source"],
            input_type=item["input_type"],
            editable_input_count=int(item["editable_input_count"]),
            required_input_count=int(item["required_input_count"]),
            parameter_count=int(item["parameter_count"]),
        )
        for item in snapshot["candidate_input"]
    ]


def score_post_run_cases(case_rows: list[dict[str, Any]], ground_truth: dict[str, Any]) -> dict[str, Any]:
    truth_by_case = {
        (scenario["scenario_id"], case["action_path"], case["parameter_name"]): bool(case["vulnerable"])
        for scenario in ground_truth.get("scenarios", [])
        for case in scenario.get("cases", [])
    }
    scored = []
    for row in case_rows:
        key = (row["scenario_id"], row["action_path"], row["parameter_name"])
        expected = truth_by_case.get(key)
        if expected is None:
            classification = "not_available"
        elif row.get("verified") and expected:
            classification = "TP"
        elif row.get("verified") and not expected:
            classification = "FP"
        elif not row.get("verified") and expected:
            classification = "FN"
        else:
            classification = "TN"
        scored.append({**row, "ground_truth_vulnerable": expected if expected is not None else NOT_AVAILABLE, "classification": classification})
    return {
        "schema_version": f"{HARNESS_VERSION}-post-run-scoring",
        "ground_truth_phase": "post_run_only",
        "case_count": len(scored),
        "rows": scored,
    }


def build_harness_readiness_package(output_dir: Path = DEFAULT_READINESS_DIR) -> dict[str, Any]:
    preflight = preflight_check(
        measured_execution=False,
        output_dir=output_dir,
        allow_existing_readiness_output=True,
    )
    if not preflight["valid"]:
        raise HarnessReadinessError("harness preflight failed: " + "; ".join(preflight["errors"]))
    snapshots = load_frozen_snapshots()
    schedule = build_execution_schedule(snapshots)
    arm_summary = summarize_schedule(schedule)
    scenario_summary = summarize_scenarios(snapshots, schedule)
    measurement_templates = measurement_template_summary()
    package = {
        "manifest": readiness_manifest(output_dir, preflight, schedule),
        "preflight": preflight,
        "schedule": schedule,
        "arm_summary": arm_summary,
        "scenario_summary": scenario_summary,
        "measurement_templates": measurement_templates,
        "validation": validate_harness_readiness(preflight, snapshots, schedule, arm_summary),
        "post_run_scoring_interface": {
            "schema_version": f"{HARNESS_VERSION}-post-run-scoring-interface",
            "ground_truth_loaded_during_preflight_or_dry_run": False,
            "ground_truth_may_load_only_after_execution_complete": True,
            "function": "adstf.xss_v13_ablation_harness.score_post_run_cases",
        },
    }
    write_readiness_package(package, output_dir)
    return package


def summarize_schedule(schedule: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for arm_id in ARM_IDS:
        items = [item for item in schedule if item["arm_id"] == arm_id]
        rows.append(
            {
                "arm_id": arm_id,
                "scenario_count": len({item["scenario_id"] for item in items}),
                "scheduled_ranking_calls": len(items),
                "trials_per_scenario": DETERMINISTIC_TRIALS if arm_id == "deterministic_structural" else LLM_TRIALS,
                "max_candidate_tests": sum(item["top_k"] for item in items),
                "provider_calls": 0 if arm_id == "deterministic_structural" else len(items),
                "dry_run_status": "planned_not_executed",
            }
        )
    return rows


def summarize_scenarios(snapshots: list[dict[str, Any]], schedule: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for snapshot in snapshots:
        items = [item for item in schedule if item["scenario_id"] == snapshot["scenario_id"]]
        rows.append(
            {
                "scenario_id": snapshot["scenario_id"],
                "candidate_count": snapshot["candidate_count"],
                "test_budget": snapshot["test_budget"],
                "top_k": snapshot["top_k"],
                "scheduled_ranking_calls": len(items),
                "max_candidate_tests": sum(item["top_k"] for item in items),
                "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
            }
        )
    return rows


def measurement_template_summary() -> dict[str, Any]:
    return {
        "schema_version": f"{HARNESS_VERSION}-measurement-template",
        "deterministic_structural": derive_measurements(arm_type="deterministic", candidate_based=True),
        "proprietary_gpt": derive_measurements(arm_type="proprietary_llm", candidate_based=True),
        "local_qwen": derive_measurements(arm_type="local_llm", candidate_based=True),
        "note": "Dry-run templates contain no experimental observations or model calls.",
    }


def validate_harness_readiness(
    preflight: dict[str, Any],
    snapshots: list[dict[str, Any]],
    schedule: list[dict[str, Any]],
    arm_summary: list[dict[str, Any]],
) -> dict[str, Any]:
    errors: list[str] = []
    expected_counts = {
        "deterministic_structural": 24,
        "proprietary_gpt": 120,
        "local_qwen": 120,
    }
    if not preflight["valid"]:
        errors.extend(preflight["errors"])
    if len(snapshots) != 24:
        errors.append("expected 24 snapshots")
    if len(schedule) != 264:
        errors.append("expected 264 scheduled ranking rows")
    for row in arm_summary:
        if row["scheduled_ranking_calls"] != expected_counts[row["arm_id"]]:
            errors.append(f"{row['arm_id']} scheduled denominator mismatch")
    if any(item["test_budget"] != FROZEN_TEST_BUDGET or item["top_k"] != FROZEN_TEST_BUDGET for item in schedule):
        errors.append("schedule does not enforce frozen budget/top-k")
    if any(item["status"] != "planned_not_executed" for item in schedule):
        errors.append("dry-run schedule contains executed items")
    return {
        "schema_version": f"{HARNESS_READINESS_VERSION}-validation",
        "valid": not errors,
        "errors": errors,
        "expected_schedule_rows": 264,
        "actual_schedule_rows": len(schedule),
        "expected_arm_denominators": expected_counts,
        "scored_calls_executed": False,
        "proprietary_api_calls_executed": False,
        "local_model_calls_executed": False,
        "browser_vulnerability_verification_executed": False,
        "zap_executed": False,
        "ground_truth_loaded": False,
    }


def readiness_manifest(output_dir: Path, preflight: dict[str, Any], schedule: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": HARNESS_READINESS_VERSION,
        "artifact_status": "harness_readiness_dry_run_no_scored_execution",
        "created_at": datetime.now(UTC).isoformat(),
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": git_output(["rev-parse", "HEAD"]),
        "arm_ids": list(ARM_IDS),
        "scenario_count": 24,
        "candidate_snapshot_count": preflight["snapshot_validation"]["scenario_count"],
        "scheduled_ranking_rows": len(schedule),
        "package_path": display_path(output_dir),
        "v1_2_artifacts_modified": False,
        "previous_v1_3_packages_overwritten": False,
    }


def write_readiness_package(package: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "raw").mkdir(exist_ok=True)
    (output_dir / "normalized").mkdir(exist_ok=True)
    (output_dir / "tables").mkdir(exist_ok=True)
    (output_dir / "figures").mkdir(exist_ok=True)

    _write_json(output_dir / "manifest.json", package["manifest"])
    _write_json(output_dir / "preflight-report.json", package["preflight"])
    _write_json(output_dir / "validation-report.json", package["validation"])
    _write_json(output_dir / "post-run-scoring-interface.json", package["post_run_scoring_interface"])
    _write_json(output_dir / "measurement-templates.json", package["measurement_templates"])
    _write_json(output_dir / "normalized" / "execution-schedule.json", package["schedule"])
    _write_csv(output_dir / "normalized" / "execution-schedule.csv", package["schedule"])
    _write_csv(output_dir / "normalized" / "arm-summary.csv", package["arm_summary"])
    _write_csv(output_dir / "normalized" / "scenario-summary.csv", package["scenario_summary"])
    _write_json(output_dir / "figures" / "schedule-source.json", package["arm_summary"])
    _write_csv(output_dir / "figures" / "schedule-source.csv", package["arm_summary"])
    _write_text(output_dir / "figures" / "README.md", "Figure PNG/PDF files are produced only after measured execution. This dry-run package contains source data only.\n")
    _write_text(output_dir / "report.md", render_readiness_report(package))
    _write_text(output_dir / "tables" / "thesis-tables.md", render_thesis_tables(package))
    _write_text(output_dir / "tables" / "thesis-tables.tex", render_thesis_tables_latex())
    for item in package["schedule"]:
        _write_json(output_dir / "raw" / f"{item['schedule_index']:03d}-{item['arm_id']}-{item['scenario_id']}-trial-{item['trial_number']}.json", item)

    checksum_paths = [
        path
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name != "checksums.sha256"
    ]
    _write_text(output_dir / "checksums.sha256", render_checksums(checksum_paths))


def render_readiness_report(package: dict[str, Any]) -> str:
    validation = package["validation"]
    lines = [
        "# XSS v1.3 Ablation Harness Readiness",
        "",
        "Status: dry-run harness validation only. No scored calls, provider calls, local-model inference, browser vulnerability verification, ZAP, IDOR or SQLi were executed.",
        "",
        f"- Validation valid: `{validation['valid']}`",
        f"- Scheduled ranking rows: `{validation['actual_schedule_rows']}`",
        f"- Candidate snapshots: `{package['manifest']['candidate_snapshot_count']}`",
        f"- Ground truth loaded: `{validation['ground_truth_loaded']}`",
        f"- Proprietary API calls executed: `{validation['proprietary_api_calls_executed']}`",
        f"- Local model calls executed: `{validation['local_model_calls_executed']}`",
        f"- Browser vulnerability verification executed: `{validation['browser_vulnerability_verification_executed']}`",
        "",
        "## Arm Denominators",
        "",
        "| Arm | Scheduled ranking rows | Trials/scenario | Max candidate tests |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in package["arm_summary"]:
        lines.append(f"| `{row['arm_id']}` | `{row['scheduled_ranking_calls']}` | `{row['trials_per_scenario']}` | `{row['max_candidate_tests']}` |")
    if validation["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in validation["errors"])
    return "\n".join(lines) + "\n"


def render_thesis_tables(package: dict[str, Any]) -> str:
    lines = [
        "# Thesis Tables: XSS v1.3 Harness Readiness",
        "",
        "Status: dry-run readiness data only. No experimental outcomes are included.",
        "",
        "| Arm | Scheduled calls | Provider calls | Max candidate tests |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in package["arm_summary"]:
        lines.append(f"| `{row['arm_id']}` | `{row['scheduled_ranking_calls']}` | `{row['provider_calls']}` | `{row['max_candidate_tests']}` |")
    return "\n".join(lines) + "\n"


def render_thesis_tables_latex() -> str:
    return (
        "% Status: dry-run readiness data only. No experimental outcomes are included.\n"
        "\\begin{table}[ht]\n"
        "\\centering\n"
        "\\caption{XSS v1.3 ablation planned execution denominators.}\n"
        "\\label{tab:xss-v13-ablation-denominators}\n"
        "\\begin{tabular}{lrrr}\n"
        "\\hline\n"
        "Arm & Scheduled calls & Provider calls & Max candidate tests \\\\\n"
        "\\hline\n"
        "deterministic\\_structural & 24 & 0 & 96 \\\\\n"
        "proprietary\\_gpt & 120 & 120 & 480 \\\\\n"
        "local\\_qwen & 120 & 120 & 480 \\\\\n"
        "\\hline\n"
        "\\end{tabular}\n"
        "\\end{table}\n"
    )


def validate_checksum_file(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return [f"checksum file missing: {path}"]
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative_path = line.split("  ", 1)
        target = REPO_ROOT / relative_path
        if not target.exists():
            errors.append(f"checksum target missing: {relative_path}")
            continue
        actual = sha256_file(target)
        if actual != expected:
            errors.append(f"checksum mismatch: {relative_path}")
    return errors


def _check_hashes(checks: list[dict[str, Any]], errors: list[str]) -> None:
    for relative_path, expected in PROTOCOL_CRITICAL_HASHES.items():
        path = REPO_ROOT / relative_path
        passed = path.exists() and sha256_file(path) == expected
        _check(f"protocol_hash:{relative_path}", passed, checks, errors)


def _check_qwen_artifacts(checks: list[dict[str, Any]], errors: list[str]) -> None:
    model = _local_model_artifact(LOCAL_PRIMARY_MODEL_ID)
    runtime_ok = LLAMA_COMPLETION_EXE.exists() and runtime_sha256_file(LLAMA_COMPLETION_EXE) == "2272eaaf8bb9477257790835d7b25aaf8fd22941e44ac3fcc9f2df389d1ef7b4"
    _check("llama_completion_runtime_hash", runtime_ok, checks, errors)
    expected_file_hashes = {
        "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf": "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db",
        "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf": "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a",
    }
    for filename, expected_hash in expected_file_hashes.items():
        path = MODEL_ROOT / model.candidate_id / filename
        _check(f"qwen_model_hash:{filename}", path.exists() and sha256_file(path) == expected_hash, checks, errors)
    _check("gemma_is_contingency_only", LOCAL_CONTINGENCY_MODEL_ID == "gemma3_4b_it_gguf_q4_k_m", checks, errors)


def _check_output_dir(output_dir: Path, checks: list[dict[str, Any]], errors: list[str], *, allow_existing_readiness_output: bool) -> None:
    resolved = output_dir.resolve()
    protected = resolved in PROTECTED_OUTPUT_DIRS or "v1.2" in str(resolved).lower()
    _check("output_not_v1_2_or_protected_v1_3", not protected, checks, errors)
    if resolved.exists() and any(resolved.iterdir()) and not (allow_existing_readiness_output and resolved == DEFAULT_READINESS_DIR.resolve()):
        _check("output_dir_empty_or_allowed_readiness_overwrite", False, checks, errors)
    else:
        checks.append({"check": "output_dir_empty_or_allowed_readiness_overwrite", "passed": True})


def _local_model_artifact(candidate_id: str):
    model = next((item for item in MODEL_ARTIFACTS if item.candidate_id == candidate_id), None)
    if model is None:
        raise HarnessReadinessError(f"unknown local model candidate: {candidate_id}")
    return model


def _check(name: str, passed: bool, checks: list[dict[str, Any]], errors: list[str]) -> None:
    checks.append({"check": name, "passed": bool(passed)})
    if not passed:
        errors.append(name)


def git_tag_is_ancestor() -> bool:
    try:
        completed = subprocess.run(
            ["git", "merge-base", "--is-ancestor", PROTOCOL_TAG, "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    return completed.returncode == 0


def git_output(args: list[str]) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, check=True, encoding="utf-8")
    return completed.stdout.strip()


def write_scenario_schema(snapshot: dict[str, Any], schema_path: Path) -> Path:
    schema = readiness_json_schema([item["candidate_id"] for item in snapshot["candidate_input"]])
    schema["$id"] = f"local-ranking-readiness-json-schema-v1.3-{snapshot['scenario_id']}"
    _write_json(schema_path, schema)
    return schema_path


def local_qwen_settings_for_schema(schema_path: Path) -> dict[str, Any]:
    return transport_settings(schema_path, LLAMA_COMPLETION_EXE)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            handle.write("")
            return
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def render_checksums(paths: list[Path]) -> str:
    return "".join(f"{sha256_file(path)}  {display_path(path)}\n" for path in paths)


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return resolved.as_posix()


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the frozen XSS v1.3 ablation execution harness.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    dry = subparsers.add_parser("dry-run", help="Generate a non-scored harness-readiness package.")
    dry.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    amendment = subparsers.add_parser("amendment-readiness", help="Generate a non-scored v1.3.1 amendment-readiness package.")
    amendment.add_argument("--output-dir", type=Path, default=DEFAULT_AMENDMENT_READINESS_DIR)
    provider = subparsers.add_parser("provider-readiness", help="Run a non-scored proprietary-provider connectivity readiness check.")
    provider.add_argument("--output-dir", type=Path, default=DEFAULT_AMENDMENT_READINESS_DIR)
    provider.add_argument("--fake", action="store_true", help="Use the fake model client for offline validation.")
    preflight = subparsers.add_parser("preflight", help="Run read-only measured-execution preflight checks.")
    preflight.add_argument("--output-dir", type=Path, default=FINAL_PACKAGE_DIR)
    execute = subparsers.add_parser("execute", help="Run the frozen measured v1.3 XSS ablation study.")
    execute.add_argument("--output-root", type=Path, default=FINAL_PACKAGE_DIR)
    execute.add_argument("--headed", action="store_true", help="Run Chromium with a visible window.")
    args = parser.parse_args()
    if args.command == "dry-run":
        package = build_harness_readiness_package(args.output_dir)
        if not package["validation"]["valid"]:
            raise SystemExit("xss v1.3 harness dry-run validation failed")
        print(f"XSS v1.3 harness readiness artifacts written to: {args.output_dir}")
    elif args.command == "amendment-readiness":
        package = build_amendment_readiness_package(args.output_dir)
        if not package["validation"]["valid"]:
            raise SystemExit("xss v1.3.1 amendment readiness validation failed")
        print(f"XSS v1.3.1 amendment readiness artifacts written to: {args.output_dir}")
    elif args.command == "provider-readiness":
        client = FakeModelClient(model_identifier=PROPRIETARY_MODEL_IDENTIFIER) if args.fake else None
        report = provider_connectivity_readiness(model_client=client, output_dir=args.output_dir)
        print(json.dumps(to_json_value(report), indent=2, sort_keys=True))
        if not report["valid"]:
            raise SystemExit(1)
    elif args.command == "preflight":
        report = preflight_check(measured_execution=True, output_dir=args.output_dir)
        print(json.dumps(to_json_value(report), indent=2, sort_keys=True))
        if not report["valid"]:
            raise SystemExit(1)
    elif args.command == "execute":
        run_dir = run_measured_xss_v13_ablation(output_root=args.output_root, headless=not args.headed)
        print(f"XSS v1.3 ablation run artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
