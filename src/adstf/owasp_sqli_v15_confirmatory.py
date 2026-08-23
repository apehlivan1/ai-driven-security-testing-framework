from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from adstf.contracts import TargetConfig
from adstf.execution import HttpExecutor
from adstf.llm_ranking import (
    CommandModelClient,
    LLMRankingResult,
    ModelClient,
    ModelProviderError,
    ModelTimeoutError,
    parse_model_ranking,
    ranking_result_artifact,
)
from adstf.local_runtime import MODEL_ARTIFACTS, MODEL_ROOT, RUNTIME_ROOT, LlamaCppCliClient, sha256_file as runtime_sha256_file
from adstf.local_runtime_output_boundary import transport_settings
from adstf.local_runtime_readiness import readiness_json_schema
from adstf.modules import mvp_modules
from adstf.owasp_sqli_v15 import (
    DEFAULT_BASE_URL,
    ExecutionSpecification,
    OriginalBenchmarkProvenance,
    OwaspInput,
    OwaspSqliCandidate,
    RankerFacingCandidate,
    execute_one_candidate,
    health_check,
    target_config_for_url,
)
from adstf.owasp_sqli_v15_protocol_prep import (
    ARM_IDS,
    LOCAL_CONTINGENCY_MODEL_ID,
    LOCAL_MODEL_IDENTIFIER,
    LOCAL_PRIMARY_MODEL_ID,
    PROPRIETARY_MODEL_IDENTIFIER,
    TEST_BUDGET,
    model_facing_snapshot_leaks,
)
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore


REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.5.md"
AMENDMENT_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.5.1.md"
PROTOCOL_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-protocol-freeze"
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-confirmatory-harness-readiness"
DEFAULT_V151_READINESS_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-1-amendment-readiness"
DEFAULT_FINAL_ROOT = REPO_ROOT / "results" / "owasp-sqli-v15-confirmatory-final"
DEFAULT_V151_FINAL_ROOT = REPO_ROOT / "results" / "owasp-sqli-v15-1-confirmatory-final"
DEFAULT_CANONICAL_DIR = DEFAULT_FINAL_ROOT / "canonical"
DEFAULT_V151_CANONICAL_DIR = DEFAULT_V151_FINAL_ROOT / "canonical"
HARNESS_VERSION = "owasp-sqli-v15-confirmatory-harness-v1"
DRY_VALIDATION_VERSION = "owasp-sqli-v15-confirmatory-dry-validation-v1"
RUNTIME_PREFLIGHT_VERSION = "owasp-sqli-v15-confirmatory-runtime-preflight-v1"
RANKING_ROW_VERSION = "owasp-sqli-v15-ranking-row-v1"
DIRECT_ROW_VERSION = "owasp-sqli-v15-direct-execution-row-v1"
LLM_SQLI_RANKING_PROMPT_VERSION = "llm-sqli-candidate-ranking-v1"
ABORTED_V15_RUN_DIR = DEFAULT_FINAL_ROOT / "owasp-sqli-v15-confirmatory-20260823T122428Z"
SYNTHETIC_CONNECTIVITY_CANDIDATE = {
    "candidate_id": "synthetic-connectivity-candidate",
    "sanitized_action_path": "/synthetic/connectivity",
    "http_method": "GET",
    "input_carrier": "query_parameter",
    "input_count_category": "single",
    "editable_input_count": 1,
    "multiple_parameters": False,
    "transport_adapter_category": "synthetic",
    "request_shape": "query",
}

EXPECTED_DENOMINATORS = {
    "deterministic_structural": 124,
    "proprietary_gpt": 620,
    "local_qwen": 620,
    "total_ranking_rows": 1364,
}
EXPECTED_DIRECT_CASES = 200
EXPECTED_DIRECT_REQUESTS = 1200
GPT_SETTINGS = {
    "temperature_parameter": "omitted",
    "provider_default_temperature_used": True,
    "max_output_tokens": 1200,
    "timeout_seconds": 60,
    "prompt_version": LLM_SQLI_RANKING_PROMPT_VERSION,
}
QWEN_RUNTIME_SHA256 = "2272eaaf8bb9477257790835d7b25aaf8fd22941e44ac3fcc9f2df389d1ef7b4"
QWEN_MODEL_HASHES = {
    "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf": "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db",
    "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf": "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a",
}
LLAMA_COMPLETION_EXE = RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"
NOT_APPLICABLE = "not_applicable"
NOT_AVAILABLE = "not_available"


class SqliConfirmatoryHarnessError(RuntimeError):
    pass


def build_sqli_ranking_prompt(candidate_input: list[dict]) -> str:
    return (
        "You rank structured SQL injection candidate records for authorized local security-testing evaluation.\n"
        "You may only choose from the supplied candidate_id values. Do not create payloads, "
        "do not construct HTTP requests, do not request execution, do not verify findings, "
        "and do not use ground truth.\n"
        "Return strict JSON in this exact shape: "
        '{"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}.\n'
        "Include every candidate exactly once.\n"
        "Candidates:\n"
        + json.dumps(candidate_input, indent=2, sort_keys=True)
    )


def run_dry_validation(
    *,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    output_dir: Path = DEFAULT_V151_READINESS_DIR,
    env: Mapping[str, str | None] | None = None,
    check_target: bool = False,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    package = load_protocol_package(protocol_package_dir)
    amendment_validation = validate_protocol_amendment()
    prompt_check = prompt_validation()
    aborted_run = interrupted_v15_run_preservation()
    output_separation = future_v151_output_is_separate()
    package_validation = validate_protocol_package(package)
    schedule_validation = validate_schedule_resolution(package)
    direct_validation = validate_direct_schedule(package)
    runtime_preflight = runtime_preflight_status(
        env=env,
        check_target=check_target,
        target_probe=target_probe,
        check_gpt_connectivity=False,
    )
    duplicate_resume = validate_duplicate_and_resume_state(output_dir, package["schedule_rows"])
    direct_resume = validate_direct_resume_state(output_dir, package["direct_rows"])
    report = {
        "schema_version": DRY_VALIDATION_VERSION,
        "harness_version": HARNESS_VERSION,
        "created_at": now_utc(),
        "mode": "dry_validation",
        "valid": (
            amendment_validation["valid"]
            and prompt_check["valid"]
            and aborted_run["valid"]
            and output_separation["valid"]
            and package_validation["valid"]
            and schedule_validation["valid"]
            and direct_validation["valid"]
            and duplicate_resume["valid"]
            and direct_resume["valid"]
        ),
        "protocol_amendment": amendment_validation,
        "prompt_validation": prompt_check,
        "interrupted_v15_run": aborted_run,
        "future_v151_output_separation": output_separation,
        "protocol_package": package_validation,
        "ranking_schedule_resolution": schedule_validation,
        "direct_schedule_resolution": direct_validation,
        "runtime_preflight": runtime_preflight,
        "duplicate_resume_validation": duplicate_resume,
        "direct_resume_validation": direct_resume,
        "canonicalization_readiness": canonicalization_readiness_summary(package),
        "git_state": git_execution_state(),
        "external_calls": {
            "gpt_calls": 0,
            "qwen_calls": 0,
            "final_sqli_runtime_executions": 0,
            "direct_http_requests": 0,
            "scored_observations": 0,
        },
        "ground_truth_isolation": {
            "ground_truth_loaded_during_dry_validation": False,
            "model_facing_snapshot_leak_count": schedule_validation["snapshot_leak_count"],
            "direct_execution_ground_truth_loaded": False,
        },
    }
    write_harness_readiness_package(output_dir, report, package)
    return report


def run_runtime_preflight(
    *,
    env: Mapping[str, str | None] | None = None,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    check_gpt_connectivity: bool = True,
    gpt_connectivity_client: ModelClient | None = None,
) -> dict[str, Any]:
    package = load_protocol_package(protocol_package_dir)
    package_validation = validate_protocol_package(package)
    schedule_validation = validate_schedule_resolution(package)
    direct_validation = validate_direct_schedule(package)
    runtime = runtime_preflight_status(
        env=env,
        check_target=True,
        target_probe=target_probe,
        check_gpt_connectivity=check_gpt_connectivity,
        gpt_connectivity_client=gpt_connectivity_client,
    )
    return {
        "schema_version": RUNTIME_PREFLIGHT_VERSION,
        "created_at": now_utc(),
        "valid": (
            validate_protocol_amendment()["valid"]
            and prompt_validation()["valid"]
            and package_validation["valid"]
            and schedule_validation["valid"]
            and direct_validation["valid"]
            and runtime["valid"]
        ),
        "protocol_amendment": validate_protocol_amendment(),
        "prompt_validation": prompt_validation(),
        "protocol_package": package_validation,
        "ranking_schedule_resolution": schedule_validation,
        "direct_schedule_resolution": direct_validation,
        "runtime_preflight": runtime,
    }


def execute_final_confirmatory(
    *,
    output_root: Path = DEFAULT_V151_FINAL_ROOT,
    resume_run_dir: Path | None = None,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    env: Mapping[str, str | None] | None = None,
    gpt_client: ModelClient | None = None,
    qwen_client_factory: Callable[[Path], ModelClient] | None = None,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
    execute_final_confirmatory_flag: bool = False,
) -> Path:
    if not execute_final_confirmatory_flag:
        raise SqliConfirmatoryHarnessError("final v1.5.1 execution requires explicit execute_final_confirmatory_flag=True")
    preflight = run_runtime_preflight(env=env, target_probe=target_probe, protocol_package_dir=protocol_package_dir)
    if not preflight["valid"]:
        raise SqliConfirmatoryHarnessError("runtime preflight failed; refusing scored execution")
    package = load_protocol_package(protocol_package_dir)
    if resume_run_dir is not None:
        run_dir = resume_run_dir
        if not run_dir.exists():
            raise SqliConfirmatoryHarnessError(f"resume run directory does not exist: {run_dir}")
        validate_resume_run_directory(run_dir, output_root)
        duplicate_state = validate_duplicate_and_resume_state(run_dir, package["schedule_rows"])
        direct_state = validate_direct_resume_state(run_dir, package["direct_rows"])
        if not duplicate_state["valid"] or not direct_state["valid"]:
            raise SqliConfirmatoryHarnessError("resume validation failed; refusing scored execution")
    else:
        ensure_not_overwriting_previous_results(output_root)
        run_dir = output_root / f"owasp-sqli-v15-1-confirmatory-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
        run_dir.mkdir(parents=True)
    write_json_atomic(run_dir / "runtime-preflight.json", preflight)
    write_json_atomic(run_dir / "execution-manifest.json", execution_manifest(run_dir, package))
    execute_ranking_schedule_rows(run_dir=run_dir, package=package, gpt_client=gpt_client, qwen_client_factory=qwen_client_factory)
    execute_direct_schedule(run_dir=run_dir, package=package, base_url=DEFAULT_BASE_URL)
    finalize_execution_package(run_dir, package)
    return run_dir


def execute_ranking_schedule_rows(
    *,
    run_dir: Path,
    package: dict[str, Any],
    gpt_client: ModelClient | None = None,
    qwen_client_factory: Callable[[Path], ModelClient] | None = None,
    max_rows: int | None = None,
) -> list[dict[str, Any]]:
    row_dir = run_dir / "raw" / "ranking-rows"
    row_dir.mkdir(parents=True, exist_ok=True)
    schemas_dir = run_dir / "runtime" / "local-qwen-schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    if qwen_client_factory is None:
        qwen_client_factory = create_local_qwen_client

    completed: list[dict[str, Any]] = []
    for row in package["schedule_rows"]:
        if max_rows is not None and len(completed) >= max_rows:
            break
        result_path = ranking_row_artifact_path(row_dir, row)
        if result_path.exists():
            existing = load_json(result_path)
            snapshot = package["snapshots_by_id"][row["scenario_id"]]
            validate_existing_ranking_artifact(existing, row, expected_candidate_input_sha256=sha256_json(snapshot["candidate_input"]))
            completed.append(existing["summary"])
            continue
        snapshot = package["snapshots_by_id"][row["scenario_id"]]
        started = time.perf_counter()
        if row["arm_id"] == "deterministic_structural":
            artifact = deterministic_ranking_artifact(row, snapshot, started)
        elif row["arm_id"] == "proprietary_gpt":
            if gpt_client is None:
                gpt_client = create_proprietary_gpt_client()
            artifact = model_ranking_artifact(row, snapshot, gpt_client, GPT_SETTINGS, started)
        elif row["arm_id"] == "local_qwen":
            schema_path = write_local_schema(snapshot, schemas_dir)
            settings = local_qwen_settings_for_schema(schema_path)
            client = qwen_client_factory(schema_path)
            artifact = model_ranking_artifact(row, snapshot, client, settings, started)
        else:
            raise SqliConfirmatoryHarnessError(f"unexpected arm in frozen schedule: {row['arm_id']}")
        write_json_atomic(result_path, artifact)
        completed.append(artifact["summary"])
    return completed


def execute_direct_schedule(
    *,
    run_dir: Path,
    package: dict[str, Any],
    base_url: str,
    max_cases: int | None = None,
) -> list[dict[str, Any]]:
    direct_dir = run_dir / "raw" / "direct-sqli-cases"
    direct_dir.mkdir(parents=True, exist_ok=True)
    target = final_target_config_for_url(base_url)
    safety = SafetyBoundary(target)
    executor = HttpExecutor(safety, verify_tls=False, timeout_seconds=8.0)
    modules = mvp_modules()
    store = RunArtifactStore(run_dir / "raw" / "direct-runtime-artifacts", "owasp-sqli-v15-direct-execution")
    store.initialize(target)
    completed: list[dict[str, Any]] = []
    for row in package["direct_rows"]:
        if max_cases is not None and len(completed) >= max_cases:
            break
        result_path = direct_case_artifact_path(direct_dir, row)
        if result_path.exists():
            existing = load_json(result_path)
            validate_existing_direct_artifact(existing, row)
            completed.append(existing["summary"])
            continue
        candidate = package["candidates_by_id"][row["candidate_id"]]
        try:
            runtime = execute_one_candidate(candidate, target, executor, store, base_url, modules)
        except Exception as exc:  # Preserve the scheduled denominator without retrying.
            runtime = direct_runtime_error_result(row, exc)
        artifact = direct_case_artifact(row, runtime)
        write_json_atomic(result_path, artifact)
        completed.append(artifact["summary"])
    return completed


def build_canonical_package(
    *,
    run_dir: Path,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    output_dir: Path = DEFAULT_V151_CANONICAL_DIR,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    protocol = load_protocol_package(protocol_package_dir)
    ranking_rows = load_raw_ranking_rows(run_dir)
    direct_rows = load_raw_direct_rows(run_dir)
    integrity = audit_integrity(run_dir, protocol, ranking_rows, direct_rows)
    if not integrity["valid"]:
        write_json_atomic(output_dir / "execution-integrity-report.json", integrity)
        raise SqliConfirmatoryHarnessError("v1.5 run integrity audit failed; canonical scoring stopped")
    scoring = load_json(protocol_package_dir / "ground-truth" / "scoring-data.json")
    scored_ranking = score_ranking_rows(ranking_rows, scoring)
    scored_direct = score_direct_rows(direct_rows, scoring)
    ranking_aggregates = aggregate_ranking_results(scored_ranking)
    reliability = reliability_aggregates(scored_ranking)
    efficiency = efficiency_aggregates(scored_ranking, scored_direct)
    direct_aggregates = direct_execution_aggregates(scored_direct)
    negative = negative_scenario_aggregates(scored_ranking)
    validation = validate_canonical_outputs(scored_ranking, scored_direct, ranking_aggregates, direct_aggregates, integrity)
    package = {
        "manifest": canonical_manifest(output_dir, run_dir, protocol_package_dir, integrity, validation),
        "integrity": integrity,
        "validation": validation,
        "ranking_rows": scored_ranking,
        "direct_rows": scored_direct,
        "ranking_aggregates": ranking_aggregates,
        "reliability": reliability,
        "efficiency": efficiency,
        "direct_aggregates": direct_aggregates,
        "negative_scenarios": negative,
    }
    write_canonical_outputs(output_dir, package)
    checksum_errors = validate_checksum_file(output_dir / "checksums.sha256", output_dir)
    write_json_atomic(output_dir / "checksum-validation-report.json", {
        "schema_version": "owasp-sqli-v15-canonical-checksum-validation-v1",
        "valid": not checksum_errors,
        "errors": checksum_errors,
    })
    return package


def load_protocol_package(root: Path) -> dict[str, Any]:
    if not root.exists():
        raise SqliConfirmatoryHarnessError(f"protocol package not found: {root}")
    snapshot_index = load_json(root / "model-facing" / "candidate-snapshot-index.json")
    snapshots_by_id = {item["scenario_id"]: load_json(root / item["path"]) for item in snapshot_index["snapshot_paths"]}
    execution_specs = load_json(root / "execution" / "execution-specifications.json")["records"]
    ranker_by_id = {
        item["candidate_id"]: RankerFacingCandidate(**item)
        for snapshot in snapshots_by_id.values()
        for item in snapshot["candidate_input"]
    }
    candidates_by_id = build_candidates_by_id(execution_specs, ranker_by_id)
    return {
        "root": root,
        "manifest": load_json(root / "manifest.json"),
        "final_corpus": load_json(root / "final-corpus-manifest.json"),
        "scenario_manifest": load_json(root / "scenario-manifest.json"),
        "snapshot_index": snapshot_index,
        "snapshots_by_id": snapshots_by_id,
        "schedule": load_json(root / "trial-schedule.json"),
        "schedule_rows": load_json(root / "trial-schedule.json")["rows"],
        "direct_schedule": load_json(root / "direct-execution-schedule.json"),
        "direct_rows": load_json(root / "direct-execution-schedule.json")["rows"],
        "arm_config": load_json(root / "arm-configurations.json"),
        "preflight_validation": load_json(root / "preflight-validation-report.json"),
        "execution_specs": execution_specs,
        "candidates_by_id": candidates_by_id,
    }


def build_candidates_by_id(
    execution_specs: list[dict[str, Any]],
    ranker_by_id: dict[str, RankerFacingCandidate],
) -> dict[str, OwaspSqliCandidate]:
    candidates: dict[str, OwaspSqliCandidate] = {}
    for item in execution_specs:
        inputs = [OwaspInput(**input_item) for input_item in item["inputs"]]
        spec = ExecutionSpecification(**{**item, "inputs": inputs})
        candidate_id = spec.opaque_candidate_id
        candidates[candidate_id] = OwaspSqliCandidate(
            provenance=runtime_only_provenance(spec),
            execution=spec,
            ranker_candidate=ranker_by_id[candidate_id],
        )
    return candidates


def runtime_only_provenance(spec: ExecutionSpecification) -> OriginalBenchmarkProvenance:
    return OriginalBenchmarkProvenance(
        opaque_candidate_id=spec.opaque_candidate_id,
        benchmark_case_id=spec.opaque_candidate_id,
        benchmark_name="OWASP Benchmark Java",
        benchmark_version="not_loaded_during_runtime_execution",
        benchmark_revision="not_loaded_during_runtime_execution",
        source_file="not_loaded_during_runtime_execution",
        endpoint=spec.endpoint,
        input_carrier_shape=spec.adapter_class,
        compatibility_class=spec.adapter_class,
        evaluation_role="FINAL_CONFIRMATORY_ELIGIBLE",
        expected_result="not_loaded_during_runtime_execution",
    )


def validate_protocol_package(package: dict[str, Any]) -> dict[str, Any]:
    root = package["root"]
    errors: list[str] = []
    manifest_protocol_sha = package["manifest"].get("protocol_sha256")
    actual_protocol_sha = sha256_file(PROTOCOL_PATH) if PROTOCOL_PATH.exists() else "missing"
    if manifest_protocol_sha != actual_protocol_sha:
        errors.append("protocol_hash_mismatch")
    checksum_errors = validate_checksum_file(root / "checksums.sha256", root)
    errors.extend(checksum_errors)
    if package["final_corpus"]["corpus_counts"]["final_confirmatory_eligible"] != EXPECTED_DIRECT_CASES:
        errors.append("final_corpus_denominator_mismatch")
    if package["preflight_validation"]["final_confirmatory_sqli_runtime_executions"] != 0:
        errors.append("protocol package unexpectedly records final execution")
    return {
        "valid": not errors,
        "errors": errors,
        "protocol_sha256": actual_protocol_sha,
        "protocol_sha256_expected": manifest_protocol_sha,
        "protocol_hash_matches": manifest_protocol_sha == actual_protocol_sha,
        "package_checksum_error_count": len(checksum_errors),
        "package_checksum_errors": checksum_errors[:10],
    }


def validate_schedule_resolution(package: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    rows = package["schedule_rows"]
    snapshots = package["snapshots_by_id"]
    scenarios = {scenario["scenario_id"]: scenario for scenario in package["scenario_manifest"]["scenarios"]}
    seen_row_ids: set[str] = set()
    counts = Counter(row["arm_id"] for row in rows)
    snapshot_leaks: set[str] = set()
    for row in rows:
        row_id = scheduled_row_id(row)
        if row_id in seen_row_ids:
            errors.append(f"duplicate scheduled row: {row_id}")
        seen_row_ids.add(row_id)
        snapshot = snapshots.get(row["scenario_id"])
        scenario = scenarios.get(row["scenario_id"])
        if snapshot is None or scenario is None:
            errors.append(f"missing snapshot or scenario for {row_id}")
            continue
        if row["candidate_test_budget"] != TEST_BUDGET or row["top_k"] != min(TEST_BUDGET, snapshot["candidate_count"]):
            errors.append(f"budget/top_k mismatch for {row_id}")
        if sha256_json(snapshot["candidate_input"]) != scenario["candidate_input_sha256"]:
            errors.append(f"candidate_input_sha256 mismatch for {row['scenario_id']}")
        if model_facing_snapshot_leaks(snapshot):
            snapshot_leaks.add(row["scenario_id"])
    if counts != Counter({"deterministic_structural": 124, "proprietary_gpt": 620, "local_qwen": 620}):
        errors.append(f"per-arm denominator mismatch: {dict(counts)}")
    if len(rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("total ranking row mismatch")
    if snapshot_leaks:
        errors.append(f"model-facing snapshot leakage: {', '.join(sorted(snapshot_leaks)[:5])}")
    return {
        "valid": not errors,
        "errors": errors,
        "per_arm_counts": dict(counts),
        "total_rows": len(rows),
        "unique_row_ids": len(seen_row_ids),
        "scenario_count": len(snapshots),
        "snapshot_leak_count": len(snapshot_leaks),
        "ground_truth_loaded": False,
    }


def validate_direct_schedule(package: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    rows = package["direct_rows"]
    seen: set[str] = set()
    for row in rows:
        candidate_id = row["candidate_id"]
        if candidate_id in seen:
            errors.append(f"duplicate direct candidate: {candidate_id}")
        seen.add(candidate_id)
        candidate = package["candidates_by_id"].get(candidate_id)
        if candidate is None:
            errors.append(f"direct candidate has no execution spec: {candidate_id}")
            continue
        if candidate.provenance.evaluation_role != "FINAL_CONFIRMATORY_ELIGIBLE":
            errors.append(f"non-final direct candidate: {candidate_id}")
        if row["expected_runtime_requests"] != 6:
            errors.append(f"unexpected direct request count for {candidate_id}")
    if len(rows) != EXPECTED_DIRECT_CASES:
        errors.append(f"direct denominator mismatch: {len(rows)}")
    if sum(int(row["expected_runtime_requests"]) for row in rows) != EXPECTED_DIRECT_REQUESTS:
        errors.append("direct expected HTTP request mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "direct_execution_cases": len(rows),
        "expected_http_requests": sum(int(row["expected_runtime_requests"]) for row in rows),
        "readiness_or_excluded_case_count": sum(
            1 for candidate in package["candidates_by_id"].values()
            if candidate.provenance.evaluation_role != "FINAL_CONFIRMATORY_ELIGIBLE"
        ),
        "ground_truth_loaded": False,
    }


def runtime_preflight_status(
    *,
    env: Mapping[str, str | None] | None = None,
    check_target: bool,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
    check_gpt_connectivity: bool = False,
    gpt_connectivity_client: ModelClient | None = None,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    gpt = gpt_preflight(env)
    if check_gpt_connectivity and gpt["valid"]:
        gpt_connectivity = gpt_connectivity_readiness(gpt_connectivity_client)
    elif check_gpt_connectivity:
        gpt_connectivity = {
            "valid": False,
            "checked": False,
            "live_provider_call_executed": False,
            "provider_failed": True,
            "errors": ["gpt_configuration_invalid"],
            "scored_observation_created": False,
            "final_confirmatory_case_used": False,
        }
    else:
        gpt_connectivity = {
            "valid": True,
            "checked": False,
            "live_provider_call_executed": False,
            "provider_failed": False,
            "status": "not_checked_in_dry_validation_mode",
            "scored_observation_created": False,
            "final_confirmatory_case_used": False,
        }
    qwen = qwen_preflight()
    target = target_preflight(target_probe=target_probe) if check_target else {
        "checked": False,
        "valid": False,
        "status": "not_checked_in_dry_validation_mode",
        "base_url": DEFAULT_BASE_URL,
    }
    return {
        "schema_version": RUNTIME_PREFLIGHT_VERSION,
        "valid": gpt["valid"] and gpt_connectivity["valid"] and qwen["valid"] and (target["valid"] if check_target else True),
        "gpt": gpt,
        "gpt_connectivity": gpt_connectivity,
        "qwen": qwen,
        "owasp_target": target,
    }


def gpt_preflight(env: Mapping[str, str | None]) -> dict[str, Any]:
    api_key_present = bool(env.get("OPENAI_API_KEY"))
    model = env.get("OPENAI_RANKING_MODEL")
    send_temperature = str(env.get("OPENAI_SEND_TEMPERATURE") or "").lower()
    temp_ok = send_temperature in {"", "0", "false", "no"}
    errors = []
    if not api_key_present:
        errors.append("OPENAI_API_KEY_missing")
    if model != PROPRIETARY_MODEL_IDENTIFIER:
        errors.append("OPENAI_RANKING_MODEL_not_frozen_value")
    if not temp_ok:
        errors.append("OPENAI_SEND_TEMPERATURE_must_be_unset_or_false")
    return {
        "valid": not errors,
        "errors": errors,
        "api_key_present": api_key_present,
        "model_identifier": model or "missing",
        "model_identifier_expected": PROPRIETARY_MODEL_IDENTIFIER,
        "send_temperature_status": "unset_or_false" if temp_ok else "enabled",
        "secret_value_recorded": False,
    }


def gpt_connectivity_readiness(model_client: ModelClient | None = None) -> dict[str, Any]:
    candidate_input = [dict(SYNTHETIC_CONNECTIVITY_CANDIDATE)]
    prompt = build_sqli_ranking_prompt(candidate_input)
    candidate_ids = [candidate_input[0]["candidate_id"]]
    client = model_client or create_proprietary_gpt_client()
    started = time.perf_counter()
    try:
        completion = client.complete(prompt, candidate_input, GPT_SETTINGS)
        latency_ms = completion.latency_ms if completion.latency_ms is not None else int((time.perf_counter() - started) * 1000)
        ordered_ids, _rationales, validation_errors = parse_model_ranking(completion.raw_response, candidate_ids)
        valid = not validation_errors and ordered_ids == candidate_ids
        return {
            "schema_version": "owasp-sqli-v15-1-gpt-connectivity-readiness-v1",
            "valid": valid,
            "checked": True,
            "live_provider_call_executed": True,
            "provider_failed": False,
            "errors": validation_errors,
            "model_identifier": completion.model_identifier,
            "model_identifier_expected": PROPRIETARY_MODEL_IDENTIFIER,
            "provider": completion.provider,
            "prompt_version": LLM_SQLI_RANKING_PROMPT_VERSION,
            "candidate_count": len(candidate_input),
            "synthetic_candidate_id": candidate_ids[0],
            "final_confirmatory_case_used": False,
            "held_out_or_final_snapshot_used": False,
            "scored_observation_created": False,
            "api_key_value_recorded": False,
            "usage_metadata_present": completion.usage is not None,
            "usage": completion.usage,
            "cost": completion.cost if completion.cost is not None else {"availability": NOT_AVAILABLE},
            "latency_ms": latency_ms,
            "provider_metadata": completion.metadata,
            "raw_response": completion.raw_response,
        }
    except ModelTimeoutError as exc:
        error_type = "timeout"
        message = str(exc)
    except ModelProviderError as exc:
        error_type = "provider_failure"
        message = str(exc)
    return {
        "schema_version": "owasp-sqli-v15-1-gpt-connectivity-readiness-v1",
        "valid": False,
        "checked": True,
        "live_provider_call_executed": False,
        "provider_failed": True,
        "error_type": error_type,
        "errors": [message],
        "model_identifier": getattr(client, "model_identifier", PROPRIETARY_MODEL_IDENTIFIER),
        "model_identifier_expected": PROPRIETARY_MODEL_IDENTIFIER,
        "provider": None,
        "prompt_version": LLM_SQLI_RANKING_PROMPT_VERSION,
        "candidate_count": len(candidate_input),
        "synthetic_candidate_id": candidate_ids[0],
        "final_confirmatory_case_used": False,
        "held_out_or_final_snapshot_used": False,
        "scored_observation_created": False,
        "api_key_value_recorded": False,
        "usage_metadata_present": False,
        "usage": None,
        "cost": {"availability": NOT_AVAILABLE},
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "provider_metadata": None,
        "raw_response": None,
    }


def validate_protocol_amendment() -> dict[str, Any]:
    errors: list[str] = []
    text = AMENDMENT_PATH.read_text(encoding="utf-8") if AMENDMENT_PATH.exists() else ""
    if not text:
        errors.append("evaluation_protocol_v1_5_1_missing")
    required_fragments = [
        "evaluation-protocol-v1.5.1",
        "WinError 10013",
        "llm-sqli-candidate-ranking-v1",
        "complete fresh v1.5.1 run",
        "must not be resumed",
        "124 deterministic",
        "620 GPT",
        "620 Qwen",
        "200 direct",
    ]
    for fragment in required_fragments:
        if fragment not in text:
            errors.append(f"amendment_missing_fragment:{fragment}")
    return {
        "valid": not errors,
        "errors": errors,
        "amendment_version": "v1.5.1",
        "path": display_path(AMENDMENT_PATH),
        "sha256": sha256_file(AMENDMENT_PATH) if AMENDMENT_PATH.exists() else "missing",
        "base_protocol": "evaluation-protocol-v1.5",
        "scored_experiment_executed_by_amendment_preparation": False,
    }


def prompt_validation() -> dict[str, Any]:
    prompt = build_sqli_ranking_prompt([dict(SYNTHETIC_CONNECTIVITY_CANDIDATE)])
    errors: list[str] = []
    required_fragments = [
        "structured SQL injection candidate",
        "You may only choose from the supplied candidate_id values",
        "Do not create payloads",
        "do not construct HTTP requests",
        "do not request execution",
        "do not verify findings",
        "do not use ground truth",
    ]
    for fragment in required_fragments:
        if fragment not in prompt:
            errors.append(f"prompt_missing_fragment:{fragment}")
    for fragment in ("reflected-input", "reflected XSS", "browser execution"):
        if fragment in prompt:
            errors.append(f"prompt_forbidden_fragment:{fragment}")
    return {
        "valid": not errors,
        "errors": errors,
        "prompt_version": LLM_SQLI_RANKING_PROMPT_VERSION,
        "base_prompt_version_superseded_for_sqli": LLM_SQLI_RANKING_PROMPT_VERSION != "llm-candidate-ranking-v1",
        "exact_prompt_text": prompt,
    }


def interrupted_v15_run_preservation() -> dict[str, Any]:
    exists = ABORTED_V15_RUN_DIR.exists()
    ranking_dir = ABORTED_V15_RUN_DIR / "raw" / "ranking-rows"
    direct_dir = ABORTED_V15_RUN_DIR / "raw" / "direct-sqli-cases"
    ranking_paths = sorted(ranking_dir.glob("sequence-*.json")) if ranking_dir.exists() else []
    direct_paths = sorted(direct_dir.glob("candidate-*.json")) if direct_dir.exists() else []
    status_counts: Counter[str] = Counter()
    arm_counts: Counter[str] = Counter()
    winerror_10013_count = 0
    for path in ranking_paths:
        row = load_json(path)
        summary = row.get("summary", {})
        arm_counts[str(summary.get("arm_id", "missing"))] += 1
        status_counts[str(summary.get("status", "missing"))] += 1
        if "WinError 10013" in json.dumps(row):
            winerror_10013_count += 1
    return {
        "valid": True,
        "status": "present_and_preserved" if exists else "not_present_in_workspace",
        "path": display_path(ABORTED_V15_RUN_DIR),
        "used_as_final_v151_evidence": False,
        "may_be_resumed": False,
        "may_be_modified": False,
        "ranking_artifact_count": len(ranking_paths),
        "direct_artifact_count": len(direct_paths),
        "ranking_counts_by_arm": dict(arm_counts),
        "ranking_status_counts": dict(status_counts),
        "winerror_10013_artifact_count": winerror_10013_count,
    }


def future_v151_output_is_separate() -> dict[str, Any]:
    errors: list[str] = []
    if DEFAULT_V151_FINAL_ROOT == DEFAULT_FINAL_ROOT:
        errors.append("v151_final_root_matches_aborted_v15_root")
    if DEFAULT_FINAL_ROOT.resolve() in DEFAULT_V151_FINAL_ROOT.resolve().parents:
        errors.append("v151_final_root_nested_inside_v15_final_root")
    if DEFAULT_V151_FINAL_ROOT.resolve() in DEFAULT_FINAL_ROOT.resolve().parents:
        errors.append("v15_final_root_nested_inside_v151_final_root")
    return {
        "valid": not errors,
        "errors": errors,
        "aborted_v15_output_root": display_path(DEFAULT_FINAL_ROOT),
        "future_v151_output_root": display_path(DEFAULT_V151_FINAL_ROOT),
        "future_v151_canonical_dir": display_path(DEFAULT_V151_CANONICAL_DIR),
        "fresh_run_required": True,
        "resume_from_aborted_v15_permitted": False,
    }


def qwen_preflight(
    *,
    runtime_path: Path = LLAMA_COMPLETION_EXE,
    model_root: Path = MODEL_ROOT,
    runtime_hasher: Callable[[Path], str] = runtime_sha256_file,
) -> dict[str, Any]:
    errors: list[str] = []
    runtime_exists = runtime_path.exists()
    runtime_hash = runtime_hasher(runtime_path) if runtime_exists else "missing"
    if runtime_hash != QWEN_RUNTIME_SHA256:
        errors.append("qwen_runtime_hash_mismatch")
    model = local_model_artifact(LOCAL_PRIMARY_MODEL_ID)
    model_checks = []
    for filename, expected in QWEN_MODEL_HASHES.items():
        path = model_root / model.candidate_id / filename
        exists = path.exists()
        actual = runtime_hasher(path) if exists else "missing"
        matches = actual == expected
        if not matches:
            errors.append(f"qwen_model_hash_mismatch:{filename}")
        model_checks.append({"filename": filename, "exists": exists, "sha256_matches": matches})
    if LOCAL_CONTINGENCY_MODEL_ID != "gemma3_4b_it_gguf_q4_k_m":
        errors.append("gemma_contingency_rule_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "runtime_exists": runtime_exists,
        "runtime_sha256_matches": runtime_hash == QWEN_RUNTIME_SHA256,
        "model_identifier": LOCAL_MODEL_IDENTIFIER,
        "model_files": model_checks,
        "gemma_contingency_only": True,
    }


def target_preflight(
    *,
    base_url: str = DEFAULT_BASE_URL,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    probe = target_probe or (lambda url: health_check(url))
    result = probe(base_url)
    reachable = bool(result.get("reachable"))
    approved_local_scope = base_url == DEFAULT_BASE_URL
    return {
        "checked": True,
        "valid": reachable and approved_local_scope,
        "base_url": base_url,
        "approved_local_scope": approved_local_scope,
        "probe_result": result,
        "final_confirmatory_case_executed": False,
    }


def deterministic_ranking_artifact(row: dict[str, Any], snapshot: dict[str, Any], started: float) -> dict[str, Any]:
    ranked = rank_sql_candidates_structurally(snapshot["candidate_input"])
    return ranking_row_artifact(
        row=row,
        snapshot=snapshot,
        ordered_candidate_ids=[item["candidate_id"] for item in ranked],
        rationales={item["candidate_id"]: "; ".join(item["rationale"]) for item in ranked},
        validation_errors=[],
        provider_failed=False,
        model_identifier="not_applicable",
        provider="deterministic",
        prompt=None,
        raw_response=None,
        model_settings={"ranking_ruleset_version": "deterministic-structural-v1"},
        usage=None,
        cost={"availability": "not_applicable"},
        provider_metadata={"scores": ranked},
        started=started,
    )


def rank_sql_candidates_structurally(candidate_input: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = []
    for candidate in candidate_input:
        score = 0
        rationale: list[str] = []
        category = candidate.get("input_count_category")
        if category == "single":
            score += 30
            rationale.append("single controllable input")
        elif category == "small_multi":
            score += 15
            rationale.append("small multi-input request")
        else:
            rationale.append("larger multi-input request")
        if candidate.get("multiple_parameters") is False:
            score += 10
            rationale.append("no additional controllable parameters")
        if int(candidate.get("editable_input_count", 0)) <= 1:
            score += 8
            rationale.append("one editable input")
        carrier = str(candidate.get("input_carrier", ""))
        if carrier == "query_parameter":
            score += 6
            rationale.append("query parameter carrier")
        elif carrier == "form_parameter":
            score += 4
            rationale.append("form parameter carrier")
        if str(candidate.get("http_method", "")).upper() == "GET":
            score += 2
            rationale.append("GET request metadata")
        scored.append({"candidate_id": candidate["candidate_id"], "score": score, "rationale": rationale})
    return sorted(scored, key=lambda item: (-int(item["score"]), item["candidate_id"]))


def model_ranking_artifact(
    row: dict[str, Any],
    snapshot: dict[str, Any],
    model_client: ModelClient,
    settings: dict[str, Any],
    started: float,
) -> dict[str, Any]:
    candidate_input = snapshot["candidate_input"]
    prompt = build_sqli_ranking_prompt(candidate_input)
    candidate_ids = [item["candidate_id"] for item in candidate_input]
    try:
        completion = model_client.complete(prompt, candidate_input, settings)
        ordered_ids, rationales, validation_errors = parse_model_ranking(completion.raw_response, candidate_ids)
        return ranking_row_artifact(
            row=row,
            snapshot=snapshot,
            ordered_candidate_ids=ordered_ids,
            rationales=rationales,
            validation_errors=validation_errors,
            provider_failed=False,
            model_identifier=completion.model_identifier,
            provider=completion.provider,
            prompt=prompt,
            raw_response=completion.raw_response,
            model_settings=settings,
            usage=completion.usage,
            cost=completion.cost,
            provider_metadata=completion.metadata,
            started=started,
        )
    except ModelTimeoutError as exc:
        error_type = "timeout"
        message = str(exc)
    except ModelProviderError as exc:
        error_type = "provider_failure"
        message = str(exc)
    return ranking_row_artifact(
        row=row,
        snapshot=snapshot,
        ordered_candidate_ids=candidate_ids,
        rationales={},
        validation_errors=[message],
        provider_failed=True,
        model_identifier=getattr(model_client, "model_identifier", "unknown-model"),
        provider=None,
        prompt=prompt,
        raw_response=None,
        model_settings=settings,
        usage=None,
        cost=None,
        provider_metadata={"failure_type": error_type},
        started=started,
    )


def ranking_row_artifact(
    *,
    row: dict[str, Any],
    snapshot: dict[str, Any],
    ordered_candidate_ids: list[str],
    rationales: dict[str, str],
    validation_errors: list[str],
    provider_failed: bool,
    model_identifier: str,
    provider: str | None,
    prompt: str | None,
    raw_response: str | None,
    model_settings: dict[str, Any],
    usage: dict[str, Any] | None,
    cost: dict[str, Any] | None,
    provider_metadata: dict[str, Any] | None,
    started: float,
) -> dict[str, Any]:
    latency_ms = int((time.perf_counter() - started) * 1000)
    result = LLMRankingResult(
        ordered_candidate_ids=ordered_candidate_ids,
        rationales=rationales,
        validation_errors=validation_errors,
        raw_response=raw_response,
        model_identifier=model_identifier,
        prompt_version=LLM_SQLI_RANKING_PROMPT_VERSION,
        model_settings=model_settings,
        candidate_input=snapshot["candidate_input"],
        prompt=prompt or "not_applicable",
        usage=usage,
        cost=cost,
        provider=provider,
        latency_ms=latency_ms,
        provider_metadata=provider_metadata,
        timestamp=now_utc(),
        trial_number=int(row["trial_number"]),
        scenario_id=row["scenario_id"],
        provider_failed=provider_failed,
    )
    summary = {
        "schema_version": RANKING_ROW_VERSION,
        "sequence": row["sequence"],
        "scenario_id": row["scenario_id"],
        "arm_id": row["arm_id"],
        "trial_number": row["trial_number"],
        "snapshot_path": row["snapshot_path"],
        "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
        "candidate_test_budget": row["candidate_test_budget"],
        "top_k": row["top_k"],
        "status": "valid" if result.is_valid else ("provider_failed" if provider_failed else "malformed"),
        "contract_valid": result.is_valid,
        "provider_failed": provider_failed,
        "validation_errors": validation_errors,
        "latency_ms": latency_ms,
        "model_identifier": model_identifier,
        "provider": provider,
        "prompt_version": LLM_SQLI_RANKING_PROMPT_VERSION,
    }
    return {
        "schema_version": RANKING_ROW_VERSION,
        "created_at": now_utc(),
        "summary": summary,
        "ranking_result": ranking_result_artifact(result),
        "ground_truth_included": False,
    }


def direct_case_artifact(row: dict[str, Any], runtime: dict[str, Any]) -> dict[str, Any]:
    summary = {
        "schema_version": DIRECT_ROW_VERSION,
        "sequence": row["sequence"],
        "candidate_id": row["candidate_id"],
        "adapter_class": row["adapter_class"],
        "expected_runtime_requests": row["expected_runtime_requests"],
        "status": "runtime_error" if runtime.get("runtime_error") else "completed",
        "baseline_stable": bool(runtime.get("baseline_stable")),
        "true_false_difference_reproducible": bool(runtime.get("true_false_difference_reproducible")),
        "server_error_observed": bool(runtime.get("server_error_observed")),
        "finding_state": runtime.get("finding_state", "inconclusive"),
        "ground_truth_used_phase": runtime.get("ground_truth_used_phase", "not_loaded_during_runtime_execution"),
        "request_count": int(row["expected_runtime_requests"]),
    }
    return {
        "schema_version": DIRECT_ROW_VERSION,
        "created_at": now_utc(),
        "summary": summary,
        "runtime_result": runtime,
        "ground_truth_included": False,
    }


def direct_runtime_error_result(row: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {
        "candidate_id": row["candidate_id"],
        "adapter_class": row["adapter_class"],
        "runtime_error": True,
        "runtime_error_type": type(exc).__name__,
        "runtime_error_message": str(exc),
        "baseline_stable": False,
        "true_false_difference_reproducible": False,
        "server_error_observed": False,
        "finding_state": "inconclusive",
        "ground_truth_used_phase": "not_loaded_during_runtime_execution",
    }


def create_proprietary_gpt_client(env: Mapping[str, str | None] | None = None) -> ModelClient:
    env = os.environ if env is None else env
    if env.get("OPENAI_RANKING_MODEL") != PROPRIETARY_MODEL_IDENTIFIER:
        raise SqliConfirmatoryHarnessError("OPENAI_RANKING_MODEL must resolve exactly to gpt-5.6-luna")
    return CommandModelClient([sys.executable, "-m", "adstf.openai_ranking_wrapper"], model_identifier=PROPRIETARY_MODEL_IDENTIFIER, timeout_seconds=60)


def create_local_qwen_client(schema_path: Path) -> ModelClient:
    model = local_model_artifact(LOCAL_PRIMARY_MODEL_ID)
    return LlamaCppCliClient(
        executable=LLAMA_COMPLETION_EXE,
        model_path=MODEL_ROOT / model.candidate_id / model.primary_model_filename,
        model_identifier=LOCAL_MODEL_IDENTIFIER,
        timeout_seconds=300,
        context_size_tokens=4096,
        max_output_tokens=768,
        temperature=0.0,
        top_p=1.0,
        seed=42,
        threads=8,
        json_schema_path=schema_path,
    )


def write_local_schema(snapshot: dict[str, Any], schemas_dir: Path) -> Path:
    schema = readiness_json_schema([item["candidate_id"] for item in snapshot["candidate_input"]])
    schema["$id"] = f"local-ranking-readiness-json-schema-v1.3-{snapshot['scenario_id']}"
    path = schemas_dir / f"{snapshot['scenario_id']}.schema.json"
    write_json_atomic(path, schema)
    return path


def local_qwen_settings_for_schema(schema_path: Path) -> dict[str, Any]:
    return transport_settings(schema_path, LLAMA_COMPLETION_EXE)


def final_target_config_for_url(base_url: str) -> TargetConfig:
    target = target_config_for_url(base_url)
    return TargetConfig(
        name="OWASP Benchmark Java SQLi v1.5 confirmatory",
        base_url=target.base_url,
        allowed_hosts=target.allowed_hosts,
        enabled_modules=target.enabled_modules,
        allowed_schemes=target.allowed_schemes,
        allowed_ports=target.allowed_ports,
        max_actions=EXPECTED_DIRECT_REQUESTS,
        metadata={"evaluation": "owasp-sqli-v15-confirmatory", "local_only": True},
    )


def validate_duplicate_and_resume_state(output_dir: Path, schedule_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_dir = output_dir / "raw" / "ranking-rows"
    errors: list[str] = []
    planned_by_id = {scheduled_row_id(row): row for row in schedule_rows}
    if len(planned_by_id) != len(schedule_rows):
        errors.append("duplicate scheduled row identities")
    existing_seen: set[str] = set()
    existing_count = 0
    if row_dir.exists():
        for path in row_dir.glob("sequence-*.json"):
            data = load_json(path)
            row_id = scheduled_row_id(data.get("summary", {}))
            if row_id not in planned_by_id:
                errors.append(f"unexpected existing row artifact: {path.name}")
            if row_id in existing_seen:
                errors.append(f"duplicate existing row artifact identity: {row_id}")
            expected_row = planned_by_id.get(row_id)
            if expected_row is not None:
                try:
                    validate_existing_ranking_artifact(data, expected_row)
                except SqliConfirmatoryHarnessError as exc:
                    errors.append(str(exc))
            existing_seen.add(row_id)
            existing_count += 1
    next_missing = next((row["sequence"] for row in schedule_rows if scheduled_row_id(row) not in existing_seen), None)
    return {
        "valid": not errors,
        "errors": errors,
        "existing_completed_rows": existing_count,
        "resume_next_missing_sequence": next_missing,
        "overwrite_policy": "existing completed scored ranking artifacts are never silently regenerated",
    }


def validate_direct_resume_state(output_dir: Path, direct_rows: list[dict[str, Any]]) -> dict[str, Any]:
    direct_dir = output_dir / "raw" / "direct-sqli-cases"
    errors: list[str] = []
    planned_by_id = {row["candidate_id"]: row for row in direct_rows}
    existing_seen: set[str] = set()
    existing_count = 0
    if direct_dir.exists():
        for path in direct_dir.glob("candidate-*.json"):
            data = load_json(path)
            candidate_id = data.get("summary", {}).get("candidate_id")
            if candidate_id not in planned_by_id:
                errors.append(f"unexpected existing direct artifact: {path.name}")
            if candidate_id in existing_seen:
                errors.append(f"duplicate existing direct artifact identity: {candidate_id}")
            expected_row = planned_by_id.get(candidate_id)
            if expected_row is not None:
                try:
                    validate_existing_direct_artifact(data, expected_row)
                except SqliConfirmatoryHarnessError as exc:
                    errors.append(str(exc))
            existing_seen.add(candidate_id)
            existing_count += 1
    next_missing = next((row["sequence"] for row in direct_rows if row["candidate_id"] not in existing_seen), None)
    return {
        "valid": not errors,
        "errors": errors,
        "existing_completed_cases": existing_count,
        "resume_next_missing_sequence": next_missing,
        "overwrite_policy": "existing completed direct artifacts are never silently regenerated",
    }


def validate_existing_ranking_artifact(
    existing: dict[str, Any],
    row: dict[str, Any],
    *,
    expected_candidate_input_sha256: str | None = None,
) -> None:
    summary = existing.get("summary", {})
    for key in ("sequence", "scenario_id", "arm_id", "trial_number", "snapshot_path", "candidate_test_budget", "top_k"):
        if summary.get(key) != row.get(key):
            raise SqliConfirmatoryHarnessError(f"inconsistent existing ranking artifact for {scheduled_row_id(row)}: {key}")
    if summary.get("schema_version") not in {RANKING_ROW_VERSION, "synthetic-test-ranking-row"}:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing ranking artifact for {scheduled_row_id(row)}: schema_version")
    if expected_candidate_input_sha256 is not None and summary.get("candidate_input_sha256") != expected_candidate_input_sha256:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing ranking artifact for {scheduled_row_id(row)}: candidate_input_sha256")
    if summary.get("status") not in {"valid", "malformed", "provider_failed", "runtime_failed", "timeout"}:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing ranking artifact for {scheduled_row_id(row)}: status")
    if existing.get("ground_truth_included") is not False:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing ranking artifact for {scheduled_row_id(row)}: ground_truth_included")


def validate_existing_direct_artifact(existing: dict[str, Any], row: dict[str, Any]) -> None:
    summary = existing.get("summary", {})
    for key in ("sequence", "candidate_id", "adapter_class", "expected_runtime_requests"):
        if summary.get(key) != row.get(key):
            raise SqliConfirmatoryHarnessError(f"inconsistent existing direct artifact for {row['candidate_id']}: {key}")
    if summary.get("schema_version") not in {DIRECT_ROW_VERSION, "synthetic-test-direct-row"}:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing direct artifact for {row['candidate_id']}: schema_version")
    if int(summary.get("request_count", -1)) != int(row["expected_runtime_requests"]):
        raise SqliConfirmatoryHarnessError(f"inconsistent existing direct artifact for {row['candidate_id']}: request_count")
    if summary.get("status") not in {"completed", "runtime_error"}:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing direct artifact for {row['candidate_id']}: status")
    if existing.get("ground_truth_included") is not False:
        raise SqliConfirmatoryHarnessError(f"inconsistent existing direct artifact for {row['candidate_id']}: ground_truth_included")


def ranking_row_artifact_path(row_dir: Path, row: dict[str, Any]) -> Path:
    return row_dir / f"sequence-{int(row['sequence']):04d}__{row['arm_id']}__{row['scenario_id']}__trial-{row['trial_number']}.json"


def direct_case_artifact_path(direct_dir: Path, row: dict[str, Any]) -> Path:
    return direct_dir / f"candidate-{int(row['sequence']):04d}__{row['candidate_id']}.json"


def scheduled_row_id(row: dict[str, Any]) -> str:
    return f"{row.get('sequence')}|{row.get('arm_id')}|{row.get('scenario_id')}|{row.get('trial_number')}"


def finalize_execution_package(run_dir: Path, package: dict[str, Any]) -> None:
    ranking_summaries = [load_json(path)["summary"] for path in sorted((run_dir / "raw" / "ranking-rows").glob("sequence-*.json"))]
    direct_summaries = [load_json(path)["summary"] for path in sorted((run_dir / "raw" / "direct-sqli-cases").glob("candidate-*.json"))]
    denominators = Counter(row["arm_id"] for row in ranking_summaries)
    validation = {
        "schema_version": "owasp-sqli-v15-confirmatory-execution-validation-v1",
        "valid": (
            dict(denominators) == {key: EXPECTED_DENOMINATORS[key] for key in ARM_IDS}
            and len(ranking_summaries) == EXPECTED_DENOMINATORS["total_ranking_rows"]
            and len(direct_summaries) == EXPECTED_DIRECT_CASES
        ),
        "actual_ranking_denominators": dict(denominators),
        "expected_ranking_denominators": EXPECTED_DENOMINATORS,
        "actual_direct_cases": len(direct_summaries),
        "expected_direct_cases": EXPECTED_DIRECT_CASES,
    }
    write_json_atomic(run_dir / "validation-report.json", validation)
    write_csv(run_dir / "normalized" / "ranking-results.csv", ranking_summaries)
    write_json_atomic(run_dir / "normalized" / "ranking-results.json", ranking_summaries)
    write_csv(run_dir / "normalized" / "direct-results.csv", direct_summaries)
    write_json_atomic(run_dir / "normalized" / "direct-results.json", direct_summaries)
    write_json_atomic(run_dir / "manifest.json", execution_manifest(run_dir, package, ranking_summaries=ranking_summaries, direct_summaries=direct_summaries, validation=validation))
    write_text_atomic(run_dir / "analysis-report.md", render_execution_report(validation, ranking_summaries, direct_summaries))
    write_text_atomic(run_dir / "checksums.sha256", render_checksums(run_dir))


def execution_manifest(
    run_dir: Path,
    package: dict[str, Any],
    *,
    ranking_summaries: list[dict[str, Any]] | None = None,
    direct_summaries: list[dict[str, Any]] | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-confirmatory-execution-manifest-v1",
        "harness_version": HARNESS_VERSION,
        "created_at": now_utc(),
        "run_dir": display_path(run_dir),
        "protocol": {"path": display_path(PROTOCOL_PATH), "sha256": sha256_file(PROTOCOL_PATH)},
        "recovery_amendment": {
            "path": display_path(AMENDMENT_PATH),
            "sha256": sha256_file(AMENDMENT_PATH) if AMENDMENT_PATH.exists() else "missing",
            "version": "evaluation-protocol-v1.5.1",
            "fresh_run_required": True,
        },
        "protocol_package": display_path(package["root"]),
        "expected_ranking_denominators": EXPECTED_DENOMINATORS,
        "expected_direct_cases": EXPECTED_DIRECT_CASES,
        "expected_direct_http_requests": EXPECTED_DIRECT_REQUESTS,
        "actual_ranking_denominators": dict(Counter(row["arm_id"] for row in ranking_summaries or [])),
        "actual_direct_cases": len(direct_summaries or []),
        "validation_valid": validation["valid"] if validation else False,
        "ground_truth_loaded_during_ranking_or_runtime": False,
    }


def canonicalization_readiness_summary(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-canonicalization-readiness-v1",
        "expected_inputs": {
            "ranking_row_artifacts": EXPECTED_DENOMINATORS["total_ranking_rows"],
            "direct_case_artifacts": EXPECTED_DIRECT_CASES,
            "ground_truth_source": "ground-truth/scoring-data.json loaded only after raw execution closes",
        },
        "expected_outputs": [
            "execution-integrity-report.json",
            "normalized/ranking-aggregates.json",
            "normalized/reliability-aggregates.json",
            "normalized/efficiency-aggregates.json",
            "normalized/direct-execution-aggregates.json",
            "normalized/scored-ranking-rows.json",
            "normalized/scored-direct-rows.json",
            "manifest.json",
            "checksums.sha256",
        ],
        "protocol_denominators": package["schedule"]["denominators"],
        "direct_denominator": package["direct_schedule"]["case_denominator"],
    }


def write_harness_readiness_package(output_dir: Path, report: dict[str, Any], package: dict[str, Any]) -> None:
    write_json_atomic(output_dir / "dry-validation-report.json", report)
    write_json_atomic(output_dir / "execution-plan-summary.json", {
        "schema_version": "owasp-sqli-v15-confirmatory-execution-plan-summary-v1",
        "scenario_count": len(package["snapshots_by_id"]),
        "per_arm_counts": report["ranking_schedule_resolution"]["per_arm_counts"],
        "total_ranking_rows": report["ranking_schedule_resolution"]["total_rows"],
        "direct_execution_cases": report["direct_schedule_resolution"]["direct_execution_cases"],
        "expected_direct_http_requests": report["direct_schedule_resolution"]["expected_http_requests"],
        "arm_order": list(ARM_IDS),
    })
    write_json_atomic(output_dir / "canonicalization-plan-summary.json", report["canonicalization_readiness"])
    write_text_atomic(output_dir / "report.md", render_dry_report(report))
    write_text_atomic(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_errors = validate_checksum_file(output_dir / "checksums.sha256", output_dir)
    write_json_atomic(output_dir / "checksum-validation-report.json", {
        "schema_version": "owasp-sqli-v15-confirmatory-harness-checksum-validation-v1",
        "valid": not checksum_errors,
        "errors": checksum_errors,
    })


def render_dry_report(report: dict[str, Any]) -> str:
    ranking = report["ranking_schedule_resolution"]
    direct = report["direct_schedule_resolution"]
    runtime = report["runtime_preflight"]
    return "\n".join(
        [
            "# OWASP SQLi v1.5.1 Confirmatory Harness Dry Validation",
            "",
            "Status: dry validation only. No scored ranking observations, model calls or final SQLi executions were created.",
            "Recovery amendment: v1.5.1 preparation for a complete fresh future scored run; the aborted v1.5 run is preserved as failed execution evidence only.",
            "",
            f"- Amendment valid: `{report['protocol_amendment']['valid']}`",
            f"- Prompt version: `{report['prompt_validation']['prompt_version']}`",
            f"- Aborted v1.5 run status: `{report['interrupted_v15_run']['status']}`",
            f"- Future v1.5.1 output root: `{report['future_v151_output_separation']['future_v151_output_root']}`",
            f"- Protocol hash matches: `{report['protocol_package']['protocol_hash_matches']}`",
            f"- Package checksum errors: `{report['protocol_package']['package_checksum_error_count']}`",
            f"- Ranking scenarios resolved: `{ranking['scenario_count']}`",
            f"- Deterministic rows: `{ranking['per_arm_counts'].get('deterministic_structural', 0)}`",
            f"- GPT rows: `{ranking['per_arm_counts'].get('proprietary_gpt', 0)}`",
            f"- Qwen rows: `{ranking['per_arm_counts'].get('local_qwen', 0)}`",
            f"- Total ranking rows: `{ranking['total_rows']}`",
            f"- Direct cases: `{direct['direct_execution_cases']}`",
            f"- Expected direct HTTP requests: `{direct['expected_http_requests']}`",
            f"- Ground truth loaded: `{ranking['ground_truth_loaded'] or direct['ground_truth_loaded']}`",
            f"- GPT environment valid: `{runtime['gpt']['valid']}`",
            f"- Qwen artifacts valid: `{runtime['qwen']['valid']}`",
            f"- OWASP target preflight: `{runtime['owasp_target']['status'] if 'status' in runtime['owasp_target'] else runtime['owasp_target']['valid']}`",
            f"- GPT calls: `{report['external_calls']['gpt_calls']}`",
            f"- Qwen calls: `{report['external_calls']['qwen_calls']}`",
            f"- Final SQLi runtime executions: `{report['external_calls']['final_sqli_runtime_executions']}`",
            f"- Direct HTTP requests: `{report['external_calls']['direct_http_requests']}`",
            f"- Scored observations: `{report['external_calls']['scored_observations']}`",
        ]
    ) + "\n"


def render_execution_report(validation: dict[str, Any], ranking_summaries: list[dict[str, Any]], direct_summaries: list[dict[str, Any]]) -> str:
    counts = Counter(row["arm_id"] for row in ranking_summaries)
    status_counts = Counter(row["status"] for row in ranking_summaries)
    direct_states = Counter(row["finding_state"] for row in direct_summaries)
    return "\n".join(
        [
            "# OWASP SQLi v1.5 Confirmatory Execution",
            "",
            f"- Validation valid: `{validation['valid']}`",
            f"- Deterministic rows: `{counts.get('deterministic_structural', 0)}`",
            f"- GPT rows: `{counts.get('proprietary_gpt', 0)}`",
            f"- Qwen rows: `{counts.get('local_qwen', 0)}`",
            f"- Ranking status counts: `{dict(status_counts)}`",
            f"- Direct cases: `{len(direct_summaries)}`",
            f"- Direct finding states: `{dict(direct_states)}`",
            "",
            "Ground truth is not included in raw ranking or direct runtime artifacts. Post-run scoring must load the separated scoring data only after execution.",
        ]
    ) + "\n"


def load_raw_ranking_rows(run_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((run_dir / "raw" / "ranking-rows").glob("sequence-*.json")):
        row = load_json(path)
        row["_artifact_path"] = display_path(path)
        rows.append(row)
    return rows


def load_raw_direct_rows(run_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted((run_dir / "raw" / "direct-sqli-cases").glob("candidate-*.json")):
        row = load_json(path)
        row["_artifact_path"] = display_path(path)
        rows.append(row)
    return rows


def audit_integrity(
    run_dir: Path,
    protocol: dict[str, Any],
    ranking_rows: list[dict[str, Any]],
    direct_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    errors: list[str] = []
    package_validation = validate_protocol_package(protocol)
    if not package_validation["valid"]:
        errors.extend(f"protocol package: {item}" for item in package_validation["errors"])
    schedule_by_id = {scheduled_row_id(row): row for row in protocol["schedule_rows"]}
    raw_by_id: dict[str, dict[str, Any]] = {}
    duplicate_raw_ids: list[str] = []
    raw_ground_truth_leaks: list[str] = []
    inconsistent_rows: list[str] = []
    for row in ranking_rows:
        summary = row.get("summary", {})
        row_id = scheduled_row_id(summary)
        if row_id in raw_by_id:
            duplicate_raw_ids.append(row_id)
        raw_by_id[row_id] = row
        if row.get("ground_truth_included") is not False:
            raw_ground_truth_leaks.append(row_id)
        if raw_ranking_leaks_ground_truth(row):
            raw_ground_truth_leaks.append(row_id)
        expected = schedule_by_id.get(row_id)
        if expected is None:
            inconsistent_rows.append(row_id)
            continue
        snapshot = protocol["snapshots_by_id"].get(expected["scenario_id"])
        if summary.get("candidate_input_sha256") != sha256_json(snapshot["candidate_input"]):
            inconsistent_rows.append(row_id)
    direct_by_id: dict[str, dict[str, Any]] = {}
    duplicate_direct: list[str] = []
    direct_ground_truth_leaks: list[str] = []
    planned_direct = {row["candidate_id"]: row for row in protocol["direct_rows"]}
    for row in direct_rows:
        summary = row.get("summary", {})
        candidate_id = str(summary.get("candidate_id"))
        if candidate_id in direct_by_id:
            duplicate_direct.append(candidate_id)
        direct_by_id[candidate_id] = row
        if row.get("ground_truth_included") is not False:
            direct_ground_truth_leaks.append(candidate_id)
        if candidate_id not in planned_direct:
            errors.append(f"unexpected direct artifact: {candidate_id}")
    missing_ids = sorted(set(schedule_by_id) - set(raw_by_id))
    unexpected_ids = sorted(set(raw_by_id) - set(schedule_by_id))
    missing_direct = sorted(set(planned_direct) - set(direct_by_id))
    ranking_counts = Counter(row["summary"]["arm_id"] for row in ranking_rows)
    ranking_status = Counter(row["summary"]["status"] for row in ranking_rows)
    direct_states = Counter(row["summary"]["finding_state"] for row in direct_rows)
    if dict(ranking_counts) != {arm: EXPECTED_DENOMINATORS[arm] for arm in ARM_IDS}:
        errors.append(f"per-arm ranking denominator mismatch: {dict(ranking_counts)}")
    if len(ranking_rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append(f"total ranking row denominator mismatch: {len(ranking_rows)}")
    if len(direct_rows) != EXPECTED_DIRECT_CASES:
        errors.append(f"direct case denominator mismatch: {len(direct_rows)}")
    if missing_ids:
        errors.append(f"missing scheduled ranking rows: {len(missing_ids)}")
    if unexpected_ids:
        errors.append(f"unexpected ranking row artifacts: {len(unexpected_ids)}")
    if duplicate_raw_ids:
        errors.append(f"duplicate raw ranking identities: {len(duplicate_raw_ids)}")
    if duplicate_direct:
        errors.append(f"duplicate direct identities: {len(duplicate_direct)}")
    if missing_direct:
        errors.append(f"missing direct case artifacts: {len(missing_direct)}")
    if raw_ground_truth_leaks:
        errors.append(f"ground truth leakage in raw ranking artifacts: {len(raw_ground_truth_leaks)}")
    if direct_ground_truth_leaks:
        errors.append(f"ground truth leakage in direct artifacts: {len(direct_ground_truth_leaks)}")
    if inconsistent_rows:
        errors.append(f"inconsistent ranking row artifacts: {len(inconsistent_rows)}")
    return {
        "schema_version": "owasp-sqli-v15-postrun-integrity-v1",
        "valid": not errors,
        "errors": errors,
        "run_dir": display_path(run_dir),
        "protocol_package_validation": package_validation,
        "scheduled_ranking_rows": len(protocol["schedule_rows"]),
        "completed_ranking_rows": len(ranking_rows),
        "missing_ranking_rows": len(missing_ids),
        "unexpected_ranking_rows": len(unexpected_ids),
        "duplicate_ranking_row_id_count": len(duplicate_raw_ids),
        "raw_ranking_ground_truth_leak_count": len(raw_ground_truth_leaks),
        "inconsistent_ranking_row_count": len(inconsistent_rows),
        "per_arm_rows": dict(ranking_counts),
        "ranking_status_counts": dict(ranking_status),
        "scheduled_direct_cases": len(protocol["direct_rows"]),
        "completed_direct_cases": len(direct_rows),
        "missing_direct_cases": len(missing_direct),
        "duplicate_direct_case_count": len(duplicate_direct),
        "direct_ground_truth_leak_count": len(direct_ground_truth_leaks),
        "direct_finding_states": dict(direct_states),
        "git_state": git_execution_state(),
    }


def raw_ranking_leaks_ground_truth(row: dict[str, Any]) -> bool:
    serialized = json.dumps(row.get("ranking_result", {}), sort_keys=True).lower()
    return any(fragment in serialized for fragment in ("expected_result", "ground_truth", "focal_vulnerable_candidate_id", "benchmarktest"))


def score_ranking_rows(rows: list[dict[str, Any]], scoring: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = {scenario["scenario_id"]: scenario for scenario in scoring["scenarios"]}
    scored_rows = []
    for row in sorted(rows, key=lambda item: int(item["summary"]["sequence"])):
        summary = row["summary"]
        ranking = row["ranking_result"]
        scenario = scenarios[summary["scenario_id"]]
        ordered = ranking["parsed_ranking"]
        scenario_type = scenario["scenario_type"]
        focal_id = scenario.get("focal_vulnerable_candidate_id")
        contract_valid = bool(summary["contract_valid"])
        rank: int | str = NOT_APPLICABLE
        top1: bool | str = NOT_APPLICABLE
        topk: bool | str = NOT_APPLICABLE
        reciprocal: float | str = NOT_APPLICABLE
        if scenario_type == "positive":
            if contract_valid and focal_id in ordered:
                rank = ordered.index(focal_id) + 1
                top1 = rank == 1
                topk = rank <= int(summary["top_k"])
                reciprocal = 1.0 / rank
            elif not contract_valid:
                rank = NOT_AVAILABLE
                top1 = NOT_AVAILABLE
                topk = NOT_AVAILABLE
                reciprocal = NOT_AVAILABLE
        scored_rows.append({
            "sequence": summary["sequence"],
            "scenario_id": summary["scenario_id"],
            "scenario_type": scenario_type,
            "arm_id": summary["arm_id"],
            "trial_number": summary["trial_number"],
            "candidate_test_budget": summary["candidate_test_budget"],
            "top_k": summary["top_k"],
            "candidate_input_sha256": summary["candidate_input_sha256"],
            "contract_valid": contract_valid,
            "status": summary["status"],
            "provider_failed": bool(summary["provider_failed"]),
            "validation_error_count": len(summary.get("validation_errors", [])),
            "validation_errors": summary.get("validation_errors", []),
            "latency_ms": summary.get("latency_ms"),
            "model_identifier": summary.get("model_identifier"),
            "provider": summary.get("provider"),
            "focal_vulnerable_candidate_id": focal_id if scenario_type == "positive" else NOT_APPLICABLE,
            "vulnerable_rank": rank,
            "top1": top1,
            "topk": topk,
            "reciprocal_rank": reciprocal,
            "parsed_ranking": ordered,
            "raw_artifact_path": row["_artifact_path"],
            "usage": ranking.get("usage"),
            "cost": ranking.get("cost"),
        })
    return scored_rows


def score_direct_rows(rows: list[dict[str, Any]], scoring: dict[str, Any]) -> list[dict[str, Any]]:
    ground_truth = {item["candidate_id"]: item for item in scoring["candidate_ground_truth"]}
    scored = []
    for row in sorted(rows, key=lambda item: int(item["summary"]["sequence"])):
        summary = row["summary"]
        truth = ground_truth[summary["candidate_id"]]
        expected = truth["expected_result"]
        finding_state = summary["finding_state"]
        runtime_error = summary["status"] == "runtime_error"
        if expected == "vulnerable":
            classification = "TP" if finding_state == "verified" else "FN"
        else:
            classification = "FP" if finding_state == "verified" else "TN"
        scored.append({
            **summary,
            "expected_result_loaded_post_run": expected,
            "original_case_id_loaded_post_run": truth["original_case_id"],
            "classification": classification,
            "runtime_error": runtime_error,
            "raw_artifact_path": row["_artifact_path"],
        })
    return scored


def aggregate_ranking_results(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_IDS:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        positive = [row for row in rows if row["scenario_type"] == "positive"]
        valid_positive = [row for row in positive if row["contract_valid"]]
        negative = [row for row in rows if row["scenario_type"] == "negative_only"]
        rank_values = [int(row["vulnerable_rank"]) for row in valid_positive if isinstance(row["vulnerable_rank"], int)]
        by_arm[arm] = {
            "scheduled_rows": len(rows),
            "positive_rows": len(positive),
            "negative_rows": len(negative),
            "valid_positive_rows": len(valid_positive),
            "invalid_positive_rows": len(positive) - len(valid_positive),
            "top1": ratio(sum(1 for row in valid_positive if row["top1"] is True), len(valid_positive)),
            "topk": ratio(sum(1 for row in valid_positive if row["topk"] is True), len(valid_positive)),
            "mrr": mean([float(row["reciprocal_rank"]) for row in valid_positive if isinstance(row["reciprocal_rank"], float)]),
            "candidate_coverage_under_budget": ratio(sum(1 for row in valid_positive if row["topk"] is True), len(valid_positive)),
            "rank_distribution": {str(rank): rank_values.count(rank) for rank in range(1, 6)},
            "scenario_level": scenario_level_metrics(rows),
        }
    return {
        "schema_version": "owasp-sqli-v15-ranking-aggregates-v1",
        "arms": by_arm,
        "scenario_denominators": {"positive_scenarios": 105, "negative_only_scenarios": 19, "total_scenarios": 124},
        "repeated_trials_policy": "LLM trials are repeated observations nested under scenario and arm, not independent benchmark scenarios.",
    }


def reliability_aggregates(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_IDS:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        status = Counter(row["status"] for row in rows)
        valid = sum(1 for row in rows if row["contract_valid"])
        provider_failures = sum(1 for row in rows if row["provider_failed"])
        malformed = sum(1 for row in rows if row["status"] == "malformed")
        timeout_count = sum(1 for row in rows if "timeout" in json.dumps(row["validation_errors"]).lower())
        by_arm[arm] = {
            "scheduled_rows": len(rows),
            "completed_raw_artifacts": len(rows),
            "attempted_model_calls": 0 if arm == "deterministic_structural" else len(rows),
            "contract_valid_outputs": valid,
            "contract_invalid_outputs": len(rows) - valid,
            "provider_or_runtime_failures": provider_failures,
            "timeouts": timeout_count,
            "malformed_outputs": malformed,
            "retries": 0,
            "contract_validity_rate": ratio(valid, len(rows)),
            "status_counts": dict(status),
        }
    return {"schema_version": "owasp-sqli-v15-reliability-aggregates-v1", "arms": by_arm}


def efficiency_aggregates(scored_rows: list[dict[str, Any]], direct_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_IDS:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        latencies = [int(row["latency_ms"]) for row in rows if isinstance(row.get("latency_ms"), int)]
        by_arm[arm] = {
            "latency_ms": describe(latencies),
            "token_usage": token_summary(rows),
            "cost": cost_summary(rows, arm),
        }
    return {
        "schema_version": "owasp-sqli-v15-efficiency-aggregates-v1",
        "ranking_arms": by_arm,
        "direct_execution": {
            "cases": len(direct_rows),
            "expected_request_count": sum(int(row.get("request_count", 0)) for row in direct_rows),
        },
    }


def direct_execution_aggregates(scored_direct: list[dict[str, Any]]) -> dict[str, Any]:
    expected = Counter(row["expected_result_loaded_post_run"] for row in scored_direct)
    states = Counter(row["finding_state"] for row in scored_direct)
    classifications = Counter(row["classification"] for row in scored_direct)
    return {
        "schema_version": "owasp-sqli-v15-direct-execution-aggregates-v1",
        "case_denominator": len(scored_direct),
        "expected_vulnerable": expected.get("vulnerable", 0),
        "expected_non_vulnerable": expected.get("non_vulnerable", 0),
        "baseline_stable_count": sum(1 for row in scored_direct if row["baseline_stable"]),
        "reproducible_boolean_difference_count": sum(1 for row in scored_direct if row["true_false_difference_reproducible"]),
        "verified_count": states.get("verified", 0),
        "rejected_count": states.get("rejected", 0),
        "inconclusive_count": states.get("inconclusive", 0),
        "runtime_error_count": sum(1 for row in scored_direct if row["runtime_error"]),
        "finding_state_counts": dict(states),
        "classification_counts": dict(classifications),
        "verifier_coverage": ratio(states.get("verified", 0) + states.get("rejected", 0), len(scored_direct)),
        "inconclusive_policy": "inconclusive outcomes remain in the denominator",
    }


def negative_scenario_aggregates(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_IDS:
        rows = [row for row in scored_rows if row["arm_id"] == arm and row["scenario_type"] == "negative_only"]
        by_arm[arm] = {
            "negative_rows": len(rows),
            "negative_scenarios": len({row["scenario_id"] for row in rows}),
            "contract_valid_rows": sum(1 for row in rows if row["contract_valid"]),
            "top1_topk_mrr": NOT_APPLICABLE,
        }
    return {"schema_version": "owasp-sqli-v15-negative-scenario-aggregates-v1", "arms": by_arm}


def validate_canonical_outputs(
    scored_ranking: list[dict[str, Any]],
    scored_direct: list[dict[str, Any]],
    ranking_aggregates: dict[str, Any],
    direct_aggregates: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    if not integrity["valid"]:
        errors.append("integrity invalid")
    for arm in ARM_IDS:
        expected = EXPECTED_DENOMINATORS[arm]
        if ranking_aggregates["arms"][arm]["scheduled_rows"] != expected:
            errors.append(f"ranking denominator mismatch for {arm}")
    if len(scored_ranking) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("scored ranking row total mismatch")
    if direct_aggregates["case_denominator"] != EXPECTED_DIRECT_CASES or len(scored_direct) != EXPECTED_DIRECT_CASES:
        errors.append("direct case denominator mismatch")
    return {
        "schema_version": "owasp-sqli-v15-canonical-validation-v1",
        "valid": not errors,
        "errors": errors,
        "scored_ranking_rows": len(scored_ranking),
        "expected_scored_ranking_rows": EXPECTED_DENOMINATORS["total_ranking_rows"],
        "scored_direct_cases": len(scored_direct),
        "expected_direct_cases": EXPECTED_DIRECT_CASES,
    }


def write_canonical_outputs(output_dir: Path, package: dict[str, Any]) -> None:
    write_json_atomic(output_dir / "manifest.json", package["manifest"])
    write_json_atomic(output_dir / "execution-integrity-report.json", package["integrity"])
    write_json_atomic(output_dir / "validation-report.json", package["validation"])
    write_json_atomic(output_dir / "normalized" / "ranking-aggregates.json", package["ranking_aggregates"])
    write_json_atomic(output_dir / "normalized" / "reliability-aggregates.json", package["reliability"])
    write_json_atomic(output_dir / "normalized" / "efficiency-aggregates.json", package["efficiency"])
    write_json_atomic(output_dir / "normalized" / "direct-execution-aggregates.json", package["direct_aggregates"])
    write_json_atomic(output_dir / "normalized" / "negative-scenario-aggregates.json", package["negative_scenarios"])
    write_json_atomic(output_dir / "normalized" / "scored-ranking-rows.json", package["ranking_rows"])
    write_json_atomic(output_dir / "normalized" / "scored-direct-rows.json", package["direct_rows"])
    write_csv(output_dir / "normalized" / "scored-ranking-rows.csv", package["ranking_rows"])
    write_csv(output_dir / "normalized" / "scored-direct-rows.csv", package["direct_rows"])
    write_text_atomic(output_dir / "analysis-report.md", render_analysis_report(package))
    write_text_atomic(output_dir / "thesis-tables.md", render_thesis_tables_md(package))
    write_text_atomic(output_dir / "thesis-tables.tex", render_thesis_tables_tex(package))
    write_text_atomic(output_dir / "checksums.sha256", render_checksums(output_dir))


def canonical_manifest(output_dir: Path, run_dir: Path, protocol_package_dir: Path, integrity: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-canonical-analysis-manifest-v1",
        "created_at": now_utc(),
        "output_dir": display_path(output_dir),
        "raw_execution_dir": display_path(run_dir),
        "protocol_package_dir": display_path(protocol_package_dir),
        "recovery_amendment": {
            "path": display_path(AMENDMENT_PATH),
            "sha256": sha256_file(AMENDMENT_PATH) if AMENDMENT_PATH.exists() else "missing",
            "version": "evaluation-protocol-v1.5.1",
        },
        "validation_valid": validation["valid"],
        "immutable_raw_artifacts_preserved": True,
        "ground_truth_loaded_only_for_post_run_scoring": True,
        "scored_execution_rerun": False,
        "gpt_calls_performed_by_canonicalization": 0,
        "qwen_calls_performed_by_canonicalization": 0,
        "owasp_cases_executed_by_canonicalization": 0,
        "integrity": {
            "completed_ranking_rows": integrity["completed_ranking_rows"],
            "completed_direct_cases": integrity["completed_direct_cases"],
            "raw_ranking_ground_truth_leak_count": integrity["raw_ranking_ground_truth_leak_count"],
            "direct_ground_truth_leak_count": integrity["direct_ground_truth_leak_count"],
        },
        "git_state": git_execution_state(),
    }


def render_analysis_report(package: dict[str, Any]) -> str:
    lines = [
        "# OWASP SQLi v1.5 Confirmatory Canonical Analysis",
        "",
        "Status: post-run deterministic scoring and analysis only. No scored observations were rerun or modified.",
        "",
        "## Integrity",
        "",
        f"- Completed ranking rows: `{package['integrity']['completed_ranking_rows']}`",
        f"- Completed direct cases: `{package['integrity']['completed_direct_cases']}`",
        f"- Raw ranking ground-truth leak count: `{package['integrity']['raw_ranking_ground_truth_leak_count']}`",
        f"- Direct ground-truth leak count: `{package['integrity']['direct_ground_truth_leak_count']}`",
        "",
        "## Ranking Results",
        "",
        "| Arm | Positive valid rows | Top-1 | Top-k | MRR | Contract-valid outputs | Invalid/failure outputs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_IDS:
        a = package["ranking_aggregates"]["arms"][arm]
        r = package["reliability"]["arms"][arm]
        lines.append(
            f"| `{arm}` | {a['valid_positive_rows']} | {fmt(a['top1'])} | {fmt(a['topk'])} | {fmt(a['mrr'])} | "
            f"{r['contract_valid_outputs']} | {r['contract_invalid_outputs']} |"
        )
    d = package["direct_aggregates"]
    lines.extend([
        "",
        "## Direct SQLi Validation",
        "",
        f"- Case denominator: `{d['case_denominator']}`",
        f"- Verified: `{d['verified_count']}`",
        f"- Rejected: `{d['rejected_count']}`",
        f"- Inconclusive: `{d['inconclusive_count']}`",
        f"- Runtime errors: `{d['runtime_error_count']}`",
        f"- Classification counts: `{d['classification_counts']}`",
    ])
    return "\n".join(lines) + "\n"


def render_thesis_tables_md(package: dict[str, Any]) -> str:
    lines = [
        "# Thesis Tables: OWASP SQLi v1.5 Confirmatory Evaluation",
        "",
        "## Ranking Effectiveness",
        "",
        "| Arm | Positive valid rows | Top-1 | Top-4 | MRR |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_IDS:
        a = package["ranking_aggregates"]["arms"][arm]
        lines.append(f"| `{arm}` | {a['valid_positive_rows']} | {fmt(a['top1'])} | {fmt(a['topk'])} | {fmt(a['mrr'])} |")
    lines.extend([
        "",
        "## Direct SQLi Validation",
        "",
        "| Cases | Verified | Rejected | Inconclusive | Runtime errors |",
        "| ---: | ---: | ---: | ---: | ---: |",
    ])
    d = package["direct_aggregates"]
    lines.append(f"| {d['case_denominator']} | {d['verified_count']} | {d['rejected_count']} | {d['inconclusive_count']} | {d['runtime_error_count']} |")
    return "\n".join(lines) + "\n"


def render_thesis_tables_tex(package: dict[str, Any]) -> str:
    rows = []
    for arm in ARM_IDS:
        a = package["ranking_aggregates"]["arms"][arm]
        rows.append(f"{arm.replace('_', '\\_')} & {a['valid_positive_rows']} & {fmt(a['top1'])} & {fmt(a['topk'])} & {fmt(a['mrr'])} \\\\")
    d = package["direct_aggregates"]
    return (
        "% OWASP SQLi v1.5 confirmatory evaluation. Generated from canonical post-run artifacts.\n"
        "\\begin{tabular}{lrrrr}\n"
        "\\toprule\n"
        "Arm & Positive valid rows & Top-1 & Top-4 & MRR \\\\\n"
        "\\midrule\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n"
        "\\end{tabular}\n\n"
        "\\begin{tabular}{rrrrr}\n"
        "\\toprule\n"
        "Cases & Verified & Rejected & Inconclusive & Runtime errors \\\\\n"
        "\\midrule\n"
        f"{d['case_denominator']} & {d['verified_count']} & {d['rejected_count']} & {d['inconclusive_count']} & {d['runtime_error_count']} \\\\\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
    )


def scenario_level_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario_id"]].append(row)
    for scenario_id, scenario_rows in sorted(by_scenario.items()):
        positive_rows = [row for row in scenario_rows if row["scenario_type"] == "positive" and row["contract_valid"]]
        result.append({
            "scenario_id": scenario_id,
            "scenario_type": scenario_rows[0]["scenario_type"],
            "rows": len(scenario_rows),
            "contract_valid_rows": sum(1 for row in scenario_rows if row["contract_valid"]),
            "top1_rate": ratio(sum(1 for row in positive_rows if row["top1"] is True), len(positive_rows)) if positive_rows else NOT_APPLICABLE,
            "topk_rate": ratio(sum(1 for row in positive_rows if row["topk"] is True), len(positive_rows)) if positive_rows else NOT_APPLICABLE,
            "mean_reciprocal_rank": mean([float(row["reciprocal_rank"]) for row in positive_rows if isinstance(row["reciprocal_rank"], float)]) if positive_rows else NOT_APPLICABLE,
        })
    return result


def token_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ("input_tokens", "output_tokens", "total_tokens")
    totals = {key: 0 for key in keys}
    counts = {key: 0 for key in keys}
    for row in rows:
        usage = row.get("usage")
        if not isinstance(usage, dict):
            continue
        for key in keys:
            value = usage.get(key)
            if isinstance(value, int):
                totals[key] += value
                counts[key] += 1
    if not any(counts.values()):
        return {key: NOT_AVAILABLE for key in keys}
    return {**totals, "rows_with_numeric_usage": max(counts.values())}


def cost_summary(rows: list[dict[str, Any]], arm: str) -> dict[str, Any] | str:
    if arm == "deterministic_structural":
        return NOT_APPLICABLE
    observed = [row.get("cost") for row in rows if row.get("cost")]
    numeric = [item for item in observed if isinstance(item, dict) and any(isinstance(v, (int, float)) for v in item.values())]
    if numeric:
        return {"availability": "available", "observed": numeric}
    return {"availability": NOT_AVAILABLE, "reason": "no frozen numeric pricing/cost artifact retained"}


def describe(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": NOT_AVAILABLE, "median": NOT_AVAILABLE, "mean": NOT_AVAILABLE, "max": NOT_AVAILABLE}
    ordered = sorted(values)
    return {
        "count": len(values),
        "min": ordered[0],
        "median": median(values),
        "mean": mean(values),
        "max": ordered[-1],
    }


def mean(values: list[float] | list[int]) -> float | str:
    if not values:
        return NOT_AVAILABLE
    return round(sum(values) / len(values), 4)


def median(values: list[int]) -> float | str:
    if not values:
        return NOT_AVAILABLE
    ordered = sorted(values)
    midpoint = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[midpoint])
    return round((ordered[midpoint - 1] + ordered[midpoint]) / 2.0, 4)


def ratio(numerator: int, denominator: int) -> float | str:
    if denominator == 0:
        return NOT_APPLICABLE
    return round(numerator / denominator, 4)


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def validate_checksum_file(checksum_path: Path, base_dir: Path) -> list[str]:
    errors: list[str] = []
    if not checksum_path.exists():
        return [f"checksum file missing: {display_path(checksum_path)}"]
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = base_dir / relative
        if not path.exists():
            errors.append(f"checksum target missing: {relative}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"checksum mismatch: {relative}")
    return errors


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def write_text_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def git_execution_state() -> dict[str, Any]:
    return {
        "branch": git_output(["branch", "--show-current"], check=False),
        "commit": git_output(["rev-parse", "HEAD"], check=False),
        "dirty": bool(git_output(["status", "--porcelain"], check=False)),
        "status_short": git_output(["status", "--short"], check=False).splitlines(),
    }


def git_output(args: list[str], *, check: bool) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    if check and completed.returncode != 0:
        raise SqliConfirmatoryHarnessError(completed.stderr.strip())
    return completed.stdout.strip()


def local_model_artifact(candidate_id: str):
    model = next((item for item in MODEL_ARTIFACTS if item.candidate_id == candidate_id), None)
    if model is None:
        raise SqliConfirmatoryHarnessError(f"unknown local model candidate: {candidate_id}")
    return model


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def ensure_not_overwriting_previous_results(path: Path) -> None:
    resolved = path.resolve()
    protected_parts = {
        "heldout-evaluation-v1.2-canonical",
        "xss-v13-ablation-v1.3",
        "xss-v13-ablation-v1.3.1-final",
        "owasp-xss-v14-confirmatory-final",
        "owasp-sqli-v15-protocol-freeze",
        "owasp-sqli-v15-readiness",
        "owasp-sqli-v15-confirmatory-final",
    }
    if any(part in resolved.parts for part in protected_parts):
        raise SqliConfirmatoryHarnessError(f"refusing to write inside protected result path: {path}")
    if path.exists() and any(path.iterdir()):
        raise SqliConfirmatoryHarnessError(f"output directory already exists and is not empty: {path}")


def validate_resume_run_directory(run_dir: Path, output_root: Path) -> None:
    resolved_run = run_dir.resolve()
    resolved_root = output_root.resolve()
    protected_parts = {
        "heldout-evaluation-v1.2-canonical",
        "xss-v13-ablation-v1.3",
        "xss-v13-ablation-v1.3.1-final",
        "owasp-xss-v14-confirmatory-final",
        "owasp-sqli-v15-protocol-freeze",
        "owasp-sqli-v15-readiness",
        "owasp-sqli-v15-confirmatory-final",
    }
    if any(part in resolved_run.parts for part in protected_parts):
        raise SqliConfirmatoryHarnessError(f"refusing to resume inside protected result path: {run_dir}")
    if resolved_run == resolved_root:
        raise SqliConfirmatoryHarnessError("resume run directory must be a specific run directory, not the output root")
    if resolved_root not in resolved_run.parents:
        raise SqliConfirmatoryHarnessError(f"resume run directory must be inside output root: {run_dir}")
    markers = (run_dir / "raw", run_dir / "runtime-preflight.json", run_dir / "execution-manifest.json")
    if any(run_dir.iterdir()) and not any(marker.exists() for marker in markers):
        raise SqliConfirmatoryHarnessError(f"resume run directory does not look like a harness run: {run_dir}")


def resolve_dry_validation_output_dir(requested: Path) -> Path:
    default_readiness_roots = {DEFAULT_READINESS_DIR.resolve(), DEFAULT_V151_READINESS_DIR.resolve()}
    if requested.resolve() in default_readiness_roots and requested.exists() and any(requested.iterdir()):
        return requested / f"dry-validation-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    return requested


def main() -> None:
    parser = argparse.ArgumentParser(description="Run or dry-validate the amended OWASP SQLi v1.5.1 confirmatory harness.")
    parser.add_argument("--mode", choices=("dry-run", "preflight", "execute", "canonicalize"), default="dry-run")
    parser.add_argument("--protocol-package", type=Path, default=PROTOCOL_PACKAGE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_V151_READINESS_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_V151_FINAL_ROOT)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--resume-run-dir", type=Path)
    parser.add_argument("--canonical-dir", type=Path, default=DEFAULT_V151_CANONICAL_DIR)
    parser.add_argument("--check-target", action="store_true", help="Include the non-scored OWASP target health check in dry-run mode.")
    parser.add_argument("--execute-final-confirmatory", action="store_true", help="Required with --mode execute.")
    args = parser.parse_args()

    if args.mode == "dry-run":
        output_dir = resolve_dry_validation_output_dir(args.output_dir)
        report = run_dry_validation(protocol_package_dir=args.protocol_package, output_dir=output_dir, check_target=args.check_target)
        print(f"OWASP SQLi v1.5.1 confirmatory dry validation valid: {report['valid']}")
        print(f"Dry-validation artifacts written to: {output_dir.resolve()}")
        return

    if args.mode == "preflight":
        report = run_runtime_preflight(protocol_package_dir=args.protocol_package)
        print(json.dumps(report, indent=2, sort_keys=True))
        if not report["valid"]:
            raise SystemExit(1)
        return

    if args.mode == "canonicalize":
        if args.run_dir is None:
            raise SystemExit("--mode canonicalize requires --run-dir")
        package = build_canonical_package(run_dir=args.run_dir, protocol_package_dir=args.protocol_package, output_dir=args.canonical_dir)
        print(f"OWASP SQLi v1.5.1 canonical analysis valid: {package['validation']['valid']}")
        print(f"Canonical artifacts written to: {args.canonical_dir.resolve()}")
        return

    run_dir = execute_final_confirmatory(
        output_root=args.output_root,
        resume_run_dir=args.resume_run_dir,
        protocol_package_dir=args.protocol_package,
        execute_final_confirmatory_flag=args.execute_final_confirmatory,
    )
    print(f"OWASP SQLi v1.5.1 confirmatory execution artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
