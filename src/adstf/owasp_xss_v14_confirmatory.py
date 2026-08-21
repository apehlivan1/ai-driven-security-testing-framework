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
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import URLError

from adstf.discovery import ReflectedInputCandidate, rank_reflected_input_candidates
from adstf.llm_ranking import (
    CommandModelClient,
    LLM_RANKING_PROMPT_VERSION,
    LLMRankingResult,
    ModelClient,
    ModelProviderError,
    ModelTimeoutError,
    build_ranking_prompt,
    parse_model_ranking,
    ranking_result_artifact,
)
from adstf.local_runtime import MODEL_ARTIFACTS, MODEL_ROOT, RUNTIME_ROOT, LlamaCppCliClient, sha256_file as runtime_sha256_file
from adstf.local_runtime_output_boundary import transport_settings
from adstf.local_runtime_readiness import readiness_json_schema
from adstf.owasp_xss_v14 import DEFAULT_BASE_URL, health_check
from adstf.owasp_xss_v14_protocol_prep import (
    ARM_IDS,
    LOCAL_CONTINGENCY_MODEL_ID,
    LOCAL_MODEL_IDENTIFIER,
    LOCAL_PRIMARY_MODEL_ID,
    PROPRIETARY_MODEL_IDENTIFIER,
    TEST_BUDGET,
    model_facing_snapshot_leaks,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"
PROTOCOL_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-harness-readiness"
DEFAULT_FINAL_ROOT = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final"
HARNESS_VERSION = "owasp-xss-v14-confirmatory-harness-v1"
DRY_VALIDATION_VERSION = "owasp-xss-v14-confirmatory-dry-validation-v1"
RUNTIME_PREFLIGHT_VERSION = "owasp-xss-v14-confirmatory-runtime-preflight-v1"
RESULT_ROW_VERSION = "owasp-xss-v14-ranking-row-v1"

EXPECTED_PROTOCOL_SHA256 = "172a583322cd73e6553ea05d9209a33bf216eed6b62d74f98653e893722e473a"
EXPECTED_DENOMINATORS = {
    "deterministic_structural": 266,
    "proprietary_gpt": 1330,
    "local_qwen": 1330,
    "total_ranking_rows": 2926,
}
GPT_SETTINGS = {
    "temperature_parameter": "omitted",
    "provider_default_temperature_used": True,
    "max_output_tokens": 1200,
    "timeout_seconds": 60,
}
QWEN_RUNTIME_SHA256 = "2272eaaf8bb9477257790835d7b25aaf8fd22941e44ac3fcc9f2df389d1ef7b4"
QWEN_MODEL_HASHES = {
    "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf": "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db",
    "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf": "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a",
}
LLAMA_COMPLETION_EXE = RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"


class ConfirmatoryHarnessError(RuntimeError):
    pass


def run_dry_validation(
    *,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    output_dir: Path = DEFAULT_READINESS_DIR,
    env: Mapping[str, str | None] | None = None,
    check_target: bool = False,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    package = load_protocol_package(protocol_package_dir)
    package_validation = validate_protocol_package(package)
    schedule_validation = validate_schedule_resolution(package)
    runtime_preflight = runtime_preflight_status(
        env=env,
        check_target=check_target,
        target_probe=target_probe,
    )
    git_state = git_execution_state()
    duplicate_resume = validate_duplicate_and_resume_state(output_dir, package["schedule_rows"])
    report = {
        "schema_version": DRY_VALIDATION_VERSION,
        "harness_version": HARNESS_VERSION,
        "created_at": now_utc(),
        "mode": "dry_validation",
        "valid": package_validation["valid"] and schedule_validation["valid"] and duplicate_resume["valid"],
        "protocol_package": package_validation,
        "schedule_resolution": schedule_validation,
        "runtime_preflight": runtime_preflight,
        "duplicate_resume_validation": duplicate_resume,
        "git_state": git_state,
        "external_calls": {
            "gpt_calls": 0,
            "qwen_calls": 0,
            "owasp_or_browser_final_case_calls": 0,
            "scored_observations": 0,
        },
        "ground_truth_isolation": {
            "ground_truth_loaded_during_dry_validation": False,
            "model_facing_snapshot_leak_count": schedule_validation["snapshot_leak_count"],
        },
    }
    write_harness_readiness_package(output_dir, report, package)
    return report


def run_runtime_preflight(
    *,
    env: Mapping[str, str | None] | None = None,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
) -> dict[str, Any]:
    package = load_protocol_package(protocol_package_dir)
    package_validation = validate_protocol_package(package)
    runtime = runtime_preflight_status(env=env, check_target=True, target_probe=target_probe)
    return {
        "schema_version": RUNTIME_PREFLIGHT_VERSION,
        "created_at": now_utc(),
        "valid": package_validation["valid"] and runtime["valid"],
        "protocol_package": package_validation,
        "runtime_preflight": runtime,
    }


def execute_final_confirmatory(
    *,
    output_root: Path = DEFAULT_FINAL_ROOT,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    env: Mapping[str, str | None] | None = None,
    gpt_client: ModelClient | None = None,
    qwen_client_factory: Callable[[Path], ModelClient] | None = None,
    max_rows: int | None = None,
) -> Path:
    preflight = run_runtime_preflight(env=env, protocol_package_dir=protocol_package_dir)
    if not preflight["valid"]:
        raise ConfirmatoryHarnessError("runtime preflight failed; refusing scored execution")
    run_dir = output_root / f"owasp-xss-v14-confirmatory-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    if run_dir.exists():
        raise ConfirmatoryHarnessError(f"output directory already exists: {run_dir}")
    run_dir.mkdir(parents=True)
    package = load_protocol_package(protocol_package_dir)
    write_json_atomic(run_dir / "runtime-preflight.json", preflight)
    write_json_atomic(run_dir / "execution-manifest.json", execution_manifest(run_dir, package))
    execute_schedule_rows(
        run_dir=run_dir,
        package=package,
        gpt_client=gpt_client,
        qwen_client_factory=qwen_client_factory,
        max_rows=max_rows,
    )
    finalize_execution_package(run_dir, package)
    return run_dir


def execute_schedule_rows(
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
        result_path = row_artifact_path(row_dir, row)
        if result_path.exists():
            existing = load_json(result_path)
            validate_existing_row_artifact(existing, row)
            completed.append(existing["summary"])
            continue
        snapshot = package["snapshots_by_id"][row["scenario_id"]]
        started = time.perf_counter()
        if row["arm_id"] == "deterministic_structural":
            artifact = deterministic_row_artifact(row, snapshot, started)
        elif row["arm_id"] == "proprietary_gpt":
            if gpt_client is None:
                gpt_client = create_proprietary_gpt_client()
            artifact = model_row_artifact(row, snapshot, gpt_client, GPT_SETTINGS, started)
        elif row["arm_id"] == "local_qwen":
            schema_path = write_local_schema(snapshot, schemas_dir)
            settings = local_qwen_settings_for_schema(schema_path)
            client = qwen_client_factory(schema_path)
            artifact = model_row_artifact(row, snapshot, client, settings, started)
        else:
            raise ConfirmatoryHarnessError(f"unexpected arm in frozen schedule: {row['arm_id']}")
        write_json_atomic(result_path, artifact)
        completed.append(artifact["summary"])
    return completed


def load_protocol_package(root: Path) -> dict[str, Any]:
    if not root.exists():
        raise ConfirmatoryHarnessError(f"protocol package not found: {root}")
    scenario_manifest = load_json(root / "scenario-manifest.json")
    schedule = load_json(root / "trial-schedule.json")
    arm_config = load_json(root / "arm-configurations.json")
    snapshot_index = load_json(root / "model-facing" / "candidate-snapshot-index.json")
    snapshots_by_id = {
        item["scenario_id"]: load_json(root / item["path"])
        for item in snapshot_index["snapshot_paths"]
    }
    return {
        "root": root,
        "scenario_manifest": scenario_manifest,
        "schedule": schedule,
        "schedule_rows": schedule["rows"],
        "arm_config": arm_config,
        "snapshot_index": snapshot_index,
        "snapshots_by_id": snapshots_by_id,
    }


def validate_protocol_package(package: dict[str, Any]) -> dict[str, Any]:
    root = package["root"]
    errors: list[str] = []
    protocol_hash = sha256_file(PROTOCOL_PATH) if PROTOCOL_PATH.exists() else "missing"
    if protocol_hash != EXPECTED_PROTOCOL_SHA256:
        errors.append("protocol_hash_mismatch")
    checksum_errors = validate_checksum_file(root / "checksums.sha256", root)
    errors.extend(checksum_errors)
    scenario_manifest = package["scenario_manifest"]
    schedule = package["schedule"]
    if scenario_manifest.get("scenario_count") != 266:
        errors.append("scenario_count_mismatch")
    if schedule.get("denominators") != EXPECTED_DENOMINATORS:
        errors.append("schedule_denominator_mismatch")
    if [arm["arm_id"] for arm in package["arm_config"]["arms"]] != list(ARM_IDS):
        errors.append("arm_order_mismatch")
    return {
        "valid": not errors,
        "errors": errors,
        "protocol_sha256": protocol_hash,
        "protocol_sha256_expected": EXPECTED_PROTOCOL_SHA256,
        "protocol_hash_matches": protocol_hash == EXPECTED_PROTOCOL_SHA256,
        "package_checksum_error_count": len(checksum_errors),
        "package_checksum_errors": checksum_errors[:10],
    }


def validate_schedule_resolution(package: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    rows = package["schedule_rows"]
    snapshots = package["snapshots_by_id"]
    seen_row_ids: set[str] = set()
    counts = Counter(row["arm_id"] for row in rows)
    missing_snapshots: list[str] = []
    snapshot_leaks: list[str] = []
    for row in rows:
        row_id = scheduled_row_id(row)
        if row_id in seen_row_ids:
            errors.append(f"duplicate scheduled row: {row_id}")
        seen_row_ids.add(row_id)
        snapshot = snapshots.get(row["scenario_id"])
        if snapshot is None:
            missing_snapshots.append(row["scenario_id"])
            continue
        if row["candidate_test_budget"] != TEST_BUDGET or row["top_k"] != min(TEST_BUDGET, snapshot["candidate_count"]):
            errors.append(f"budget/top_k mismatch for {row_id}")
        if sha256_json(snapshot["candidate_input"]) != package["scenario_manifest"]["scenarios"][scenario_index(row["scenario_id"])]["candidate_input_sha256"]:
            errors.append(f"candidate_input_sha256 mismatch for {row['scenario_id']}")
        if model_facing_snapshot_leaks(snapshot):
            snapshot_leaks.append(row["scenario_id"])
    if missing_snapshots:
        errors.append(f"missing snapshots: {', '.join(sorted(set(missing_snapshots))[:5])}")
    if counts != Counter({"deterministic_structural": 266, "proprietary_gpt": 1330, "local_qwen": 1330}):
        errors.append(f"per-arm denominator mismatch: {dict(counts)}")
    if len(rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("total schedule row mismatch")
    if snapshot_leaks:
        errors.append(f"model-facing snapshot leakage: {', '.join(sorted(set(snapshot_leaks))[:5])}")
    return {
        "valid": not errors,
        "errors": errors,
        "per_arm_counts": dict(counts),
        "total_rows": len(rows),
        "unique_row_ids": len(seen_row_ids),
        "scenario_count": len(snapshots),
        "snapshot_leak_count": len(set(snapshot_leaks)),
        "ground_truth_loaded": False,
    }


def runtime_preflight_status(
    *,
    env: Mapping[str, str | None] | None = None,
    check_target: bool,
    target_probe: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    gpt = gpt_preflight(env)
    qwen = qwen_preflight()
    target = target_preflight(target_probe=target_probe) if check_target else {
        "checked": False,
        "valid": False,
        "status": "not_checked_in_dry_validation_mode",
        "base_url": DEFAULT_BASE_URL,
    }
    return {
        "schema_version": RUNTIME_PREFLIGHT_VERSION,
        "valid": gpt["valid"] and qwen["valid"] and (target["valid"] if check_target else True),
        "gpt": gpt,
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
    return {
        "checked": True,
        "valid": reachable,
        "base_url": base_url,
        "approved_local_scope": base_url == "https://127.0.0.1:8443/benchmark",
        "probe_result": result,
        "final_confirmatory_case_executed": False,
        "browser_verification_executed": False,
    }


def deterministic_row_artifact(row: dict[str, Any], snapshot: dict[str, Any], started: float) -> dict[str, Any]:
    candidates = reflected_candidates_from_snapshot(snapshot)
    ranking = rank_reflected_input_candidates(candidates, lambda _: True)
    ordered_ids = [item.candidate.candidate_id for item in ranking]
    return ranking_row_artifact(
        row=row,
        snapshot=snapshot,
        ordered_candidate_ids=ordered_ids,
        rationales={item.candidate.candidate_id: "; ".join(item.rationale) for item in ranking},
        validation_errors=[],
        provider_failed=False,
        model_identifier="not_applicable",
        provider="deterministic",
        prompt=None,
        raw_response=None,
        model_settings={"ranking_ruleset_version": "deterministic-structural-v1"},
        usage=None,
        cost={"availability": "not_applicable"},
        provider_metadata={"scores": [to_json_value(item) for item in ranking]},
        started=started,
    )


def model_row_artifact(
    row: dict[str, Any],
    snapshot: dict[str, Any],
    model_client: ModelClient,
    settings: dict[str, Any],
    started: float,
) -> dict[str, Any]:
    candidate_input = snapshot["candidate_input"]
    prompt = build_ranking_prompt(candidate_input)
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
        prompt_version=LLM_RANKING_PROMPT_VERSION,
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
        "schema_version": RESULT_ROW_VERSION,
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
    }
    return {
        "schema_version": RESULT_ROW_VERSION,
        "created_at": now_utc(),
        "summary": summary,
        "ranking_result": ranking_result_artifact(result),
        "ground_truth_included": False,
    }


def create_proprietary_gpt_client(env: Mapping[str, str | None] | None = None) -> ModelClient:
    env = os.environ if env is None else env
    if env.get("OPENAI_RANKING_MODEL") != PROPRIETARY_MODEL_IDENTIFIER:
        raise ConfirmatoryHarnessError("OPENAI_RANKING_MODEL must resolve exactly to gpt-5.6-luna")
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


def reflected_candidates_from_snapshot(snapshot: dict[str, Any]) -> list[ReflectedInputCandidate]:
    return [
        ReflectedInputCandidate(
            candidate_id=item["candidate_id"],
            page_url=f"https://127.0.0.1:8443{item['action_path']}",
            action_url=f"https://127.0.0.1:8443{item['action_path']}",
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


def validate_duplicate_and_resume_state(output_dir: Path, schedule_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_dir = output_dir / "raw" / "ranking-rows"
    errors: list[str] = []
    planned_ids = {scheduled_row_id(row) for row in schedule_rows}
    if len(planned_ids) != len(schedule_rows):
        errors.append("duplicate scheduled row identities")
    existing_count = 0
    next_missing = None
    if row_dir.exists():
        for path in row_dir.glob("sequence-*.json"):
            data = load_json(path)
            summary = data.get("summary", {})
            row_id = scheduled_row_id(summary)
            if row_id not in planned_ids:
                errors.append(f"unexpected existing row artifact: {path.name}")
            existing_count += 1
    existing_ids = set()
    if row_dir.exists():
        for path in row_dir.glob("sequence-*.json"):
            data = load_json(path)
            existing_ids.add(scheduled_row_id(data["summary"]))
    for row in schedule_rows:
        if scheduled_row_id(row) not in existing_ids:
            next_missing = row["sequence"]
            break
    return {
        "valid": not errors,
        "errors": errors,
        "existing_completed_rows": existing_count,
        "resume_next_missing_sequence": next_missing,
        "overwrite_policy": "existing completed scored artifacts are never silently regenerated",
    }


def validate_existing_row_artifact(existing: dict[str, Any], row: dict[str, Any]) -> None:
    summary = existing.get("summary", {})
    for key in ("sequence", "scenario_id", "arm_id", "trial_number"):
        if summary.get(key) != row.get(key):
            raise ConfirmatoryHarnessError(f"inconsistent existing artifact for {scheduled_row_id(row)}: {key}")


def row_artifact_path(row_dir: Path, row: dict[str, Any]) -> Path:
    return row_dir / f"sequence-{int(row['sequence']):04d}__{row['arm_id']}__{row['scenario_id']}__trial-{row['trial_number']}.json"


def scheduled_row_id(row: dict[str, Any]) -> str:
    return f"{row['sequence']}|{row['arm_id']}|{row['scenario_id']}|{row['trial_number']}"


def scenario_index(scenario_id: str) -> int:
    return int(scenario_id.rsplit("s", 1)[1]) - 1


def finalize_execution_package(run_dir: Path, package: dict[str, Any]) -> None:
    summaries = [load_json(path)["summary"] for path in sorted((run_dir / "raw" / "ranking-rows").glob("sequence-*.json"))]
    denominators = Counter(row["arm_id"] for row in summaries)
    validation = {
        "schema_version": "owasp-xss-v14-confirmatory-execution-validation-v1",
        "valid": dict(denominators) == {key: EXPECTED_DENOMINATORS[key] for key in ARM_IDS},
        "actual_denominators": dict(denominators),
        "expected_denominators": EXPECTED_DENOMINATORS,
        "total_rows": len(summaries),
        "expected_total_rows": EXPECTED_DENOMINATORS["total_ranking_rows"],
    }
    write_json_atomic(run_dir / "validation-report.json", validation)
    write_csv(run_dir / "normalized" / "ranking-results.csv", summaries)
    write_json_atomic(run_dir / "normalized" / "ranking-results.json", summaries)
    write_json_atomic(run_dir / "manifest.json", execution_manifest(run_dir, package, summaries=summaries, validation=validation))
    write_text_atomic(run_dir / "analysis-report.md", render_execution_report(validation, summaries))
    write_text_atomic(run_dir / "checksums.sha256", render_checksums(run_dir))


def execution_manifest(
    run_dir: Path,
    package: dict[str, Any],
    *,
    summaries: list[dict[str, Any]] | None = None,
    validation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-confirmatory-execution-manifest-v1",
        "harness_version": HARNESS_VERSION,
        "created_at": now_utc(),
        "run_dir": display_path(run_dir),
        "protocol": {"path": display_path(PROTOCOL_PATH), "sha256": sha256_file(PROTOCOL_PATH)},
        "protocol_package": display_path(package["root"]),
        "expected_denominators": EXPECTED_DENOMINATORS,
        "actual_denominators": dict(Counter(row["arm_id"] for row in summaries or [])),
        "validation_valid": validation["valid"] if validation else False,
        "ground_truth_loaded_during_ranking": False,
    }


def write_harness_readiness_package(output_dir: Path, report: dict[str, Any], package: dict[str, Any]) -> None:
    write_json_atomic(output_dir / "dry-validation-report.json", report)
    write_json_atomic(output_dir / "execution-plan-summary.json", {
        "schema_version": "owasp-xss-v14-confirmatory-execution-plan-summary-v1",
        "scenario_count": len(package["snapshots_by_id"]),
        "per_arm_counts": report["schedule_resolution"]["per_arm_counts"],
        "total_rows": report["schedule_resolution"]["total_rows"],
        "arm_order": list(ARM_IDS),
    })
    write_text_atomic(output_dir / "report.md", render_dry_report(report))
    write_text_atomic(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_validation = validate_checksum_file(output_dir / "checksums.sha256", output_dir)
    write_json_atomic(output_dir / "checksum-validation-report.json", {
        "schema_version": "owasp-xss-v14-confirmatory-harness-checksum-validation-v1",
        "valid": not checksum_validation,
        "errors": checksum_validation,
    })


def render_dry_report(report: dict[str, Any]) -> str:
    schedule = report["schedule_resolution"]
    runtime = report["runtime_preflight"]
    return "\n".join(
        [
            "# OWASP XSS v1.4 Confirmatory Harness Dry Validation",
            "",
            "Status: dry validation only. No scored ranking observations were created.",
            "",
            f"- Protocol hash matches: `{report['protocol_package']['protocol_hash_matches']}`",
            f"- Package checksum errors: `{report['protocol_package']['package_checksum_error_count']}`",
            f"- Scenarios resolved: `{schedule['scenario_count']}`",
            f"- Deterministic rows: `{schedule['per_arm_counts'].get('deterministic_structural', 0)}`",
            f"- GPT rows: `{schedule['per_arm_counts'].get('proprietary_gpt', 0)}`",
            f"- Qwen rows: `{schedule['per_arm_counts'].get('local_qwen', 0)}`",
            f"- Total rows: `{schedule['total_rows']}`",
            f"- Ground truth loaded: `{schedule['ground_truth_loaded']}`",
            f"- GPT environment valid: `{runtime['gpt']['valid']}`",
            f"- Qwen artifacts valid: `{runtime['qwen']['valid']}`",
            f"- OWASP target preflight: `{runtime['owasp_target']['status'] if 'status' in runtime['owasp_target'] else runtime['owasp_target']['valid']}`",
            f"- GPT calls: `{report['external_calls']['gpt_calls']}`",
            f"- Qwen calls: `{report['external_calls']['qwen_calls']}`",
            f"- OWASP/browser final-case calls: `{report['external_calls']['owasp_or_browser_final_case_calls']}`",
            f"- Scored observations: `{report['external_calls']['scored_observations']}`",
        ]
    ) + "\n"


def render_execution_report(validation: dict[str, Any], summaries: list[dict[str, Any]]) -> str:
    counts = Counter(row["arm_id"] for row in summaries)
    status_counts = Counter(row["status"] for row in summaries)
    return "\n".join(
        [
            "# OWASP XSS v1.4 Confirmatory Ranking Execution",
            "",
            f"- Validation valid: `{validation['valid']}`",
            f"- Deterministic rows: `{counts.get('deterministic_structural', 0)}`",
            f"- GPT rows: `{counts.get('proprietary_gpt', 0)}`",
            f"- Qwen rows: `{counts.get('local_qwen', 0)}`",
            f"- Status counts: `{dict(status_counts)}`",
            "",
            "Ground truth is not included in raw ranking artifacts. Post-run scoring must load the separated scoring data only after execution.",
        ]
    ) + "\n"


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
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True), encoding="utf-8")
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
        raise ConfirmatoryHarnessError(completed.stderr.strip())
    return completed.stdout.strip()


def local_model_artifact(candidate_id: str):
    model = next((item for item in MODEL_ARTIFACTS if item.candidate_id == candidate_id), None)
    if model is None:
        raise ConfirmatoryHarnessError(f"unknown local model candidate: {candidate_id}")
    return model


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def ensure_not_overwriting_previous_results(path: Path) -> None:
    resolved = path.resolve()
    protected_parts = {"heldout-evaluation-v1.2-canonical", "xss-v13-ablation-v1.3", "xss-v13-ablation-v1.3.1-final"}
    if any(part in resolved.parts for part in protected_parts):
        raise ConfirmatoryHarnessError(f"refusing to write inside protected historical result path: {path}")
    if path.exists() and any(path.iterdir()):
        raise ConfirmatoryHarnessError(f"output directory already exists and is not empty: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run or dry-validate the frozen OWASP XSS v1.4 confirmatory harness.")
    parser.add_argument("--mode", choices=("dry-run", "preflight", "execute"), default="dry-run")
    parser.add_argument("--protocol-package", type=Path, default=PROTOCOL_PACKAGE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_FINAL_ROOT)
    parser.add_argument("--check-target", action="store_true", help="Include the non-scored OWASP target health check in dry-run mode.")
    parser.add_argument("--execute-final-confirmatory", action="store_true", help="Required with --mode execute.")
    args = parser.parse_args()

    if args.mode == "dry-run":
        report = run_dry_validation(
            protocol_package_dir=args.protocol_package,
            output_dir=args.output_dir,
            check_target=args.check_target,
        )
        print(f"OWASP XSS v1.4 confirmatory dry validation valid: {report['valid']}")
        print(f"Dry-validation artifacts written to: {args.output_dir.resolve()}")
        return

    if args.mode == "preflight":
        report = run_runtime_preflight(protocol_package_dir=args.protocol_package)
        print(json.dumps(report, indent=2, sort_keys=True))
        if not report["valid"]:
            raise SystemExit(1)
        return

    if not args.execute_final_confirmatory:
        raise SystemExit("--mode execute requires --execute-final-confirmatory")
    ensure_not_overwriting_previous_results(args.output_root)
    run_dir = execute_final_confirmatory(
        output_root=args.output_root,
        protocol_package_dir=args.protocol_package,
    )
    print(f"OWASP XSS v1.4 confirmatory execution artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
