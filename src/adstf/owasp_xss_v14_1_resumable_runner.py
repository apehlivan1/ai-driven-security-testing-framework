from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Mapping

from adstf.llm_ranking import (
    LLM_RANKING_PROMPT_VERSION,
    ModelClient,
    ModelProviderError,
    ModelTimeoutError,
    build_ranking_prompt,
    parse_model_ranking,
    ranking_result_artifact,
)
from adstf.local_runtime import MODEL_ROOT, RUNTIME_ROOT, LlamaCppCliClient, sha256_file as runtime_sha256_file
from adstf.local_runtime_output_boundary import transport_settings
from adstf.local_runtime_readiness import readiness_json_schema
from adstf.owasp_xss_v14_1_context_enrichment import ENRICHED_RANKING_RULESET_VERSION, enriched_rankings
from adstf.owasp_xss_v14_confirmatory import (
    LOCAL_MODEL_IDENTIFIER,
    LOCAL_PRIMARY_MODEL_ID,
    PROPRIETARY_MODEL_IDENTIFIER,
    QWEN_MODEL_HASHES,
    QWEN_RUNTIME_SHA256,
    create_proprietary_gpt_client,
    local_model_artifact,
    ranking_row_artifact,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.1.md"
PROTOCOL_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-xss-v14-1-protocol-freeze"
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-xss-v14-1-resumable-runner-readiness"
DEFAULT_FINAL_ROOT = REPO_ROOT / "results" / "owasp-xss-v14-1-confirmatory-final"

RUNNER_VERSION = "owasp-xss-v14-1-resumable-runner-v1"
READINESS_VERSION = "owasp-xss-v14-1-resumable-runner-readiness-v1"
SCHEDULE_VERSION = "owasp-xss-v14-1-immutable-execution-schedule-v1"
RESULT_ROW_VERSION = "owasp-xss-v14-1-ranking-row-v1"
JOURNAL_VERSION = "owasp-xss-v14-1-execution-journal-v1"

PROTOCOL_COMMIT = "08e72f32c9de7e0fb80f3ccfd64c85b6fe99ddb3"
PROTOCOL_TAG = "evaluation-protocol-v1.4.1-ready"
EXPECTED_DENOMINATORS = {
    "deterministic_minimal": 266,
    "deterministic_enriched": 266,
    "deterministic_total": 532,
    "gpt_minimal": 1330,
    "gpt_enriched": 1330,
    "gpt_total": 2660,
    "qwen_minimal": 1330,
    "qwen_enriched": 1330,
    "qwen_total": 2660,
    "total_ranking_rows": 5852,
}
GPT_SETTINGS = {
    "temperature_parameter": "omitted",
    "provider_default_temperature_used": True,
    "max_output_tokens": 1200,
    "timeout_seconds": 60,
    "prompt_version": LLM_RANKING_PROMPT_VERSION,
}
QWEN_SETTINGS = {
    "context_size_tokens": 4096,
    "max_output_tokens": 768,
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 42,
    "threads": 8,
    "timeout_seconds": 300,
    "prompt_version": LLM_RANKING_PROMPT_VERSION,
}
LLAMA_COMPLETION_EXE = RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"

TERMINAL_STATES = {
    "completed_valid",
    "completed_contract_invalid",
    "completed_provider_failure",
    "completed_runtime_failure",
    "completed_timeout",
}
ARTIFACT_STATUSES = {
    "completed_valid": "valid",
    "completed_contract_invalid": "malformed",
    "completed_provider_failure": "provider_failed",
    "completed_runtime_failure": "runtime_failed",
    "completed_timeout": "timeout",
}


class ResumableRunnerError(RuntimeError):
    pass


class ResumeAuditRequired(ResumableRunnerError):
    pass


def load_protocol_package(root: Path = PROTOCOL_PACKAGE_DIR) -> dict[str, Any]:
    if not root.exists():
        raise ResumableRunnerError(f"protocol package not found: {root}")
    minimal_index = load_json(root / "model-facing" / "minimal-candidate-snapshot-index.json")
    enriched_index = load_json(root / "model-facing" / "enriched-candidate-snapshot-index.json")
    minimal_snapshots = {
        item["scenario_id"]: load_json(root / item["path"])
        for item in minimal_index["snapshot_paths"]
    }
    enriched_snapshots = {
        item["scenario_id"]: load_json(root / item["path"])
        for item in enriched_index["snapshot_paths"]
    }
    return {
        "root": root,
        "manifest": load_json(root / "manifest.json"),
        "schedule": load_json(root / "trial-schedule.json"),
        "schedule_rows": load_json(root / "trial-schedule.json")["rows"],
        "arm_config": load_json(root / "arm-configurations.json"),
        "minimal_index": minimal_index,
        "enriched_index": enriched_index,
        "minimal_snapshots": minimal_snapshots,
        "enriched_snapshots": enriched_snapshots,
        "validation": load_json(root / "validation-report.json"),
    }


def build_execution_schedule(package: dict[str, Any]) -> list[dict[str, Any]]:
    validate_protocol_package(package)
    arm_by_id = {arm["arm_id"]: arm for arm in package["arm_config"]["arms"]}
    index_by_condition = {
        "minimal": {item["scenario_id"]: item for item in package["minimal_index"]["snapshot_paths"]},
        "enriched": {item["scenario_id"]: item for item in package["enriched_index"]["snapshot_paths"]},
    }
    schedule: list[dict[str, Any]] = []
    for row in package["schedule_rows"]:
        condition = row["representation_condition"]
        arm = arm_by_id[row["arm_id"]]
        snapshot_ref = index_by_condition[condition][row["scenario_id"]]
        schedule.append(
            {
                "schema_version": SCHEDULE_VERSION,
                "protocol_tag": PROTOCOL_TAG,
                "protocol_commit": PROTOCOL_COMMIT,
                "sequence": int(row["sequence"]),
                "row_id": row["row_id"],
                "arm_id": row["arm_id"],
                "arm_family": arm_family(row["arm_id"]),
                "representation_condition": condition,
                "scenario_id": row["scenario_id"],
                "trial_number": int(row["trial_number"]),
                "candidate_test_budget": int(row["candidate_test_budget"]),
                "top_k": int(row["top_k"]),
                "snapshot_path": row["snapshot_path"],
                "snapshot_reference": {
                    "path": snapshot_ref["path"],
                    "snapshot_sha256": snapshot_ref["snapshot_sha256"],
                    "candidate_input_sha256": snapshot_ref["candidate_input_sha256"],
                },
                "expected_model_runtime": expected_model_runtime(row["arm_id"], arm),
                "scored": bool(row["scored"]),
                "ground_truth_available_to_runner": False,
            }
        )
    validate_execution_schedule(schedule)
    return schedule


def validate_protocol_package(package: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    root = package["root"]
    manifest = package["manifest"]
    if manifest.get("denominators") != EXPECTED_DENOMINATORS:
        errors.append("manifest_denominator_mismatch")
    if package["schedule"].get("denominators") != EXPECTED_DENOMINATORS:
        errors.append("schedule_denominator_mismatch")
    checksum_errors = validate_checksum_file(root / "checksums.sha256", root)
    errors.extend(checksum_errors)
    if package["validation"].get("valid") is not True:
        errors.append("protocol_package_validation_not_valid")
    if manifest.get("external_activity", {}).get("scored_ranking_rows") != 0:
        errors.append("protocol_package_records_scored_rows")
    result = {
        "valid": not errors,
        "errors": errors,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": PROTOCOL_COMMIT,
        "package_checksum_error_count": len(checksum_errors),
        "package_checksum_errors": checksum_errors[:10],
    }
    if errors:
        raise ResumableRunnerError(f"v1.4.1 protocol package validation failed: {errors[:5]}")
    return result


def validate_execution_schedule(schedule: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    sequences = [row["sequence"] for row in schedule]
    if sequences != list(range(1, len(schedule) + 1)):
        errors.append("non_contiguous_sequence_ids")
    arm_counts = Counter(row["arm_id"] for row in schedule)
    expected_by_arm = {
        "deterministic_minimal": 266,
        "deterministic_enriched": 266,
        "gpt_minimal": 1330,
        "gpt_enriched": 1330,
        "qwen_minimal": 1330,
        "qwen_enriched": 1330,
    }
    if dict(arm_counts) != expected_by_arm:
        errors.append(f"arm_denominator_mismatch:{dict(arm_counts)}")
    if len(schedule) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("total_denominator_mismatch")
    for row in schedule:
        if row["candidate_test_budget"] != 4 or row["top_k"] != 4:
            errors.append(f"budget_or_top_k_mismatch:{row['sequence']}")
    if errors:
        raise ResumableRunnerError(f"v1.4.1 schedule validation failed: {errors[:5]}")
    return {
        "valid": True,
        "errors": [],
        "per_arm_counts": dict(arm_counts),
        "per_family_counts": dict(Counter(row["arm_family"] for row in schedule)),
        "total_rows": len(schedule),
        "schedule_sha256": sha256_json(schedule),
    }


def run_fake_batch(
    *,
    run_dir: Path,
    schedule: list[dict[str, Any]],
    max_scheduled_calls: int,
    fake_terminal_states: Mapping[int, str] | None = None,
) -> dict[str, Any]:
    if max_scheduled_calls <= 0:
        raise ValueError("max_scheduled_calls must be positive")
    fake_terminal_states = fake_terminal_states or {}
    state = validate_resume_state(run_dir, schedule)
    executed: list[int] = []
    rows_by_sequence = {row["sequence"]: row for row in schedule}
    next_sequence = state["next_sequence"]
    while next_sequence is not None and len(executed) < max_scheduled_calls:
        row = rows_by_sequence[next_sequence]
        terminal_state = fake_terminal_states.get(next_sequence, "completed_valid")
        artifact = fake_artifact(row, terminal_state)
        write_terminal_artifact(run_dir, artifact)
        executed.append(next_sequence)
        state = validate_resume_state(run_dir, schedule)
        next_sequence = state["next_sequence"]
    return {
        "schema_version": f"{RUNNER_VERSION}.fake-batch-result",
        "executed_this_batch": len(executed),
        "executed_sequences": executed,
        "next_sequence": next_sequence,
        "external_calls": {"gpt_calls": 0, "qwen_calls": 0, "scored_rows": 0},
    }


def validate_resume_state(run_dir: Path, schedule: list[dict[str, Any]]) -> dict[str, Any]:
    row_dir = run_dir / "raw" / "ranking-rows"
    errors: list[str] = []
    for path in run_dir.rglob("*.tmp") if run_dir.exists() else []:
        errors.append(f"incomplete temporary artifact present:{display_path(path)}")
    planned_by_sequence = {row["sequence"]: row for row in schedule}
    planned_identity = {scheduled_identity(row): row for row in schedule}
    artifacts_by_sequence: dict[int, dict[str, Any]] = {}
    if row_dir.exists():
        for path in sorted(row_dir.glob("sequence-*.json")):
            try:
                artifact = load_json(path)
            except Exception as exc:
                errors.append(f"unreadable artifact:{display_path(path)}:{type(exc).__name__}")
                continue
            summary = artifact.get("summary", {})
            sequence = summary.get("sequence")
            if sequence not in planned_by_sequence:
                errors.append(f"unscheduled result artifact:{path.name}")
                continue
            if sequence in artifacts_by_sequence:
                errors.append(f"duplicate artifact for sequence:{sequence}")
                continue
            identity = scheduled_identity(summary)
            if identity not in planned_identity:
                errors.append(f"inconsistent artifact identity:{path.name}")
            else:
                _validate_artifact_matches_schedule(artifact, planned_by_sequence[sequence])
            terminal_state = artifact.get("terminal_state")
            if terminal_state not in TERMINAL_STATES:
                errors.append(f"non_terminal_or_unknown_state:{path.name}:{terminal_state}")
            artifacts_by_sequence[int(sequence)] = artifact
    journal = read_journal(run_dir)
    journal_sequences: set[int] = set()
    for entry in journal:
        sequence = entry.get("sequence")
        if sequence in journal_sequences:
            errors.append(f"duplicate journal sequence:{sequence}")
        journal_sequences.add(sequence)
        artifact = artifacts_by_sequence.get(sequence)
        if artifact is None:
            errors.append(f"journal_without_artifact:{sequence}")
        elif entry.get("artifact_sha256") != sha256_json(artifact):
            errors.append(f"journal_artifact_checksum_mismatch:{sequence}")
    artifact_sequences = set(artifacts_by_sequence)
    if journal_sequences != artifact_sequences:
        errors.append("journal_artifact_sequence_set_mismatch")
    if errors:
        raise ResumeAuditRequired("; ".join(errors[:10]))
    next_sequence = next((row["sequence"] for row in schedule if row["sequence"] not in artifacts_by_sequence), None)
    state = {
        "schema_version": f"{RUNNER_VERSION}.resume-state",
        "valid": True,
        "completed_count": len(artifacts_by_sequence),
        "next_sequence": next_sequence,
        "completed_by_terminal_state": dict(Counter(str(item.get("terminal_state")) for item in artifacts_by_sequence.values())),
        "duplicate_sequences": [],
        "unscheduled_results": [],
        "corrupt_or_incomplete_artifacts": [],
    }
    write_json_atomic(run_dir / "completion-index.json", state)
    return state


def generate_readiness_package(
    *,
    output_dir: Path = DEFAULT_READINESS_DIR,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    package = load_protocol_package(protocol_package_dir)
    schedule = build_execution_schedule(package)
    validation = validate_execution_schedule(schedule)
    fake_run_dir = output_dir / "fake-interruption-run"
    if fake_run_dir.exists() and any(fake_run_dir.iterdir()):
        fake_run_dir = output_dir / f"fake-interruption-run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    first = run_fake_batch(run_dir=fake_run_dir, schedule=schedule[:8], max_scheduled_calls=3)
    restart_state = validate_resume_state(fake_run_dir, schedule[:8])
    resume = run_fake_batch(
        run_dir=fake_run_dir,
        schedule=schedule[:8],
        max_scheduled_calls=1,
        fake_terminal_states={4: "completed_contract_invalid"},
    )
    after_malformed = validate_resume_state(fake_run_dir, schedule[:8])
    corruption_passed = False
    corruption_dir = output_dir / "fake-corrupt-artifact-check"
    (corruption_dir / "raw" / "ranking-rows").mkdir(parents=True, exist_ok=True)
    (corruption_dir / "raw" / "ranking-rows" / "sequence-000001.tmp").write_text("partial", encoding="utf-8")
    try:
        validate_resume_state(corruption_dir, schedule[:2])
    except ResumeAuditRequired:
        corruption_passed = True
    report = {
        "schema_version": READINESS_VERSION,
        "runner_version": RUNNER_VERSION,
        "created_at": now_utc(),
        "valid": validation["valid"] and corruption_passed and after_malformed["next_sequence"] == 5,
        "protocol": {
            "tag": PROTOCOL_TAG,
            "commit": PROTOCOL_COMMIT,
            "document": display_path(PROTOCOL_PATH),
            "package": display_path(protocol_package_dir),
        },
        "schedule_validation": validation,
        "resume_policy": resume_policy(),
        "terminal_states": sorted(TERMINAL_STATES),
        "fake_interruption_test": {
            "first_batch": first,
            "state_after_fresh_restart": restart_state,
            "resume_batch": resume,
            "state_after_malformed_terminal": after_malformed,
            "corrupt_artifact_stops_for_audit": corruption_passed,
        },
        "projected_qwen_batch_durations": projected_qwen_batch_durations(),
        "external_calls": {"gpt_calls": 0, "qwen_calls": 0, "scored_rows": 0, "http_requests": 0},
        "ground_truth_loaded": False,
        "readiness_decision": "READY_FOR_LIVE_SCORED_EXECUTION_AFTER_USER_AUTHORIZATION" if validation["valid"] and corruption_passed else "BLOCKED",
        "git_state": git_execution_state(),
    }
    write_json_atomic(output_dir / "frozen-execution-schedule.json", schedule)
    write_csv(output_dir / "frozen-execution-schedule.csv", schedule)
    write_json_atomic(output_dir / "schedule-validation-report.json", validation)
    write_json_atomic(output_dir / "resume-validation-report.json", report["fake_interruption_test"])
    write_json_atomic(output_dir / "readiness-report.json", report)
    write_json_atomic(output_dir / "projected-qwen-batch-durations.json", projected_qwen_batch_durations())
    write_text_atomic(output_dir / "README.md", render_readiness_readme(report))
    write_text_atomic(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_errors = validate_checksum_file(output_dir / "checksums.sha256", output_dir)
    write_json_atomic(output_dir / "checksum-validation-report.json", {
        "schema_version": f"{READINESS_VERSION}.checksum-validation",
        "valid": not checksum_errors,
        "errors": checksum_errors,
    })
    return report


def execute_real_schedule_row(
    row: dict[str, Any],
    snapshot: dict[str, Any],
    *,
    gpt_client: ModelClient | None = None,
    qwen_client_factory: Callable[[Path], ModelClient] | None = None,
    schemas_dir: Path | None = None,
) -> dict[str, Any]:
    started = time.perf_counter()
    if row["arm_family"] == "deterministic":
        ranking = enriched_rankings(snapshot["candidate_input"])
        return ranking_row_artifact(
            row=row,
            snapshot=snapshot,
            ordered_candidate_ids=[item["candidate_id"] for item in ranking],
            rationales={item["candidate_id"]: "; ".join(item["rationale"]) for item in ranking},
            validation_errors=[],
            provider_failed=False,
            model_identifier="not_applicable",
            provider="deterministic",
            prompt=None,
            raw_response=None,
            model_settings={
                "ranking_ruleset_version": (
                    ENRICHED_RANKING_RULESET_VERSION
                    if row["representation_condition"] == "enriched"
                    else "deterministic-abstract-structural-v1.4.1"
                )
            },
            usage=None,
            cost={"availability": "not_applicable"},
            provider_metadata={"scores": ranking},
            started=started,
        )
    if row["arm_family"] == "gpt":
        client = gpt_client or create_proprietary_gpt_client()
        return model_row_artifact(row, snapshot, client, GPT_SETTINGS, started)
    if row["arm_family"] == "qwen":
        if schemas_dir is None:
            raise ResumableRunnerError("schemas_dir is required for Qwen execution")
        schema_path = write_local_schema(snapshot, schemas_dir)
        client_factory = qwen_client_factory or create_local_qwen_client
        return model_row_artifact(row, snapshot, client_factory(schema_path), local_qwen_settings_for_schema(schema_path), started)
    raise ResumableRunnerError(f"unknown arm family: {row['arm_family']}")


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
        terminal_state = "completed_timeout"
        message = str(exc)
    except ModelProviderError as exc:
        error_type = "provider_failure"
        terminal_state = "completed_provider_failure"
        message = str(exc)
    artifact = ranking_row_artifact(
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
    artifact["terminal_state"] = terminal_state
    return artifact


def run_scored_batch(
    *,
    run_dir: Path,
    schedule: list[dict[str, Any]],
    package: dict[str, Any],
    max_scheduled_calls: int,
    gpt_client: ModelClient | None = None,
    qwen_client_factory: Callable[[Path], ModelClient] | None = None,
) -> dict[str, Any]:
    scored_preflight = validate_scored_preflight()
    if not scored_preflight["valid"]:
        raise ResumableRunnerError(f"scored preflight failed: {scored_preflight['errors']}")
    state = validate_resume_state(run_dir, schedule)
    snapshots = snapshots_by_condition(package)
    rows_by_sequence = {row["sequence"]: row for row in schedule}
    schemas_dir = run_dir / "runtime" / "local-qwen-schemas"
    executed: list[int] = []
    while state["next_sequence"] is not None and len(executed) < max_scheduled_calls:
        row = rows_by_sequence[state["next_sequence"]]
        snapshot = snapshots[row["representation_condition"]][row["scenario_id"]]
        artifact = execute_real_schedule_row(
            row,
            snapshot,
            gpt_client=gpt_client,
            qwen_client_factory=qwen_client_factory,
            schemas_dir=schemas_dir,
        )
        artifact = normalize_row_artifact(artifact, row)
        artifact.setdefault("terminal_state", terminal_state_from_artifact(artifact))
        write_terminal_artifact(run_dir, artifact)
        executed.append(row["sequence"])
        state = validate_resume_state(run_dir, schedule)
    return {
        "schema_version": f"{RUNNER_VERSION}.scored-batch-result",
        "executed_this_batch": len(executed),
        "executed_sequences": executed,
        "next_sequence": state["next_sequence"],
    }


def normalize_row_artifact(artifact: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    summary = artifact.setdefault("summary", {})
    summary["schema_version"] = RESULT_ROW_VERSION
    summary["sequence"] = row["sequence"]
    summary["row_id"] = row["row_id"]
    summary["scenario_id"] = row["scenario_id"]
    summary["arm_id"] = row["arm_id"]
    summary["arm_family"] = row["arm_family"]
    summary["representation_condition"] = row["representation_condition"]
    summary["trial_number"] = row["trial_number"]
    summary["snapshot_path"] = row["snapshot_path"]
    summary["candidate_input_sha256"] = row["snapshot_reference"]["candidate_input_sha256"]
    summary["candidate_test_budget"] = row["candidate_test_budget"]
    summary["top_k"] = row["top_k"]
    artifact["schema_version"] = RESULT_ROW_VERSION
    artifact["terminal_state"] = terminal_state_from_artifact(artifact)
    artifact["ground_truth_included"] = False
    return artifact


def validate_scored_preflight(
    *,
    env: Mapping[str, str | None] | None = None,
    runtime_path: Path = LLAMA_COMPLETION_EXE,
    model_root: Path = MODEL_ROOT,
    runtime_hasher: Callable[[Path], str] = runtime_sha256_file,
) -> dict[str, Any]:
    env = os.environ if env is None else env
    errors: list[str] = []
    tag_target = git_output(["rev-parse", f"{PROTOCOL_TAG}^{{}}"], check=False)
    if tag_target != PROTOCOL_COMMIT:
        errors.append("protocol_tag_target_mismatch")
    if not git_success(["merge-base", "--is-ancestor", PROTOCOL_TAG, "HEAD"]):
        errors.append("head_does_not_descend_from_protocol_tag")
    if env.get("OPENAI_RANKING_MODEL") != PROPRIETARY_MODEL_IDENTIFIER:
        errors.append("OPENAI_RANKING_MODEL_not_frozen_value")
    if not env.get("OPENAI_API_KEY"):
        errors.append("OPENAI_API_KEY_missing")
    send_temperature = str(env.get("OPENAI_SEND_TEMPERATURE") or "").lower()
    if send_temperature not in {"", "0", "false", "no"}:
        errors.append("OPENAI_SEND_TEMPERATURE_must_be_unset_or_false")
    runtime_exists = runtime_path.exists()
    runtime_hash = runtime_hasher(runtime_path) if runtime_exists else "missing"
    if runtime_hash != QWEN_RUNTIME_SHA256:
        errors.append("qwen_runtime_hash_mismatch")
    model = local_model_artifact(LOCAL_PRIMARY_MODEL_ID)
    model_checks: list[dict[str, Any]] = []
    for filename, expected in QWEN_MODEL_HASHES.items():
        path = model_root / model.candidate_id / filename
        exists = path.exists()
        actual = runtime_hasher(path) if exists else "missing"
        matches = actual == expected
        if not matches:
            errors.append(f"qwen_model_hash_mismatch:{filename}")
        model_checks.append({"filename": filename, "exists": exists, "sha256_matches": matches})
    return {
        "schema_version": f"{RUNNER_VERSION}.scored-preflight",
        "valid": not errors,
        "errors": errors,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_tag_target": tag_target,
        "protocol_commit_expected": PROTOCOL_COMMIT,
        "openai_model_identifier": env.get("OPENAI_RANKING_MODEL") or "missing",
        "api_key_present": bool(env.get("OPENAI_API_KEY")),
        "api_key_value_recorded": False,
        "qwen_runtime_sha256_matches": runtime_hash == QWEN_RUNTIME_SHA256,
        "qwen_model_files": model_checks,
    }


def fake_artifact(row: dict[str, Any], terminal_state: str) -> dict[str, Any]:
    if terminal_state not in TERMINAL_STATES:
        raise ValueError(f"unknown terminal state: {terminal_state}")
    now = now_utc()
    return {
        "schema_version": RESULT_ROW_VERSION,
        "created_at": now,
        "terminal_state": terminal_state,
        "summary": {
            "schema_version": RESULT_ROW_VERSION,
            "sequence": row["sequence"],
            "row_id": row["row_id"],
            "scenario_id": row["scenario_id"],
            "arm_id": row["arm_id"],
            "arm_family": row["arm_family"],
            "representation_condition": row["representation_condition"],
            "trial_number": row["trial_number"],
            "snapshot_path": row["snapshot_path"],
            "candidate_input_sha256": row["snapshot_reference"]["candidate_input_sha256"],
            "candidate_test_budget": row["candidate_test_budget"],
            "top_k": row["top_k"],
            "status": ARTIFACT_STATUSES[terminal_state],
            "contract_valid": terminal_state == "completed_valid",
            "provider_failed": terminal_state in {"completed_provider_failure", "completed_timeout"},
            "validation_errors": [] if terminal_state == "completed_valid" else [f"fake {terminal_state}"],
            "latency_ms": 0,
            "model_identifier": row["expected_model_runtime"]["model_identifier"],
            "provider": row["expected_model_runtime"]["provider"],
            "prompt_version": row["expected_model_runtime"].get("prompt_version", "not_applicable"),
        },
        "ranking_result": {
            "schema_version": "fake-non-experimental-ranking-result",
            "raw_response": None,
            "ordered_candidate_ids": [],
            "validation_errors": [] if terminal_state == "completed_valid" else [f"fake {terminal_state}"],
        },
        "fake_non_experimental": True,
        "ground_truth_included": False,
    }


def write_terminal_artifact(run_dir: Path, artifact: dict[str, Any]) -> Path:
    sequence = int(artifact["summary"]["sequence"])
    row = artifact["summary"]
    path = row_artifact_path(run_dir / "raw" / "ranking-rows", row)
    if path.exists():
        raise ResumeAuditRequired(f"refusing to overwrite existing artifact: {path.name}")
    artifact.setdefault("terminal_state", terminal_state_from_artifact(artifact))
    if artifact["terminal_state"] not in TERMINAL_STATES:
        raise ResumeAuditRequired(f"artifact is not terminal: {artifact['terminal_state']}")
    write_json_atomic(path, artifact)
    journal_entry = {
        "schema_version": JOURNAL_VERSION,
        "created_at": now_utc(),
        "sequence": sequence,
        "row_id": row.get("row_id"),
        "arm_id": row["arm_id"],
        "scenario_id": row["scenario_id"],
        "trial_number": row["trial_number"],
        "terminal_state": artifact["terminal_state"],
        "artifact_path": display_path(path),
        "artifact_sha256": sha256_json(artifact),
    }
    append_jsonl(run_dir / "execution-journal.jsonl", journal_entry)
    return path


def read_journal(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "execution-journal.jsonl"
    if not path.exists():
        return []
    entries = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ResumeAuditRequired(f"unreadable journal line {line_no}: {exc}") from exc
    return entries


def _validate_artifact_matches_schedule(artifact: dict[str, Any], row: dict[str, Any]) -> None:
    summary = artifact.get("summary", {})
    for key in ("sequence", "row_id", "scenario_id", "arm_id", "trial_number", "representation_condition"):
        if summary.get(key) != row.get(key):
            raise ResumeAuditRequired(f"artifact identity mismatch for sequence {row['sequence']}: {key}")
    if summary.get("candidate_input_sha256") != row["snapshot_reference"]["candidate_input_sha256"]:
        raise ResumeAuditRequired(f"candidate input checksum mismatch for sequence {row['sequence']}")


def terminal_state_from_artifact(artifact: dict[str, Any]) -> str:
    summary = artifact.get("summary", {})
    status = summary.get("status")
    if status == "valid":
        return "completed_valid"
    if status == "malformed":
        return "completed_contract_invalid"
    if status == "timeout":
        return "completed_timeout"
    if status == "runtime_failed":
        return "completed_runtime_failure"
    if status == "provider_failed":
        provider_meta = artifact.get("ranking_result", {}).get("provider_metadata") or {}
        if provider_meta.get("failure_type") == "timeout":
            return "completed_timeout"
        return "completed_provider_failure"
    return "completed_contract_invalid"


def row_artifact_path(row_dir: Path, row: Mapping[str, Any]) -> Path:
    return (
        row_dir
        / f"sequence-{int(row['sequence']):06d}__{row['arm_id']}__{row['scenario_id']}__trial-{row['trial_number']}.json"
    )


def scheduled_identity(row: Mapping[str, Any]) -> str:
    return f"{row.get('sequence')}|{row.get('row_id')}|{row.get('arm_id')}|{row.get('scenario_id')}|{row.get('trial_number')}|{row.get('representation_condition')}"


def snapshots_by_condition(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {"minimal": package["minimal_snapshots"], "enriched": package["enriched_snapshots"]}


def expected_model_runtime(arm_id: str, arm: dict[str, Any]) -> dict[str, Any]:
    if arm_id.startswith("deterministic_"):
        return {
            "provider": "deterministic",
            "model_identifier": "not_applicable",
            "runtime": "in_process_deterministic_ranker",
            "prompt_version": "not_applicable",
            "model_hashes": "not_applicable",
        }
    if arm_id.startswith("gpt_"):
        return {
            "provider": "OpenAI",
            "model_identifier": PROPRIETARY_MODEL_IDENTIFIER,
            "runtime": "adstf.openai_ranking_wrapper",
            "prompt_version": LLM_RANKING_PROMPT_VERSION,
            "settings": arm.get("settings", {}),
        }
    if arm_id.startswith("qwen_"):
        return {
            "provider": "local llama.cpp",
            "model_identifier": LOCAL_MODEL_IDENTIFIER,
            "runtime": "llama-completion.exe",
            "runtime_executable_sha256": QWEN_RUNTIME_SHA256,
            "model_file_sha256": QWEN_MODEL_HASHES,
            "prompt_version": LLM_RANKING_PROMPT_VERSION,
            "settings": arm.get("settings", {}),
        }
    raise ResumableRunnerError(f"unknown frozen arm id: {arm_id}")


def arm_family(arm_id: str) -> str:
    if arm_id.startswith("deterministic_"):
        return "deterministic"
    if arm_id.startswith("gpt_"):
        return "gpt"
    if arm_id.startswith("qwen_"):
        return "qwen"
    raise ResumableRunnerError(f"unknown frozen arm id: {arm_id}")


def resume_policy() -> dict[str, Any]:
    return {
        "schema_version": f"{RUNNER_VERSION}.resume-policy",
        "atomic_artifact_write": "Each call writes a temporary JSON file and atomically replaces it with the final sequence artifact.",
        "journal_policy": "After the terminal artifact exists, one journal line records its sequence, terminal state and checksum.",
        "resume_source": "Resume derives completed work from persisted artifacts and journal consistency only.",
        "retry_policy": "No silent retries. Valid, malformed, provider-failed, runtime-failed and timed-out terminal artifacts are complete observations.",
        "corrupt_artifact_policy": "Temporary, unreadable, duplicate, unscheduled or checksum-inconsistent artifacts stop execution for audit.",
        "next_sequence_policy": "Resume starts at the lowest scheduled sequence whose terminal artifact is absent.",
    }


def projected_qwen_batch_durations() -> dict[str, Any]:
    per_call_seconds = 55
    examples = {}
    for label, calls in {"30_min": 32, "1_hour": 65, "2_hours": 130, "overnight_conservative": 500, "overnight_upper": 650}.items():
        examples[label] = {
            "scheduled_calls": calls,
            "approx_seconds": calls * per_call_seconds,
            "approx_minutes": round((calls * per_call_seconds) / 60, 1),
            "approx_hours": round((calls * per_call_seconds) / 3600, 2),
        }
    return {
        "schema_version": f"{RUNNER_VERSION}.qwen-duration-projection",
        "basis": "planning estimate from prior observed Qwen latency around 55 seconds per call; not a scored result",
        "assumed_seconds_per_qwen_call": per_call_seconds,
        "batch_examples": examples,
    }


def render_readiness_readme(report: dict[str, Any]) -> str:
    durations = report["projected_qwen_batch_durations"]["batch_examples"]
    return "\n".join(
        [
            "# v1.4.1 Resumable Runner Readiness",
            "",
            "Status: non-scored execution-readiness package. No GPT call, Qwen call, HTTP benchmark request or scored ranking row was executed.",
            "",
            f"- Protocol tag: `{PROTOCOL_TAG}`",
            f"- Protocol commit: `{PROTOCOL_COMMIT}`",
            f"- Total frozen rows: `{report['schedule_validation']['total_rows']}`",
            f"- Deterministic rows: `{report['schedule_validation']['per_family_counts']['deterministic']}`",
            f"- GPT rows: `{report['schedule_validation']['per_family_counts']['gpt']}`",
            f"- Qwen rows: `{report['schedule_validation']['per_family_counts']['qwen']}`",
            f"- Schedule checksum: `{report['schedule_validation']['schedule_sha256']}`",
            "",
            "## Batch Command Examples",
            "",
            "These examples are documentation only. Execute them only after explicit scored-execution authorization.",
            "",
            "```powershell",
            "$env:OPENAI_RANKING_MODEL = \"gpt-5.6-luna\"",
            "python -m adstf.owasp_xss_v14_1_resumable_runner --mode execute --max-scheduled-calls 65 --execute-scored-ranking",
            "```",
            "",
            "## Qwen Batch Planning",
            "",
            f"- 30 minute planning batch: `{durations['30_min']['scheduled_calls']}` calls",
            f"- 1 hour planning batch: `{durations['1_hour']['scheduled_calls']}` calls",
            f"- 2 hour planning batch: `{durations['2_hours']['scheduled_calls']}` calls",
            f"- Overnight conservative batch: `{durations['overnight_conservative']['scheduled_calls']}` calls",
            f"- Overnight upper batch: `{durations['overnight_upper']['scheduled_calls']}` calls",
        ]
    ) + "\n"


def write_local_schema(snapshot: dict[str, Any], schemas_dir: Path) -> Path:
    schema = readiness_json_schema([item["candidate_id"] for item in snapshot["candidate_input"]])
    schema["$id"] = f"local-ranking-readiness-json-schema-v1.3-{snapshot['scenario_id']}-{snapshot.get('schema_version', 'unknown')}"
    path = schemas_dir / f"{snapshot['scenario_id']}__{snapshot.get('schema_version', 'snapshot')}.schema.json"
    write_json_atomic(path, schema)
    return path


def local_qwen_settings_for_schema(schema_path: Path) -> dict[str, Any]:
    return transport_settings(schema_path, LLAMA_COMPLETION_EXE)


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


def git_execution_state() -> dict[str, Any]:
    return {
        "branch": git_output(["branch", "--show-current"]),
        "commit": git_output(["rev-parse", "HEAD"]),
        "descends_from_protocol_tag": git_success(["merge-base", "--is-ancestor", PROTOCOL_TAG, "HEAD"]),
        "dirty": bool(git_output(["status", "--porcelain"])),
        "status_short": git_output(["status", "--short"]).splitlines(),
    }


def git_success(args: list[str]) -> bool:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    return completed.returncode == 0


def git_output(args: list[str], *, check: bool = False) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    if check and completed.returncode != 0:
        raise ResumableRunnerError(completed.stderr.strip())
    return completed.stdout.strip()


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


def append_jsonl(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(to_json_value(data), sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def validate_checksum_file(checksum_path: Path, base_dir: Path) -> list[str]:
    if not checksum_path.exists():
        return [f"checksum file missing:{display_path(checksum_path)}"]
    errors: list[str] = []
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = base_dir / relative
        if not path.exists():
            errors.append(f"checksum target missing:{relative}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"checksum mismatch:{relative}")
    return errors


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare or execute the v1.4.1 resumable ranking schedule.")
    parser.add_argument("--mode", choices=("readiness", "execute"), default="readiness")
    parser.add_argument("--protocol-package", type=Path, default=PROTOCOL_PACKAGE_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_FINAL_ROOT)
    parser.add_argument("--max-scheduled-calls", type=int, default=65)
    parser.add_argument("--execute-scored-ranking", action="store_true")
    args = parser.parse_args()

    if args.mode == "readiness":
        report = generate_readiness_package(output_dir=args.output_dir, protocol_package_dir=args.protocol_package)
        print(f"v1.4.1 resumable runner readiness valid: {report['valid']}")
        print(f"Readiness artifacts written to: {args.output_dir.resolve()}")
        return

    if not args.execute_scored_ranking:
        raise SystemExit("--mode execute requires --execute-scored-ranking")
    package = load_protocol_package(args.protocol_package)
    schedule = build_execution_schedule(package)
    run_dir = args.run_dir or (args.output_root / f"owasp-xss-v14-1-confirmatory-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}")
    if run_dir.exists():
        validate_resume_state(run_dir, schedule)
    else:
        run_dir.mkdir(parents=True)
        write_json_atomic(run_dir / "execution-manifest.json", {
            "schema_version": f"{RUNNER_VERSION}.execution-manifest",
            "created_at": now_utc(),
            "protocol_tag": PROTOCOL_TAG,
            "protocol_commit": PROTOCOL_COMMIT,
            "schedule_sha256": sha256_json(schedule),
            "ground_truth_loaded": False,
        })
    result = run_scored_batch(run_dir=run_dir, schedule=schedule, package=package, max_scheduled_calls=args.max_scheduled_calls)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
