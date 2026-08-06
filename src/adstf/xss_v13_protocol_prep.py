from __future__ import annotations

import argparse
import csv
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from adstf.discovery import DETERMINISTIC_RANKING_RULESET_VERSION, discover_reflected_input_candidates
from adstf.llm_ranking import LLM_RANKING_PROMPT_VERSION, candidate_input_for_prompt
from adstf.metrics import derive_measurements
from adstf.serialization import to_json_value
from adstf.xss_v13_benchmark import (
    BENCHMARK_ID,
    DEFAULT_BASE_URL,
    DEFAULT_MANIFEST_PATH,
    DEFAULT_TARGET_CONFIG_PATH,
    MANIFEST_VERSION,
    REPO_ROOT,
    render_v13_xss_response,
)


PROTOCOL_PREP_VERSION = "xss-v13-protocol-prep-v1"
CANDIDATE_SNAPSHOT_VERSION = "xss-v13-candidate-snapshot-v1"
ARM_INPUT_LEDGER_VERSION = "xss-v13-three-arm-input-ledger-v1"
DRY_VALIDATION_VERSION = "xss-v13-protocol-dry-validation-v1"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "xss-v13-protocol-prep"
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.3.md"
SNAPSHOT_DIR_NAME = "candidate-snapshots"
ARM_IDS = ("deterministic_structural", "proprietary_gpt", "local_qwen")
LOCAL_PRIMARY_MODEL_ID = "qwen2_5_7b_instruct_gguf_q4_k_m"
LOCAL_CONTINGENCY_MODEL_ID = "gemma3_4b_it_gguf_q4_k_m"
PROPRIETARY_MODEL_IDENTIFIER = "gpt-5.6-luna"
LLM_TRIALS_PER_SCENARIO = 5
DETERMINISTIC_TRIALS_PER_SCENARIO = 1
NOT_EXPERIMENTAL = "dry_validation_only_no_scored_trials_no_vulnerability_testing"

FORBIDDEN_SNAPSHOT_KEYS = {
    "behavior",
    "cases",
    "expected_vulnerable_count",
    "ground_truth",
    "ground_truth_path",
    "outcome_class",
    "vulnerable",
}


def build_protocol_prep_package(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
    target_config_path: Path = DEFAULT_TARGET_CONFIG_PATH,
    protocol_path: Path = PROTOCOL_PATH,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    target_config = json.loads(target_config_path.read_text(encoding="utf-8"))
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_dir = output_dir / SNAPSHOT_DIR_NAME
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    snapshot_records = []
    for scenario in manifest["scenarios"]:
        snapshot = candidate_snapshot_for_scenario(scenario, target_config["base_url"])
        snapshot_path = snapshot_dir / f"{scenario['id']}.json"
        _write_json(snapshot_path, snapshot)
        snapshot_records.append(snapshot_record(snapshot, snapshot_path, output_dir))

    arm_input_ledger = build_arm_input_ledger(snapshot_records)
    dry_run_config = build_dry_run_config(
        manifest=manifest,
        target_config=target_config,
        snapshot_records=snapshot_records,
        protocol_path=protocol_path,
    )
    validation = validate_protocol_prep_package(
        manifest=manifest,
        snapshots=[_load_json(output_dir / record["snapshot_path"]) for record in snapshot_records],
        arm_input_ledger=arm_input_ledger,
        dry_run_config=dry_run_config,
    )
    scenario_rows = scenario_snapshot_rows(manifest, snapshot_records)

    _write_json(output_dir / "candidate-snapshot-index.json", {"snapshots": snapshot_records})
    _write_csv(output_dir / "scenario-snapshot-ledger.csv", scenario_rows)
    _write_json(output_dir / "arm-input-ledger.json", arm_input_ledger)
    _write_json(output_dir / "dry-run-config.json", dry_run_config)
    _write_json(output_dir / "dry-validation-summary.json", validation)
    _write_text(output_dir / "report.md", render_report(validation, snapshot_records, dry_run_config))
    _write_text(output_dir / "thesis-three-arm-configuration-table.md", render_arm_table(dry_run_config))
    _write_text(output_dir / "thesis-three-arm-configuration-table.tex", render_arm_table_latex())

    package_manifest = package_manifest_data(
        output_dir=output_dir,
        manifest=manifest,
        target_config=target_config,
        validation=validation,
        snapshot_records=snapshot_records,
        protocol_path=protocol_path,
    )
    _write_json(output_dir / "manifest.json", package_manifest)
    checksum_paths = [
        path
        for path in sorted(output_dir.rglob("*"))
        if path.is_file() and path.name != "checksums.sha256"
    ]
    _write_text(output_dir / "checksums.sha256", render_checksums(checksum_paths))
    return package_manifest


def candidate_snapshot_for_scenario(scenario: dict[str, Any], base_url: str = DEFAULT_BASE_URL) -> dict[str, Any]:
    candidates = []
    for seed_path in scenario["seed_paths"]:
        seed_url = seed_path if str(seed_path).startswith(("http://", "https://")) else urljoin(f"{base_url.rstrip('/')}/", str(seed_path))
        parsed = urlparse(seed_url)
        status, body, _ = render_v13_xss_response(parsed.path, parsed.query)
        if status != 200:
            raise RuntimeError(f"{scenario['id']} seed {seed_path} rendered status {status}")
        candidates.extend(discover_reflected_input_candidates(parsed.geturl(), body))

    candidate_input = candidate_input_for_prompt(candidates)
    return {
        "schema_version": CANDIDATE_SNAPSHOT_VERSION,
        "artifact_status": NOT_EXPERIMENTAL,
        "benchmark_id": BENCHMARK_ID,
        "manifest_version": MANIFEST_VERSION,
        "scenario_id": scenario["id"],
        "seed_paths": list(scenario["seed_paths"]),
        "candidate_count": len(candidate_input),
        "test_budget": int(scenario["test_budget"]),
        "top_k": min(int(scenario["test_budget"]), len(candidate_input)),
        "ranking_prompt_version": LLM_RANKING_PROMPT_VERSION,
        "candidate_input_schema": "llm-candidate-ranking-v1.candidate_input",
        "candidate_input": candidate_input,
        "excluded_data": [
            "semantic case labels",
            "vulnerability status",
            "ground-truth cases",
            "credentials",
            "session values",
            "raw HTML",
            "browser state",
            "source code",
        ],
        "created_from": "rendered v1.3 seed pages processed by discover_reflected_input_candidates",
    }


def snapshot_record(snapshot: dict[str, Any], snapshot_path: Path, output_dir: Path) -> dict[str, Any]:
    candidate_input_sha = sha256_json(snapshot["candidate_input"])
    return {
        "scenario_id": snapshot["scenario_id"],
        "snapshot_path": snapshot_path.relative_to(output_dir).as_posix(),
        "snapshot_sha256": sha256_file(snapshot_path),
        "candidate_input_sha256": candidate_input_sha,
        "candidate_count": snapshot["candidate_count"],
        "test_budget": snapshot["test_budget"],
        "top_k": snapshot["top_k"],
        "candidate_ids": [item["candidate_id"] for item in snapshot["candidate_input"]],
    }


def build_arm_input_ledger(snapshot_records: list[dict[str, Any]]) -> dict[str, Any]:
    scenarios = [
        {
            "scenario_id": record["scenario_id"],
            "snapshot_path": record["snapshot_path"],
            "snapshot_sha256": record["snapshot_sha256"],
            "candidate_input_sha256": record["candidate_input_sha256"],
            "candidate_ids": record["candidate_ids"],
            "candidate_count": record["candidate_count"],
            "test_budget": record["test_budget"],
            "top_k": record["top_k"],
        }
        for record in snapshot_records
    ]
    return {
        "schema_version": ARM_INPUT_LEDGER_VERSION,
        "artifact_status": NOT_EXPERIMENTAL,
        "arm_ids": list(ARM_IDS),
        "input_policy": "Every arm consumes the same immutable per-scenario candidate snapshot by SHA-256 reference.",
        "arms": [
            {
                "arm_id": arm_id,
                "scenario_inputs": scenarios,
            }
            for arm_id in ARM_IDS
        ],
    }


def build_dry_run_config(
    *,
    manifest: dict[str, Any],
    target_config: dict[str, Any],
    snapshot_records: list[dict[str, Any]],
    protocol_path: Path,
) -> dict[str, Any]:
    del target_config
    return {
        "schema_version": DRY_VALIDATION_VERSION,
        "artifact_status": NOT_EXPERIMENTAL,
        "protocol_path": protocol_path.relative_to(REPO_ROOT).as_posix(),
        "protocol_status": "frozen_pending_repository_commit_and_annotated_tag",
        "benchmark_id": manifest["benchmark_id"],
        "manifest_version": manifest["manifest_version"],
        "snapshot_version": CANDIDATE_SNAPSHOT_VERSION,
        "scenario_count": len(snapshot_records),
        "scenario_ids": [record["scenario_id"] for record in snapshot_records],
        "ranking_arms": [
            {
                "arm_id": "deterministic_structural",
                "arm_type": "deterministic",
                "ranking_ruleset_version": DETERMINISTIC_RANKING_RULESET_VERSION,
                "trial_count_per_scenario": DETERMINISTIC_TRIALS_PER_SCENARIO,
                "provider_cost": "not_applicable",
            },
            {
                "arm_id": "proprietary_gpt",
                "arm_type": "proprietary_llm",
                "provider": "openai",
                "model_identifier": PROPRIETARY_MODEL_IDENTIFIER,
                "command_client": "python -m adstf.openai_ranking_wrapper",
                "prompt_version": LLM_RANKING_PROMPT_VERSION,
                "parser": "adstf.llm_ranking.parse_model_ranking",
                "settings": {
                    "OPENAI_RANKING_MODEL": PROPRIETARY_MODEL_IDENTIFIER,
                    "OPENAI_SEND_TEMPERATURE": "unset_or_false",
                    "temperature_parameter": "omitted",
                    "provider_default_temperature": "used",
                    "max_output_tokens": 1200,
                    "timeout_seconds": 60,
                    "structured_output": "OpenAI Responses API json_schema candidate_ranking",
                },
                "trial_count_per_scenario": LLM_TRIALS_PER_SCENARIO,
            },
            {
                "arm_id": "local_qwen",
                "arm_type": "local_llm",
                "provider": "local-llama.cpp",
                "primary_model_candidate_id": LOCAL_PRIMARY_MODEL_ID,
                "contingency_model_candidate_id": LOCAL_CONTINGENCY_MODEL_ID,
                "model_identifier": "Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M",
                "prompt_version": LLM_RANKING_PROMPT_VERSION,
                "parser": "adstf.llm_ranking.parse_model_ranking after llama-completion transport parsing",
                "settings_source": "results/local-runtime-output-boundary-v1.3/transport-settings.json",
                "settings": {
                    "runtime": "llama.cpp b9637 Windows CPU x64",
                    "transport": "llama-completion stdout/stderr with llama-completion-transport-parser-v1.3",
                    "context_size_tokens": 4096,
                    "max_output_tokens": 768,
                    "temperature": 0.0,
                    "top_p": 1.0,
                    "seed": 42,
                    "threads": 8,
                    "timeout_seconds": 300,
                    "json_schema": "local-ranking-readiness-json-schema-v1.3 with scenario-specific candidate_id enum",
                },
                "trial_count_per_scenario": LLM_TRIALS_PER_SCENARIO,
            },
        ],
        "candidate_budget": {
            "source": "xss-v13 manifest per-scenario test_budget",
            "unique_budget_values": sorted({record["test_budget"] for record in snapshot_records}),
            "top_k_definition": "top_k = min(test_budget, discovered_candidate_count)",
        },
        "failure_handling": {
            "invalid_model_output": "record validation errors; exclude from valid LLM ranking metrics; do not silently repair",
            "duplicate_unknown_or_omitted_ids": "invalid model output; parser records exact validation errors",
            "provider_failure_or_timeout": "record failed trial; do not silently retry or improve ranking metrics",
            "scored_retry_policy": "no silent retry; infrastructure retries require predeclared rule and retained artifacts",
        },
        "fallback_rule": {
            "local_scored_arm": "Qwen only",
            "silent_replacement_allowed": False,
            "contingency_model": LOCAL_CONTINGENCY_MODEL_ID,
            "activation_condition": "documented pre-execution technical failure preventing Qwen from participating",
            "activation_requirement": "protocol revision and complete rerun of affected local-model experiment",
        },
        "metric_capability": metric_capability_summary(),
        "v1_2_separation": {
            "v1_2_protocol_files_modified": False,
            "v1_2_result_artifacts_modified": False,
            "v1_2_canonical_artifacts_modified": False,
        },
    }


def metric_capability_summary() -> dict[str, Any]:
    deterministic = derive_measurements(arm_type="deterministic", candidate_based=True)
    proprietary = derive_measurements(arm_type="proprietary_llm", candidate_based=True)
    local = derive_measurements(arm_type="local_llm", candidate_based=True)
    return {
        "measurement_schema_version": deterministic["schema_version"],
        "required_metric_groups": [
            "action_counts",
            "request_counts",
            "first_verified_finding",
            "verifier_decisions",
            "model_provider",
            "classification_counts",
            "case_accounting",
        ],
        "dry_shape_validation": {
            "deterministic_structural": sorted(deterministic.keys()),
            "proprietary_gpt": sorted(proprietary.keys()),
            "local_qwen": sorted(local.keys()),
        },
        "undefined_value_policy": deterministic["undefined_values"],
        "deterministic_provider_cost_policy": deterministic["model_provider"]["cost_per_ranking_trial_usd"],
        "llm_provider_cost_missing_policy": proprietary["model_provider"]["cost_per_ranking_trial_usd"],
    }


def validate_protocol_prep_package(
    *,
    manifest: dict[str, Any],
    snapshots: list[dict[str, Any]],
    arm_input_ledger: dict[str, Any],
    dry_run_config: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    if manifest.get("scenario_count") != 24:
        errors.append("manifest scenario_count is not 24")
    if len(snapshots) != 24:
        errors.append("expected exactly 24 candidate snapshots")
    if arm_input_ledger.get("arm_ids") != list(ARM_IDS):
        errors.append("arm ledger does not contain the expected three arm IDs in order")
    if dry_run_config["scenario_ids"] != [scenario["id"] for scenario in manifest["scenarios"]]:
        errors.append("dry-run scenario IDs do not match manifest order")

    snapshot_by_id = {snapshot["scenario_id"]: snapshot for snapshot in snapshots}
    for scenario in manifest["scenarios"]:
        snapshot = snapshot_by_id.get(scenario["id"])
        if snapshot is None:
            errors.append(f"missing snapshot for {scenario['id']}")
            continue
        if snapshot.get("candidate_count") != scenario["candidate_count"]:
            errors.append(f"{scenario['id']} snapshot candidate count differs from manifest")
        if snapshot.get("test_budget") != scenario["test_budget"]:
            errors.append(f"{scenario['id']} snapshot test budget differs from manifest")
        if snapshot_contains_forbidden_data(snapshot):
            errors.append(f"{scenario['id']} snapshot contains ground-truth-like fields")

    arm_refs = arm_input_ledger.get("arms", [])
    if len(arm_refs) != len(ARM_IDS):
        errors.append("arm input ledger does not contain exactly three arms")
    else:
        baseline = arm_refs[0].get("scenario_inputs", [])
        for arm in arm_refs[1:]:
            if arm.get("scenario_inputs", []) != baseline:
                errors.append(f"{arm.get('arm_id')} does not reference the exact same scenario snapshots")

    budget_values = dry_run_config["candidate_budget"]["unique_budget_values"]
    if budget_values != [4]:
        errors.append(f"expected a single candidate-test budget of 4, found {budget_values}")
    if dry_run_config["candidate_budget"]["top_k_definition"] != "top_k = min(test_budget, discovered_candidate_count)":
        errors.append("top-k definition is not explicit")
    local_arm = next((arm for arm in dry_run_config["ranking_arms"] if arm["arm_id"] == "local_qwen"), {})
    fallback = dry_run_config["fallback_rule"]
    if local_arm.get("primary_model_candidate_id") != LOCAL_PRIMARY_MODEL_ID:
        errors.append("local arm primary model is not Qwen")
    if fallback.get("silent_replacement_allowed") is not False:
        errors.append("fallback rule must forbid silent replacement")
    if fallback.get("contingency_model") != LOCAL_CONTINGENCY_MODEL_ID:
        errors.append("fallback rule does not name Gemma as contingency")

    metric_groups = dry_run_config["metric_capability"]["required_metric_groups"]
    for required in ("action_counts", "request_counts", "first_verified_finding", "model_provider"):
        if required not in metric_groups:
            errors.append(f"metric capability missing {required}")

    if "v1.2" in json.dumps(dry_run_config.get("scenario_ids", [])):
        errors.append("dry-run scenario IDs unexpectedly reference v1.2")

    if not errors and not warnings:
        warnings.append("ready for protocol commit/tag only after generated files are committed and the working tree is clean")

    return {
        "schema_version": DRY_VALIDATION_VERSION,
        "artifact_status": NOT_EXPERIMENTAL,
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "scenario_count": len(snapshots),
        "arm_ids": list(ARM_IDS),
        "ground_truth_semantics_loaded": False,
        "candidate_snapshots_contain_ground_truth": any(snapshot_contains_forbidden_data(snapshot) for snapshot in snapshots),
        "shared_candidate_inputs_across_arms": not any(
            arm.get("scenario_inputs", []) != arm_refs[0].get("scenario_inputs", [])
            for arm in arm_refs[1:]
        )
        if arm_refs
        else False,
        "budget_values": budget_values,
        "top_k_definition": dry_run_config["candidate_budget"]["top_k_definition"],
        "scored_trials_executed": False,
        "browser_vulnerability_verification_executed": False,
        "zap_executed": False,
        "v1_2_artifacts_modified": False,
    }


def snapshot_contains_forbidden_data(value: Any) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower() in FORBIDDEN_SNAPSHOT_KEYS:
                return True
            if snapshot_contains_forbidden_data(item):
                return True
    elif isinstance(value, list):
        return any(snapshot_contains_forbidden_data(item) for item in value)
    return False


def scenario_snapshot_rows(manifest: dict[str, Any], snapshot_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    manifest_by_id = {scenario["id"]: scenario for scenario in manifest["scenarios"]}
    return [
        {
            "scenario_id": record["scenario_id"],
            "seed_count": len(manifest_by_id[record["scenario_id"]]["seed_paths"]),
            "candidate_count": record["candidate_count"],
            "test_budget": record["test_budget"],
            "top_k": record["top_k"],
            "snapshot_path": record["snapshot_path"],
            "snapshot_sha256": record["snapshot_sha256"],
            "candidate_input_sha256": record["candidate_input_sha256"],
        }
        for record in snapshot_records
    ]


def package_manifest_data(
    *,
    output_dir: Path,
    manifest: dict[str, Any],
    target_config: dict[str, Any],
    validation: dict[str, Any],
    snapshot_records: list[dict[str, Any]],
    protocol_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": PROTOCOL_PREP_VERSION,
        "artifact_status": NOT_EXPERIMENTAL,
        "created_at": datetime.now(UTC).isoformat(),
        "benchmark_id": manifest["benchmark_id"],
        "manifest_version": manifest["manifest_version"],
        "target_config": target_config.get("name"),
        "scenario_count": len(snapshot_records),
        "arm_ids": list(ARM_IDS),
        "validation_valid": validation["valid"],
        "protocol_path": protocol_path.relative_to(REPO_ROOT).as_posix(),
        "protocol_sha256": sha256_file(protocol_path) if protocol_path.exists() else "not_available",
        "included_artifacts": [
            path.relative_to(output_dir).as_posix()
            for path in sorted(output_dir.rglob("*"))
            if path.is_file() and path.name not in {"manifest.json", "checksums.sha256"}
        ],
        "v1_2_artifacts_modified": False,
        "freeze_status": "frozen_protocol_pending_repository_commit_and_annotated_tag",
        "freeze_condition": "dry validation must pass, protocol package must be committed, working tree must be clean, and annotated tag evaluation-protocol-v1.3 must point to that commit",
    }


def render_report(validation: dict[str, Any], snapshot_records: list[dict[str, Any]], dry_run_config: dict[str, Any]) -> str:
    lines = [
        "# XSS v1.3 Protocol Preparation Dry Validation",
        "",
        "Status: dry validation only. No scored ranking trials, browser vulnerability verification, deterministic evaluation, local-model trials, proprietary-model trials or ZAP runs were executed.",
        "",
        f"- Validation valid: `{validation['valid']}`",
        f"- Scenario snapshots: `{len(snapshot_records)}`",
        f"- Arms: `{', '.join(dry_run_config['scenario_ids'][:0] or ARM_IDS)}`",
        f"- Shared candidate inputs across arms: `{validation['shared_candidate_inputs_across_arms']}`",
        f"- Ground-truth semantics loaded: `{validation['ground_truth_semantics_loaded']}`",
        f"- Candidate snapshots contain ground truth: `{validation['candidate_snapshots_contain_ground_truth']}`",
        f"- Budget values: `{validation['budget_values']}`",
        f"- Top-k definition: `{validation['top_k_definition']}`",
        "",
        "## Arm Summary",
        "",
        "| Arm | Trials per scenario | Main settings |",
        "| --- | ---: | --- |",
    ]
    for arm in dry_run_config["ranking_arms"]:
        settings = arm.get("settings", {})
        if arm["arm_id"] == "deterministic_structural":
            setting_text = arm["ranking_ruleset_version"]
        elif arm["arm_id"] == "proprietary_gpt":
            setting_text = f"{arm['model_identifier']}; temperature parameter {settings['temperature_parameter']}; max output {settings['max_output_tokens']}"
        else:
            setting_text = f"{arm['model_identifier']}; temp {settings['temperature']}; max output {settings['max_output_tokens']}; timeout {settings['timeout_seconds']}s"
        lines.append(f"| `{arm['arm_id']}` | `{arm['trial_count_per_scenario']}` | {setting_text} |")

    lines.extend(
        [
            "",
            "## Freeze Blockers",
            "",
            "- The generated package records protocol-freeze readiness.",
            "- The final repository-level freeze is complete only when this package is committed and tagged with `evaluation-protocol-v1.3`.",
            "- Any later methodological change requires a separately versioned protocol revision.",
        ]
    )
    if validation["errors"]:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in validation["errors"])
    if validation["warnings"]:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in validation["warnings"])
    return "\n".join(lines) + "\n"


def render_arm_table(dry_run_config: dict[str, Any]) -> str:
    lines = [
        "# Thesis Table Template: v1.3 XSS Ablation Arms",
        "",
        "Status: configuration table only. No experimental results are included.",
        "",
        "| Arm | Authority | Trials/scenario | Provider/model | Key frozen settings |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for arm in dry_run_config["ranking_arms"]:
        if arm["arm_id"] == "deterministic_structural":
            authority = "deterministic structural ranking"
            provider = arm["ranking_ruleset_version"]
            settings = "no provider cost; no model output"
        elif arm["arm_id"] == "proprietary_gpt":
            authority = "bounded hosted LLM ranking"
            provider = f"{arm['provider']} / {arm['model_identifier']}"
            settings = "temperature omitted; JSON schema output; candidate IDs only"
        else:
            authority = "bounded local open-weights ranking"
            provider = f"{arm['provider']} / {arm['model_identifier']}"
            settings = "llama-completion; JSON schema; temp 0.0; seed 42"
        lines.append(f"| `{arm['arm_id']}` | {authority} | `{arm['trial_count_per_scenario']}` | {provider} | {settings} |")
    return "\n".join(lines) + "\n"


def render_arm_table_latex() -> str:
    return (
        "% Status: configuration table only. No experimental results are included.\n"
        "\\begin{table}[ht]\n"
        "\\centering\n"
        "\\caption{Frozen arms proposed for the v1.3 XSS ablation study.}\n"
        "\\label{tab:xss-v13-ablation-arms}\n"
        "\\begin{tabular}{llll}\n"
        "\\hline\n"
        "Arm & Authority & Trials/scenario & Provider/model \\\\\n"
        "\\hline\n"
        "deterministic\\_structural & Deterministic ranking & 1 & deterministic-structural-v1 \\\\\n"
        "proprietary\\_gpt & Bounded hosted LLM ranking & 5 & OpenAI gpt-5.6-luna \\\\\n"
        "local\\_qwen & Bounded local LLM ranking & 5 & Qwen2.5 7B Instruct GGUF Q4\\_K\\_M \\\\\n"
        "\\hline\n"
        "\\end{tabular}\n"
        "\\end{table}\n"
    )


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


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


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_checksums(paths: list[Path]) -> str:
    return "".join(f"{sha256_file(path)}  {_display_path(path)}\n" for path in paths)


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare and dry-validate the frozen v1.3 XSS ablation protocol.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    manifest = build_protocol_prep_package(output_dir=args.output_dir)
    if not manifest["validation_valid"]:
        raise SystemExit("v1.3 XSS protocol preparation dry validation failed")
    print(f"XSS v1.3 protocol preparation artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
