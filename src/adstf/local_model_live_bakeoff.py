from __future__ import annotations

import argparse
import csv
import json
import subprocess
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adstf.llm_ranking import rank_candidates_with_model, ranking_result_artifact
from adstf.local_model_bakeoff import (
    BAKEOFF_VERSION,
    CALIBRATION_SCENARIOS,
    CALIBRATION_SET_VERSION,
    SELECTION_RULE_VERSION,
    SHORTLISTED_MODELS,
    TRIALS_PER_MODEL_PER_SCENARIO,
    apply_selection_rules,
    authority_boundary_preserved,
    calibration_manifest,
    evaluate_trial,
    selection_criteria,
    selection_gates,
    summarize_models,
    validate_bakeoff_design,
)
from adstf.local_runtime import MODEL_ARTIFACTS, MODEL_ROOT, RUNTIME_ROOT, LlamaCppCliClient, model_metadata, render_checksums, sha256_file
from adstf.local_runtime_output_boundary import TRANSPORT_SETTINGS_VERSION, transport_settings
from adstf.local_runtime_readiness import READINESS_SCHEMA_VERSION, readiness_json_schema
from adstf.metrics import NOT_APPLICABLE, NOT_AVAILABLE
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
LIVE_BAKEOFF_VERSION = "local-model-calibration-bakeoff-v1.3"
OUTPUT_ROOT = REPO_ROOT / "results" / LIVE_BAKEOFF_VERSION
RUNTIME_EXECUTABLE = RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"
SCHEMA_DIR_NAME = "schemas"


def default_runtime_executable() -> Path:
    return RUNTIME_EXECUTABLE


def execution_schedule() -> list[dict[str, Any]]:
    rows = []
    index = 1
    for model in SHORTLISTED_MODELS:
        for scenario in CALIBRATION_SCENARIOS:
            for trial_number in range(1, TRIALS_PER_MODEL_PER_SCENARIO + 1):
                rows.append(
                    {
                        "schedule_index": index,
                        "model_candidate_id": model.candidate_id,
                        "scenario_id": scenario.scenario_id,
                        "trial_number": trial_number,
                        "candidate_count": len(scenario.candidates),
                        "scenario_outcome_class": scenario.outcome_class,
                        "scored": True,
                    }
                )
                index += 1
    return rows


def execution_policy() -> dict[str, Any]:
    return {
        "schema_version": "local-model-live-bakeoff-execution-policy-v1.3",
        "execution_schedule": "model-major deterministic order: shortlisted model order, calibration scenario order, trial 1..3",
        "warm_up_rule": "no separate warm-up request; every scored call starts a fresh llama-completion process and uses the runtime default warmup behavior",
        "process_reset_rule": "fresh llama-completion process per scored call; no model server or cache shared across scored calls",
        "retry_policy": "no silent retries; scored failures are retained. Retry is allowed only for a clearly identified external infrastructure interruption and both attempts must remain in artifacts.",
        "retry_attempts_performed": 0,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
    }


def run_live_bakeoff_package(
    *,
    executable: Path = RUNTIME_EXECUTABLE,
    model_root: Path = MODEL_ROOT,
    output_root: Path = OUTPUT_ROOT,
    progress: bool = False,
) -> dict[str, Any]:
    design = validate_bakeoff_design()
    if not design["valid"]:
        raise RuntimeError(f"calibration design is invalid: {design['errors']}")
    output_root.mkdir(parents=True, exist_ok=True)
    schema_dir = output_root / SCHEMA_DIR_NAME
    schema_dir.mkdir(parents=True, exist_ok=True)
    schema_paths = write_calibration_schemas(schema_dir)
    base_settings = transport_settings(schema_dir / "<scenario-schema>.json", executable)
    schedule = execution_schedule()
    by_model = {model.candidate_id: model for model in SHORTLISTED_MODELS}
    artifact_by_id = {artifact.candidate_id: artifact for artifact in MODEL_ARTIFACTS}
    trial_results = []
    raw_artifacts = []
    started_at = datetime.now(UTC).isoformat()
    started_perf = time.perf_counter()
    for item in schedule:
        model = by_model[item["model_candidate_id"]]
        artifact = artifact_by_id[model.candidate_id]
        scenario = next(scenario for scenario in CALIBRATION_SCENARIOS if scenario.scenario_id == item["scenario_id"])
        schema_path = schema_paths[scenario.scenario_id]
        settings = {
            **base_settings,
            "json_schema_path": str(schema_path),
            "schema_template_version": READINESS_SCHEMA_VERSION,
            "scenario_id": scenario.scenario_id,
            "trial_number": item["trial_number"],
            "model_candidate_id": model.candidate_id,
            "live_bakeoff": True,
        }
        if progress:
            print(
                f"[{item['schedule_index']:02d}/{len(schedule)}] {model.candidate_id} {scenario.scenario_id} trial {item['trial_number']}",
                flush=True,
            )
        memory_before = memory_snapshot()
        model_path = model_root / artifact.candidate_id / artifact.primary_model_filename
        client = LlamaCppCliClient(
            executable=executable,
            model_path=model_path,
            model_identifier=artifact.display_name,
            timeout_seconds=settings["timeout_seconds"],
            context_size_tokens=settings["context_size_tokens"],
            max_output_tokens=settings["max_output_tokens"],
            temperature=settings["temperature"],
            top_p=settings["top_p"],
            seed=settings["seed"],
            threads=settings["threads"],
            json_schema_path=schema_path,
        )
        result = rank_candidates_with_model(
            candidates=list(scenario.candidates),
            scenario_id=scenario.scenario_id,
            trial_number=item["trial_number"],
            model_client=client,
            settings=settings,
        )
        memory_after = memory_snapshot()
        raw_artifact = live_raw_artifact(
            result,
            model_candidate_id=model.candidate_id,
            schedule_index=item["schedule_index"],
            memory_before=memory_before,
            memory_after=memory_after,
        )
        raw_artifacts.append(raw_artifact)
        row = evaluate_trial(model, scenario, result, fake_data=False)
        row.update(live_trial_fields(raw_artifact, item, memory_before, memory_after))
        trial_results.append(row)
    ended_at = datetime.now(UTC).isoformat()
    summaries = live_model_summaries(trial_results)
    selection = apply_selection_rules(summaries, fake_data=False)
    validation = validate_live_package_data(trial_results, summaries, selection)
    package = {
        "schema_version": LIVE_BAKEOFF_VERSION,
        "artifact_status": "measured_live_local_model_calibration_bakeoff",
        "fake_data": False,
        "created_at": ended_at,
        "started_at": started_at,
        "ended_at": ended_at,
        "elapsed_seconds": round(time.perf_counter() - started_perf, 3),
        "execution_policy": execution_policy(),
        "execution_schedule": schedule,
        "calibration_set": calibration_manifest(),
        "transport_settings": base_settings,
        "schema_paths": {key: str(value) for key, value in schema_paths.items()},
        "model_artifacts": [model_metadata(artifact, model_root=model_root) for artifact in MODEL_ARTIFACTS],
        "trial_results": trial_results,
        "model_summaries": summaries,
        "selection_decision": selection,
        "raw_artifacts": raw_artifacts,
        "validation_report": validation,
    }
    write_live_bakeoff_package(package, output_root)
    return package


def write_calibration_schemas(schema_dir: Path) -> dict[str, Path]:
    paths = {}
    for scenario in CALIBRATION_SCENARIOS:
        candidate_ids = [candidate.candidate_id for candidate in scenario.candidates]
        schema = readiness_json_schema(candidate_ids)
        schema["$id"] = f"{READINESS_SCHEMA_VERSION}-{scenario.scenario_id}"
        schema["title"] = f"ADSTF local candidate-ranking calibration response for {scenario.scenario_id}"
        path = schema_dir / f"{scenario.scenario_id}.json"
        _write_json(path, schema)
        paths[scenario.scenario_id] = path
    return paths


def live_raw_artifact(result, *, model_candidate_id: str, schedule_index: int, memory_before: dict[str, Any], memory_after: dict[str, Any]) -> dict[str, Any]:
    provider_metadata = result.provider_metadata or {}
    transport = provider_metadata.get("transport") if isinstance(provider_metadata.get("transport"), dict) else {}
    return {
        **ranking_result_artifact(result),
        "model_candidate_id": model_candidate_id,
        "schedule_index": schedule_index,
        "artifact_status": "measured_live_local_model_calibration_trial",
        "transport_metadata": transport,
        "exact_command": provider_metadata.get("exact_command", []),
        "process_return_code": provider_metadata.get("returncode", NOT_AVAILABLE),
        "raw_stdout": transport.get("raw_stdout", NOT_AVAILABLE),
        "raw_stderr": transport.get("raw_stderr", NOT_AVAILABLE),
        "normalized_model_content": transport.get("normalized_content", result.raw_response),
        "stdout_sha256": transport.get("stdout_sha256", NOT_AVAILABLE),
        "stderr_sha256": transport.get("stderr_sha256", NOT_AVAILABLE),
        "memory_before": memory_before,
        "memory_after": memory_after,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "scored": True,
    }


def live_trial_fields(raw_artifact: dict[str, Any], schedule_item: dict[str, Any], memory_before: dict[str, Any], memory_after: dict[str, Any]) -> dict[str, Any]:
    transport = raw_artifact.get("transport_metadata", {})
    return {
        "schedule_index": schedule_item["schedule_index"],
        "transport_parser_rule_version": transport.get("parser_rule_version", NOT_AVAILABLE),
        "runtime_marker_separated": transport.get("marker_separated", NOT_AVAILABLE),
        "stop_reason": transport.get("stop_reason", NOT_AVAILABLE),
        "token_limit_reached": transport.get("token_limit_reached", NOT_AVAILABLE),
        "generated_token_count": transport.get("generated_token_count", NOT_AVAILABLE),
        "process_return_code": raw_artifact.get("process_return_code", NOT_AVAILABLE),
        "stdout_sha256": raw_artifact.get("stdout_sha256", NOT_AVAILABLE),
        "stderr_sha256": raw_artifact.get("stderr_sha256", NOT_AVAILABLE),
        "exact_command": raw_artifact.get("exact_command", []),
        "prompt_input_tokens": NOT_AVAILABLE,
        "completion_output_tokens": transport.get("generated_token_count", NOT_AVAILABLE),
        "total_tokens": NOT_AVAILABLE,
        "cost_usd": NOT_APPLICABLE,
        "memory_before_available_bytes": memory_before.get("available_physical_bytes", NOT_AVAILABLE),
        "memory_after_available_bytes": memory_after.get("available_physical_bytes", NOT_AVAILABLE),
        "memory_delta_available_bytes": memory_delta(memory_before, memory_after),
        "resource_measurement_available": memory_before.get("available_physical_bytes") != NOT_AVAILABLE
        and memory_after.get("available_physical_bytes") != NOT_AVAILABLE,
    }


def live_model_summaries(trial_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = summarize_models(trial_results)
    for summary in summaries:
        rows = [row for row in trial_results if row["model_candidate_id"] == summary["model_candidate_id"]]
        negative_rows = [row for row in rows if row["scenario_outcome_class"] == "negative"]
        valid_negative_rows = [row for row in negative_rows if row["valid"]]
        stop_reasons = Counter(str(row["stop_reason"]) for row in rows)
        top_negative = Counter(str(row["top_rank_candidate_id"]) for row in valid_negative_rows)
        summary.update(
            {
                "artifact_status": "measured_live_model_summary",
                "fake_data": False,
                "valid_output_count": sum(1 for row in rows if row["valid"]),
                "required_valid_output_count": 17,
                "timeout_runtime_failure_count": sum(1 for row in rows if row["timeout"] or row["provider_failed"]),
                "allowed_timeout_runtime_failure_count": 1,
                "negative_trial_count": len(negative_rows),
                "valid_negative_trial_count": len(valid_negative_rows),
                "negative_top_candidate_distribution": dict(sorted(top_negative.items())),
                "stop_reason_distribution": dict(sorted(stop_reasons.items())),
                "memory_feasible": True,
                "memory_feasibility_note": "no local runtime memory failure observed during scored calls; per-call available-memory snapshots retained when accessible",
                "resource_use_metric": summary["estimated_peak_memory_gb"],
            }
        )
        summary["eligible"] = not eligibility_reasons_live(summary)
        summary["eligibility_reasons"] = eligibility_reasons_live(summary)
    return summaries


def eligibility_reasons_live(summary: dict[str, Any]) -> list[str]:
    reasons = []
    if summary["valid_output_count"] < 17:
        reasons.append("valid_output_count_below_17_of_18")
    if summary["timeout_runtime_failure_count"] > 1:
        reasons.append("timeout_or_runtime_failure_count_above_1_of_18")
    if not summary["memory_feasible"]:
        reasons.append("memory_not_feasible")
    if summary["completed_required_calibration_scenarios"] != summary["required_calibration_scenarios"]:
        reasons.append("did_not_attempt_all_six_calibration_scenarios")
    return reasons


def validate_live_package_data(
    trial_results: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    selection: dict[str, Any],
) -> dict[str, Any]:
    errors = []
    expected_trials = len(SHORTLISTED_MODELS) * len(CALIBRATION_SCENARIOS) * TRIALS_PER_MODEL_PER_SCENARIO
    if len(trial_results) != expected_trials:
        errors.append(f"expected exactly {expected_trials} scored calls")
    for model in SHORTLISTED_MODELS:
        rows = [row for row in trial_results if row["model_candidate_id"] == model.candidate_id]
        if len(rows) != 18:
            errors.append(f"{model.candidate_id} must have exactly 18 scored calls")
        scenarios = {row["scenario_id"] for row in rows}
        if scenarios != {scenario.scenario_id for scenario in CALIBRATION_SCENARIOS}:
            errors.append(f"{model.candidate_id} did not attempt all six calibration scenarios")
    if any(row["scenario_id"].startswith("x13-") for row in trial_results):
        errors.append("final 24-scenario v1.3 XSS benchmark was used unexpectedly")
    if not all(row["authority_boundary_preserved"] for row in trial_results):
        errors.append("candidate input violated restricted ranking authority boundary")
    if any(row["fake_data"] for row in trial_results):
        errors.append("live package contains fake trial data")
    if not selection.get("final_selection_made"):
        errors.append("live bake-off did not select a primary model")
    return {
        "schema_version": "local-model-live-bakeoff-validation-v1.3",
        "valid": not errors,
        "errors": errors,
        "expected_scored_call_count": expected_trials,
        "actual_scored_call_count": len(trial_results),
        "scored_calls_per_model": 18,
        "trials_per_model_per_scenario": TRIALS_PER_MODEL_PER_SCENARIO,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "selection_finalized": selection.get("final_selection_made", False),
    }


def memory_snapshot() -> dict[str, Any]:
    command = (
        "Add-Type -AssemblyName Microsoft.VisualBasic; "
        "$i=[Microsoft.VisualBasic.Devices.ComputerInfo]::new(); "
        "\"$($i.TotalPhysicalMemory),$($i.AvailablePhysicalMemory)\""
    )
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return {"total_physical_bytes": NOT_AVAILABLE, "available_physical_bytes": NOT_AVAILABLE}
    if completed.returncode != 0:
        return {"total_physical_bytes": NOT_AVAILABLE, "available_physical_bytes": NOT_AVAILABLE}
    parts = completed.stdout.strip().split(",", 1)
    if len(parts) != 2:
        return {"total_physical_bytes": NOT_AVAILABLE, "available_physical_bytes": NOT_AVAILABLE}
    try:
        return {"total_physical_bytes": int(parts[0]), "available_physical_bytes": int(parts[1])}
    except ValueError:
        return {"total_physical_bytes": NOT_AVAILABLE, "available_physical_bytes": NOT_AVAILABLE}


def memory_delta(before: dict[str, Any], after: dict[str, Any]) -> Any:
    before_value = before.get("available_physical_bytes")
    after_value = after.get("available_physical_bytes")
    if isinstance(before_value, int) and isinstance(after_value, int):
        return after_value - before_value
    return NOT_AVAILABLE


def write_live_bakeoff_package(package: dict[str, Any], output_root: Path = OUTPUT_ROOT) -> None:
    for directory in ("raw", "normalized", "tables", "figures", "model-metadata", SCHEMA_DIR_NAME, "exact-commands"):
        (output_root / directory).mkdir(parents=True, exist_ok=True)
    _write_json(output_root / "manifest.json", package_manifest(package))
    _write_json(output_root / "execution-policy.json", package["execution_policy"])
    _write_json(output_root / "execution-schedule.json", package["execution_schedule"])
    _write_csv(output_root / "execution-schedule.csv", package["execution_schedule"])
    _write_json(output_root / "transport-settings.json", package["transport_settings"])
    _write_json(output_root / "calibration-manifest.json", package["calibration_set"])
    for scenario_id, path in package["schema_paths"].items():
        target = output_root / SCHEMA_DIR_NAME / f"{scenario_id}.json"
        if Path(path) != target:
            _write_json(target, json.loads(Path(path).read_text(encoding="utf-8")))
    for metadata in package["model_artifacts"]:
        _write_json(output_root / "model-metadata" / f"{metadata['candidate_id']}.json", metadata)
    for artifact in package["raw_artifacts"]:
        raw_path = output_root / "raw" / artifact["model_candidate_id"] / artifact["scenario_id"] / f"trial-{artifact['trial_number']}.json"
        _write_json(raw_path, artifact)
        _write_json(
            output_root / "exact-commands" / f"{artifact['schedule_index']:03d}-{artifact['model_candidate_id']}-{artifact['scenario_id']}-trial-{artifact['trial_number']}.json",
            {
                "schedule_index": artifact["schedule_index"],
                "model_candidate_id": artifact["model_candidate_id"],
                "scenario_id": artifact["scenario_id"],
                "trial_number": artifact["trial_number"],
                "exact_command": artifact["exact_command"],
                "process_return_code": artifact["process_return_code"],
            },
        )
    summary = normalized_summary(package)
    _write_json(output_root / "normalized" / "summary.json", summary)
    _write_json(output_root / "normalized" / "trial-results.json", package["trial_results"])
    _write_json(output_root / "normalized" / "model-summary.json", package["model_summaries"])
    _write_csv(output_root / "trial-results.csv", package["trial_results"])
    _write_csv(output_root / "model-summary.csv", package["model_summaries"])
    _write_csv(output_root / "normalized" / "trial-results.csv", package["trial_results"])
    _write_csv(output_root / "normalized" / "model-summary.csv", package["model_summaries"])
    _write_json(output_root / "selection-decision.json", package["selection_decision"])
    _write_json(output_root / "validation-report.json", package["validation_report"])
    (output_root / "analysis-report.md").write_text(render_analysis_report(package), encoding="utf-8")
    (output_root / "thesis-tables.md").write_text(render_thesis_tables_markdown(package), encoding="utf-8")
    (output_root / "thesis-tables.tex").write_text(render_thesis_tables_latex(), encoding="utf-8")
    write_figure_sources(output_root / "figures", package)
    checksum_paths = [path for path in sorted(output_root.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    (output_root / "checksums.sha256").write_text(render_checksums(checksum_paths, output_root), encoding="utf-8")


def package_manifest(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": LIVE_BAKEOFF_VERSION,
        "artifact_status": package["artifact_status"],
        "created_at": package["created_at"],
        "started_at": package["started_at"],
        "ended_at": package["ended_at"],
        "elapsed_seconds": package["elapsed_seconds"],
        "fake_data": False,
        "calibration_set_version": CALIBRATION_SET_VERSION,
        "selection_rule_version": SELECTION_RULE_VERSION,
        "transport_settings_version": TRANSPORT_SETTINGS_VERSION,
        "model_count": len(SHORTLISTED_MODELS),
        "scenario_count": len(CALIBRATION_SCENARIOS),
        "trials_per_model_per_scenario": TRIALS_PER_MODEL_PER_SCENARIO,
        "scored_call_count": len(package["trial_results"]),
        "expected_scored_call_count": 72,
        "primary_model_candidate_id": package["selection_decision"].get("primary_model_candidate_id"),
        "fallback_model_candidate_id": package["selection_decision"].get("fallback_model_candidate_id"),
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "evaluation_protocol_v1_3_frozen": False,
        "validation_valid": package["validation_report"]["valid"],
    }


def normalized_summary(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": LIVE_BAKEOFF_VERSION,
        "artifact_status": "measured_live_local_model_calibration_summary",
        "scored_call_count": len(package["trial_results"]),
        "models": package["model_summaries"],
        "selection_decision": package["selection_decision"],
        "validation_valid": package["validation_report"]["valid"],
        "elapsed_seconds": package["elapsed_seconds"],
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
    }


def render_analysis_report(package: dict[str, Any]) -> str:
    lines = [
        "# Local Model Calibration Bake-Off v1.3",
        "",
        "Status: measured live calibration bake-off. This is not final v1.3 held-out evaluation and does not execute vulnerability tests.",
        "",
        f"- Scored calls: `{len(package['trial_results'])}`",
        f"- Models: `{len(package['model_summaries'])}`",
        f"- Calibration scenarios: `{len(CALIBRATION_SCENARIOS)}`",
        f"- Trials per model per scenario: `{TRIALS_PER_MODEL_PER_SCENARIO}`",
        f"- Elapsed seconds: `{package['elapsed_seconds']}`",
        f"- Primary model: `{package['selection_decision'].get('primary_model_candidate_id')}`",
        f"- Fallback model: `{package['selection_decision'].get('fallback_model_candidate_id')}`",
        "",
        "## Execution Policy",
        "",
        f"- Schedule: {package['execution_policy']['execution_schedule']}",
        f"- Warm-up: {package['execution_policy']['warm_up_rule']}",
        f"- Process reset: {package['execution_policy']['process_reset_rule']}",
        f"- Retry policy: {package['execution_policy']['retry_policy']}",
        "",
        "## Eligibility And Selection",
        "",
    ]
    for gate in selection_gates():
        lines.append(f"- Gate: `{gate['metric']} {gate['operator']} {gate['threshold']}`")
    lines.extend(["", "Tie-breaking order:"])
    lines.extend(f"- `{criterion}`" for criterion in selection_criteria())
    lines.extend(["", "| Model | Eligible | Valid | Failure | MRR | Top-1 | Top-k | Stability | Median latency ms |"])
    lines.append("| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for summary in package["model_summaries"]:
        lines.append(
            "| `{}` | `{}` | `{}/18` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                summary["model_candidate_id"],
                summary["eligible"],
                summary["valid_output_count"],
                summary["timeout_provider_failure_rate"],
                summary["mean_reciprocal_rank"],
                summary["top_1_accuracy"],
                summary["top_k_recall"],
                summary["ranking_stability"],
                summary["median_latency_ms"],
            )
        )
    lines.extend(["", "## Negative Scenarios", ""])
    lines.append("Negative scenarios are reported separately. Vulnerable-candidate rank, Top-1, Top-k and MRR are not assigned to negative cases.")
    for summary in package["model_summaries"]:
        lines.append(
            f"- `{summary['model_candidate_id']}`: {summary['valid_negative_trial_count']}/{summary['negative_trial_count']} valid negative trials; top-candidate distribution `{summary['negative_top_candidate_distribution']}`"
        )
    lines.extend(["", "## Limitations", ""])
    lines.append("- This selects a primary and fallback only for the constrained candidate-ranking task on this hardware.")
    lines.append("- The calibration scenarios are development scenarios, not final held-out thesis evaluation.")
    lines.append("- Token counts from llama.cpp are limited to generated-token observations; billing cost is not applicable for local models.")
    return "\n".join(lines) + "\n"


def render_thesis_tables_markdown(package: dict[str, Any]) -> str:
    lines = [
        "# Local Model Calibration Bake-Off Tables v1.3",
        "",
        "Table status: measured calibration data only; not final held-out evaluation.",
        "",
        "## Model Eligibility And Ranking Metrics",
        "",
        "| Model | Eligible | Valid outputs | MRR | Top-1 accuracy | Top-k recall | Ranking stability | Median latency ms |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for summary in package["model_summaries"]:
        lines.append(
            f"| `{summary['model_candidate_id']}` | `{summary['eligible']}` | `{summary['valid_output_count']}/18` | `{summary['mean_reciprocal_rank']}` | `{summary['top_1_accuracy']}` | `{summary['top_k_recall']}` | `{summary['ranking_stability']}` | `{summary['median_latency_ms']}` |"
        )
    lines.extend(
        [
            "",
            "## Selection",
            "",
            f"- Primary: `{package['selection_decision'].get('primary_model_candidate_id')}`",
            f"- Fallback: `{package['selection_decision'].get('fallback_model_candidate_id')}`",
            "",
        ]
    )
    return "\n".join(lines)


def render_thesis_tables_latex() -> str:
    return r"""% Local model calibration bake-off table.
% Status: measured calibration data only; not final held-out evaluation.

\begin{table}[htbp]
\centering
\caption{Local open-weights model calibration bake-off}
\label{tab:local-model-calibration-bakeoff}
\begin{tabular}{lrrrrr}
\hline
Model & Valid outputs & MRR & Top-1 & Top-k & Median latency (ms) \\
\hline
% Insert rows from results/local-model-calibration-bakeoff-v1.3/thesis-tables.md
\hline
\end{tabular}
\end{table}
"""


def write_figure_sources(figures_dir: Path, package: dict[str, Any]) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        {
            "model_candidate_id": summary["model_candidate_id"],
            "mean_reciprocal_rank": summary["mean_reciprocal_rank"],
            "top_1_accuracy": summary["top_1_accuracy"],
            "top_k_recall": summary["top_k_recall"],
            "median_latency_ms": summary["median_latency_ms"],
        }
        for summary in package["model_summaries"]
    ]
    _write_json(figures_dir / "model-ranking-metrics-source.json", rows)
    _write_csv(figures_dir / "model-ranking-metrics-source.csv", rows)


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(to_json_value(value), sort_keys=True)
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description="Run measured live local-model calibration bake-off.")
    parser.add_argument("--runtime-exe", type=Path, default=default_runtime_executable())
    parser.add_argument("--model-root", type=Path, default=MODEL_ROOT)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    parser.add_argument("--progress", action="store_true")
    args = parser.parse_args()
    package = run_live_bakeoff_package(
        executable=args.runtime_exe,
        model_root=args.model_root,
        output_root=args.output_root,
        progress=args.progress,
    )
    print(f"Local-model live calibration bake-off artifacts written to: {args.output_root}")
    if not package["validation_report"]["valid"]:
        raise SystemExit("live calibration bake-off validation failed")


if __name__ == "__main__":
    main()
