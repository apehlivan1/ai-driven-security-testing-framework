from __future__ import annotations

import argparse
import csv
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adstf.llm_ranking import rank_candidates_with_model, ranking_result_artifact
from adstf.local_runtime import (
    MODEL_ARTIFACTS,
    MODEL_ROOT,
    RUNTIME_ROOT,
    LlamaCppCliClient,
    model_metadata,
    render_checksums,
    runtime_metadata,
    sha256_file,
)
from adstf.local_runtime_readiness import (
    FROZEN_EXECUTION_SETTINGS,
    MAX_CANDIDATES,
    READINESS_SCHEMA_VERSION,
    READINESS_SCENARIO_ID,
    frozen_execution_settings,
    readiness_candidates,
    readiness_json_schema,
)
from adstf.metrics import NOT_AVAILABLE
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
OUTPUT_BOUNDARY_VERSION = "local-runtime-output-boundary-v1.3"
TRANSPORT_SETTINGS_VERSION = "llama-completion-transport-boundary-v1.3"
OUTPUT_ROOT = REPO_ROOT / "results" / OUTPUT_BOUNDARY_VERSION
PREVIOUS_READINESS_ROOT = REPO_ROOT / "results" / "local-runtime-readiness-v1.3"
SERVER_EXECUTABLE = RUNTIME_ROOT / "cpu-x64" / "llama-server.exe"


def default_runtime_executable() -> Path:
    return RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"


def run_output_boundary_package(
    *,
    executable: Path,
    model_root: Path = MODEL_ROOT,
    output_root: Path = OUTPUT_ROOT,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    schema_path = output_root / "local-ranking-readiness-schema-v1.3.json"
    _write_json(schema_path, readiness_json_schema())
    settings = transport_settings(schema_path, executable)
    audit = audit_previous_readiness_artifacts()
    model_rows = []
    readiness_rows = []
    raw_artifacts = []
    for model in MODEL_ARTIFACTS:
        model_rows.append(model_metadata(model, model_root=model_root))
        result = run_one_corrected_readiness(
            model.candidate_id,
            executable=executable,
            model_root=model_root,
            settings=settings,
        )
        readiness_rows.append(result["row"])
        raw_artifacts.append(result["artifact"])
    validation = validate_output_boundary_package(readiness_rows, settings, schema_path)
    package = {
        "manifest": package_manifest(readiness_rows, validation, settings, schema_path),
        "transport_settings": settings,
        "schema_path": schema_path,
        "audit": audit,
        "models": model_rows,
        "readiness_rows": readiness_rows,
        "raw_artifacts": raw_artifacts,
        "validation": validation,
    }
    write_output_boundary_package(package, output_root)
    return package


def run_one_corrected_readiness(
    model_candidate_id: str,
    *,
    executable: Path,
    model_root: Path,
    settings: dict[str, Any],
) -> dict[str, Any]:
    model = next(item for item in MODEL_ARTIFACTS if item.candidate_id == model_candidate_id)
    model_path = model_root / model.candidate_id / model.primary_model_filename
    client = LlamaCppCliClient(
        executable=executable,
        model_path=model_path,
        model_identifier=model.display_name,
        timeout_seconds=settings["timeout_seconds"],
        context_size_tokens=settings["context_size_tokens"],
        max_output_tokens=settings["max_output_tokens"],
        temperature=settings["temperature"],
        top_p=settings["top_p"],
        seed=settings["seed"],
        threads=settings["threads"],
        json_schema_path=Path(settings["json_schema_path"]),
    )
    result = rank_candidates_with_model(
        candidates=readiness_candidates(),
        scenario_id=READINESS_SCENARIO_ID,
        trial_number=1,
        model_client=client,
        settings={**settings, "model_candidate_id": model.candidate_id, "output_boundary_readiness_only": True},
    )
    transport = _transport(result.provider_metadata)
    expected_ids = [candidate.candidate_id for candidate in readiness_candidates()]
    no_truncation = transport.get("token_limit_reached") is False
    all_once = result.is_valid and sorted(result.ordered_candidate_ids) == sorted(expected_ids)
    row = {
        "model_candidate_id": model.candidate_id,
        "display_name": model.display_name,
        "readiness_status": "ready" if result.is_valid and all_once and no_truncation else "not_ready",
        "valid_json": result.is_valid,
        "all_candidate_ids_once": all_once,
        "unknown_candidate_ids": any("unknown candidate_id" in item for item in result.validation_errors),
        "duplicate_candidate_ids": any("duplicate candidate_id" in item for item in result.validation_errors),
        "omitted_candidate_ids": any("omitted candidate_id" in item for item in result.validation_errors),
        "provider_failed": result.provider_failed,
        "process_return_code": result.provider_metadata.get("returncode") if result.provider_metadata else NOT_AVAILABLE,
        "runtime_marker_separated": transport.get("marker_separated", NOT_AVAILABLE),
        "runtime_marker": transport.get("runtime_marker", NOT_AVAILABLE),
        "stop_reason": transport.get("stop_reason", NOT_AVAILABLE),
        "token_limit_reached": transport.get("token_limit_reached", NOT_AVAILABLE),
        "generated_token_count": transport.get("generated_token_count", NOT_AVAILABLE),
        "latency_ms": result.latency_ms if result.latency_ms is not None else NOT_AVAILABLE,
        "validation_errors": result.validation_errors,
        "exact_command": result.provider_metadata.get("exact_command") if result.provider_metadata else [],
        "scored": False,
        "final_model_selection_made": False,
    }
    artifact = {
        **ranking_result_artifact(result),
        "model_candidate_id": model.candidate_id,
        "artifact_status": "non_scored_local_runtime_output_boundary_readiness",
        "transport_metadata": transport,
        "exact_command": row["exact_command"],
        "process_return_code": row["process_return_code"],
        "raw_stdout": transport.get("raw_stdout", NOT_AVAILABLE),
        "raw_stderr": transport.get("raw_stderr", NOT_AVAILABLE),
        "normalized_model_content": transport.get("normalized_content", result.raw_response),
        "stdout_byte_length": transport.get("stdout_byte_length", NOT_AVAILABLE),
        "stderr_byte_length": transport.get("stderr_byte_length", NOT_AVAILABLE),
        "stdout_sha256": transport.get("stdout_sha256", NOT_AVAILABLE),
        "stderr_sha256": transport.get("stderr_sha256", NOT_AVAILABLE),
        "final_24_scenario_xss_v13_used": False,
        "calibration_bakeoff_scenario_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
    }
    return {"row": row, "artifact": artifact}


def transport_settings(schema_path: Path, executable: Path) -> dict[str, Any]:
    settings = frozen_execution_settings(schema_path)
    settings.update(
        {
            "transport_settings_version": TRANSPORT_SETTINGS_VERSION,
            "selected_common_transport_interface": "llama-completion stdout/stderr with versioned output-boundary parser",
            "runtime_executable_sha256": sha256_file(executable) if executable.exists() else NOT_AVAILABLE,
            "server_executable_available": SERVER_EXECUTABLE.exists(),
            "server_executable_sha256": sha256_file(SERVER_EXECUTABLE) if SERVER_EXECUTABLE.exists() else NOT_AVAILABLE,
            "special_token_display": "disabled; --special is not sent and llama.cpp default is false",
            "prompt_display": "disabled with --no-display-prompt",
            "conversation_mode": "single-turn conversation mode via --single-turn",
            "timing_display": "enabled on stderr for reproducibility timing; not part of model content",
            "transport_parser_rule_version": "llama-completion-transport-parser-v1.3",
            "known_runtime_marker": "[end of text]",
            "known_marker_handling": "separate only when it is an exact trailing suffix after an otherwise valid JSON object",
            "arbitrary_suffix_stripping": False,
        }
    )
    return settings


def audit_previous_readiness_artifacts(previous_root: Path = PREVIOUS_READINESS_ROOT) -> dict[str, Any]:
    rows = []
    raw_dir = previous_root / "raw"
    for model in MODEL_ARTIFACTS:
        path = raw_dir / f"{model.candidate_id}.json"
        if not path.exists():
            rows.append({"model_candidate_id": model.candidate_id, "artifact_present": False})
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        provider_metadata = data.get("provider_metadata") if isinstance(data.get("provider_metadata"), dict) else {}
        runtime_settings = provider_metadata.get("runtime_settings") if isinstance(provider_metadata.get("runtime_settings"), dict) else {}
        raw_response = str(data.get("raw_response", ""))
        stderr_tail = str(provider_metadata.get("stderr_tail", ""))
        rows.append(
            {
                "model_candidate_id": model.candidate_id,
                "artifact_present": True,
                "exact_command_retained": False,
                "retained_command_template": runtime_settings.get("runtime_arguments", []),
                "stdout_contains_prompt": False,
                "stdout_contains_generated_json": raw_response.lstrip().startswith("{"),
                "stdout_contains_timing_data": "common_perf_print" in raw_response,
                "stdout_contains_end_marker": raw_response.rstrip().endswith("[end of text]"),
                "stderr_contains_prompt_template_example": "template example" in stderr_tail,
                "stderr_contains_timing_data": "common_perf_print" in stderr_tail,
                "process_return_code_retained": False,
                "provider_failed": data.get("provider_failed"),
                "special_enabled": False,
                "conversation_mode": "single-turn",
                "prompt_display": "disabled",
                "timing_display": "stderr",
                "stop_condition_inferred": "EOS/runtime terminator outside JSON content",
                "ended_by_token_limit": False,
            }
        )
    return {
        "schema_version": "local-runtime-output-boundary-audit-v1.3",
        "previous_package": str(previous_root),
        "root_cause": "llama-completion stdout contained schema-constrained JSON followed by a fixed [end of text] runtime terminator",
        "classification": "shared runtime/output-boundary issue, not model-quality failure",
        "rows": rows,
    }


def validate_output_boundary_package(
    readiness_rows: list[dict[str, Any]],
    settings: dict[str, Any],
    schema_path: Path,
) -> dict[str, Any]:
    errors = []
    if len(readiness_rows) != len(MODEL_ARTIFACTS):
        errors.append("expected one corrected readiness row per shortlisted model")
    if len(readiness_candidates()) != MAX_CANDIDATES:
        errors.append("readiness input must contain exactly eight candidates")
    if not schema_path.exists():
        errors.append("JSON schema artifact is missing")
    if settings["json_schema_version"] != READINESS_SCHEMA_VERSION:
        errors.append("JSON schema version changed unexpectedly")
    if any(row["scored"] for row in readiness_rows):
        errors.append("readiness rows must remain non-scored")
    ready_count = sum(1 for row in readiness_rows if row["readiness_status"] == "ready")
    measured_bakeoff_ready = ready_count == len(MODEL_ARTIFACTS) and not errors
    return {
        "schema_version": "local-runtime-output-boundary-validation-v1.3",
        "valid": not errors,
        "errors": errors,
        "ready_model_count": ready_count,
        "readiness_row_count": len(readiness_rows),
        "measured_bakeoff_ready": measured_bakeoff_ready,
        "calibration_bakeoff_executed": False,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
    }


def package_manifest(
    readiness_rows: list[dict[str, Any]],
    validation: dict[str, Any],
    settings: dict[str, Any],
    schema_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": OUTPUT_BOUNDARY_VERSION,
        "artifact_status": "non_scored_local_runtime_output_boundary_audit_and_readiness",
        "created_at": datetime.now(UTC).isoformat(),
        "transport_settings_version": settings["transport_settings_version"],
        "selected_common_transport_interface": settings["selected_common_transport_interface"],
        "json_schema_version": settings["json_schema_version"],
        "json_schema_sha256": sha256_file(schema_path),
        "model_count": len(MODEL_ARTIFACTS),
        "readiness_request_count": len(readiness_rows),
        "ready_model_count": validation["ready_model_count"],
        "measured_bakeoff_ready": validation["measured_bakeoff_ready"],
        "calibration_bakeoff_executed": False,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
    }


def write_output_boundary_package(package: dict[str, Any], output_root: Path = OUTPUT_ROOT) -> None:
    for directory in ("exact-commands", "raw", "normalized", "model-metadata", "tables"):
        (output_root / directory).mkdir(parents=True, exist_ok=True)
    _write_json(output_root / "manifest.json", package["manifest"])
    _write_json(output_root / "transport-settings.json", package["transport_settings"])
    _write_json(output_root / "validation-report.json", package["validation"])
    _write_json(output_root / "audit.json", package["audit"])
    _write_json(output_root / "local-ranking-readiness-schema-v1.3.json", readiness_json_schema())
    for metadata in package["models"]:
        _write_json(output_root / "model-metadata" / f"{metadata['candidate_id']}.json", metadata)
    for artifact in package["raw_artifacts"]:
        _write_json(output_root / "raw" / f"{artifact['model_candidate_id']}.json", artifact)
        _write_json(
            output_root / "exact-commands" / f"{artifact['model_candidate_id']}.json",
            {
                "model_candidate_id": artifact["model_candidate_id"],
                "exact_command": artifact["exact_command"],
                "process_return_code": artifact["process_return_code"],
            },
        )
    _write_json(output_root / "normalized" / "readiness-results.json", package["readiness_rows"])
    _write_csv(output_root / "normalized" / "readiness-results.csv", package["readiness_rows"])
    _write_csv(output_root / "tables" / "runtime-interface-table.csv", runtime_interface_rows(package))
    (output_root / "output-boundary-audit.md").write_text(render_audit_report(package), encoding="utf-8")
    (output_root / "thesis-runtime-interface-table.md").write_text(render_runtime_interface_table_md(package), encoding="utf-8")
    (output_root / "thesis-runtime-interface-table.tex").write_text(render_runtime_interface_table_tex(), encoding="utf-8")
    checksum_paths = [path for path in sorted(output_root.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    (output_root / "checksums.sha256").write_text(render_checksums(checksum_paths, base_dir=output_root), encoding="utf-8")


def runtime_interface_rows(package: dict[str, Any]) -> list[dict[str, Any]]:
    settings = package["transport_settings"]
    return [
        {
            "interface": "llama-completion",
            "selected": True,
            "content_boundary": "stdout normalized content after exact trailing runtime marker separation",
            "metadata_boundary": "stderr plus transport metadata",
            "schema_validation": "llama.cpp --json-schema-file plus strict application JSON parser",
            "timing_metadata": "stderr common_perf_print parsed into transport metadata",
            "stop_metadata": "exact [end of text] suffix classified as EOS runtime marker after valid JSON",
            "reason": "minimal adapter, direct ModelClient compatibility, raw stdout/stderr retained",
        },
        {
            "interface": "llama-server",
            "selected": False,
            "content_boundary": "documented response content field",
            "metadata_boundary": "server JSON response fields",
            "schema_validation": "server supports JSON schema options",
            "timing_metadata": "available through server response/metrics depending endpoint",
            "stop_metadata": "available through server response depending endpoint",
            "reason": "available but not chosen for this correction because it introduces server lifecycle and HTTP transport before needed",
        },
        {
            "interface": "clean llama-completion with no-perf/log-disable",
            "selected": False,
            "content_boundary": "stdout",
            "metadata_boundary": "reduced stderr",
            "schema_validation": "llama.cpp --json-schema-file",
            "timing_metadata": "reduced or unavailable if --no-perf is used",
            "stop_metadata": "not improved over selected path",
            "reason": "less useful because timing metadata is required and the EOS marker still needs a content-boundary rule",
        },
    ]


def render_audit_report(package: dict[str, Any]) -> str:
    lines = [
        "# Local Runtime Output-Boundary Audit v1.3",
        "",
        "Status: non-scored transport audit and corrected readiness validation. This is not the measured calibration bake-off and not model selection.",
        "",
        "## Root Cause",
        "",
        "The previous readiness package showed schema-constrained JSON on stdout followed by a fixed literal `[end of text]` suffix. Timing and system logs were on stderr. Because the application parser received stdout as model content, it correctly rejected the response as extra data.",
        "",
        "The suffix is treated as a llama.cpp runtime/EOS presentation marker outside the generated JSON boundary because it appeared after an otherwise complete JSON object for all four models while `--special` was not enabled. The adapter now separates only this exact trailing marker after verifying that the preceding text is valid JSON. Raw stdout and stderr remain preserved.",
        "",
        "## Selected Common Transport",
        "",
        f"- Interface: `{package['transport_settings']['selected_common_transport_interface']}`",
        f"- Parser rule: `{package['transport_settings']['transport_parser_rule_version']}`",
        f"- JSON schema: `{package['transport_settings']['json_schema_version']}`",
        f"- Special tokens: `{package['transport_settings']['special_token_display']}`",
        f"- Prompt display: `{package['transport_settings']['prompt_display']}`",
        f"- Conversation mode: `{package['transport_settings']['conversation_mode']}`",
        "",
        "## Interface Comparison",
        "",
        "| Interface | Selected | Reason |",
        "| --- | --- | --- |",
    ]
    for row in runtime_interface_rows(package):
        lines.append(f"| `{row['interface']}` | `{row['selected']}` | {row['reason']} |")
    lines.extend(
        [
            "",
            "## Corrected Readiness Results",
            "",
            "| Model | Status | Valid JSON | All IDs once | Stop | Token limit | Latency ms |",
            "| --- | --- | --- | --- | --- | --- | ---: |",
        ]
    )
    for row in package["readiness_rows"]:
        lines.append(
            f"| `{row['model_candidate_id']}` | `{row['readiness_status']}` | `{row['valid_json']}` | `{row['all_candidate_ids_once']}` | `{row['stop_reason']}` | `{row['token_limit_reached']}` | `{row['latency_ms']}` |"
        )
    lines.extend(
        [
            "",
            "## Package Validation",
            "",
            f"- Package valid: `{package['validation']['valid']}`",
            f"- Ready models: `{package['validation']['ready_model_count']}` of `{package['validation']['readiness_row_count']}`",
            f"- Measured bake-off ready: `{package['validation']['measured_bakeoff_ready']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def render_runtime_interface_table_md(package: dict[str, Any]) -> str:
    lines = [
        "# Runtime Interface Table v1.3",
        "",
        "Table status: output-boundary audit only; not model ranking performance.",
        "",
        "| Interface | Selected | Content boundary | Metadata boundary | Reason |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in runtime_interface_rows(package):
        lines.append(
            f"| `{row['interface']}` | `{row['selected']}` | {row['content_boundary']} | {row['metadata_boundary']} | {row['reason']} |"
        )
    return "\n".join(lines) + "\n"


def render_runtime_interface_table_tex() -> str:
    return r"""% Local runtime interface table template.
% Status: output-boundary audit only; not model ranking performance.

\begin{table}[htbp]
\centering
\caption{Local runtime transport interfaces considered for v1.3}
\label{tab:local-runtime-interface}
\begin{tabular}{llll}
\hline
Interface & Selected & Content boundary & Metadata boundary \\
\hline
% Insert rows from results/local-runtime-output-boundary-v1.3/thesis-runtime-interface-table.md
\hline
\end{tabular}
\end{table}
"""


def _transport(provider_metadata: dict[str, Any] | None) -> dict[str, Any]:
    if not provider_metadata:
        return {}
    transport = provider_metadata.get("transport")
    return transport if isinstance(transport, dict) else {}


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
    parser = argparse.ArgumentParser(description="Run local runtime output-boundary audit and corrected readiness.")
    parser.add_argument("--runtime-exe", type=Path, default=default_runtime_executable())
    parser.add_argument("--model-root", type=Path, default=MODEL_ROOT)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    package = run_output_boundary_package(executable=args.runtime_exe, model_root=args.model_root, output_root=args.output_root)
    print(f"Local runtime output-boundary artifacts written to: {args.output_root}")
    if not package["validation"]["measured_bakeoff_ready"]:
        raise SystemExit("local runtime output-boundary readiness did not complete for every model")


if __name__ == "__main__":
    main()
