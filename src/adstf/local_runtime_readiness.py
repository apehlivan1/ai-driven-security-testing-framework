from __future__ import annotations

import argparse
import csv
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adstf.discovery import ReflectedInputCandidate
from adstf.llm_ranking import LLM_RANKING_PROMPT_VERSION, rank_candidates_with_model, ranking_result_artifact
from adstf.local_model_bakeoff import CALIBRATION_SCENARIOS
from adstf.local_runtime import (
    MODEL_ARTIFACTS,
    MODEL_ROOT,
    OUTPUT_ROOT as PROVISIONING_OUTPUT_ROOT,
    RUNTIME_ROOT,
    LlamaCppCliClient,
    _memory_bytes,
    hardware_report,
    model_metadata,
    render_checksums,
    runtime_metadata,
    sha256_file,
)
from adstf.metrics import NOT_AVAILABLE
from adstf.serialization import to_json_value
from adstf.xss_v13_benchmark import SCENARIOS as FINAL_XSS_V13_SCENARIOS


REPO_ROOT = Path(__file__).resolve().parents[2]
READINESS_VERSION = "local-runtime-readiness-v1.3"
READINESS_SCHEMA_VERSION = "local-ranking-readiness-json-schema-v1.3"
READINESS_SCENARIO_ID = "local-runtime-readiness-synthetic-max-shape-v1.3"
OUTPUT_ROOT = REPO_ROOT / "results" / READINESS_VERSION
MAX_RATIONALE_CHARS = 96
MAX_CANDIDATES = 8
FROZEN_EXECUTION_SETTINGS = {
    "configuration_version": "local-ranking-execution-settings-v1.3-readiness",
    "runtime": "llama.cpp",
    "runtime_executable": "llama-completion.exe",
    "constrained_output_mechanism": "llama.cpp --json-schema-file",
    "json_schema_version": READINESS_SCHEMA_VERSION,
    "context_size_tokens": 4096,
    "max_output_tokens": 768,
    "timeout_seconds": 300,
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 42,
    "threads": 8,
    "prompt_version": LLM_RANKING_PROMPT_VERSION,
    "prompt_template_handling": "plain llm-candidate-ranking-v1 prompt passed by file; model chat template not changed per model",
    "maximum_candidate_count": MAX_CANDIDATES,
    "maximum_rationale_chars": MAX_RATIONALE_CHARS,
    "candidate_id_policy": "every provided candidate_id must appear exactly once; unknown, duplicate, or omitted IDs invalidate the response",
    "truncation_detection": "valid JSON plus generated-token count below the maximum when available; malformed output near the output cap is marked possible_truncation",
    "malformed_output_handling": "record validation errors; do not repair or complete malformed model output",
}


def default_runtime_executable() -> Path:
    return RUNTIME_ROOT / "cpu-x64" / "llama-completion.exe"


def readiness_candidates() -> list[ReflectedInputCandidate]:
    return [
        _candidate("alpha", "term", "get_form", "text", 1, 0),
        _candidate("bravo", "memo", "get_form", "textarea", 1, 0),
        _candidate("cedar", "query", "get_form", "search", 1, 0),
        _candidate("delta", "name", "get_form", "text", 2, 1),
        _candidate("ember", "note", "get_form", "text", 2, 1),
        _candidate("fable", "ref", "query_parameter", "query_parameter", 1, 0),
        _candidate("grove", "page", "query_parameter", "query_parameter", 3, 0),
        _candidate("harbor", "mode", "query_parameter", "query_parameter", 3, 0),
    ]


def readiness_json_schema(candidate_ids: list[str] | None = None) -> dict[str, Any]:
    ids = candidate_ids or [candidate.candidate_id for candidate in readiness_candidates()]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": READINESS_SCHEMA_VERSION,
        "title": "ADSTF local candidate-ranking readiness response",
        "type": "object",
        "additionalProperties": False,
        "required": ["ranking"],
        "properties": {
            "ranking": {
                "type": "array",
                "minItems": len(ids),
                "maxItems": len(ids),
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["candidate_id", "rationale"],
                    "properties": {
                        "candidate_id": {
                            "type": "string",
                            "enum": ids,
                        },
                        "rationale": {
                            "type": "string",
                            "maxLength": MAX_RATIONALE_CHARS,
                        },
                    },
                },
            }
        },
    }


def run_readiness_package(
    *,
    executable: Path,
    model_root: Path = MODEL_ROOT,
    output_root: Path = OUTPUT_ROOT,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    schema_path = output_root / "local-ranking-readiness-schema-v1.3.json"
    _write_json(schema_path, readiness_json_schema())

    settings = frozen_execution_settings(schema_path)
    model_rows = []
    readiness_rows = []
    raw_artifacts = []
    for model in MODEL_ARTIFACTS:
        model_rows.append(model_metadata(model, model_root=model_root))
        result = readiness_one_model(model.candidate_id, executable=executable, model_root=model_root, settings=settings)
        readiness_rows.append(result["row"])
        raw_artifacts.append(result["artifact"])

    validation = validate_readiness_package(readiness_rows, schema_path, settings)
    package = {
        "manifest": package_manifest(readiness_rows, validation, settings, schema_path),
        "hardware": hardware_report(),
        "runtime": readiness_runtime_metadata(executable, schema_path, settings),
        "models": model_rows,
        "settings": settings,
        "schema_path": schema_path,
        "readiness_rows": readiness_rows,
        "raw_artifacts": raw_artifacts,
        "validation": validation,
    }
    write_readiness_package(package, output_root)
    return package


def readiness_one_model(
    model_candidate_id: str,
    *,
    executable: Path,
    model_root: Path,
    settings: dict[str, Any],
) -> dict[str, Any]:
    model = next(item for item in MODEL_ARTIFACTS if item.candidate_id == model_candidate_id)
    model_path = model_root / model.candidate_id / model.primary_model_filename
    memory_before = _memory_bytes("FreePhysicalMemory")
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
        settings={**settings, "model_candidate_id": model.candidate_id, "readiness_only": True},
    )
    memory_after = _memory_bytes("FreePhysicalMemory")
    observations = readiness_observations(result, memory_before=memory_before, memory_after=memory_after)
    row = {
        "model_candidate_id": model.candidate_id,
        "display_name": model.display_name,
        "readiness_status": "ready" if observations["contract_completed"] else "not_ready",
        "contract_completed": observations["contract_completed"],
        "output_not_truncated": observations["output_not_truncated"],
        "json_parsed": observations["json_parsed"],
        "all_candidate_ids_once": observations["all_candidate_ids_once"],
        "unknown_candidate_ids": observations["unknown_candidate_ids"],
        "duplicate_candidate_ids": observations["duplicate_candidate_ids"],
        "omitted_candidate_ids": observations["omitted_candidate_ids"],
        "provider_failed": result.provider_failed,
        "validation_errors": result.validation_errors,
        "latency_ms": result.latency_ms if result.latency_ms is not None else NOT_AVAILABLE,
        "generated_token_count_observed": observations["generated_token_count_observed"],
        "memory_available_before_bytes": memory_before,
        "memory_available_after_bytes": memory_after,
        "memory_available_delta_bytes": _memory_delta(memory_before, memory_after),
        "scored": False,
        "final_model_selection_made": False,
    }
    artifact = {
        **ranking_result_artifact(result),
        "model_candidate_id": model.candidate_id,
        "artifact_status": "non_scored_local_runtime_readiness",
        "readiness_observations": observations,
        "memory_observations": {
            "available_before_bytes": memory_before,
            "available_after_bytes": memory_after,
            "available_delta_bytes": row["memory_available_delta_bytes"],
            "peak_process_memory_bytes": NOT_AVAILABLE,
        },
        "final_24_scenario_xss_v13_used": False,
        "calibration_bakeoff_scenario_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
    }
    return {"row": row, "artifact": artifact}


def readiness_observations(result, *, memory_before: Any, memory_after: Any) -> dict[str, Any]:
    candidate_ids = [candidate.candidate_id for candidate in readiness_candidates()]
    stderr_tail = ""
    if result.provider_metadata and isinstance(result.provider_metadata.get("stderr_tail"), str):
        stderr_tail = result.provider_metadata["stderr_tail"]
    generated = _generated_token_count(stderr_tail)
    possible_truncation = (
        isinstance(generated, int)
        and generated >= FROZEN_EXECUTION_SETTINGS["max_output_tokens"] - 1
        and not result.is_valid
    )
    json_parsed = not any("malformed JSON" in error for error in result.validation_errors) and not result.provider_failed
    duplicate = any("duplicate candidate_id" in error for error in result.validation_errors)
    unknown = any("unknown candidate_id" in error for error in result.validation_errors)
    omitted = any("omitted candidate_id" in error for error in result.validation_errors)
    ordered_set = set(result.ordered_candidate_ids)
    all_once = result.is_valid and len(result.ordered_candidate_ids) == len(candidate_ids) and ordered_set == set(candidate_ids)
    return {
        "scenario_id": READINESS_SCENARIO_ID,
        "candidate_count": len(candidate_ids),
        "json_schema_version": READINESS_SCHEMA_VERSION,
        "json_schema_constrained": True,
        "contract_completed": bool(result.is_valid and all_once and not possible_truncation),
        "output_not_truncated": bool(result.is_valid and not possible_truncation),
        "possible_truncation": possible_truncation,
        "json_parsed": json_parsed,
        "all_candidate_ids_once": all_once,
        "unknown_candidate_ids": unknown,
        "duplicate_candidate_ids": duplicate,
        "omitted_candidate_ids": omitted,
        "generated_token_count_observed": generated,
        "memory_available_before_bytes": memory_before,
        "memory_available_after_bytes": memory_after,
    }


def frozen_execution_settings(schema_path: Path) -> dict[str, Any]:
    settings = dict(FROZEN_EXECUTION_SETTINGS)
    settings["threads"] = min(FROZEN_EXECUTION_SETTINGS["threads"], 8)
    settings["json_schema_path"] = str(schema_path)
    settings["runtime_arguments"] = [
        "llama-completion.exe",
        "-m",
        "<model.gguf>",
        "-f",
        "<prompt-file>",
        "-c",
        str(settings["context_size_tokens"]),
        "-n",
        str(settings["max_output_tokens"]),
        "--temp",
        str(settings["temperature"]),
        "--top-p",
        str(settings["top_p"]),
        "--seed",
        str(settings["seed"]),
        "-t",
        str(settings["threads"]),
        "--no-display-prompt",
        "--single-turn",
        "--json-schema-file",
        "<schema-file>",
    ]
    return settings


def readiness_runtime_metadata(executable: Path, schema_path: Path, settings: dict[str, Any]) -> dict[str, Any]:
    return {
        **runtime_metadata(executable),
        "schema_version": "local-runtime-readiness-runtime-metadata-v1.3",
        "readiness_execution_settings": settings,
        "json_schema_file": str(schema_path),
        "json_schema_sha256": sha256_file(schema_path),
        "previous_32_token_smoke_interpretation": "configuration-validation outputs truncated by intentionally small cap; not model-quality failures",
    }


def validate_readiness_package(readiness_rows: list[dict[str, Any]], schema_path: Path, settings: dict[str, Any]) -> dict[str, Any]:
    errors = []
    final_ids = {scenario.scenario_id for scenario in FINAL_XSS_V13_SCENARIOS}
    calibration_ids = {scenario.scenario_id for scenario in CALIBRATION_SCENARIOS}
    if READINESS_SCENARIO_ID in final_ids:
        errors.append("readiness scenario overlaps final v1.3 XSS benchmark")
    if READINESS_SCENARIO_ID in calibration_ids:
        errors.append("readiness scenario overlaps calibration bake-off scenarios")
    if len(readiness_candidates()) != MAX_CANDIDATES:
        errors.append("readiness input must contain exactly eight synthetic candidates")
    if len(readiness_rows) != 4:
        errors.append("expected exactly one readiness row for each shortlisted model")
    if not schema_path.exists():
        errors.append("readiness JSON schema file is missing")
    if settings.get("max_output_tokens") != FROZEN_EXECUTION_SETTINGS["max_output_tokens"]:
        errors.append("readiness output limit must remain common and frozen")
    ready_count = sum(1 for row in readiness_rows if row["contract_completed"])
    measured_bakeoff_ready = ready_count == len(readiness_rows) and not errors
    return {
        "schema_version": "local-runtime-readiness-validation-v1.3",
        "valid": not errors,
        "errors": errors,
        "readiness_row_count": len(readiness_rows),
        "ready_model_count": ready_count,
        "measured_bakeoff_ready": measured_bakeoff_ready,
        "global_configuration_revision_required": not measured_bakeoff_ready,
        "proposed_global_revision_if_needed": (
            "If any model remains not_ready, revise only the common configuration, for example by increasing the shared output cap or timeout, then rerun readiness for all four models."
            if not measured_bakeoff_ready
            else NOT_AVAILABLE
        ),
        "live_model_execution_performed": True,
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
        "schema_version": READINESS_VERSION,
        "artifact_status": "non_scored_local_runtime_structured_output_readiness",
        "created_at": datetime.now(UTC).isoformat(),
        "settings_version": settings["configuration_version"],
        "json_schema_version": READINESS_SCHEMA_VERSION,
        "json_schema_sha256": sha256_file(schema_path),
        "model_count": len(MODEL_ARTIFACTS),
        "readiness_request_count": len(readiness_rows),
        "ready_model_count": validation["ready_model_count"],
        "measured_bakeoff_ready": validation["measured_bakeoff_ready"],
        "calibration_bakeoff_executed": False,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
        "previous_32_token_smoke_interpretation": "truncated configuration-validation outputs, not model-quality failures",
        "provisioning_package_reference": str(PROVISIONING_OUTPUT_ROOT),
    }


def write_readiness_package(package: dict[str, Any], output_root: Path = OUTPUT_ROOT) -> None:
    for directory in ("model-metadata", "raw", "normalized", "tables"):
        (output_root / directory).mkdir(parents=True, exist_ok=True)
    _write_json(output_root / "manifest.json", package["manifest"])
    _write_json(output_root / "hardware-report.json", package["hardware"])
    _write_json(output_root / "runtime-metadata.json", package["runtime"])
    _write_json(output_root / "execution-settings.json", package["settings"])
    _write_json(output_root / "validation-report.json", package["validation"])
    for metadata in package["models"]:
        _write_json(output_root / "model-metadata" / f"{metadata['candidate_id']}.json", metadata)
    for artifact in package["raw_artifacts"]:
        _write_json(output_root / "raw" / f"{artifact['model_candidate_id']}.json", artifact)
    _write_json(output_root / "normalized" / "readiness-results.json", package["readiness_rows"])
    _write_csv(output_root / "normalized" / "readiness-results.csv", package["readiness_rows"])
    _write_csv(output_root / "tables" / "readiness-table.csv", package["readiness_rows"])
    (output_root / "readiness-report.md").write_text(render_readiness_report(package), encoding="utf-8")
    (output_root / "thesis-configuration-table.md").write_text(render_configuration_table_md(package), encoding="utf-8")
    (output_root / "thesis-readiness-table.md").write_text(render_readiness_table_md(package), encoding="utf-8")
    (output_root / "thesis-readiness-table.tex").write_text(render_readiness_table_tex(), encoding="utf-8")
    checksum_paths = [path for path in sorted(output_root.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    (output_root / "checksums.sha256").write_text(render_checksums(checksum_paths, base_dir=output_root), encoding="utf-8")


def render_readiness_report(package: dict[str, Any]) -> str:
    lines = [
        "# Local Runtime Structured-Output Readiness v1.3",
        "",
        "Status: non-scored readiness validation. This is not the measured 72-call calibration bake-off, not model selection, and not final v1.3 evaluation.",
        "",
        "The earlier 32-token smoke outputs are treated as truncated configuration-validation outputs, not as model-quality failures.",
        "",
        "## Frozen Common Settings",
        "",
        f"- Runtime: `{package['runtime']['runtime_id']}`",
        f"- Output mechanism: `{package['settings']['constrained_output_mechanism']}`",
        f"- JSON schema version: `{package['settings']['json_schema_version']}`",
        f"- Context size: `{package['settings']['context_size_tokens']}` tokens",
        f"- Maximum output: `{package['settings']['max_output_tokens']}` tokens",
        f"- Timeout: `{package['settings']['timeout_seconds']}` seconds",
        f"- Temperature: `{package['settings']['temperature']}`",
        f"- Top-p: `{package['settings']['top_p']}`",
        f"- Seed: `{package['settings']['seed']}`",
        f"- Maximum rationale length: `{package['settings']['maximum_rationale_chars']}` characters",
        "",
        "## Readiness Results",
        "",
        "| Model | Status | JSON parsed | All IDs once | Not truncated | Latency ms | Validation errors |",
        "| --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for row in package["readiness_rows"]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row["model_candidate_id"],
                row["readiness_status"],
                row["json_parsed"],
                row["all_candidate_ids_once"],
                row["output_not_truncated"],
                row["latency_ms"],
                "; ".join(row["validation_errors"]),
            )
        )
    lines.extend(
        [
            "",
            "## Package Validation",
            "",
            f"- Package structurally valid: `{package['validation']['valid']}`",
            f"- Measured bake-off ready: `{package['validation']['measured_bakeoff_ready']}`",
            f"- Global configuration revision required: `{package['validation']['global_configuration_revision_required']}`",
        ]
    )
    if package["validation"]["errors"]:
        lines.extend(["", "Validation errors:"])
        lines.extend(f"- {error}" for error in package["validation"]["errors"])
    return "\n".join(lines) + "\n"


def render_configuration_table_md(package: dict[str, Any]) -> str:
    settings = package["settings"]
    return "\n".join(
        [
            "# Local Ranking Execution Configuration v1.3",
            "",
            "Table status: readiness configuration, not model selection.",
            "",
            "| Setting | Frozen value |",
            "| --- | --- |",
            f"| Runtime | `{settings['runtime']}` |",
            f"| Output constraint | `{settings['constrained_output_mechanism']}` |",
            f"| JSON schema | `{settings['json_schema_version']}` |",
            f"| Context size | `{settings['context_size_tokens']}` |",
            f"| Max output tokens | `{settings['max_output_tokens']}` |",
            f"| Temperature | `{settings['temperature']}` |",
            f"| Top-p | `{settings['top_p']}` |",
            f"| Seed | `{settings['seed']}` |",
            f"| Timeout seconds | `{settings['timeout_seconds']}` |",
            f"| Max candidates | `{settings['maximum_candidate_count']}` |",
            f"| Max rationale chars | `{settings['maximum_rationale_chars']}` |",
            "",
        ]
    )


def render_readiness_table_md(package: dict[str, Any]) -> str:
    lines = [
        "# Local Model Readiness Table v1.3",
        "",
        "Table status: non-scored readiness validation only.",
        "",
        "| Model | Readiness | Contract completed | Latency ms | Memory before bytes | Memory after bytes |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for row in package["readiness_rows"]:
        lines.append(
            f"| `{row['model_candidate_id']}` | `{row['readiness_status']}` | `{row['contract_completed']}` | `{row['latency_ms']}` | `{row['memory_available_before_bytes']}` | `{row['memory_available_after_bytes']}` |"
        )
    return "\n".join(lines) + "\n"


def render_readiness_table_tex() -> str:
    return r"""% Local model readiness table template.
% Status: non-scored readiness validation only; not model selection.

\begin{table}[htbp]
\centering
\caption{Local open-weights structured-output readiness}
\label{tab:local-model-readiness}
\begin{tabular}{llll}
\hline
Model & Readiness & Contract completed & Latency (ms) \\
\hline
% Insert rows from results/local-runtime-readiness-v1.3/thesis-readiness-table.md
\hline
\end{tabular}
\end{table}
"""


def _candidate(
    route: str,
    parameter_name: str,
    source: str,
    input_type: str,
    editable_input_count: int,
    required_input_count: int,
) -> ReflectedInputCandidate:
    return ReflectedInputCandidate(
        candidate_id=f"local-readiness-{route}-{parameter_name}",
        page_url="http://127.0.0.1:4998/local-readiness/seed",
        action_url=f"http://127.0.0.1:4998/local-readiness/{route}",
        method="GET",
        parameter_name=parameter_name,
        source=source,
        input_type=input_type,
        editable_input_count=editable_input_count,
        required_input_count=required_input_count,
        parameter_count=editable_input_count,
    )


def _generated_token_count(stderr_tail: str) -> Any:
    matches = re.findall(r"eval time\s*=.*?/\s*(\d+)\s+runs", stderr_tail, flags=re.IGNORECASE)
    if not matches:
        return NOT_AVAILABLE
    return int(matches[-1])


def _memory_delta(before: Any, after: Any) -> Any:
    if isinstance(before, int) and isinstance(after, int):
        return after - before
    return NOT_AVAILABLE


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
    parser = argparse.ArgumentParser(description="Run non-scored local model structured-output readiness validation.")
    parser.add_argument("--runtime-exe", type=Path, default=default_runtime_executable())
    parser.add_argument("--model-root", type=Path, default=MODEL_ROOT)
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    package = run_readiness_package(executable=args.runtime_exe, model_root=args.model_root, output_root=args.output_root)
    print(f"Local runtime readiness artifacts written to: {args.output_root}")
    if not package["validation"]["measured_bakeoff_ready"]:
        raise SystemExit("local runtime readiness did not complete for every model; see readiness package")


if __name__ == "__main__":
    main()
