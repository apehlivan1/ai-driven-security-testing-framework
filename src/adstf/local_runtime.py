from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from adstf.discovery import ReflectedInputCandidate
from adstf.llm_ranking import ModelCompletion, ModelProviderError, ModelTimeoutError, rank_candidates_with_model, ranking_result_artifact
from adstf.metrics import NOT_AVAILABLE
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISIONING_VERSION = "local-runtime-provisioning-v1.3"
OUTPUT_ROOT = REPO_ROOT / "results" / PROVISIONING_VERSION
RUNTIME_ROOT = REPO_ROOT / ".adstf-runtimes" / "llama.cpp-b9637"
MODEL_ROOT = REPO_ROOT / ".adstf-models" / PROVISIONING_VERSION

LLAMA_CPP_RELEASE = {
    "runtime_id": "llama.cpp-b9637-win-cpu-x64-llama-completion",
    "release_tag": "b9637",
    "target_commitish": "aedb2a5e9ca3d4064148bbb919e0ddc0c1b70ab3",
    "official_source": "https://github.com/ggml-org/llama.cpp/releases/tag/b9637",
    "asset_name": "llama-b9637-bin-win-cpu-x64.zip",
    "asset_url": "https://github.com/ggml-org/llama.cpp/releases/download/b9637/llama-b9637-bin-win-cpu-x64.zip",
    "published_at": "2026-06-14T18:50:23Z",
    "release_asset_sha256": "f7783c2b8c007f95e710ac40f26a24861a80b603b0b739fc54d7c926a4716c1e",
    "release_asset_size_bytes": 16906751,
    "backend": "cpu",
}

RUNTIME_SETTINGS = {
    "context_size_tokens": 4096,
    "max_output_tokens": 32,
    "timeout_seconds": 120,
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 42,
    "threads": min(os.cpu_count() or 1, 8),
    "prompt_template": "llm-candidate-ranking-v1 prompt passed to llama.cpp as a plain completion prompt",
}


@dataclass(frozen=True)
class LocalModelArtifact:
    candidate_id: str
    family: str
    display_name: str
    repository: str
    revision: str
    filenames: tuple[str, ...]
    primary_model_filename: str
    quantization: str
    license: str
    source: str
    chat_template: str
    required_runtime_arguments: tuple[str, ...]


MODEL_ARTIFACTS: tuple[LocalModelArtifact, ...] = (
    LocalModelArtifact(
        candidate_id="qwen2_5_7b_instruct_gguf_q4_k_m",
        family="Qwen",
        display_name="Qwen2.5 7B Instruct GGUF Q4_K_M",
        repository="Qwen/Qwen2.5-7B-Instruct-GGUF",
        revision="bb5d59e06d9551d752d08b292a50eb208b07ab1f",
        filenames=(
            "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
            "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf",
        ),
        primary_model_filename="qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
        quantization="Q4_K_M",
        license="apache-2.0",
        source="https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF",
        chat_template="repository GGUF chat template recorded by Hugging Face metadata",
        required_runtime_arguments=("-m", "<first split GGUF file; companion shard in same directory>"),
    ),
    LocalModelArtifact(
        candidate_id="phi3_5_mini_instruct_gguf_q4_k_m",
        family="Phi",
        display_name="Phi-3.5 Mini Instruct GGUF Q4_K_M",
        repository="bartowski/Phi-3.5-mini-instruct-GGUF",
        revision="6d70da17e749a471ccb62ade694486011a75cda3",
        filenames=("Phi-3.5-mini-instruct-Q4_K_M.gguf",),
        primary_model_filename="Phi-3.5-mini-instruct-Q4_K_M.gguf",
        quantization="Q4_K_M",
        license="mit",
        source="https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF",
        chat_template="repository GGUF chat template recorded by Hugging Face metadata",
        required_runtime_arguments=("-m", "<GGUF file>"),
    ),
    LocalModelArtifact(
        candidate_id="mistral_7b_instruct_v0_3_gguf_q4_k_m",
        family="Mistral",
        display_name="Mistral 7B Instruct v0.3 GGUF Q4_K_M",
        repository="bartowski/Mistral-7B-Instruct-v0.3-GGUF",
        revision="61fd4167fff3ab01ee1cfe0da183fa27a944db48",
        filenames=("Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",),
        primary_model_filename="Mistral-7B-Instruct-v0.3-Q4_K_M.gguf",
        quantization="Q4_K_M",
        license="apache-2.0",
        source="https://huggingface.co/bartowski/Mistral-7B-Instruct-v0.3-GGUF",
        chat_template="repository GGUF chat template recorded by Hugging Face metadata",
        required_runtime_arguments=("-m", "<GGUF file>"),
    ),
    LocalModelArtifact(
        candidate_id="gemma3_4b_it_gguf_q4_k_m",
        family="Gemma",
        display_name="Gemma 3 4B IT GGUF Q4_K_M",
        repository="ggml-org/gemma-3-4b-it-GGUF",
        revision="d0976223747697cb51e056d85c532013931fe52e",
        filenames=("gemma-3-4b-it-Q4_K_M.gguf",),
        primary_model_filename="gemma-3-4b-it-Q4_K_M.gguf",
        quantization="Q4_K_M",
        license="gemma",
        source="https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF",
        chat_template="repository GGUF chat template recorded by Hugging Face metadata",
        required_runtime_arguments=("-m", "<GGUF file>"),
    ),
)

SMOKE_MODEL_ORDER = (
    "phi3_5_mini_instruct_gguf_q4_k_m",
    "gemma3_4b_it_gguf_q4_k_m",
    "mistral_7b_instruct_v0_3_gguf_q4_k_m",
    "qwen2_5_7b_instruct_gguf_q4_k_m",
)

LLAMA_COMPLETION_EOS_MARKER = " [end of text]"


@dataclass(frozen=True)
class LlamaCompletionTransport:
    raw_stdout: str
    raw_stderr: str
    normalized_content: str
    runtime_marker: str | None
    marker_separated: bool
    parser_rule_version: str
    stdout_byte_length: int
    stderr_byte_length: int
    stdout_sha256: str
    stderr_sha256: str
    stop_reason: str
    generated_token_count: int | str
    token_limit_reached: bool | str
    timing: dict[str, Any]


@dataclass(frozen=True)
class LlamaCppCliClient:
    executable: Path
    model_path: Path
    model_identifier: str
    timeout_seconds: int = RUNTIME_SETTINGS["timeout_seconds"]
    context_size_tokens: int = RUNTIME_SETTINGS["context_size_tokens"]
    max_output_tokens: int = RUNTIME_SETTINGS["max_output_tokens"]
    temperature: float = RUNTIME_SETTINGS["temperature"]
    top_p: float = RUNTIME_SETTINGS["top_p"]
    seed: int = RUNTIME_SETTINGS["seed"]
    threads: int = RUNTIME_SETTINGS["threads"]
    json_schema_path: Path | None = None
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        del candidate_input
        runtime_settings = {
            **RUNTIME_SETTINGS,
            **settings,
            "context_size_tokens": int(settings.get("context_size_tokens", self.context_size_tokens)),
            "max_output_tokens": int(settings.get("max_output_tokens", self.max_output_tokens)),
            "timeout_seconds": int(settings.get("timeout_seconds", self.timeout_seconds)),
            "temperature": float(settings.get("temperature", self.temperature)),
            "top_p": float(settings.get("top_p", self.top_p)),
            "seed": int(settings.get("seed", self.seed)),
            "threads": int(settings.get("threads", self.threads)),
            "json_schema_path": settings.get("json_schema_path", str(self.json_schema_path) if self.json_schema_path else None),
        }
        started = time.perf_counter()
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".prompt.txt", delete=False) as handle:
            prompt_path = Path(handle.name)
            handle.write(prompt)
        try:
            command = llama_cli_command(
                self.executable,
                self.model_path,
                prompt_path,
                context_size_tokens=runtime_settings["context_size_tokens"],
                max_output_tokens=runtime_settings["max_output_tokens"],
                temperature=runtime_settings["temperature"],
                top_p=runtime_settings["top_p"],
                seed=runtime_settings["seed"],
                threads=runtime_settings["threads"],
                json_schema_path=Path(runtime_settings["json_schema_path"])
                if runtime_settings.get("json_schema_path")
                else None,
            )
            try:
                runner = self.runner or run_subprocess_with_timeout
                completed = runner(
                    command,
                    timeout=runtime_settings["timeout_seconds"],
                )
            except subprocess.TimeoutExpired as exc:
                raise ModelTimeoutError(
                    f"local llama.cpp command timed out after {runtime_settings['timeout_seconds']} seconds"
                ) from exc
        finally:
            prompt_path.unlink(missing_ok=True)

        latency_ms = int((time.perf_counter() - started) * 1000)
        if completed.returncode != 0:
            raise ModelProviderError(_safe_stderr(completed.stderr) or f"llama.cpp exited with {completed.returncode}")
        transport = parse_llama_completion_transport(
            stdout=completed.stdout,
            stderr=completed.stderr,
            max_output_tokens=runtime_settings["max_output_tokens"],
        )
        return ModelCompletion(
            model_identifier=self.model_identifier,
            raw_response=transport.normalized_content,
            usage={"input_tokens": NOT_AVAILABLE, "output_tokens": NOT_AVAILABLE, "total_tokens": NOT_AVAILABLE},
            cost={"availability": NOT_AVAILABLE},
            provider="local-llama.cpp",
            latency_ms=latency_ms,
            metadata={
                "runtime": "llama.cpp",
                "runtime_backend": LLAMA_CPP_RELEASE["backend"],
                "runtime_settings": runtime_settings,
                "exact_command": command,
                "returncode": completed.returncode,
                "transport": to_json_value(transport),
                "stderr_tail": _safe_stderr(completed.stderr),
            },
        )


def llama_cli_command(
    executable: Path,
    model_path: Path,
    prompt_path: Path,
    *,
    context_size_tokens: int,
    max_output_tokens: int,
    temperature: float,
    top_p: float,
    seed: int,
    threads: int,
    json_schema_path: Path | None = None,
) -> list[str]:
    command = [
        str(executable),
        "-m",
        str(model_path),
        "-f",
        str(prompt_path),
        "-c",
        str(context_size_tokens),
        "-n",
        str(max_output_tokens),
        "--temp",
        str(temperature),
        "--top-p",
        str(top_p),
        "--seed",
        str(seed),
        "-t",
        str(threads),
        "--no-display-prompt",
        "--single-turn",
    ]
    if json_schema_path is not None:
        command.extend(["--json-schema-file", str(json_schema_path)])
    return command


def run_subprocess_with_timeout(
    command: list[str],
    *,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding="utf-8",
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=10)
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr)
    return subprocess.CompletedProcess(command, process.returncode, stdout=stdout, stderr=stderr)


def parse_llama_completion_transport(
    *,
    stdout: str,
    stderr: str,
    max_output_tokens: int,
) -> LlamaCompletionTransport:
    stripped = stdout.strip()
    marker = None
    marker_separated = False
    normalized = stripped
    if stripped.endswith(LLAMA_COMPLETION_EOS_MARKER):
        prefix = stripped[: -len(LLAMA_COMPLETION_EOS_MARKER)].rstrip()
        if _is_json_object(prefix):
            marker = LLAMA_COMPLETION_EOS_MARKER.strip()
            marker_separated = True
            normalized = prefix

    generated = _generated_token_count(stderr)
    token_limit_reached: bool | str = NOT_AVAILABLE
    if isinstance(generated, int):
        token_limit_reached = generated >= max_output_tokens - 1

    return LlamaCompletionTransport(
        raw_stdout=stdout,
        raw_stderr=stderr,
        normalized_content=normalized,
        runtime_marker=marker,
        marker_separated=marker_separated,
        parser_rule_version="llama-completion-transport-parser-v1.3",
        stdout_byte_length=len(stdout.encode("utf-8")),
        stderr_byte_length=len(stderr.encode("utf-8")),
        stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
        stderr_sha256=hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
        stop_reason="eos_runtime_marker" if marker_separated else "not_available",
        generated_token_count=generated,
        token_limit_reached=token_limit_reached,
        timing=_timing_metadata(stderr),
    )


def _is_json_object(text: str) -> bool:
    try:
        return isinstance(json.loads(text), dict)
    except json.JSONDecodeError:
        return False


def _generated_token_count(stderr: str) -> Any:
    import re

    matches = re.findall(r"eval time\s*=.*?/\s*(\d+)\s+runs", stderr, flags=re.IGNORECASE)
    if not matches:
        return NOT_AVAILABLE
    return int(matches[-1])


def _timing_metadata(stderr: str) -> dict[str, Any]:
    import re

    patterns = {
        "load_time_ms": r"load time\s*=\s*([0-9.]+)\s*ms",
        "prompt_eval_time_ms": r"prompt eval time\s*=\s*([0-9.]+)\s*ms",
        "eval_time_ms": r"eval time\s*=\s*([0-9.]+)\s*ms",
        "total_time_ms": r"total time\s*=\s*([0-9.]+)\s*ms",
    }
    result: dict[str, Any] = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, stderr, flags=re.IGNORECASE)
        result[key] = float(matches[-1]) if matches else NOT_AVAILABLE
    return result


def smoke_candidates() -> list[ReflectedInputCandidate]:
    return [
        ReflectedInputCandidate(
            candidate_id="local-smoke-alpha-term",
            page_url="http://127.0.0.1:4999/local-smoke/seed",
            action_url="http://127.0.0.1:4999/local-smoke/alpha",
            method="GET",
            parameter_name="term",
            source="get_form",
            input_type="text",
            editable_input_count=1,
            required_input_count=0,
            parameter_count=1,
        ),
        ReflectedInputCandidate(
            candidate_id="local-smoke-bravo-ref",
            page_url="http://127.0.0.1:4999/local-smoke/seed",
            action_url="http://127.0.0.1:4999/local-smoke/bravo",
            method="GET",
            parameter_name="ref",
            source="query_parameter",
            input_type="query_parameter",
            editable_input_count=1,
            required_input_count=0,
            parameter_count=1,
        ),
        ReflectedInputCandidate(
            candidate_id="local-smoke-cedar-note",
            page_url="http://127.0.0.1:4999/local-smoke/seed",
            action_url="http://127.0.0.1:4999/local-smoke/cedar",
            method="GET",
            parameter_name="note",
            source="get_form",
            input_type="textarea",
            editable_input_count=2,
            required_input_count=1,
            parameter_count=2,
        ),
    ]


def run_smoke_package(
    *,
    executable: Path,
    model_root: Path = MODEL_ROOT,
    output_root: Path = OUTPUT_ROOT,
) -> dict[str, Any]:
    output_root.mkdir(parents=True, exist_ok=True)
    hardware = hardware_report()
    runtime = runtime_metadata(executable)
    smoke_rows = []
    raw_artifacts = []
    model_metadata_rows = []
    for model in _smoke_ordered_models():
        metadata = model_metadata(model, model_root=model_root)
        model_metadata_rows.append(metadata)
        result = smoke_one_model(model, executable=executable, model_root=model_root)
        smoke_rows.append(result["row"])
        raw_artifacts.append(result["artifact"])
    validation = validate_smoke_package(smoke_rows, model_metadata_rows, runtime)
    package = {
        "manifest": package_manifest(runtime, model_metadata_rows, smoke_rows, validation),
        "hardware": hardware,
        "runtime": runtime,
        "models": model_metadata_rows,
        "smoke_rows": smoke_rows,
        "raw_artifacts": raw_artifacts,
        "validation": validation,
    }
    write_smoke_package(package, output_root)
    return package


def _smoke_ordered_models() -> list[LocalModelArtifact]:
    by_id = {model.candidate_id: model for model in MODEL_ARTIFACTS}
    return [by_id[candidate_id] for candidate_id in SMOKE_MODEL_ORDER]


def smoke_one_model(model: LocalModelArtifact, *, executable: Path, model_root: Path) -> dict[str, Any]:
    model_path = model_root / model.candidate_id / model.primary_model_filename
    client = LlamaCppCliClient(executable=executable, model_path=model_path, model_identifier=model.display_name)
    result = rank_candidates_with_model(
        candidates=smoke_candidates(),
        scenario_id="local-runtime-smoke-non-scored",
        trial_number=1,
        model_client=client,
        settings={**RUNTIME_SETTINGS, "model_candidate_id": model.candidate_id, "smoke_only": True},
    )
    artifact = {
        **ranking_result_artifact(result),
        "model_candidate_id": model.candidate_id,
        "artifact_status": "non_scored_local_runtime_smoke",
        "final_24_scenario_xss_v13_used": False,
        "calibration_bakeoff_scenario_used": False,
        "vulnerability_testing_performed": False,
    }
    return {
        "artifact": artifact,
        "row": {
            "model_candidate_id": model.candidate_id,
            "display_name": model.display_name,
            "repository": model.repository,
            "revision": model.revision,
            "primary_model_filename": model.primary_model_filename,
            "smoke_status": "valid" if result.is_valid else "invalid_or_failed",
            "model_loaded_or_call_completed": not result.provider_failed,
            "parser_executed": True,
            "valid_schema_output": result.is_valid,
            "provider_failed": result.provider_failed,
            "validation_errors": result.validation_errors,
            "raw_response_retained": result.raw_response is not None,
            "existing_candidate_ids_only": not any("unknown candidate_id" in error for error in result.validation_errors),
            "latency_ms": result.latency_ms if result.latency_ms is not None else NOT_AVAILABLE,
            "memory_observation": "peak_memory_not_measured_by_cli_adapter",
            "scored": False,
        },
    }


def model_metadata(model: LocalModelArtifact, *, model_root: Path = MODEL_ROOT) -> dict[str, Any]:
    model_dir = model_root / model.candidate_id
    files = []
    total_size = 0
    for filename in model.filenames:
        path = model_dir / filename
        size = path.stat().st_size if path.exists() else NOT_AVAILABLE
        if isinstance(size, int):
            total_size += size
        files.append(
            {
                "filename": filename,
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": size,
                "sha256": sha256_file(path) if path.exists() else NOT_AVAILABLE,
            }
        )
    return {
        "schema_version": "local-model-artifact-metadata-v1.3",
        "candidate_id": model.candidate_id,
        "family": model.family,
        "display_name": model.display_name,
        "repository": model.repository,
        "revision": model.revision,
        "source": model.source,
        "license": model.license,
        "quantization": model.quantization,
        "chat_template": model.chat_template,
        "required_runtime_arguments": list(model.required_runtime_arguments),
        "primary_model_filename": model.primary_model_filename,
        "file_count": len(model.filenames),
        "files": files,
        "all_files_present": all(item["exists"] for item in files),
        "total_size_bytes": total_size if total_size else NOT_AVAILABLE,
    }


def runtime_metadata(executable: Path) -> dict[str, Any]:
    version_output = NOT_AVAILABLE
    if executable.exists():
        try:
            completed = subprocess.run(
                [str(executable), "--version"],
                capture_output=True,
                check=False,
                encoding="utf-8",
                timeout=15,
            )
            version_output = (completed.stdout or completed.stderr).strip() or NOT_AVAILABLE
        except (OSError, subprocess.SubprocessError):
            version_output = NOT_AVAILABLE
    return {
        "schema_version": "local-runtime-metadata-v1.3",
        **LLAMA_CPP_RELEASE,
        "executable_path": str(executable),
        "executable_exists": executable.exists(),
        "executable_sha256": sha256_file(executable) if executable.exists() else NOT_AVAILABLE,
        "version_output": version_output,
        "command_line_configuration": llama_cli_command(
            Path("<llama-completion>"),
            Path("<model.gguf>"),
            Path("<prompt-file>"),
            context_size_tokens=RUNTIME_SETTINGS["context_size_tokens"],
            max_output_tokens=RUNTIME_SETTINGS["max_output_tokens"],
            temperature=RUNTIME_SETTINGS["temperature"],
            top_p=RUNTIME_SETTINGS["top_p"],
            seed=RUNTIME_SETTINGS["seed"],
            threads=RUNTIME_SETTINGS["threads"],
        ),
        "cpu_gpu_backend_actually_used": LLAMA_CPP_RELEASE["backend"],
        "settings": RUNTIME_SETTINGS,
    }


def hardware_report() -> dict[str, Any]:
    return {
        "schema_version": "local-runtime-hardware-report-v1.3",
        "captured_at": datetime.now(UTC).isoformat(),
        "operating_system": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "logical_processors": os.cpu_count() or NOT_AVAILABLE,
        "total_ram_bytes": _memory_bytes("TotalVisibleMemorySize"),
        "available_ram_bytes": _memory_bytes("FreePhysicalMemory"),
        "gpu": _powershell_lines("Get-CimInstance Win32_VideoController | Select-Object -ExpandProperty Name"),
        "cuda_detected": bool(_where("nvidia-smi") or _where("nvcc")),
        "llama_cpp_runtime": _where("llama-cli") or _where("llama-server") or NOT_AVAILABLE,
        "ollama_runtime": _where("ollama") or NOT_AVAILABLE,
        "lm_studio_runtime": _where("lmstudio") or NOT_AVAILABLE,
        "disk_free_bytes_repo_drive": _disk_free_bytes(REPO_ROOT),
    }


def validate_smoke_package(
    smoke_rows: list[dict[str, Any]],
    model_metadata_rows: list[dict[str, Any]],
    runtime: dict[str, Any],
) -> dict[str, Any]:
    errors = []
    if len(smoke_rows) != 4:
        errors.append("expected exactly one smoke row for each of the four shortlisted models")
    if len(model_metadata_rows) != 4:
        errors.append("expected metadata for four shortlisted models")
    if not runtime.get("executable_exists"):
        errors.append("llama.cpp executable is missing")
    for metadata in model_metadata_rows:
        if not metadata["all_files_present"]:
            errors.append(f"model files missing for {metadata['candidate_id']}")
    for row in smoke_rows:
        if row["scored"]:
            errors.append(f"smoke row must be non-scored for {row['model_candidate_id']}")
    return {
        "schema_version": "local-runtime-smoke-validation-v1.3",
        "valid": not errors,
        "errors": errors,
        "smoke_row_count": len(smoke_rows),
        "model_metadata_count": len(model_metadata_rows),
        "live_model_execution_performed": True,
        "calibration_bakeoff_executed": False,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "final_model_selection_made": False,
    }


def package_manifest(
    runtime: dict[str, Any],
    model_metadata_rows: list[dict[str, Any]],
    smoke_rows: list[dict[str, Any]],
    validation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": PROVISIONING_VERSION,
        "artifact_status": "non_scored_local_runtime_provisioning_and_smoke",
        "created_at": datetime.now(UTC).isoformat(),
        "runtime_id": runtime["runtime_id"],
        "runtime_release_tag": runtime["release_tag"],
        "runtime_backend": runtime["backend"],
        "model_count": len(model_metadata_rows),
        "smoke_request_count": len(smoke_rows),
        "measured_calibration_bakeoff_executed": False,
        "final_model_selection_made": False,
        "final_24_scenario_xss_v13_used": False,
        "vulnerability_testing_performed": False,
        "validation_valid": validation["valid"],
    }


def write_smoke_package(package: dict[str, Any], output_root: Path = OUTPUT_ROOT) -> None:
    for directory in ("model-metadata", "raw-smoke-outputs", "normalized"):
        (output_root / directory).mkdir(parents=True, exist_ok=True)
    _write_json(output_root / "manifest.json", package["manifest"])
    _write_json(output_root / "hardware-report.json", package["hardware"])
    _write_json(output_root / "runtime-metadata.json", package["runtime"])
    for metadata in package["models"]:
        _write_json(output_root / "model-metadata" / f"{metadata['candidate_id']}.json", metadata)
    for artifact in package["raw_artifacts"]:
        _write_json(output_root / "raw-smoke-outputs" / f"{artifact['model_candidate_id']}.json", artifact)
    _write_json(output_root / "normalized" / "smoke-results.json", package["smoke_rows"])
    _write_csv(output_root / "normalized" / "smoke-results.csv", package["smoke_rows"])
    _write_csv(output_root / "download-and-licence-ledger.csv", download_ledger(package["models"], package["runtime"]))
    _write_json(output_root / "validation-report.json", package["validation"])
    (output_root / "smoke-report.md").write_text(render_smoke_report(package), encoding="utf-8")
    (output_root / "thesis-model-artifact-table.md").write_text(render_model_table_md(package["models"]), encoding="utf-8")
    (output_root / "thesis-model-artifact-table.tex").write_text(render_model_table_tex(), encoding="utf-8")
    (output_root / "reproducibility-resource-limitations.md").write_text(render_limitations(), encoding="utf-8")
    checksum_paths = [path for path in sorted(output_root.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    (output_root / "checksums.sha256").write_text(render_checksums(checksum_paths, output_root), encoding="utf-8")


def download_ledger(models: list[dict[str, Any]], runtime: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {
            "artifact_type": "runtime",
            "identifier": runtime["runtime_id"],
            "source": runtime["asset_url"],
            "revision_or_version": runtime["release_tag"],
            "license": "MIT",
            "sha256": runtime["executable_sha256"],
            "size_bytes": runtime["release_asset_size_bytes"],
        }
    ]
    for model in models:
        for item in model["files"]:
            rows.append(
                {
                    "artifact_type": "model",
                    "identifier": model["candidate_id"],
                    "source": f"https://huggingface.co/{model['repository']}/resolve/{model['revision']}/{item['filename']}",
                    "revision_or_version": model["revision"],
                    "license": model["license"],
                    "sha256": item["sha256"],
                    "size_bytes": item["size_bytes"],
                }
            )
    return rows


def render_smoke_report(package: dict[str, Any]) -> str:
    lines = [
        "# Local Runtime Provisioning Smoke Report v1.3",
        "",
        "Status: non-scored local runtime smoke validation. This is not the measured 72-call bake-off and not final v1.3 evaluation.",
        "",
        f"- Runtime: `{package['runtime']['runtime_id']}`",
        f"- Backend: `{package['runtime']['backend']}`",
        f"- Validation valid: `{package['validation']['valid']}`",
        f"- Smoke requests: `{len(package['smoke_rows'])}`",
        f"- Final 24-scenario XSS v1.3 benchmark used: `false`",
        f"- Vulnerability tests executed: `false`",
        f"- Final local model selected: `false`",
        "",
        "## Smoke Outcomes",
        "",
        "| Model | Status | Valid JSON contract | Provider failed | Latency ms | Validation errors |",
        "| --- | --- | --- | --- | ---: | --- |",
    ]
    for row in package["smoke_rows"]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                row["model_candidate_id"],
                row["smoke_status"],
                row["valid_schema_output"],
                row["provider_failed"],
                row["latency_ms"],
                "; ".join(row["validation_errors"]),
            )
        )
    if package["validation"]["errors"]:
        lines.extend(["", "## Validation Errors", ""])
        lines.extend(f"- {error}" for error in package["validation"]["errors"])
    return "\n".join(lines) + "\n"


def render_model_table_md(models: list[dict[str, Any]]) -> str:
    lines = [
        "# Local Model Artifact Table v1.3",
        "",
        "Table status: provisioning metadata only; not a model-selection result.",
        "",
        "| Candidate | Repository | Revision | File(s) | Size bytes | SHA-256 | License |",
        "| --- | --- | --- | --- | ---: | --- | --- |",
    ]
    for model in models:
        file_names = "<br>".join(item["filename"] for item in model["files"])
        sizes = "<br>".join(str(item["size_bytes"]) for item in model["files"])
        hashes = "<br>".join(str(item["sha256"]) for item in model["files"])
        lines.append(
            f"| `{model['candidate_id']}` | `{model['repository']}` | `{model['revision']}` | {file_names} | {sizes} | {hashes} | `{model['license']}` |"
        )
    return "\n".join(lines) + "\n"


def render_model_table_tex() -> str:
    return r"""% Local model artifact table template.
% Status: provisioning metadata only; not a model-selection result.

\begin{table}[htbp]
\centering
\caption{Local open-weights model artifacts provisioned for the v1.3 bake-off}
\label{tab:local-model-artifacts}
\begin{tabular}{llll}
\hline
Candidate & Repository & Quantization & License \\
\hline
% Insert rows from results/local-runtime-provisioning-v1.3/thesis-model-artifact-table.md
\hline
\end{tabular}
\end{table}
"""


def render_limitations() -> str:
    return """# Reproducibility and Resource Limitations

- The provisioning smoke uses the Windows CPU build of llama.cpp and therefore measures CPU-first feasibility.
- The smoke request is intentionally non-scored and does not select a primary or fallback model.
- The smoke uses a 32-token output cap to test local load, raw output capture and parser execution on CPU; malformed JSON is expected unless the model completes the strict JSON object inside that cap.
- Token counts are `not_available` because the llama.cpp CLI adapter does not expose token usage in a normalized provider envelope.
- Cost is `not_available` for local models because no external provider billing applies.
- Peak process memory is not yet measured by the minimal CLI adapter; the measured bake-off should record operating-system memory snapshots before and after each call.
- A malformed smoke response is a recorded interoperability fact, not grounds for removing a shortlisted model unless the model cannot load or execute.
"""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_checksums(paths: list[Path], base_dir: Path) -> str:
    lines = []
    for path in paths:
        lines.append(f"{sha256_file(path)}  {path.relative_to(base_dir).as_posix()}\n")
    return "".join(lines)


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
    if isinstance(value, list | dict):
        return json.dumps(to_json_value(value), sort_keys=True)
    return value


def _safe_stderr(stderr: str | None) -> str:
    if not stderr:
        return ""
    tail = stderr[-2000:]
    return tail.replace(str(REPO_ROOT), "<repo>")


def _memory_bytes(property_name: str) -> Any:
    value = _powershell_lines(f"(Get-CimInstance Win32_OperatingSystem).{property_name}")
    if not value:
        return NOT_AVAILABLE
    try:
        return int(value[0]) * 1024
    except ValueError:
        return NOT_AVAILABLE


def _powershell_lines(command: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _where(command: str) -> list[str]:
    try:
        completed = subprocess.run(
            ["where.exe", command],
            capture_output=True,
            check=False,
            encoding="utf-8",
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _disk_free_bytes(path: Path) -> Any:
    try:
        return os.statvfs(path).f_bavail * os.statvfs(path).f_frsize
    except (AttributeError, OSError):
        try:
            import shutil

            return shutil.disk_usage(path).free
        except OSError:
            return NOT_AVAILABLE
