from __future__ import annotations

import argparse
import hashlib
import json
import sys
import threading
import time
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from adstf.config import load_target_config
from adstf.heldout_benchmark_server import make_server
from adstf.heldout_evaluation import validate_heldout_evaluation_harness
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"
DEFAULT_MANIFEST_PATH = REPO_ROOT / "examples" / "benchmarks" / "heldout-manifest-v1.json"


def validate_heldout_manifest(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> dict:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if manifest.get("manifest_id") != "heldout-evaluation-manifest-v1":
        errors.append("unexpected manifest_id")
    if manifest.get("protocol_version") != "evaluation-protocol-v1":
        errors.append("unexpected protocol_version")
    if manifest.get("ground_truth_available_to_framework") is not False:
        errors.append("ground_truth_available_to_framework must be false")

    targets = manifest.get("targets", [])
    evaluation_units = manifest.get("evaluation_units", [])
    target_ids = {target.get("target_id") for target in targets}
    case_ids = [unit.get("case_id") for unit in evaluation_units]
    if len(case_ids) != len(set(case_ids)):
        errors.append("evaluation unit case IDs must be unique")

    target_results = []
    for target in targets:
        result = _validate_target_entry(target, target_ids, case_ids)
        target_results.append(result)
        errors.extend(result["errors"])

    ground_truth_path = REPO_ROOT / str(manifest.get("ground_truth_path", ""))
    return {
        "manifest_path": str(manifest_path),
        "manifest_id": manifest.get("manifest_id"),
        "protocol_version": manifest.get("protocol_version"),
        "target_count": len(targets),
        "evaluation_unit_count": len(evaluation_units),
        "target_results": target_results,
        "ground_truth_path_declared": str(ground_truth_path),
        "ground_truth_file_exists": ground_truth_path.exists(),
        "ground_truth_loaded": False,
        "valid": not errors and ground_truth_path.exists(),
        "errors": errors,
    }


def run_heldout_structural_validation(
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    manifest_path: Path = DEFAULT_MANIFEST_PATH,
) -> Path:
    run_id = f"heldout-structural-validation-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)

    manifest_result = validate_heldout_manifest(manifest_path)
    harness_result = validate_heldout_evaluation_harness(manifest_path)
    target_checks: list[dict] = []
    with HeldoutValidationServers():
        time.sleep(0.2)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for target in manifest["targets"]:
            target_checks.extend(_health_reset_checks(target))

    completed = datetime.now(UTC)
    file_hashes = _hash_protocol_files(manifest_path)
    result = {
        "validation_id": "heldout-structural-validation-v1",
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "git_commit": _git_commit(),
        "manifest_validation": manifest_result,
        "harness_validation": harness_result,
        "target_checks": target_checks,
        "artifact_schema_checks": {
            "manifest_has_targets": manifest_result["target_count"] == 3,
            "manifest_has_evaluation_units": manifest_result["evaluation_unit_count"] == 7,
            "ground_truth_not_loaded": True,
            "health_reset_only": True,
        },
        "file_hashes": file_hashes,
        "valid": (
            manifest_result["valid"]
            and harness_result["valid"]
            and all(check["ok"] for check in target_checks)
        ),
    }
    (artifact_dir / "heldout-structural-validation.json").write_text(
        json.dumps(to_json_value(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(_render_report(result), encoding="utf-8")
    if not result["valid"]:
        raise RuntimeError("held-out structural validation failed")
    return run_dir


def _validate_target_entry(target: dict, target_ids: set[str], case_ids: list[str]) -> dict:
    errors: list[str] = []
    config_path = REPO_ROOT / target.get("config_path", "")
    try:
        config = load_target_config(config_path)
    except Exception as exc:
        return {
            "target_id": target.get("target_id"),
            "config_path": str(config_path),
            "valid": False,
            "errors": [str(exc)],
        }
    parsed = urlparse(config.base_url)
    if parsed.hostname not in target.get("allowed_hosts", []):
        errors.append("config base_url host is outside manifest allowed_hosts")
    if parsed.port not in target.get("allowed_ports", []):
        errors.append("config base_url port is outside manifest allowed_ports")
    for case_id in target.get("case_ids", []):
        if case_id not in case_ids:
            errors.append(f"case_id missing from evaluation_units: {case_id}")
    if target.get("target_id") not in target_ids:
        errors.append("target_id missing from target set")
    if config.metadata.get("held_out_benchmark") is not True:
        errors.append("target config must be marked held_out_benchmark")
    return {
        "target_id": target.get("target_id"),
        "config_path": str(config_path),
        "base_url": config.base_url,
        "enabled_modules": config.enabled_modules,
        "max_actions": config.max_actions,
        "valid": not errors,
        "errors": errors,
    }


def _health_reset_checks(target: dict) -> list[dict]:
    checks = []
    for purpose, path_key in (("health", "health_path"), ("reset", "reset_path")):
        url = target["base_url"] + target[path_key]
        started = datetime.now(UTC)
        try:
            with urlopen(url, timeout=5) as response:
                status_code = response.status
                body_prefix = response.read(120).decode("utf-8", errors="replace")
            ok = status_code == 200
            error = None
        except Exception as exc:
            ok = False
            status_code = None
            body_prefix = ""
            error = str(exc)
        checks.append(
            {
                "target_id": target["target_id"],
                "purpose": purpose,
                "url": url,
                "status_code": status_code,
                "body_prefix": body_prefix,
                "checked_at": started.isoformat(),
                "ok": ok,
                "error": error,
            }
        )
    return checks


class HeldoutValidationServers(AbstractContextManager):
    def __init__(self) -> None:
        self._servers = []
        self._threads: list[threading.Thread] = []

    def __enter__(self) -> "HeldoutValidationServers":
        for target_kind, port in (("xss", 4391), ("idor", 4392), ("sqli", 4393)):
            server = make_server("127.0.0.1", port, target_kind)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._servers.append(server)
            self._threads.append(thread)
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore[no-untyped-def]
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)


def _hash_protocol_files(manifest_path: Path) -> dict:
    paths = [
        manifest_path,
        REPO_ROOT / "examples" / "benchmarks" / "heldout-ground-truth-v1.json",
        REPO_ROOT / "examples" / "targets" / "heldout-xss-local.json",
        REPO_ROOT / "examples" / "targets" / "heldout-idor-local.json",
        REPO_ROOT / "examples" / "targets" / "heldout-sqli-local.json",
        REPO_ROOT / "src" / "adstf" / "verification.py",
        REPO_ROOT / "src" / "adstf" / "discovery.py",
        REPO_ROOT / "src" / "adstf" / "llm_ranking.py",
        REPO_ROOT / "src" / "adstf" / "openai_ranking_wrapper.py",
        REPO_ROOT / "src" / "adstf" / "zap_baseline.py",
        REPO_ROOT / "src" / "adstf" / "mvp_benchmark.py",
        REPO_ROOT / "src" / "adstf" / "heldout_benchmark_server.py",
        REPO_ROOT / "src" / "adstf" / "heldout_evaluation.py",
        REPO_ROOT / "src" / "adstf" / "heldout_validation.py",
    ]
    return {
        str(path.relative_to(REPO_ROOT)): _sha256(path)
        for path in paths
        if path.exists()
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit() -> str | None:
    git_head = REPO_ROOT / ".git" / "HEAD"
    if not git_head.exists():
        return None
    head = git_head.read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref = REPO_ROOT / ".git" / head.removeprefix("ref: ")
        return ref.read_text(encoding="utf-8").strip() if ref.exists() else None
    return head


def _render_report(result: dict) -> str:
    lines = [
        "# Held-Out Structural Validation",
        "",
        f"- Valid: `{result['valid']}`",
        f"- Git commit: `{result['git_commit']}`",
        f"- Ground truth loaded: `{result['manifest_validation']['ground_truth_loaded']}`",
        f"- Harness validation: `{result['harness_validation']['valid']}`",
        f"- Health/reset only: `{result['artifact_schema_checks']['health_reset_only']}`",
        "",
        "## Target Checks",
        "",
    ]
    for check in result["target_checks"]:
        lines.append(
            f"- `{check['target_id']}` {check['purpose']}: status `{check['status_code']}`, ok `{check['ok']}`"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run held-out benchmark structural validation.")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST_PATH)
    args = parser.parse_args()
    try:
        run_dir = run_heldout_structural_validation(args.output_root, args.manifest)
    except Exception as exc:
        print(f"Held-out structural validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Held-out structural validation artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
