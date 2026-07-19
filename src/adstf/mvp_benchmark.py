from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from adstf.config import load_target_config
from adstf.dev_benchmark_idor import (
    DEFAULT_CONFIG_PATH as IDOR_CONFIG_PATH,
    run_development_benchmark_idor,
)
from adstf.dev_benchmark_server import DevelopmentBenchmarkHandler
from adstf.dev_benchmark_sqli import (
    DEFAULT_CONFIG_PATH as SQLI_CONFIG_PATH,
    run_development_benchmark_sqli,
)
from adstf.dev_benchmark_xss import (
    DEFAULT_CONFIG_PATH as XSS_CONFIG_PATH,
    run_development_benchmark_reflected_xss,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


@dataclass(frozen=True)
class BenchmarkSlice:
    name: str
    module_id: str
    category: str
    config_path: Path
    port: int
    evaluation_artifact: str
    runner: Callable[[Path, Path], Path]


SLICES = [
    BenchmarkSlice(
        name="reflected-xss",
        module_id="xss.reflected",
        category="reflected_xss",
        config_path=XSS_CONFIG_PATH,
        port=4291,
        evaluation_artifact="benchmark-evaluation.json",
        runner=lambda config, output: run_development_benchmark_reflected_xss(
            config,
            output,
            ranking_mode="deterministic",
        ),
    ),
    BenchmarkSlice(
        name="read-only-idor",
        module_id="access.idor_read_only",
        category="read_only_idor",
        config_path=IDOR_CONFIG_PATH,
        port=4292,
        evaluation_artifact="idor-benchmark-evaluation.json",
        runner=run_development_benchmark_idor,
    ),
    BenchmarkSlice(
        name="boolean-sqli",
        module_id="sqli.boolean",
        category="boolean_sqli",
        config_path=SQLI_CONFIG_PATH,
        port=4293,
        evaluation_artifact="sqli-benchmark-evaluation.json",
        runner=run_development_benchmark_sqli,
    ),
]


def run_mvp_benchmark(output_root: Path = DEFAULT_OUTPUT_ROOT, start_servers: bool = True) -> Path:
    run_id = f"mvp-benchmark-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC)

    server_context: AbstractContextManager | None = (
        LocalBenchmarkServers(SLICES) if start_servers else None
    )
    slice_results: list[dict] = []
    if server_context is None:
        _run_slices(output_root, slice_results)
    else:
        with server_context:
            _run_slices(output_root, slice_results)

    completed = datetime.now(UTC)
    summary = normalize_mvp_results(
        slice_results,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
        settings={
            "start_local_servers": start_servers,
            "runner_mode": "deterministic_mvp_development",
            "xss_ranking_mode": "deterministic",
            "llm_enabled": False,
            "traditional_scanner_enabled": False,
        },
    )
    (artifact_dir / "mvp-evaluation-summary.json").write_text(
        json.dumps(to_json_value(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(render_mvp_report(summary), encoding="utf-8")
    return run_dir


def _run_slices(output_root: Path, slice_results: list[dict]) -> None:
    for benchmark_slice in SLICES:
        target = load_target_config(benchmark_slice.config_path)
        started = datetime.now(UTC)
        started_perf = time.perf_counter()
        result = {
            "name": benchmark_slice.name,
            "module_id": benchmark_slice.module_id,
            "category": benchmark_slice.category,
            "target_name": target.name,
            "target_base_url": target.base_url,
            "benchmark_id": target.metadata.get("benchmark"),
            "config_path": str(benchmark_slice.config_path.relative_to(REPO_ROOT)),
            "enabled_modules": target.enabled_modules,
            "max_actions": target.max_actions,
            "settings": {
                "port": benchmark_slice.port,
                "evaluation_artifact": benchmark_slice.evaluation_artifact,
            },
            "started_at": started.isoformat(),
            "status": "not_started",
        }
        try:
            child_run_dir = benchmark_slice.runner(benchmark_slice.config_path, output_root)
            completed = datetime.now(UTC)
            evaluation_path = child_run_dir / "artifacts" / benchmark_slice.evaluation_artifact
            evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
            result.update(
                {
                    "status": "completed",
                    "completed_at": completed.isoformat(),
                    "duration_ms": int((time.perf_counter() - started_perf) * 1000),
                    "run_dir": str(child_run_dir),
                    "evaluation_artifact": str(evaluation_path),
                    "evaluation": evaluation,
                }
            )
        except Exception as exc:
            completed = datetime.now(UTC)
            result.update(
                {
                    "status": "failed",
                    "completed_at": completed.isoformat(),
                    "duration_ms": int((time.perf_counter() - started_perf) * 1000),
                    "failure": str(exc),
                }
            )
        slice_results.append(result)


def normalize_mvp_results(
    slice_results: list[dict],
    *,
    started_at: str,
    completed_at: str,
    settings: dict,
) -> dict:
    normalized_slices = [_normalize_slice(result) for result in slice_results]
    cases = [
        case
        for result in normalized_slices
        for case in result.get("cases", [])
    ]
    counts = _classification_counts(cases)
    return {
        "benchmark_suite_id": "mvp-development-suite",
        "summary_version": "mvp-evaluation-summary-v1",
        "started_at": started_at,
        "completed_at": completed_at,
        "settings": settings,
        "ground_truth_used_phase": "post_run_evaluation_only",
        "slice_count": len(normalized_slices),
        "failed_slice_count": sum(1 for result in normalized_slices if result["status"] == "failed"),
        "case_count": len(cases),
        "counts": counts,
        "slices": normalized_slices,
        "cases": cases,
    }


def _normalize_slice(result: dict) -> dict:
    base = {
        "name": result["name"],
        "module_id": result["module_id"],
        "category": result["category"],
        "target_name": result["target_name"],
        "target_base_url": result["target_base_url"],
        "benchmark_id": result["benchmark_id"],
        "config_path": result["config_path"],
        "enabled_modules": result["enabled_modules"],
        "max_actions": result["max_actions"],
        "settings": result["settings"],
        "status": result["status"],
        "started_at": result["started_at"],
        "completed_at": result.get("completed_at"),
        "duration_ms": result.get("duration_ms"),
        "run_dir": result.get("run_dir"),
        "evaluation_artifact": result.get("evaluation_artifact"),
        "failure": result.get("failure"),
    }
    if result["status"] != "completed":
        return {**base, "cases": [], "counts": _classification_counts([])}
    cases = _normalize_cases(result)
    return {**base, "cases": cases, "counts": _classification_counts(cases)}


def _normalize_cases(result: dict) -> list[dict]:
    if result["module_id"] == "xss.reflected":
        return _normalize_xss_cases(result)
    return [
        _case_record(
            result,
            case_id=case["case_id"],
            expected_vulnerable=bool(case["expected_vulnerable"]),
            finding_state=str(case["finding_state"]),
            raw_case=case,
        )
        for case in result["evaluation"].get("case_results", [])
    ]


def _normalize_xss_cases(result: dict) -> list[dict]:
    baseline = result["evaluation"].get("deterministic_baseline") or {}
    cases = []
    for scenario in baseline.get("scenario_results", []):
        expected_vulnerable = scenario["vulnerable_candidate_count"] > 0
        verified = scenario["verified_finding_count"] > 0
        if verified:
            finding_state = "verified"
        elif expected_vulnerable:
            finding_state = "inconclusive"
        else:
            finding_state = "rejected"
        cases.append(
            _case_record(
                result,
                case_id=scenario["scenario_id"],
                expected_vulnerable=expected_vulnerable,
                finding_state=finding_state,
                raw_case=scenario,
            )
        )
    return cases


def _case_record(
    result: dict,
    *,
    case_id: str,
    expected_vulnerable: bool,
    finding_state: str,
    raw_case: dict,
) -> dict:
    verified = finding_state == "verified"
    return {
        "suite_case_id": f"{result['name']}::{case_id}",
        "case_id": case_id,
        "benchmark_slice": result["name"],
        "benchmark_id": result["benchmark_id"],
        "module_id": result["module_id"],
        "category": result["category"],
        "target_name": result["target_name"],
        "expected_vulnerable": expected_vulnerable,
        "finding_state": finding_state,
        "verified": verified,
        "rejected": finding_state == "rejected",
        "inconclusive": finding_state == "inconclusive",
        "classification": _classification(expected_vulnerable, verified),
        "raw_case": raw_case,
    }


def _classification(expected_vulnerable: bool, verified: bool) -> str:
    if expected_vulnerable and verified:
        return "TP"
    if not expected_vulnerable and verified:
        return "FP"
    if expected_vulnerable and not verified:
        return "FN"
    return "TN"


def _classification_counts(cases: list[dict]) -> dict:
    return {
        "verified": sum(1 for case in cases if case["verified"]),
        "rejected": sum(1 for case in cases if case["rejected"]),
        "inconclusive": sum(1 for case in cases if case["inconclusive"]),
        "TP": sum(1 for case in cases if case["classification"] == "TP"),
        "FP": sum(1 for case in cases if case["classification"] == "FP"),
        "FN": sum(1 for case in cases if case["classification"] == "FN"),
        "TN": sum(1 for case in cases if case["classification"] == "TN"),
    }


def render_mvp_report(summary: dict) -> str:
    lines = [
        "# MVP Development Benchmark Report",
        "",
        "## Summary",
        "",
        f"- Slices: `{summary['slice_count']}`",
        f"- Failed slices: `{summary['failed_slice_count']}`",
        f"- Cases: `{summary['case_count']}`",
        f"- Verified: `{summary['counts']['verified']}`",
        f"- Rejected: `{summary['counts']['rejected']}`",
        f"- Inconclusive: `{summary['counts']['inconclusive']}`",
        f"- TP: `{summary['counts']['TP']}`",
        f"- FP: `{summary['counts']['FP']}`",
        f"- FN: `{summary['counts']['FN']}`",
        f"- TN: `{summary['counts']['TN']}`",
        f"- Ground truth phase: `{summary['ground_truth_used_phase']}`",
        "",
        "## Slices",
        "",
    ]
    for result in summary["slices"]:
        lines.extend(
            [
                f"### {result['name']}",
                "",
                f"- Status: `{result['status']}`",
                f"- Module: `{result['module_id']}`",
                f"- Target: `{result['target_name']}`",
                f"- Benchmark: `{result['benchmark_id']}`",
                f"- Duration ms: `{result.get('duration_ms')}`",
                f"- Run dir: `{result.get('run_dir')}`",
                f"- TP/FP/FN/TN: `{result['counts']['TP']}/{result['counts']['FP']}/{result['counts']['FN']}/{result['counts']['TN']}`",
                "",
            ]
        )
    lines.extend(["## Cases", ""])
    for case in summary["cases"]:
        lines.append(
            f"- `{case['suite_case_id']}`: state `{case['finding_state']}`, classification `{case['classification']}`"
        )
    lines.append("")
    return "\n".join(lines)


class LocalBenchmarkServers(AbstractContextManager):
    def __init__(self, slices: list[BenchmarkSlice]) -> None:
        self._slices = slices
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []

    def __enter__(self) -> "LocalBenchmarkServers":
        for benchmark_slice in self._slices:
            server = ThreadingHTTPServer(("127.0.0.1", benchmark_slice.port), DevelopmentBenchmarkHandler)
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the unified MVP development benchmark harness.")
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument(
        "--no-start-servers",
        action="store_true",
        help="Assume benchmark servers are already running on configured ports.",
    )
    args = parser.parse_args()
    try:
        run_dir = run_mvp_benchmark(args.output_root, start_servers=not args.no_start_servers)
    except Exception as exc:
        print(f"MVP benchmark harness failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"MVP benchmark artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
