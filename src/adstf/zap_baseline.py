from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import threading
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen
from urllib.parse import parse_qs, urlparse

from adstf.dev_benchmark_server import DevelopmentBenchmarkHandler
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"
DEFAULT_ZAP_IMAGE = "zaproxy/zap-stable:2.16.1"
ZAP_PASSIVE_SUMMARY_VERSION = "zap-passive-summary-v1"
ZAP_PASSIVE_MAPPING_VERSION = "zap-passive-mapping-v1"
ZAP_ACTIVE_SUMMARY_VERSION = "zap-active-summary-v1"
ZAP_ACTIVE_MAPPING_VERSION = "zap-active-mapping-v1"
ZAP_ACTIVE_POLICY_VERSION = "zap-active-policy-v1"

ACTIVE_SCAN_RULES = [
    {
        "id": 40012,
        "name": "Cross Site Scripting (Reflected)",
        "threshold": "Medium",
        "strength": "Low",
    },
    {
        "id": 40018,
        "name": "SQL Injection",
        "threshold": "Medium",
        "strength": "Low",
    },
]


@dataclass(frozen=True)
class ZapMappingRule:
    suite_case_id: str
    case_id: str
    benchmark_slice: str
    benchmark_id: str
    module_id: str
    category: str
    target_name: str
    expected_vulnerable: bool
    path: str
    parameter: str
    alert_terms: tuple[str, ...]


EVALUATED_MAPPING_RULES = [
    ZapMappingRule(
        suite_case_id="reflected-xss::case-a",
        case_id="case-a",
        benchmark_slice="reflected-xss",
        benchmark_id="reflected-input-development",
        module_id="xss.reflected",
        category="reflected_xss",
        target_name="Reflected Input Development Benchmark",
        expected_vulnerable=True,
        path="/alpha",
        parameter="term",
        alert_terms=("cross site scripting", "xss"),
    ),
    ZapMappingRule(
        suite_case_id="reflected-xss::case-b",
        case_id="case-b",
        benchmark_slice="reflected-xss",
        benchmark_id="reflected-input-development",
        module_id="xss.reflected",
        category="reflected_xss",
        target_name="Reflected Input Development Benchmark",
        expected_vulnerable=True,
        path="/s/case-b/lambda",
        parameter="entry",
        alert_terms=("cross site scripting", "xss"),
    ),
    ZapMappingRule(
        suite_case_id="reflected-xss::case-c",
        case_id="case-c",
        benchmark_slice="reflected-xss",
        benchmark_id="reflected-input-development",
        module_id="xss.reflected",
        category="reflected_xss",
        target_name="Reflected Input Development Benchmark",
        expected_vulnerable=False,
        path="/s/case-c",
        parameter="",
        alert_terms=("cross site scripting", "xss"),
    ),
    ZapMappingRule(
        suite_case_id="reflected-xss::case-d",
        case_id="case-d",
        benchmark_slice="reflected-xss",
        benchmark_id="reflected-input-development",
        module_id="xss.reflected",
        category="reflected_xss",
        target_name="Reflected Input Development Benchmark",
        expected_vulnerable=True,
        path="/s/case-d/purple",
        parameter="slot",
        alert_terms=("cross site scripting", "xss"),
    ),
    ZapMappingRule(
        suite_case_id="boolean-sqli::view-boolean",
        case_id="view-boolean",
        benchmark_slice="boolean-sqli",
        benchmark_id="boolean-sqli-development",
        module_id="sqli.boolean",
        category="boolean_sqli",
        target_name="Boolean SQLi Development Benchmark",
        expected_vulnerable=True,
        path="/sqli/view",
        parameter="item",
        alert_terms=("sql injection",),
    ),
    ZapMappingRule(
        suite_case_id="boolean-sqli::safe-boolean",
        case_id="safe-boolean",
        benchmark_slice="boolean-sqli",
        benchmark_id="boolean-sqli-development",
        module_id="sqli.boolean",
        category="boolean_sqli",
        target_name="Boolean SQLi Development Benchmark",
        expected_vulnerable=False,
        path="/sqli/safe",
        parameter="item",
        alert_terms=("sql injection",),
    ),
]

UNSUPPORTED_IDOR_CASES = [
    {
        "suite_case_id": "read-only-idor::open-cross-user",
        "case_id": "open-cross-user",
        "benchmark_slice": "read-only-idor",
        "benchmark_id": "read-only-idor-development",
        "module_id": "access.idor_read_only",
        "category": "read_only_idor",
        "evaluation_status": "unsupported",
        "reason": "ZAP passive spider alerts do not establish two-user read-only authorization behavior.",
    },
    {
        "suite_case_id": "read-only-idor::guarded-cross-user",
        "case_id": "guarded-cross-user",
        "benchmark_slice": "read-only-idor",
        "benchmark_id": "read-only-idor-development",
        "module_id": "access.idor_read_only",
        "category": "read_only_idor",
        "evaluation_status": "unsupported",
        "reason": "ZAP passive spider alerts do not establish two-user read-only authorization behavior.",
    },
]


def load_zap_report(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def extract_zap_alerts(report: dict, *, source: str = "zap_passive") -> list[dict]:
    alerts: list[dict] = []
    for alert in _iter_report_alerts(report):
        instances = alert.get("instances") or []
        if not instances:
            instances = [
                {
                    "uri": alert.get("url") or alert.get("uri") or "",
                    "param": alert.get("param") or "",
                    "method": alert.get("method") or "",
                    "evidence": alert.get("evidence") or "",
                    "attack": alert.get("attack") or "",
                }
            ]
        for index, instance in enumerate(instances):
            normalized = _normalize_alert_instance(alert, instance, index, source=source)
            alerts.append(normalized)
    return alerts


def normalize_zap_passive_report(
    report: dict,
    *,
    report_path: str | None = None,
    settings: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict:
    return _normalize_zap_report(
        report,
        baseline_id="zap_passive",
        summary_version=ZAP_PASSIVE_SUMMARY_VERSION,
        mapping_version=ZAP_PASSIVE_MAPPING_VERSION,
        source="zap_passive",
        report_path=report_path,
        settings=settings,
        started_at=started_at,
        completed_at=completed_at,
    )


def normalize_zap_active_report(
    report: dict,
    *,
    report_path: str | None = None,
    settings: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict:
    return _normalize_zap_report(
        report,
        baseline_id="zap_active",
        summary_version=ZAP_ACTIVE_SUMMARY_VERSION,
        mapping_version=ZAP_ACTIVE_MAPPING_VERSION,
        source="zap_active",
        report_path=report_path,
        settings=settings,
        started_at=started_at,
        completed_at=completed_at,
    )


def _normalize_zap_report(
    report: dict,
    *,
    baseline_id: str,
    summary_version: str,
    mapping_version: str,
    source: str,
    report_path: str | None,
    settings: dict | None,
    started_at: str | None,
    completed_at: str | None,
) -> dict:
    raw_alerts = extract_zap_alerts(report, source=source)
    mapped_alert_ids: set[str] = set()
    cases = []
    for rule in EVALUATED_MAPPING_RULES:
        matching_alerts = [alert for alert in raw_alerts if _alert_matches_rule(alert, rule)]
        for alert in matching_alerts:
            mapped_alert_ids.add(alert["alert_instance_id"])
        scanner_alerted = bool(matching_alerts)
        cases.append(_case_record(rule, matching_alerts, scanner_alerted))

    unmatched_alerts = [
        alert for alert in raw_alerts if alert["alert_instance_id"] not in mapped_alert_ids
    ]
    counts = _classification_counts(cases)
    return {
        "baseline_id": baseline_id,
        "summary_version": summary_version,
        "mapping_version": mapping_version,
        "started_at": started_at,
        "completed_at": completed_at,
        "report_path": report_path,
        "report_format": "owasp_zap_json",
        "report_metadata": _report_metadata(report),
        "ground_truth_used_phase": "post_run_evaluation_only",
        "scan_configuration": {
            **_default_scan_configuration(baseline_id),
            **(settings or {}),
        },
        "evaluated_case_count": len(cases),
        "unsupported_case_count": len(_unsupported_idor_cases(baseline_id)),
        "raw_alert_count": len(raw_alerts),
        "matched_alert_count": sum(len(case["mapped_alerts"]) for case in cases),
        "unmatched_alert_count": len(unmatched_alerts),
        "counts": counts,
        "cases": cases,
        "unsupported_cases": _unsupported_idor_cases(baseline_id),
        "unmatched_alerts": unmatched_alerts,
        "raw_alerts": raw_alerts,
    }


def write_zap_passive_summary(
    report_path: Path,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    *,
    settings: dict | None = None,
) -> Path:
    run_id = f"zap-passive-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC).isoformat()
    report = load_zap_report(report_path)
    completed = datetime.now(UTC).isoformat()
    summary = normalize_zap_passive_report(
        report,
        report_path=str(report_path),
        settings=settings,
        started_at=started,
        completed_at=completed,
    )
    (artifact_dir / "zap-passive-summary.json").write_text(
        json.dumps(to_json_value(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "zap-passive-raw-alerts.json").write_text(
        json.dumps(to_json_value(summary["raw_alerts"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(render_zap_passive_report(summary), encoding="utf-8")
    return run_dir


def run_live_passive_zap_smoke(
    target_urls: list[str],
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    *,
    zap_image: str = DEFAULT_ZAP_IMAGE,
    runtime_budget_minutes: int = 1,
    start_development_targets: bool = False,
) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for the optional live ZAP passive smoke.")
    if not target_urls:
        raise ValueError("at least one target URL is required")
    run_id = f"zap-passive-live-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    zap_image_digest = _docker_image_digest(zap_image)
    started = datetime.now(UTC)

    target_context: AbstractContextManager | None = (
        LocalZapDevelopmentTargets() if start_development_targets else None
    )
    target_status: list[dict] = []
    command_results: list[dict] = []
    report_paths: list[Path] = []
    if target_context is None:
        _check_live_target_urls(target_urls, target_status)
        _run_zap_for_targets(
            target_urls,
            artifact_dir,
            zap_image,
            runtime_budget_minutes,
            command_results,
            report_paths,
        )
    else:
        with target_context as targets:
            target_status.extend(targets.status)
            _run_zap_for_targets(
                target_urls,
                artifact_dir,
                zap_image,
                runtime_budget_minutes,
                command_results,
                report_paths,
            )

    completed = datetime.now(UTC)
    for command_result in command_results:
        if command_result["returncode"] not in {0, 1, 2}:
            raise RuntimeError(
                "ZAP command failed before producing a usable baseline report: "
                + str(command_result["returncode"])
            )
    combined_report = _combine_zap_reports([load_zap_report(path) for path in report_paths])
    combined_report_path = artifact_dir / "zap-combined-report.json"
    combined_report_path.write_text(
        json.dumps(to_json_value(combined_report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    settings = {
        "zap_image": zap_image,
        "zap_image_digest": zap_image_digest,
        "target_urls": target_urls,
        "runtime_budget_minutes": runtime_budget_minutes,
        "traffic_source": "zap_spider_generated",
        "active_scan_enabled": False,
        "authenticated_context": False,
        "start_development_targets": start_development_targets,
        "target_status": target_status,
        "zap_command_results": command_results,
        "scope_validation": _scope_validation(combined_report, target_urls),
    }
    summary = normalize_zap_passive_report(
        combined_report,
        report_path=str(combined_report_path),
        settings=settings,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
    )
    (artifact_dir / "zap-passive-summary.json").write_text(
        json.dumps(to_json_value(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "zap-passive-raw-alerts.json").write_text(
        json.dumps(to_json_value(summary["raw_alerts"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(render_zap_passive_report(summary), encoding="utf-8")
    return run_dir


def run_live_active_zap_baseline(
    target_urls: list[str],
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    *,
    zap_image: str = DEFAULT_ZAP_IMAGE,
    spider_max_duration_minutes: int = 1,
    active_max_scan_duration_minutes: int = 2,
    active_max_rule_duration_minutes: int = 1,
    start_development_targets: bool = False,
) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required for the live ZAP active baseline.")
    if not target_urls:
        raise ValueError("at least one target URL is required")
    run_id = f"zap-active-live-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    zap_image_digest = _docker_image_digest(zap_image)
    started = datetime.now(UTC)

    target_context: AbstractContextManager | None = (
        LocalZapDevelopmentTargets() if start_development_targets else None
    )
    target_status: list[dict] = []
    command_results: list[dict] = []
    report_paths: list[Path] = []
    if target_context is None:
        _check_live_target_urls(target_urls, target_status)
        _run_active_zap_for_targets(
            target_urls,
            artifact_dir,
            zap_image,
            spider_max_duration_minutes,
            active_max_scan_duration_minutes,
            active_max_rule_duration_minutes,
            command_results,
            report_paths,
        )
    else:
        with target_context as targets:
            target_status.extend(targets.status)
            _run_active_zap_for_targets(
                target_urls,
                artifact_dir,
                zap_image,
                spider_max_duration_minutes,
                active_max_scan_duration_minutes,
                active_max_rule_duration_minutes,
                command_results,
                report_paths,
            )

    completed = datetime.now(UTC)
    for command_result in command_results:
        if command_result["returncode"] not in {0, 1, 2}:
            raise RuntimeError(
                "ZAP active command failed before producing a usable report: "
                + str(command_result["returncode"])
            )
    combined_report = _combine_zap_reports([load_zap_report(path) for path in report_paths])
    combined_report_path = artifact_dir / "zap-active-combined-report.json"
    combined_report_path.write_text(
        json.dumps(to_json_value(combined_report), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    settings = {
        "zap_image": zap_image,
        "zap_image_digest": zap_image_digest,
        "target_urls": target_urls,
        "traffic_source": "zap_spider_and_active_scan_generated",
        "active_scan_enabled": True,
        "authenticated_context": False,
        "start_development_targets": start_development_targets,
        "policy_version": ZAP_ACTIVE_POLICY_VERSION,
        "mapping_version": ZAP_ACTIVE_MAPPING_VERSION,
        "enabled_scan_rules": ACTIVE_SCAN_RULES,
        "spider_max_duration_minutes": spider_max_duration_minutes,
        "active_max_scan_duration_minutes": active_max_scan_duration_minutes,
        "active_max_rule_duration_minutes": active_max_rule_duration_minutes,
        "target_status": target_status,
        "zap_command_results": command_results,
        "scope_validation": _scope_validation(combined_report, target_urls),
    }
    summary = normalize_zap_active_report(
        combined_report,
        report_path=str(combined_report_path),
        settings=settings,
        started_at=started.isoformat(),
        completed_at=completed.isoformat(),
    )
    (artifact_dir / "zap-active-summary.json").write_text(
        json.dumps(to_json_value(summary), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (artifact_dir / "zap-active-raw-alerts.json").write_text(
        json.dumps(to_json_value(summary["raw_alerts"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(render_zap_report(summary), encoding="utf-8")
    return run_dir


def render_zap_passive_report(summary: dict) -> str:
    return render_zap_report(summary)


def render_zap_report(summary: dict) -> str:
    counts = summary["counts"]
    title = "ZAP Active Baseline Report" if summary["baseline_id"] == "zap_active" else "ZAP Passive Baseline Report"
    lines = [
        f"# {title}",
        "",
        f"- Baseline: `{summary['baseline_id']}`",
        f"- Mapping version: `{summary['mapping_version']}`",
        f"- Evaluated cases: `{summary['evaluated_case_count']}`",
        f"- Unsupported cases: `{summary['unsupported_case_count']}`",
        f"- Raw alerts: `{summary['raw_alert_count']}`",
        f"- Matched alerts: `{summary['matched_alert_count']}`",
        f"- Unmatched alerts: `{summary['unmatched_alert_count']}`",
        f"- TP/FP/FN/TN: `{counts['TP']}/{counts['FP']}/{counts['FN']}/{counts['TN']}`",
        "",
        "## Cases",
        "",
    ]
    for case in summary["cases"]:
        lines.append(
            f"- `{case['suite_case_id']}`: scanner `{case['scanner_state']}`, classification `{case['classification']}`"
        )
    lines.extend(["", "## Unsupported", ""])
    for case in summary["unsupported_cases"]:
        lines.append(f"- `{case['suite_case_id']}`: `{case['reason']}`")
    lines.append("")
    return "\n".join(lines)


def _iter_report_alerts(report: dict) -> list[dict]:
    if isinstance(report.get("alerts"), list):
        return report["alerts"]
    alerts: list[dict] = []
    for site in report.get("site", []) or []:
        alerts.extend(site.get("alerts", []) or [])
    return alerts


def _normalize_alert_instance(alert: dict, instance: dict, index: int, *, source: str) -> dict:
    alert_id = str(alert.get("pluginid") or alert.get("pluginId") or alert.get("id") or "")
    name = str(alert.get("alert") or alert.get("name") or "")
    url = str(instance.get("uri") or instance.get("url") or "")
    param = str(instance.get("param") or instance.get("parameter") or "")
    return {
        "alert_instance_id": f"{alert_id}:{name}:{url}:{param}:{index}",
        "alert_id": alert_id,
        "name": name,
        "risk": str(alert.get("riskcode") or alert.get("risk") or ""),
        "risk_description": str(alert.get("riskdesc") or alert.get("riskDescription") or ""),
        "confidence": str(alert.get("confidence") or ""),
        "url": url,
        "method": str(instance.get("method") or ""),
        "parameter": param,
        "evidence": str(instance.get("evidence") or ""),
        "attack": str(instance.get("attack") or ""),
        "cwe_id": str(alert.get("cweid") or ""),
        "wasc_id": str(alert.get("wascid") or ""),
        "source": source,
    }


def _alert_matches_rule(alert: dict, rule: ZapMappingRule) -> bool:
    name = alert["name"].lower()
    if not any(term in name for term in rule.alert_terms):
        return False
    parsed = urlparse(alert["url"])
    if rule.parameter:
        parameters = set(parse_qs(parsed.query).keys())
        if alert["parameter"]:
            parameters.add(alert["parameter"])
        if rule.parameter not in parameters:
            return False
    if rule.path == "/s/case-c":
        return parsed.path.startswith("/s/case-c/")
    return parsed.path == rule.path


def _case_record(rule: ZapMappingRule, alerts: list[dict], scanner_alerted: bool) -> dict:
    classification = _classification(rule.expected_vulnerable, scanner_alerted)
    return {
        "suite_case_id": rule.suite_case_id,
        "case_id": rule.case_id,
        "benchmark_slice": rule.benchmark_slice,
        "benchmark_id": rule.benchmark_id,
        "module_id": rule.module_id,
        "category": rule.category,
        "target_name": rule.target_name,
        "expected_vulnerable": rule.expected_vulnerable,
        "evaluation_status": "evaluated",
        "scanner_state": "alerted" if scanner_alerted else "no_alert",
        "scanner_alerted": scanner_alerted,
        "classification": classification,
        "mapped_alert_count": len(alerts),
        "mapped_alerts": alerts,
    }


def _classification(expected_vulnerable: bool, scanner_alerted: bool) -> str:
    if expected_vulnerable and scanner_alerted:
        return "TP"
    if not expected_vulnerable and scanner_alerted:
        return "FP"
    if expected_vulnerable and not scanner_alerted:
        return "FN"
    return "TN"


def _classification_counts(cases: list[dict]) -> dict:
    return {
        "alerted": sum(1 for case in cases if case["scanner_alerted"]),
        "no_alert": sum(1 for case in cases if not case["scanner_alerted"]),
        "TP": sum(1 for case in cases if case["classification"] == "TP"),
        "FP": sum(1 for case in cases if case["classification"] == "FP"),
        "FN": sum(1 for case in cases if case["classification"] == "FN"),
        "TN": sum(1 for case in cases if case["classification"] == "TN"),
    }


def _default_scan_configuration(baseline_id: str) -> dict:
    active = baseline_id == "zap_active"
    return {
        "baseline_type": baseline_id,
        "zap_image": DEFAULT_ZAP_IMAGE,
        "zap_version": "2.16.1",
        "active_scan_enabled": active,
        "authenticated_context": False,
        "traffic_source": (
            "zap_spider_and_active_scan_generated"
            if active
            else "zap_spider_generated_or_report_fixture"
        ),
        "runtime_budget_minutes": None,
        "report_format": "json",
        "rule_addon_versions": "not_present_in_report_unless_report_metadata_provides_them",
        "scope": "explicit mapped local development benchmark cases only",
    }


def _unsupported_idor_cases(baseline_id: str) -> list[dict]:
    reason = (
        "ZAP active unauthenticated scanner alerts do not establish two-user read-only authorization behavior."
        if baseline_id == "zap_active"
        else "ZAP passive spider alerts do not establish two-user read-only authorization behavior."
    )
    return [
        {
            **case,
            "reason": reason,
        }
        for case in UNSUPPORTED_IDOR_CASES
    ]


def _report_metadata(report: dict) -> dict:
    return {
        "zap_report_version": str(
            report.get("@version") or report.get("version") or report.get("zapVersion") or ""
        ),
        "generated_at": str(report.get("@generated") or report.get("generated") or ""),
        "site_count": len(report.get("site", []) or []),
        "rule_addon_versions": report.get("addons")
        or report.get("passiveScanRules")
        or "not_present_in_report",
    }


def _docker_image_digest(zap_image: str) -> str | None:
    completed = subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            zap_image,
            "--format",
            "{{json .RepoDigests}}",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        return None
    try:
        digests = json.loads(completed.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return None
    return str(digests[0]) if digests else None


def _run_zap_for_targets(
    target_urls: list[str],
    artifact_dir: Path,
    zap_image: str,
    runtime_budget_minutes: int,
    command_results: list[dict],
    report_paths: list[Path],
) -> None:
    for index, target_url in enumerate(target_urls, start=1):
        report_name = f"zap-report-{index}.json"
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{artifact_dir}:/zap/wrk:rw",
            zap_image,
            "zap-baseline.py",
            "-t",
            target_url,
            "-J",
            report_name,
            "-I",
            "-m",
            str(runtime_budget_minutes),
        ]
        started = datetime.now(UTC)
        started_perf = time.perf_counter()
        completed_process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=max(90, runtime_budget_minutes * 90),
        )
        completed = datetime.now(UTC)
        report_path = artifact_dir / report_name
        command_result = {
            "target_url": target_url,
            "report_name": report_name,
            "report_path": str(report_path),
            "command": command,
            "returncode": completed_process.returncode,
            "stdout": completed_process.stdout,
            "stderr": completed_process.stderr,
            "duration_ms": int((time.perf_counter() - started_perf) * 1000),
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "report_written": report_path.exists(),
        }
        command_results.append(command_result)
        if not report_path.exists():
            raise RuntimeError(f"ZAP did not write the expected JSON report: {report_path}")
        report_paths.append(report_path)
    (artifact_dir / "zap-commands.json").write_text(
        json.dumps(to_json_value(command_results), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _run_active_zap_for_targets(
    target_urls: list[str],
    artifact_dir: Path,
    zap_image: str,
    spider_max_duration_minutes: int,
    active_max_scan_duration_minutes: int,
    active_max_rule_duration_minutes: int,
    command_results: list[dict],
    report_paths: list[Path],
) -> None:
    for index, target_url in enumerate(target_urls, start=1):
        report_name = f"zap-active-report-{index}.json"
        plan_name = f"zap-active-plan-{index}.yaml"
        plan_path = artifact_dir / plan_name
        plan_path.write_text(
            _active_automation_plan(
                target_url,
                report_name,
                spider_max_duration_minutes=spider_max_duration_minutes,
                active_max_scan_duration_minutes=active_max_scan_duration_minutes,
                active_max_rule_duration_minutes=active_max_rule_duration_minutes,
            ),
            encoding="utf-8",
        )
        command = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{artifact_dir}:/zap/wrk:rw",
            zap_image,
            "zap.sh",
            "-cmd",
            "-autorun",
            f"/zap/wrk/{plan_name}",
        ]
        started = datetime.now(UTC)
        started_perf = time.perf_counter()
        timeout_seconds = max(
            180,
            (spider_max_duration_minutes + active_max_scan_duration_minutes + 1) * 90,
        )
        completed_process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        completed = datetime.now(UTC)
        report_path = artifact_dir / report_name
        command_result = {
            "target_url": target_url,
            "plan_name": plan_name,
            "plan_path": str(plan_path),
            "report_name": report_name,
            "report_path": str(report_path),
            "command": command,
            "returncode": completed_process.returncode,
            "stdout": completed_process.stdout,
            "stderr": completed_process.stderr,
            "duration_ms": int((time.perf_counter() - started_perf) * 1000),
            "started_at": started.isoformat(),
            "completed_at": completed.isoformat(),
            "report_written": report_path.exists(),
        }
        command_results.append(command_result)
    (artifact_dir / "zap-active-commands.json").write_text(
        json.dumps(to_json_value(command_results), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for command_result in command_results:
        report_path = Path(command_result["report_path"])
        if not report_path.exists():
            raise RuntimeError(f"ZAP did not write the expected active JSON report: {report_path}")
        report_paths.append(report_path)


def _active_automation_plan(
    target_url: str,
    report_name: str,
    *,
    spider_max_duration_minutes: int,
    active_max_scan_duration_minutes: int,
    active_max_rule_duration_minutes: int,
) -> str:
    context_name = "zap-active-local-development"
    rule_lines = "\n".join(
        [
            "    - id: {id}\n      name: {name}\n      threshold: {threshold}\n      strength: {strength}".format(
                **rule
            )
            for rule in ACTIVE_SCAN_RULES
        ]
    )
    include_path = _automation_include_path(target_url)
    return f"""env:
  contexts:
  - name: {context_name}
    urls:
    - {target_url}
    includePaths:
    - {include_path}
    excludePaths: []
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: false
jobs:
- type: passiveScan-config
  parameters:
    maxAlertsPerRule: 10
- type: spider
  parameters:
    context: {context_name}
    url: {target_url}
    maxDuration: {spider_max_duration_minutes}
- type: activeScan
  parameters:
    context: {context_name}
    policy: Default Policy
    maxScanDurationInMins: {active_max_scan_duration_minutes}
    maxRuleDurationInMins: {active_max_rule_duration_minutes}
  policyDefinition:
    defaultStrength: Low
    defaultThreshold: Off
    rules:
{rule_lines}
- type: passiveScan-wait
  parameters:
    maxDuration: 1
- type: report
  parameters:
    template: traditional-json
    reportDir: /zap/wrk/
    reportFile: {report_name}
    reportTitle: ZAP Active Baseline Report
    reportDescription: {ZAP_ACTIVE_POLICY_VERSION}
"""


def _automation_include_path(target_url: str) -> str:
    parsed = urlparse(target_url)
    if parsed.query:
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}.*"
    if parsed.path and parsed.path != "/":
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}.*"
    return f"{parsed.scheme}://{parsed.netloc}/.*"


def _combine_zap_reports(reports: list[dict]) -> dict:
    sites = []
    versions = []
    generated = []
    for report in reports:
        version = report.get("@version") or report.get("version") or report.get("zapVersion")
        if version:
            versions.append(str(version))
        report_generated = report.get("@generated") or report.get("generated")
        if report_generated:
            generated.append(str(report_generated))
        sites.extend(report.get("site", []) or [])
        if isinstance(report.get("alerts"), list):
            sites.append({"@name": "top-level-alerts", "alerts": report["alerts"]})
    return {
        "@version": versions[0] if versions else "",
        "@generated": generated[0] if generated else "",
        "combined_report": True,
        "source_report_count": len(reports),
        "site": sites,
    }


def _scope_validation(report: dict, target_urls: list[str]) -> dict:
    allowed_netlocs = {urlparse(url).netloc for url in target_urls}
    report_netlocs = set()
    for site in report.get("site", []) or []:
        site_name = str(site.get("@name") or site.get("name") or "")
        if site_name:
            parsed = urlparse(site_name)
            if parsed.netloc:
                report_netlocs.add(parsed.netloc)
    alert_netlocs = {
        urlparse(alert["url"]).netloc
        for alert in extract_zap_alerts(report)
        if alert.get("url")
    }
    observed_netlocs = sorted(report_netlocs | alert_netlocs)
    out_of_scope_netlocs = sorted(set(observed_netlocs) - allowed_netlocs)
    return {
        "allowed_netlocs": sorted(allowed_netlocs),
        "observed_netlocs": observed_netlocs,
        "out_of_scope_netlocs": out_of_scope_netlocs,
        "in_scope_only": not out_of_scope_netlocs,
    }


def _check_live_target_urls(target_urls: list[str], target_status: list[dict]) -> None:
    for target_url in target_urls:
        started = datetime.now(UTC)
        try:
            with urlopen(target_url, timeout=5) as response:
                status_code = response.status
            status = "reachable"
            error = None
        except Exception as exc:
            status_code = None
            status = "unreachable"
            error = str(exc)
        target_status.append(
            {
                "target_url": target_url,
                "status": status,
                "status_code": status_code,
                "error": error,
                "checked_at": started.isoformat(),
            }
        )
        if status != "reachable":
            raise RuntimeError(f"target URL is not reachable before ZAP run: {target_url}")


def _fetch_status(url: str) -> dict:
    started = datetime.now(UTC)
    try:
        with urlopen(url, timeout=5) as response:
            body = response.read(128).decode("utf-8", errors="replace")
            return {
                "url": url,
                "status": "ok",
                "status_code": response.status,
                "body_prefix": body,
                "checked_at": started.isoformat(),
            }
    except Exception as exc:
        return {
            "url": url,
            "status": "failed",
            "status_code": None,
            "error": str(exc),
            "checked_at": started.isoformat(),
        }


class LocalZapDevelopmentTargets(AbstractContextManager):
    def __init__(self) -> None:
        self.status: list[dict] = []
        self._servers: list[ThreadingHTTPServer] = []
        self._threads: list[threading.Thread] = []

    def __enter__(self) -> "LocalZapDevelopmentTargets":
        for port in (4291, 4293):
            server = ThreadingHTTPServer(("127.0.0.1", port), DevelopmentBenchmarkHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._servers.append(server)
            self._threads.append(thread)
        time.sleep(0.2)
        self.status.extend(
            [
                _fetch_status("http://127.0.0.1:4291/health"),
                _fetch_status("http://127.0.0.1:4291/reset"),
                _fetch_status("http://127.0.0.1:4293/sqli/health"),
                _fetch_status("http://127.0.0.1:4293/reset"),
            ]
        )
        failed = [item for item in self.status if item["status"] != "ok"]
        if failed:
            raise RuntimeError("development targets did not start/reset cleanly")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # type: ignore[no-untyped-def]
        for server in self._servers:
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize an OWASP ZAP passive baseline report.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Ingest an existing ZAP JSON report fixture.")
    ingest.add_argument("--report", type=Path, required=True)
    ingest.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)

    live = subparsers.add_parser("live", help="Run an optional live ZAP passive smoke with Docker.")
    live.add_argument("--target-url", action="append", default=[])
    live.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    live.add_argument("--zap-image", default=DEFAULT_ZAP_IMAGE)
    live.add_argument("--runtime-budget-minutes", type=int, default=1)
    live.add_argument(
        "--development-xss-sqli",
        action="store_true",
        help="Start/reset local XSS and SQLi development targets and scan their Docker-facing URLs.",
    )

    active = subparsers.add_parser("active-live", help="Run a bounded live ZAP active baseline.")
    active.add_argument("--target-url", action="append", default=[])
    active.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    active.add_argument("--zap-image", default=DEFAULT_ZAP_IMAGE)
    active.add_argument("--spider-max-duration-minutes", type=int, default=1)
    active.add_argument("--active-max-scan-duration-minutes", type=int, default=2)
    active.add_argument("--active-max-rule-duration-minutes", type=int, default=1)
    active.add_argument(
        "--development-xss-sqli",
        action="store_true",
        help="Start/reset local XSS and SQLi development targets and scan bounded local seed URLs.",
    )

    args = parser.parse_args()
    try:
        if args.command == "ingest":
            run_dir = write_zap_passive_summary(args.report, args.output_root)
        elif args.command == "live":
            target_urls = list(args.target_url)
            if args.development_xss_sqli:
                target_urls.extend(
                    [
                        "http://host.docker.internal:4291/",
                        "http://host.docker.internal:4293/sqli/health",
                    ]
                )
            run_dir = run_live_passive_zap_smoke(
                target_urls,
                args.output_root,
                zap_image=args.zap_image,
                runtime_budget_minutes=args.runtime_budget_minutes,
                start_development_targets=args.development_xss_sqli,
            )
        else:
            target_urls = list(args.target_url)
            if args.development_xss_sqli:
                target_urls.extend(
                    [
                        "http://host.docker.internal:4291/",
                        "http://host.docker.internal:4293/sqli/view?item=alpha",
                        "http://host.docker.internal:4293/sqli/safe?item=alpha",
                    ]
                )
            run_dir = run_live_active_zap_baseline(
                target_urls,
                args.output_root,
                zap_image=args.zap_image,
                spider_max_duration_minutes=args.spider_max_duration_minutes,
                active_max_scan_duration_minutes=args.active_max_scan_duration_minutes,
                active_max_rule_duration_minutes=args.active_max_rule_duration_minutes,
                start_development_targets=args.development_xss_sqli,
            )
    except Exception as exc:
        print(f"ZAP baseline failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"ZAP baseline artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
