from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
from collections import Counter
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from adstf.contracts import FindingState, TargetConfig
from adstf.owasp_sqli_v15 import build_request as build_sqli_request
from adstf.owasp_sqli_v15 import health_check as benchmark_health_check
from adstf.owasp_sqli_v15_confirmatory import (
    direct_case_artifact,
    direct_case_artifact_path,
    direct_runtime_error_result,
    execute_one_candidate as execute_sqli_candidate,
    final_target_config_for_url as sqli_target_config_for_url,
    load_protocol_package as load_sqli_protocol_package,
)
from adstf.owasp_xss_v14 import (
    OwaspExternalCandidate,
    build_value_request as build_xss_value_request,
    construct_external_candidate,
    execute_one_candidate as execute_xss_candidate,
    health_check as xss_health_check,
    load_case_audit as load_xss_case_audit,
    target_config_for_url as xss_target_config_for_url,
)
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier
from adstf.execution import HttpExecutor
from adstf.modules import mvp_modules
from adstf.zap_baseline import (
    ACTIVE_SCAN_RULES,
    DEFAULT_ZAP_IMAGE,
    ZapMappingRule,
    _active_automation_plan,
    _alert_matches_rule,
    _case_record,
    _classification_counts,
    _combine_zap_reports,
    _docker_image_digest,
    _scope_validation,
    extract_zap_alerts,
    load_zap_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "framework-zap-common-scope-v1.3"
XSS_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
SQLI_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-protocol-freeze"
XSS_AUDIT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-compatibility-audit"
DEFAULT_FRAMEWORK_BASE_URL = "https://127.0.0.1:8443/benchmark"
DEFAULT_ZAP_BASE_URL = "https://host.docker.internal:8443/benchmark"
SELECTION_SEED = "framework-zap-common-scope-v1.3-selection-v1"
PROTOCOL_VERSION = "framework-zap-common-scope-v1.3"
ZAP_MAPPING_VERSION = "zap-owasp-common-scope-v1"
EXPECTED_TOTAL_CASES = 50
EXPECTED_BY_CATEGORY = {"reflected_xss": 25, "boolean_sqli": 25}
EXPECTED_BY_CATEGORY_AND_LABEL = {
    ("reflected_xss", "vulnerable"): 15,
    ("reflected_xss", "non_vulnerable"): 10,
    ("boolean_sqli", "vulnerable"): 15,
    ("boolean_sqli", "non_vulnerable"): 10,
}
COMMON_XSS_SOURCES = {"request_parameter", "request_parameter_map", "query_string"}
COMMON_SQLI_ADAPTERS = {"multi_query"}


class CommonScopeError(RuntimeError):
    pass


def prepare_protocol(output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise CommonScopeError(f"output directory already exists and is not empty: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    selected = select_cases()
    write_json(output_dir / "selected-cases.json", ground_truth_free_selection(selected))
    write_json(output_dir / "ground-truth" / "scoring-data.json", scoring_data(selected))
    write_json(output_dir / "execution" / "framework-execution-specifications.json", execution_specs(selected))
    write_json(output_dir / "execution" / "zap-targets.json", zap_targets(selected))
    write_text(output_dir / "protocol.md", render_protocol(selected))
    write_json(output_dir / "manifest.json", protocol_manifest(output_dir, selected))
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    validation = validate_protocol(output_dir)
    write_json(output_dir / "validation-report.json", validation)
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    if not validation["valid"]:
        raise CommonScopeError("framework/ZAP common-scope protocol validation failed")
    return validation


def select_cases() -> list[dict[str, Any]]:
    xss_pool = xss_common_scope_pool()
    sqli_pool = sqli_common_scope_pool()
    selected: list[dict[str, Any]] = []
    sequence = 1
    for category, expected in EXPECTED_BY_CATEGORY_AND_LABEL:
        pool = xss_pool if category == "reflected_xss" else sqli_pool
        stratum = [row for row in pool if row["expected_result"] == expected]
        required = EXPECTED_BY_CATEGORY_AND_LABEL[(category, expected)]
        if len(stratum) < required:
            raise CommonScopeError(f"not enough {category}/{expected} cases: {len(stratum)} available, {required} required")
        ordered = sorted(stratum, key=lambda row: selection_key(row, category, expected))
        for item in ordered[:required]:
            selected.append({**item, "selection_sequence": sequence})
            sequence += 1
    return selected


def xss_common_scope_pool() -> list[dict[str, Any]]:
    corpus = read_csv(XSS_PACKAGE_DIR / "final-corpus.csv")
    by_candidate = {row["candidate_id"]: row for row in corpus}
    specs = {
        row["opaque_candidate_id"]: row
        for row in load_json(XSS_PACKAGE_DIR / "execution" / "execution-specifications.json")
    }
    truth = {
        row["candidate_id"]: row
        for row in load_json(XSS_PACKAGE_DIR / "ground-truth" / "scoring-data.json")["candidate_ground_truth"]
    }
    audit_by_case = {row["benchmark_case_id"]: row for row in load_xss_case_audit(XSS_AUDIT_DIR / "case-audit.csv")}
    pool = []
    for candidate_id, row in by_candidate.items():
        source = row["source"]
        if source not in COMMON_XSS_SOURCES:
            continue
        spec = specs[candidate_id]
        original_case_id = truth[candidate_id]["original_case_id"]
        audit_row = audit_by_case[original_case_id]
        pool.append(
            {
                "case_key": f"xss::{candidate_id}",
                "category": "reflected_xss",
                "module_id": "xss.reflected",
                "candidate_id": candidate_id,
                "original_case_id": original_case_id,
                "expected_result": truth[candidate_id]["expected_result"],
                "endpoint": spec["endpoint"],
                "transport": spec["transport"],
                "parameter": spec["input_name"],
                "method": spec["method"],
                "source": source,
                "execution_spec": spec,
                "xss_audit_row": audit_row,
            }
        )
    return add_selection_hashes(pool)


def sqli_common_scope_pool() -> list[dict[str, Any]]:
    package = load_sqli_protocol_package(SQLI_PACKAGE_DIR)
    truth = {
        row["candidate_id"]: row
        for row in load_json(SQLI_PACKAGE_DIR / "ground-truth" / "scoring-data.json")["candidate_ground_truth"]
    }
    pool = []
    for row in package["direct_rows"]:
        candidate_id = row["candidate_id"]
        candidate = package["candidates_by_id"][candidate_id]
        if candidate.execution.adapter_class not in COMMON_SQLI_ADAPTERS:
            continue
        pool.append(
            {
                "case_key": f"sqli::{candidate_id}",
                "category": "boolean_sqli",
                "module_id": "sqli.boolean",
                "candidate_id": candidate_id,
                "original_case_id": truth[candidate_id]["original_case_id"],
                "expected_result": truth[candidate_id]["expected_result"],
                "endpoint": candidate.execution.endpoint,
                "transport": candidate.execution.adapter_class,
                "parameter": candidate.execution.target_input_name,
                "method": candidate.execution.method,
                "source": candidate.ranker_candidate.input_carrier,
                "direct_row": row,
                "direct_sequence": row["sequence"],
            }
        )
    return add_selection_hashes(pool)


def add_selection_hashes(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        item = dict(row)
        item["selection_hash"] = selection_key(item, item["category"], item["expected_result"])
        output.append(item)
    return output


def selection_key(row: dict[str, Any], category: str, expected: str) -> str:
    text = "|".join([SELECTION_SEED, category, expected, row["candidate_id"], row["original_case_id"]])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ground_truth_free_selection(selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-selected-cases-v1",
        "ground_truth_included": False,
        "selection_seed": SELECTION_SEED,
        "case_count": len(selected),
        "cases": [
            {
                "case_key": row["case_key"],
                "category": row["category"],
                "module_id": row["module_id"],
                "candidate_id": row["candidate_id"],
                "original_case_id": row["original_case_id"],
                "endpoint": row["endpoint"],
                "method": row["method"],
                "transport": row["transport"],
                "parameter": row["parameter"],
                "source": row["source"],
                "selection_hash": row["selection_hash"],
                "selection_sequence": row["selection_sequence"],
            }
            for row in selected
        ],
    }


def scoring_data(selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-post-run-scoring-v1",
        "artifact_status": "post_run_scoring_only_not_runtime_facing",
        "ground_truth_load_policy": "May be loaded only after framework and ZAP runtime/scanner artifacts are closed.",
        "candidate_ground_truth": [
            {
                "case_key": row["case_key"],
                "category": row["category"],
                "candidate_id": row["candidate_id"],
                "original_case_id": row["original_case_id"],
                "expected_result": row["expected_result"],
            }
            for row in selected
        ],
    }


def execution_specs(selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-framework-execution-specifications-v1",
        "ground_truth_included": False,
        "records": [
            {
                key: row[key]
                for key in ("case_key", "category", "module_id", "candidate_id", "original_case_id", "endpoint", "method", "transport", "parameter", "source")
            }
            for row in selected
        ],
    }


def zap_targets(selected: list[dict[str, Any]], base_url: str = DEFAULT_ZAP_BASE_URL) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-zap-targets-v1",
        "ground_truth_included": False,
        "base_url": base_url,
        "targets": [zap_target_for_case(row, base_url) for row in selected],
    }


def zap_target_for_case(row: dict[str, Any], base_url: str = DEFAULT_ZAP_BASE_URL) -> dict[str, Any]:
    if row["category"] == "reflected_xss":
        spec = row.get("execution_spec") or xss_execution_spec_by_candidate()[row["candidate_id"]]
        url, _headers = build_xss_value_request(base_url, object_from_dict(spec), "adstf_zap_seed")
    else:
        package = load_sqli_protocol_package(SQLI_PACKAGE_DIR)
        candidate = package["candidates_by_id"][row["candidate_id"]]
        url, method, _headers, body = build_sqli_request(base_url, candidate.execution, candidate.execution.baseline_value)
        if method != "GET" or body is not None:
            raise CommonScopeError(f"ZAP common-scope SQLi case is not GET/query shaped: {row['candidate_id']}")
    return {
        "case_key": row["case_key"],
        "category": row["category"],
        "candidate_id": row["candidate_id"],
        "original_case_id": row["original_case_id"],
        "target_url": url,
        "path": urlparse(url).path,
        "parameter": row["parameter"],
    }


def xss_execution_spec_by_candidate() -> dict[str, dict[str, Any]]:
    return {
        row["opaque_candidate_id"]: row
        for row in load_json(XSS_PACKAGE_DIR / "execution" / "execution-specifications.json")
    }


def run_pilot_or_full(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    pilot_size: int = 5,
    continue_threshold_hours: float = 3.0,
    framework_base_url: str = DEFAULT_FRAMEWORK_BASE_URL,
    zap_base_url: str = DEFAULT_ZAP_BASE_URL,
) -> dict[str, Any]:
    protocol = require_prepared_protocol(output_dir)
    selected = load_json(output_dir / "selected-cases.json")["cases"]
    run_dir = output_dir / "runs" / f"framework-zap-common-scope-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir.mkdir(parents=True, exist_ok=False)
    write_json(run_dir / "execution-plan.json", {"protocol": str(output_dir), "case_count": len(selected), "pilot_size": pilot_size})
    started = time.perf_counter()
    pilot_cases = selected[:pilot_size]
    execute_case_set(pilot_cases, run_dir, framework_base_url=framework_base_url, zap_base_url=zap_base_url, stage="pilot")
    pilot_elapsed = time.perf_counter() - started
    projection = (pilot_elapsed / max(1, len(pilot_cases))) * len(selected)
    pilot_report = {
        "schema_version": f"{PROTOCOL_VERSION}-pilot-report-v1",
        "pilot_case_count": len(pilot_cases),
        "elapsed_seconds": round(pilot_elapsed, 3),
        "average_seconds_per_case": round(pilot_elapsed / max(1, len(pilot_cases)), 3),
        "projected_full_seconds": round(projection, 3),
        "projected_full_hours": round(projection / 3600, 4),
        "continue_threshold_hours": continue_threshold_hours,
        "continue_automatically": projection < continue_threshold_hours * 3600,
    }
    write_json(run_dir / "pilot-report.json", pilot_report)
    if not pilot_report["continue_automatically"]:
        finalize_partial_run(output_dir, run_dir)
        return {"run_dir": str(run_dir), "pilot": pilot_report, "full_executed": False}
    execute_case_set(selected[pilot_size:], run_dir, framework_base_url=framework_base_url, zap_base_url=zap_base_url, stage="full_remainder")
    package = canonicalize(output_dir=output_dir, run_dir=run_dir)
    return {"run_dir": str(run_dir), "pilot": pilot_report, "full_executed": True, "summary": package["summary"]}


def execute_case_set(
    cases: list[dict[str, Any]],
    run_dir: Path,
    *,
    framework_base_url: str,
    zap_base_url: str,
    stage: str,
) -> None:
    if not cases:
        return
    health = benchmark_health_check(framework_base_url)
    if not health["reachable"]:
        raise CommonScopeError(f"OWASP Benchmark target is not reachable: {health}")
    write_json(run_dir / f"{stage}-target-health.json", health)
    execute_framework_cases(cases, run_dir, framework_base_url=framework_base_url, stage=stage)
    execute_zap_cases(cases, run_dir, zap_base_url=zap_base_url, mode="passive", stage=stage)
    execute_zap_cases(cases, run_dir, zap_base_url=zap_base_url, mode="active", stage=stage)


def execute_framework_cases(cases: list[dict[str, Any]], run_dir: Path, *, framework_base_url: str, stage: str) -> None:
    framework_dir = run_dir / "raw" / "framework"
    xss_dir = framework_dir / "xss-cases"
    sqli_dir = framework_dir / "sqli-cases"
    xss_dir.mkdir(parents=True, exist_ok=True)
    sqli_dir.mkdir(parents=True, exist_ok=True)
    xss_cases = [case for case in cases if case["category"] == "reflected_xss"]
    if xss_cases:
        from playwright.sync_api import sync_playwright

        target = xss_target_config_for_url(framework_base_url)
        safety = SafetyBoundary(target)
        modules = mvp_modules()
        store = RunArtifactStore(run_dir / "raw" / "framework-runtime-artifacts" / "xss", f"framework-zap-common-xss-{stage}")
        store.initialize(target)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            try:
                for case in xss_cases:
                    path = xss_dir / f"{case['case_key'].replace('::', '__')}.json"
                    if path.exists():
                        continue
                    candidate = xss_candidate_without_ground_truth(case)
                    started = datetime.now(UTC)
                    try:
                        runtime = execute_xss_candidate(candidate, target, safety, store, framework_base_url, page, modules)
                        runtime["runtime_error"] = False
                    except Exception as exc:
                        runtime = runtime_error_summary(case, exc)
                    write_json(path, framework_case_artifact(case, runtime, started))
            finally:
                context.close()
                browser.close()
    sqli_cases = [case for case in cases if case["category"] == "boolean_sqli"]
    if sqli_cases:
        package = selected_sqli_package(sqli_cases)
        execute_sqli_subset(package, run_dir, framework_base_url, sqli_dir)


def xss_candidate_without_ground_truth(case: dict[str, Any]) -> OwaspExternalCandidate:
    audit_by_case = {row["benchmark_case_id"]: row for row in load_xss_case_audit(XSS_AUDIT_DIR / "case-audit.csv")}
    row = dict(audit_by_case[case["original_case_id"]])
    row["evaluation_role"] = "COMMON_SCOPE_SELECTED"
    row["expected_result"] = "not_loaded_during_runtime_execution"
    candidate = construct_external_candidate(row)
    return replace(candidate, provenance=replace(candidate.provenance, expected_result="not_loaded_during_runtime_execution"))


def selected_sqli_package(cases: list[dict[str, Any]]) -> dict[str, Any]:
    package = load_sqli_protocol_package(SQLI_PACKAGE_DIR)
    case_ids = {case["candidate_id"] for case in cases}
    direct_rows = [row for row in package["direct_rows"] if row["candidate_id"] in case_ids]
    return {**package, "direct_rows": direct_rows}


def execute_sqli_subset(package: dict[str, Any], run_dir: Path, base_url: str, output_dir: Path) -> None:
    target = sqli_target_config_for_url(base_url)
    safety = SafetyBoundary(target)
    executor = HttpExecutor(safety, verify_tls=False, timeout_seconds=8.0)
    modules = mvp_modules()
    store = RunArtifactStore(run_dir / "raw" / "framework-runtime-artifacts" / "sqli", "framework-zap-common-sqli")
    store.initialize(target)
    for row in package["direct_rows"]:
        path = output_dir / f"sqli__{row['candidate_id']}.json"
        if path.exists():
            validate_existing_case_path(path)
            continue
        candidate = package["candidates_by_id"][row["candidate_id"]]
        started = datetime.now(UTC)
        try:
            runtime = execute_sqli_candidate(candidate, target, executor, store, base_url, modules)
        except Exception as exc:
            runtime = direct_runtime_error_result(row, exc)
        artifact = direct_case_artifact(row, runtime)
        artifact["case_key"] = f"sqli::{row['candidate_id']}"
        artifact["created_at"] = started.isoformat()
        write_json(path, artifact)


def execute_zap_cases(cases: list[dict[str, Any]], run_dir: Path, *, zap_base_url: str, mode: str, stage: str) -> None:
    if not shutil.which("docker"):
        raise CommonScopeError("Docker is required for live ZAP execution")
    zap_dir = run_dir / "raw" / f"zap-{mode}" / stage
    zap_dir.mkdir(parents=True, exist_ok=True)
    commands = []
    reports = []
    for index, case in enumerate(cases, start=1):
        target = zap_target_for_case(case, zap_base_url)["target_url"]
        report_name = f"{mode}-{index:03d}-{case['case_key'].replace('::', '__')}.json"
        report_path = zap_dir / report_name
        if report_path.exists():
            reports.append(report_path)
            continue
        if mode == "passive":
            command = [
                "docker", "run", "--rm", "-v", f"{zap_dir.resolve()}:/zap/wrk:rw", DEFAULT_ZAP_IMAGE,
                "zap-baseline.py", "-t", target, "-J", report_name, "-I", "-m", "1",
            ]
        elif mode == "active":
            plan_name = f"active-{index:03d}-{case['case_key'].replace('::', '__')}.yaml"
            (zap_dir / plan_name).write_text(
                _active_automation_plan(
                    target,
                    report_name,
                    spider_max_duration_minutes=1,
                    active_max_scan_duration_minutes=2,
                    active_max_rule_duration_minutes=1,
                ),
                encoding="utf-8",
            )
            command = ["docker", "run", "--rm", "-v", f"{zap_dir.resolve()}:/zap/wrk:rw", DEFAULT_ZAP_IMAGE, "zap.sh", "-cmd", "-autorun", f"/zap/wrk/{plan_name}"]
        else:
            raise CommonScopeError(f"unknown ZAP mode: {mode}")
        started = datetime.now(UTC)
        started_perf = time.perf_counter()
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=360)
        result = {
            "case_key": case["case_key"],
            "candidate_id": case["candidate_id"],
            "mode": mode,
            "target_url": target,
            "command": command,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "duration_ms": int((time.perf_counter() - started_perf) * 1000),
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "report_path": str(report_path),
            "report_written": report_path.exists(),
        }
        commands.append(result)
        if not report_path.exists():
            write_json(zap_dir / f"{report_name}.failed-command.json", result)
            raise CommonScopeError(f"ZAP {mode} did not write report for {case['case_key']}")
        reports.append(report_path)
    write_json(zap_dir / "zap-commands.json", commands)


def canonicalize(*, output_dir: Path = DEFAULT_OUTPUT_DIR, run_dir: Path) -> dict[str, Any]:
    selected = load_json(output_dir / "selected-cases.json")["cases"]
    truth = {row["case_key"]: row for row in load_json(output_dir / "ground-truth" / "scoring-data.json")["candidate_ground_truth"]}
    framework = score_framework(run_dir, selected, truth)
    zap_passive = score_zap(run_dir, selected, truth, mode="passive")
    zap_active = score_zap(run_dir, selected, truth, mode="active")
    comparison = framework + zap_passive + zap_active
    summary = {
        "schema_version": f"{PROTOCOL_VERSION}-summary-v1",
        "case_denominator": len(selected),
        "evaluators": {
            "framework": aggregate(comparison, "framework"),
            "zap_passive": aggregate(comparison, "zap_passive"),
            "zap_active": aggregate(comparison, "zap_active"),
        },
    }
    canonical_dir = output_dir / "canonical"
    canonical_dir.mkdir(parents=True, exist_ok=True)
    write_json(canonical_dir / "framework-results.json", framework)
    write_json(canonical_dir / "zap-passive-results.json", zap_passive)
    write_json(canonical_dir / "zap-active-results.json", zap_active)
    write_csv(canonical_dir / "case-level-comparison.csv", comparison)
    write_json(canonical_dir / "summary.json", summary)
    write_text(canonical_dir / "analysis-report.md", render_analysis_report(summary))
    write_text(canonical_dir / "thesis-table.md", render_thesis_table(summary))
    write_json(canonical_dir / "manifest.json", canonical_manifest(output_dir, run_dir, summary))
    write_text(canonical_dir / "checksums.sha256", render_checksums(canonical_dir))
    return {"summary": summary, "canonical_dir": str(canonical_dir)}


def score_framework(run_dir: Path, selected: list[dict[str, Any]], truth: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for case in selected:
        if case["category"] == "reflected_xss":
            path = run_dir / "raw" / "framework" / "xss-cases" / f"{case['case_key'].replace('::', '__')}.json"
            runtime = load_json(path)["runtime_result"]
            detected = runtime.get("runtime_finding_state") == FindingState.VERIFIED.value
            state = runtime.get("runtime_finding_state", "inconclusive")
        else:
            path = run_dir / "raw" / "framework" / "sqli-cases" / f"sqli__{case['candidate_id']}.json"
            runtime = load_json(path)["runtime_result"]
            detected = runtime.get("finding_state") == FindingState.VERIFIED.value
            state = runtime.get("finding_state", "inconclusive")
        results.append(case_result("framework", case, truth[case["case_key"]], detected, state, []))
    return results


def score_zap(run_dir: Path, selected: list[dict[str, Any]], truth: dict[str, Any], *, mode: str) -> list[dict[str, Any]]:
    reports = sorted((run_dir / "raw" / f"zap-{mode}").glob("*/*.json"))
    reports = [path for path in reports if not path.name.endswith("commands.json") and not path.name.endswith("failed-command.json")]
    combined = _combine_zap_reports([load_zap_report(path) for path in reports])
    alerts = extract_zap_alerts(combined, source=f"zap_{mode}")
    output = []
    for case in selected:
        rule = zap_rule_for_case(case, truth[case["case_key"]])
        matched = [alert for alert in alerts if _alert_matches_rule(alert, rule)]
        output.append(case_result(f"zap_{mode}", case, truth[case["case_key"]], bool(matched), "alerted" if matched else "no_alert", matched))
    write_json(run_dir / "normalized" / f"zap-{mode}-raw-alerts.json", alerts)
    write_json(run_dir / "normalized" / f"zap-{mode}-scope-validation.json", _scope_validation(combined, [zap_target_for_case(case)["target_url"] for case in selected]))
    return output


def zap_rule_for_case(case: dict[str, Any], truth: dict[str, Any]) -> ZapMappingRule:
    terms = ("cross site scripting", "xss") if case["category"] == "reflected_xss" else ("sql injection",)
    target = zap_target_for_case(case)
    return ZapMappingRule(
        suite_case_id=case["case_key"],
        case_id=case["candidate_id"],
        benchmark_slice="owasp-benchmark-java",
        benchmark_id=PROTOCOL_VERSION,
        module_id=case["module_id"],
        category=case["category"],
        target_name="OWASP Benchmark Java common-scope selected case",
        expected_vulnerable=truth["expected_result"] == "vulnerable",
        path=target["path"],
        parameter=target["parameter"],
        alert_terms=terms,
    )


def case_result(evaluator: str, case: dict[str, Any], truth: dict[str, Any], detected: bool, state: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    expected_vulnerable = truth["expected_result"] == "vulnerable"
    if expected_vulnerable and detected:
        classification = "TP"
    elif expected_vulnerable and not detected:
        classification = "FN"
    elif not expected_vulnerable and detected:
        classification = "FP"
    else:
        classification = "TN"
    return {
        "evaluator": evaluator,
        "case_key": case["case_key"],
        "category": case["category"],
        "candidate_id": case["candidate_id"],
        "original_case_id": case["original_case_id"],
        "expected_result_loaded_post_run": truth["expected_result"],
        "detected": detected,
        "runtime_or_scanner_state": state,
        "classification": classification,
        "mapped_alert_count": len(evidence),
    }


def aggregate(rows: list[dict[str, Any]], evaluator: str) -> dict[str, Any]:
    subset = [row for row in rows if row["evaluator"] == evaluator]
    counts = Counter(row["classification"] for row in subset)
    tp, fp, fn, tn = counts["TP"], counts["FP"], counts["FN"], counts["TN"]
    return {
        "cases": len(subset),
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": tn,
        "sensitivity": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "false_positive_rate": ratio(fp, fp + tn),
        "accuracy": ratio(tp + tn, len(subset)),
    }


def validate_protocol(output_dir: Path = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
    errors = []
    selected = load_json(output_dir / "selected-cases.json")
    scoring = load_json(output_dir / "ground-truth" / "scoring-data.json")
    cases = selected["cases"]
    truth = scoring["candidate_ground_truth"]
    counts = Counter(case["category"] for case in cases)
    labels = Counter((row["category"], row["expected_result"]) for row in truth)
    if selected.get("ground_truth_included") is not False:
        errors.append("selected-cases.json includes ground truth")
    if len(cases) != EXPECTED_TOTAL_CASES:
        errors.append(f"selected case denominator mismatch: {len(cases)}")
    if dict(counts) != EXPECTED_BY_CATEGORY:
        errors.append(f"category distribution mismatch: {dict(counts)}")
    for key, expected in EXPECTED_BY_CATEGORY_AND_LABEL.items():
        if labels[key] != expected:
            errors.append(f"label distribution mismatch for {key}: {labels[key]}")
    if len({case["case_key"] for case in cases}) != len(cases):
        errors.append("duplicate case_key in selection")
    if any(case["category"] == "reflected_xss" and case["source"] not in COMMON_XSS_SOURCES for case in cases):
        errors.append("non-query-style XSS case selected")
    if any(case["category"] == "boolean_sqli" and case["transport"] not in COMMON_SQLI_ADAPTERS for case in cases):
        errors.append("non-query-style SQLi case selected")
    return {
        "schema_version": f"{PROTOCOL_VERSION}-validation-v1",
        "valid": not errors,
        "errors": errors,
        "case_count": len(cases),
        "category_counts": dict(counts),
        "label_counts": {f"{category}/{label}": count for (category, label), count in labels.items()},
        "checksums_valid": validate_checksums(output_dir / "checksums.sha256", output_dir)["valid"] if (output_dir / "checksums.sha256").exists() else False,
    }


def require_prepared_protocol(output_dir: Path) -> dict[str, Any]:
    if not (output_dir / "protocol.md").exists():
        raise CommonScopeError("protocol must be prepared and frozen before execution")
    validation = validate_protocol(output_dir)
    if not validation["valid"]:
        raise CommonScopeError("prepared common-scope protocol is not valid")
    return validation


def finalize_partial_run(output_dir: Path, run_dir: Path) -> None:
    write_json(run_dir / "partial-run-manifest.json", {"protocol_dir": str(output_dir), "run_dir": str(run_dir), "completed_at": datetime.now(UTC).isoformat()})
    write_text(run_dir / "checksums.sha256", render_checksums(run_dir))


def protocol_manifest(output_dir: Path, selected: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-manifest-v1",
        "protocol_version": PROTOCOL_VERSION,
        "status": "frozen_before_runtime_execution",
        "created_at": datetime.now(UTC).isoformat(),
        "output_dir": str(output_dir),
        "selection_seed": SELECTION_SEED,
        "case_count": len(selected),
        "case_distribution": dict(Counter(row["category"] for row in selected)),
        "label_distribution": {f"{category}/{label}": EXPECTED_BY_CATEGORY_AND_LABEL[(category, label)] for category, label in EXPECTED_BY_CATEGORY_AND_LABEL},
        "source_packages": {
            "xss": str(XSS_PACKAGE_DIR),
            "sqli": str(SQLI_PACKAGE_DIR),
        },
        "zap": {
            "image": DEFAULT_ZAP_IMAGE,
            "image_digest": _docker_image_digest(DEFAULT_ZAP_IMAGE),
            "active_rules": ACTIVE_SCAN_RULES,
            "mapping_version": ZAP_MAPPING_VERSION,
        },
        "ground_truth_policy": "Separated scoring data is not consumed by runtime framework or ZAP execution.",
    }


def canonical_manifest(output_dir: Path, run_dir: Path, summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-canonical-manifest-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "protocol_dir": str(output_dir),
        "run_dir": str(run_dir),
        "summary": summary,
        "ground_truth_loaded_only_for_post_run_scoring": True,
    }


def render_protocol(selected: list[dict[str, Any]]) -> str:
    lines = [
        "# Framework versus ZAP Common-Scope Protocol v1.3",
        "",
        "Status: frozen before runtime execution.",
        "",
        "This supporting evaluation compares the deterministic framework, OWASP ZAP passive scanning, and OWASP ZAP active scanning on the same independently selected OWASP Benchmark Java cases.",
        "",
        "## Case Design",
        "",
        "- Total independent cases: `50`.",
        "- Reflected-XSS cases: `25` (`15` vulnerable, `10` non-vulnerable).",
        "- Boolean SQL-injection cases: `25` (`15` vulnerable, `10` non-vulnerable).",
        "- Overall composition: `30` vulnerable and `20` non-vulnerable cases.",
        "- Common-scope eligibility is restricted to query-parameter-shaped cases that can be exercised by both the framework runtime path and the evaluated ZAP configurations without per-case credentials, headers, cookies, or manual state.",
        "",
        "## Deterministic Selection",
        "",
        f"Selection uses SHA-256 over `{SELECTION_SEED}|category|expected_result|candidate_id|original_case_id` within each stratum. The first required cases per stratum are selected before runtime execution. Ground truth is used only to create the frozen positive/negative strata and is stored separately for post-run scoring.",
        "",
        "## Execution and Mapping",
        "",
        "- Framework XSS cases use the existing deterministic browser observation and verifier path.",
        "- Framework SQLi cases use the existing non-destructive boolean SQL-injection direct execution and verifier path.",
        "- ZAP passive uses the evaluated `zap-baseline.py` workflow.",
        "- ZAP active uses the evaluated active policy with rules `40012` and `40018` at the already used low-strength bounded configuration.",
        "- Scanner alerts are mapped to a case only when the alert name matches the vulnerability family and the alert URL path and parameter match the frozen selected case target.",
        "- Failures are preserved as observations. No silent retries or case substitution are permitted.",
        "",
        "## Pilot Rule",
        "",
        "The first five selected cases are executed as a pilot using the complete framework, ZAP passive, and ZAP active workflow. The selected 50-case list is not changed based on pilot outcomes. If the projected total runtime is below approximately three hours, execution may continue automatically with the remaining cases; otherwise execution stops after the pilot.",
        "",
        "## Selected Case IDs",
        "",
        "| Case key | Category | Candidate ID | Original OWASP ID |",
        "| --- | --- | --- | --- |",
    ]
    for row in ground_truth_free_selection(selected)["cases"]:
        lines.append(f"| `{row['case_key']}` | `{row['category']}` | `{row['candidate_id']}` | `{row['original_case_id']}` |")
    return "\n".join(lines) + "\n"


def render_analysis_report(summary: dict[str, Any]) -> str:
    lines = ["# Framework versus ZAP Common-Scope Results", "", f"Case denominator: `{summary['case_denominator']}`.", ""]
    for evaluator, values in summary["evaluators"].items():
        lines.extend(
            [
                f"## {evaluator}",
                "",
                f"- TP: `{values['TP']}`",
                f"- FP: `{values['FP']}`",
                f"- FN: `{values['FN']}`",
                f"- TN: `{values['TN']}`",
                f"- Sensitivity: `{values['sensitivity']}`",
                f"- Specificity: `{values['specificity']}`",
                f"- False-positive rate: `{values['false_positive_rate']}`",
                f"- Accuracy: `{values['accuracy']}`",
                "",
            ]
        )
    return "\n".join(lines)


def render_thesis_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Evaluator | Cases | TP | FP | FN | TN | Sensitivity | Specificity | FPR | Accuracy |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    labels = {
        "framework": "Framework common XSS+SQLi scope",
        "zap_passive": "ZAP passive common scope",
        "zap_active": "ZAP active common scope",
    }
    for evaluator, label in labels.items():
        row = summary["evaluators"][evaluator]
        lines.append(f"| {label} | {row['cases']} | {row['TP']} | {row['FP']} | {row['FN']} | {row['TN']} | {row['sensitivity']} | {row['specificity']} | {row['false_positive_rate']} | {row['accuracy']} |")
    return "\n".join(lines) + "\n"


def runtime_error_summary(case: dict[str, Any], exc: Exception) -> dict[str, Any]:
    return {
        "case_key": case["case_key"],
        "candidate_id": case["candidate_id"],
        "runtime_error": True,
        "runtime_error_type": type(exc).__name__,
        "runtime_error_message": str(exc),
        "runtime_finding_state": "inconclusive",
        "ground_truth_used_phase": "not_loaded_during_runtime_execution",
    }


def framework_case_artifact(case: dict[str, Any], runtime: dict[str, Any], started: datetime) -> dict[str, Any]:
    return {
        "schema_version": f"{PROTOCOL_VERSION}-framework-case-v1",
        "case_key": case["case_key"],
        "candidate_id": case["candidate_id"],
        "category": case["category"],
        "created_at": datetime.now(UTC).isoformat(),
        "started_at": started.isoformat(),
        "runtime_result": {key: value for key, value in runtime.items() if key not in {"expected_result", "matches_readiness_ground_truth"}},
        "ground_truth_included": False,
    }


def object_from_dict(data: dict[str, Any]) -> Any:
    class Obj:
        pass
    obj = Obj()
    for key, value in data.items():
        setattr(obj, key, value)
    return obj


def validate_existing_case_path(path: Path) -> None:
    data = load_json(path)
    if data.get("ground_truth_included") is not False:
        raise CommonScopeError(f"existing artifact includes ground truth: {path}")


def ratio(numerator: int, denominator: int) -> float | str:
    return "not_available" if denominator == 0 else round(numerator / denominator, 4)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksums(checksum_path: Path, root: Path) -> dict[str, Any]:
    errors = []
    if not checksum_path.exists():
        return {"valid": False, "errors": ["missing checksums.sha256"]}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = root / relative
        if not path.exists():
            errors.append(f"missing: {relative}")
        elif sha256_file(path) != expected:
            errors.append(f"mismatch: {relative}")
    return {"valid": not errors, "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the framework/ZAP common-scope supporting evaluation.")
    parser.add_argument("--mode", choices=("prepare", "run", "canonicalize", "validate"), required=True)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--pilot-size", type=int, default=5)
    parser.add_argument("--continue-threshold-hours", type=float, default=3.0)
    args = parser.parse_args()
    if args.mode == "prepare":
        report = prepare_protocol(args.output_dir)
        print(f"Common-scope protocol valid: {report['valid']}")
    elif args.mode == "validate":
        report = validate_protocol(args.output_dir)
        print(json.dumps(report, indent=2, sort_keys=True))
        if not report["valid"]:
            raise SystemExit(1)
    elif args.mode == "run":
        result = run_pilot_or_full(output_dir=args.output_dir, pilot_size=args.pilot_size, continue_threshold_hours=args.continue_threshold_hours)
        print(json.dumps(result, indent=2, sort_keys=True))
    elif args.mode == "canonicalize":
        if args.run_dir is None:
            raise SystemExit("--run-dir is required for canonicalize")
        result = canonicalize(output_dir=args.output_dir, run_dir=args.run_dir)
        print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
