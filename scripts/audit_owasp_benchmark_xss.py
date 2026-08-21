from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK_ROOT = REPO_ROOT / ".external" / "owasp-benchmark-java"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-compatibility-audit"

CASE_AUDIT_FIELDS = [
    "benchmark_case_id",
    "benchmark_name",
    "benchmark_version",
    "benchmark_revision",
    "source_file",
    "label_source",
    "vulnerability_label",
    "expected_result",
    "ground_truth_granularity",
    "request_method",
    "input_source",
    "endpoint",
    "parameter",
    "content_type",
    "encoding_or_transform",
    "context_or_category",
    "authentication_required",
    "stateful_prerequisite",
    "current_framework_compatible",
    "compatibility_class",
    "evaluation_role",
    "incompatibility_reason",
    "required_adapter",
    "adapter_changes_vulnerability_semantics",
    "verifier_compatible",
    "payload_support",
    "candidate_representation_support",
    "candidate_representation_gap",
    "eligible_for_direct_external_execution",
    "eligible_for_external_ranking",
    "ranking_candidate_source",
    "benchmark_identity_leakage_fields",
    "sanitization_required",
    "sanitized_candidate_id",
    "sanitized_action_path",
    "sanitized_parameter_name",
    "retained_model_facing_fields",
    "excluded_from_model_input_fields",
    "exclusion_reason",
    "audit_status",
    "auditor_notes",
]

MODEL_FACING_FIELDS = [
    "opaque_candidate_id",
    "sanitized_action_path",
    "method",
    "sanitized_parameter_name",
    "input_source",
    "input_type",
    "editable_input_count",
    "required_input_count",
    "parameter_count",
]

EXCLUDED_MODEL_FIELDS = [
    "benchmark_case_id",
    "source_file",
    "java_class_name",
    "servlet_name",
    "vulnerability_label",
    "expected_result",
    "ground_truth",
]


@dataclass(frozen=True)
class ExpectedResult:
    case_id: str
    category: str
    expected_result: str
    cwe: str


@dataclass(frozen=True)
class SourceInfo:
    source_file: str
    endpoint: str
    has_do_get: bool
    has_do_post: bool
    do_get_calls_do_post: bool
    do_get_dispatches_form: bool
    request_method: str
    input_source: str
    parameter: str
    content_type: str
    encoding_or_transform: str
    output_behavior: str
    authentication_required: str
    stateful_prerequisite: str
    extraction_notes: list[str]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_git(args: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={cwd}", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def benchmark_provenance(benchmark_root: Path, expected_results: Path) -> dict[str, Any]:
    return {
        "official_remote": run_git(["remote", "get-url", "origin"], benchmark_root),
        "current_branch": run_git(["branch", "--show-current"], benchmark_root),
        "pinned_git_revision": run_git(["rev-parse", "HEAD"], benchmark_root),
        "repository_status": run_git(["status", "--short"], benchmark_root) or "clean",
        "declared_benchmark_version": declared_version(benchmark_root / "pom.xml"),
        "expected_results_file": str(expected_results.relative_to(benchmark_root)),
        "expected_results_sha256": sha256_file(expected_results),
    }


def declared_version(pom_path: Path) -> str:
    tree = ElementTree.parse(pom_path)
    root = tree.getroot()
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    version = root.findtext("m:version", namespaces=namespace)
    return version or "unknown"


def parse_expected_results(path: Path) -> list[ExpectedResult]:
    rows: list[ExpectedResult] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for raw in reader:
            if not raw or raw[0].startswith("#"):
                continue
            if len(raw) < 4:
                raise ValueError(f"Malformed expected-results row: {raw}")
            case_id, category, expected, cwe = [item.strip() for item in raw[:4]]
            rows.append(ExpectedResult(case_id, category, expected.lower(), cwe))
    return rows


def extract_source_info(benchmark_root: Path, case_id: str) -> SourceInfo:
    java_path = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode" / f"{case_id}.java"
    if not java_path.exists():
        return SourceInfo(
            source_file=str(java_path.relative_to(benchmark_root)),
            endpoint="unknown",
            has_do_get=False,
            has_do_post=False,
            do_get_calls_do_post=False,
            do_get_dispatches_form=False,
            request_method="unknown",
            input_source="unknown",
            parameter="unknown",
            content_type="unknown",
            encoding_or_transform="unknown",
            output_behavior="unknown",
            authentication_required="unknown",
            stateful_prerequisite="source_file_missing",
            extraction_notes=["source file missing"],
        )

    source = java_path.read_text(encoding="utf-8", errors="replace")
    do_get_body = method_body(source, "doGet")
    do_post_body = method_body(source, "doPost")
    has_do_get = do_get_body is not None
    has_do_post = do_post_body is not None
    do_get_calls_do_post = bool(do_get_body and "doPost(request, response)" in do_get_body)
    do_get_dispatches_form = bool(do_get_body and "getRequestDispatcher" in do_get_body)
    endpoint = first_match(r"@WebServlet\s*\(\s*value\s*=\s*\"([^\"]+)\"", source) or "unknown"
    content_type = first_match(r"setContentType\s*\(\s*\"([^\"]+)\"", source) or "unknown"
    parameter, input_source, source_notes = extract_input_source(source, case_id)
    encoding = extract_encoding_or_transform(source)
    output_behavior = extract_output_behavior(source)
    request_method = classify_request_method(has_do_get, has_do_post, do_get_calls_do_post, do_get_dispatches_form)
    authentication_required = "not_identified"
    stateful_prerequisite = "form_setup_required" if do_get_dispatches_form and not do_get_calls_do_post else "not_identified"
    notes = list(source_notes)
    if do_get_dispatches_form:
        notes.append("doGet dispatches to a form/template instead of directly invoking doPost")

    return SourceInfo(
        source_file=str(java_path.relative_to(benchmark_root)),
        endpoint=endpoint,
        has_do_get=has_do_get,
        has_do_post=has_do_post,
        do_get_calls_do_post=do_get_calls_do_post,
        do_get_dispatches_form=do_get_dispatches_form,
        request_method=request_method,
        input_source=input_source,
        parameter=parameter,
        content_type=content_type,
        encoding_or_transform=encoding,
        output_behavior=output_behavior,
        authentication_required=authentication_required,
        stateful_prerequisite=stateful_prerequisite,
        extraction_notes=notes,
    )


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1) if match else None


def method_body(source: str, method_name: str) -> str | None:
    match = re.search(rf"void\s+{method_name}\s*\([^)]*\)\s*(?:throws[^\{{]+)?\{{", source)
    if not match:
        return None
    start = match.end()
    depth = 1
    index = start
    while index < len(source):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
        index += 1
    return None


def extract_input_source(source: str, case_id: str) -> tuple[str, str, list[str]]:
    notes: list[str] = []
    headers = re.findall(r"getHeaders?\s*\(\s*\"([^\"]+)\"", source)
    parameters = re.findall(r"getParameter(?:Values)?\s*\(\s*\"([^\"]+)\"", source)
    separate_class_parameters = re.findall(r"getTheParameter\s*\(\s*\"([^\"]+)\"", source)
    separate_class_static_values = re.findall(r"getTheValue\s*\(\s*\"([^\"]+)\"", source)
    map_parameters = re.findall(r"\.get\s*\(\s*\"([^\"]+)\"\s*\)", source)
    cookie_names = re.findall(r"\.getName\(\)\.equals\s*\(\s*\"([^\"]+)\"\s*\)", source)

    if "getReader(" in source or "getInputStream(" in source:
        return "request_body", "request_body", notes
    if headers:
        return headers[0], "header", notes
    if "getHeaderNames(" in source:
        return "dynamic_header_name", "header_enumeration", ["dynamic header enumeration"]
    if "getCookies(" in source:
        name = cookie_names[0] if cookie_names else case_id
        return name, "cookie", notes
    if "getQueryString(" in source:
        return case_id, "query_string", ["query string parsed manually for benchmark parameter"]
    if parameters:
        return parameters[0], "parameter", notes
    if separate_class_parameters:
        return separate_class_parameters[0], "parameter", ["parameter read through helper wrapper"]
    if separate_class_static_values:
        return separate_class_static_values[0], "no_external_input", ["helper returns a static safe value rather than request input"]
    if "getParameterMap(" in source:
        candidate = next((item for item in map_parameters if item.startswith("BenchmarkTest")), case_id)
        return candidate, "parameter_map", notes
    if "getParameterNames(" in source or "getParameterValues(name)" in source:
        return "dynamic_parameter_name", "parameter_name_enumeration", ["dynamic parameter-name/value enumeration"]
    return "unknown", "unknown", ["input source not statically recognized"]


def extract_encoding_or_transform(source: str) -> str:
    markers = []
    if "URLDecoder.decode" in source:
        markers.append("url_decode")
    if "URLEncoder.encode" in source:
        markers.append("url_encode")
    if "encodeForHTML" in source or "forHtml" in source or "escapeHtml" in source:
        markers.append("html_encoding")
    if "Base64" in source:
        markers.append("base64_transform")
    if "StringEscapeUtils" in source:
        markers.append("string_escape_utils")
    return ";".join(markers) if markers else "none_identified"


def extract_output_behavior(source: str) -> str:
    if "response.getWriter()" not in source:
        return "unknown"
    behaviors = []
    for name in ["print", "println", "write", "printf", "format", "append"]:
        if f".{name}(" in source:
            behaviors.append(f"writer_{name}")
    return ";".join(sorted(set(behaviors))) if behaviors else "response_writer"


def classify_request_method(has_get: bool, has_post: bool, get_calls_post: bool, get_dispatches_form: bool) -> str:
    if has_get and has_post and get_calls_post:
        return "GET_delegates_to_POST"
    if has_get and has_post and get_dispatches_form:
        return "POST_with_GET_form_setup"
    if has_get and has_post:
        return "GET_and_POST"
    if has_get:
        return "GET"
    if has_post:
        return "POST"
    return "unknown"


def classify_case(expected: ExpectedResult, source: SourceInfo, index: int, version: str, revision: str) -> dict[str, str]:
    current_supported_sources = {"parameter", "parameter_map", "query_string"}
    adapter_by_source = {
        "header": "header_input",
        "header_enumeration": "header_enumeration_input",
        "cookie": "cookie_input",
        "request_body": "request_body",
        "parameter_name_enumeration": "parameter_name_value_adapter",
        "unknown": "needs_static_review",
    }
    current_method_supported = source.request_method in {"GET_delegates_to_POST", "GET", "GET_and_POST"}
    source_supported_currently = source.input_source in current_supported_sources
    current_compatible = current_method_supported and source_supported_currently and source.endpoint != "unknown"

    if current_compatible:
        compatibility_class = "DIRECT"
        incompatibility_reason = ""
        required_adapter = ""
        candidate_representation_support = "current"
        candidate_representation_gap = ""
    elif source.input_source == "no_external_input":
        compatibility_class = "EXCLUDED"
        incompatibility_reason = "no_externally_controllable_input_source"
        required_adapter = ""
        candidate_representation_support = "unnecessary"
        candidate_representation_gap = ""
    elif source.input_source == "unknown" or source.endpoint == "unknown":
        compatibility_class = "EXCLUDED"
        incompatibility_reason = "source_or_route_not_statically_recognized"
        required_adapter = ""
        candidate_representation_support = "required_extension"
        candidate_representation_gap = "unknown_request_input_source"
    else:
        compatibility_class = "ADAPTER_SUPPORTED"
        reasons = []
        if not current_method_supported:
            reasons.append("current_get_url_mutation_path_cannot_exercise_original_method_flow")
        if not source_supported_currently:
            reasons.append(f"current_candidate_transport_does_not_support_{source.input_source}")
        if source.do_get_dispatches_form:
            reasons.append("deterministic_form_or_post_submission_adapter_required")
        incompatibility_reason = ";".join(reasons) or "deterministic_adapter_required"
        required_adapter = adapter_by_source.get(source.input_source, f"{source.input_source}_adapter")
        if source.do_get_dispatches_form and required_adapter == "":
            required_adapter = "post_form"
        candidate_representation_support = "required_extension"
        candidate_representation_gap = candidate_gap_for_source(source.input_source)

    eligible = compatibility_class in {"DIRECT", "ADAPTER_SUPPORTED"}
    verifier = verifier_compatibility(source)
    payload_support = "current_marker_control" if verifier == "current_marker_control_likely_sufficient" else verifier
    opaque = f"ox14-c{index:06d}"
    sanitized_path = sanitized_action_path(source.endpoint, index)
    sanitized_parameter = sanitized_parameter_name(source.input_source, index)
    leakage = [
        "benchmark_case_id",
        "source_file",
        "java_class_name",
        "servlet_route",
        "vulnerability_label",
        "expected_result",
    ]
    if source.parameter.startswith("BenchmarkTest") or source.parameter in {"Referer", "dynamic_header_name", "dynamic_parameter_name"}:
        leakage.append("parameter")

    return {
        "benchmark_case_id": expected.case_id,
        "benchmark_name": "OWASP Benchmark Java",
        "benchmark_version": version,
        "benchmark_revision": revision,
        "source_file": source.source_file,
        "label_source": "expectedresults-1.2.csv",
        "vulnerability_label": expected.category,
        "expected_result": "vulnerable" if expected.expected_result == "true" else "non_vulnerable",
        "ground_truth_granularity": "case_level",
        "request_method": source.request_method,
        "input_source": source.input_source,
        "endpoint": source.endpoint,
        "parameter": source.parameter,
        "content_type": source.content_type,
        "encoding_or_transform": source.encoding_or_transform,
        "context_or_category": f"cwe-{expected.cwe}",
        "authentication_required": source.authentication_required,
        "stateful_prerequisite": source.stateful_prerequisite,
        "current_framework_compatible": str(current_compatible).lower(),
        "compatibility_class": compatibility_class,
        "evaluation_role": "FINAL_CONFIRMATORY_ELIGIBLE" if eligible else "EXCLUDED",
        "incompatibility_reason": incompatibility_reason,
        "required_adapter": required_adapter,
        "adapter_changes_vulnerability_semantics": "false" if compatibility_class == "ADAPTER_SUPPORTED" else "not_applicable",
        "verifier_compatible": verifier,
        "payload_support": payload_support,
        "candidate_representation_support": candidate_representation_support,
        "candidate_representation_gap": candidate_representation_gap,
        "eligible_for_direct_external_execution": str(eligible).lower(),
        "eligible_for_external_ranking": str(eligible).lower(),
        "ranking_candidate_source": "metadata_constructed" if eligible else "not_eligible",
        "benchmark_identity_leakage_fields": ";".join(leakage),
        "sanitization_required": "true",
        "sanitized_candidate_id": opaque if eligible else "",
        "sanitized_action_path": sanitized_path if eligible else "",
        "sanitized_parameter_name": sanitized_parameter if eligible else "",
        "retained_model_facing_fields": ";".join(MODEL_FACING_FIELDS) if eligible else "",
        "excluded_from_model_input_fields": ";".join(EXCLUDED_MODEL_FIELDS),
        "exclusion_reason": incompatibility_reason if compatibility_class == "EXCLUDED" else "",
        "audit_status": "audited",
        "auditor_notes": ";".join(source.extraction_notes),
    }


def candidate_gap_for_source(input_source: str) -> str:
    gaps = {
        "header": "input_source_header;header_name_transport",
        "header_enumeration": "input_source_header_enumeration;dynamic_header_selection",
        "cookie": "input_source_cookie;cookie_name_transport",
        "request_body": "input_source_request_body;body_encoding",
        "parameter_name_enumeration": "dynamic_parameter_name_and_value_transport",
        "unknown": "unknown_input_source",
    }
    return gaps.get(input_source, f"input_source_{input_source}")


def verifier_compatibility(source: SourceInfo) -> str:
    if source.output_behavior == "unknown":
        return "runtime_probe_required"
    if "text/html" in source.content_type.lower() and "writer" in source.output_behavior:
        return "current_marker_control_likely_sufficient"
    return "runtime_probe_required"


def sanitized_action_path(endpoint: str, index: int) -> str:
    if endpoint == "unknown":
        return "unknown"
    return f"/external-v14/case-{index:06d}"


def sanitized_parameter_name(input_source: str, index: int) -> str:
    if input_source in {"header", "header_enumeration"}:
        return f"header_{index:06d}"
    if input_source == "cookie":
        return f"cookie_{index:06d}"
    if input_source == "request_body":
        return f"body_{index:06d}"
    return f"input_{index:06d}"


def build_case_audit(benchmark_root: Path) -> tuple[list[dict[str, str]], dict[str, Any]]:
    expected_path = benchmark_root / "expectedresults-1.2.csv"
    expected_rows = parse_expected_results(expected_path)
    provenance = benchmark_provenance(benchmark_root, expected_path)
    xss_rows = [row for row in expected_rows if row.category == "xss"]
    audit_rows = [
        classify_case(
            expected=row,
            source=extract_source_info(benchmark_root, row.case_id),
            index=index,
            version=provenance["declared_benchmark_version"],
            revision=provenance["pinned_git_revision"],
        )
        for index, row in enumerate(xss_rows, start=1)
    ]
    return audit_rows, {"provenance": provenance, "all_expected_results": expected_rows}


def summarize(audit_rows: list[dict[str, str]], provenance: dict[str, Any]) -> dict[str, Any]:
    total = len(audit_rows)
    vulnerable = [row for row in audit_rows if row["expected_result"] == "vulnerable"]
    negative = [row for row in audit_rows if row["expected_result"] == "non_vulnerable"]
    compatible = [row for row in audit_rows if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}]
    compatible_vulnerable = [row for row in compatible if row["expected_result"] == "vulnerable"]
    compatible_negative = [row for row in compatible if row["expected_result"] == "non_vulnerable"]
    for row in audit_rows:
        row.setdefault(
            "evaluation_role",
            "FINAL_CONFIRMATORY_ELIGIBLE" if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"} else "EXCLUDED",
        )
    readiness = [row for row in audit_rows if row["evaluation_role"] == "READINESS_ONLY"]
    final_eligible = [row for row in audit_rows if row["evaluation_role"] == "FINAL_CONFIRMATORY_ELIGIBLE"]
    final_eligible_vulnerable = [row for row in final_eligible if row["expected_result"] == "vulnerable"]
    final_eligible_negative = [row for row in final_eligible if row["expected_result"] == "non_vulnerable"]
    pack_options = {
        str(pack): ranking_scale(
            vulnerable_count=len(compatible_vulnerable),
            negative_count=len(compatible_negative),
            pack_size=pack,
            budget=4,
        )
        for pack in (5, 6, 8)
    }
    recommended_pack = recommend_pack(pack_options)
    recommended_scenarios = pack_options[str(recommended_pack)]["core_external_ranking_scenarios"]
    trial_options = {
        str(trials): trial_scale(recommended_scenarios, trials, budget=4)
        for trials in (1, 3, 5)
    }
    return {
        "benchmark_provenance": provenance,
        "total_xss": total,
        "vulnerable_xss": len(vulnerable),
        "negative_xss": len(negative),
        "category_distribution": dict(Counter(row["vulnerability_label"] for row in audit_rows)),
        "cwe_distribution": dict(Counter(row["context_or_category"] for row in audit_rows)),
        "http_method_distribution": dict(Counter(row["request_method"] for row in audit_rows)),
        "input_source_distribution": dict(Counter(row["input_source"] for row in audit_rows)),
        "compatibility_distribution": nested_counts(
            audit_rows,
            "compatibility_class",
            {"DIRECT", "ADAPTER_SUPPORTED", "DERIVED_ADAPTED", "EXCLUDED"},
        ),
        "evaluation_role_distribution": nested_counts(
            audit_rows,
            "evaluation_role",
            {"READINESS_ONLY", "FINAL_CONFIRMATORY_ELIGIBLE", "EXCLUDED"},
        ),
        "verifier_compatibility_distribution": dict(Counter(row["verifier_compatible"] for row in audit_rows)),
        "payload_support_distribution": dict(Counter(row["payload_support"] for row in audit_rows)),
        "candidate_representation_distribution": dict(Counter(row["candidate_representation_support"] for row in audit_rows)),
        "direct_vulnerable": count_rows(audit_rows, "DIRECT", "vulnerable"),
        "direct_negative": count_rows(audit_rows, "DIRECT", "non_vulnerable"),
        "adapter_supported_vulnerable": count_rows(audit_rows, "ADAPTER_SUPPORTED", "vulnerable"),
        "adapter_supported_negative": count_rows(audit_rows, "ADAPTER_SUPPORTED", "non_vulnerable"),
        "derived_vulnerable": count_rows(audit_rows, "DERIVED_ADAPTED", "vulnerable"),
        "derived_negative": count_rows(audit_rows, "DERIVED_ADAPTED", "non_vulnerable"),
        "excluded_vulnerable": count_rows(audit_rows, "EXCLUDED", "vulnerable"),
        "excluded_negative": count_rows(audit_rows, "EXCLUDED", "non_vulnerable"),
        "currently_usable_original_cases": sum(row["compatibility_class"] == "DIRECT" for row in audit_rows),
        "projected_usable_original_cases_after_justified_adapters": len(compatible),
        "projected_usable_vulnerable_after_adapters": len(compatible_vulnerable),
        "projected_usable_negative_after_adapters": len(compatible_negative),
        "readiness_only_count": len(readiness),
        "readiness_only_vulnerable": sum(row["expected_result"] == "vulnerable" for row in readiness),
        "readiness_only_negative": sum(row["expected_result"] == "non_vulnerable" for row in readiness),
        "final_confirmatory_eligible_count": len(final_eligible),
        "final_confirmatory_eligible_vulnerable": len(final_eligible_vulnerable),
        "final_confirmatory_eligible_negative": len(final_eligible_negative),
        "top_incompatibility_reasons": dict(Counter(reason for row in audit_rows for reason in split_field(row["incompatibility_reason"]))),
        "required_adapter_distribution": dict(Counter(row["required_adapter"] for row in audit_rows if row["required_adapter"])),
        "candidate_representation_gaps": dict(Counter(gap for row in audit_rows for gap in split_field(row["candidate_representation_gap"]))),
        "sanitization_required_count": sum(row["sanitization_required"] == "true" for row in audit_rows),
        "ranking_scale_by_pack_size": pack_options,
        "recommended_pack_size": recommended_pack,
        "recommended_k": 4,
        "trial_count_feasibility": trial_options,
        "recommended_trial_count": recommend_trials(trial_options),
        "direct_external_execution_case_count_current": sum(row["compatibility_class"] == "DIRECT" for row in audit_rows),
        "direct_external_execution_case_count_after_adapters": len(compatible),
        "final_confirmatory_ranking_scale_by_pack_size": {
            str(pack): ranking_scale(
                vulnerable_count=len(final_eligible_vulnerable),
                negative_count=len(final_eligible_negative),
                pack_size=pack,
                budget=4,
            )
            for pack in (5, 6, 8)
        },
    }


def count_rows(rows: Iterable[dict[str, str]], compatibility: str, expected: str) -> int:
    return sum(row["compatibility_class"] == compatibility and row["expected_result"] == expected for row in rows)


def nested_counts(
    rows: list[dict[str, str]],
    field: str,
    expected_values: set[str] | None = None,
) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    for value in sorted({row[field] for row in rows} | (expected_values or set())):
        selected = [row for row in rows if row[field] == value]
        output[value] = {
            "total": len(selected),
            "vulnerable": sum(row["expected_result"] == "vulnerable" for row in selected),
            "negative": sum(row["expected_result"] == "non_vulnerable" for row in selected),
        }
    return output


def split_field(value: str) -> list[str]:
    return [item for item in value.split(";") if item]


def ranking_scale(*, vulnerable_count: int, negative_count: int, pack_size: int, budget: int) -> dict[str, Any]:
    decoys_per_positive = max(pack_size - 1, 0)
    positive_scenarios = vulnerable_count if vulnerable_count and negative_count >= decoys_per_positive else 0
    negative_decoy_assignments = positive_scenarios * decoys_per_positive
    negative_scenarios_disjoint = negative_count // pack_size if pack_size else 0
    core_scenarios = positive_scenarios + negative_scenarios_disjoint
    mean_reuse = negative_decoy_assignments / negative_count if negative_count else "not_applicable"
    max_reuse = math.ceil(negative_decoy_assignments / negative_count) if negative_count else "not_applicable"
    unique_cases = vulnerable_count + negative_count if positive_scenarios else negative_count
    return {
        "pack_size": pack_size,
        "budget_k": budget,
        "positive_ranking_scenarios": positive_scenarios,
        "negative_ranking_scenarios_disjoint": negative_scenarios_disjoint,
        "core_external_ranking_scenarios": core_scenarios,
        "required_negative_decoy_assignments": negative_decoy_assignments,
        "mean_negative_case_reuse_for_positive_scenarios": mean_reuse,
        "maximum_negative_case_reuse_for_positive_scenarios": max_reuse,
        "unique_original_cases_represented": unique_cases,
        "total_candidate_placements_core": positive_scenarios * pack_size + negative_scenarios_disjoint * pack_size,
        "candidate_tests_per_deterministic_arm": core_scenarios * budget,
        "candidate_tests_per_llm_trial_set": core_scenarios * budget,
    }


def recommend_pack(pack_options: dict[str, dict[str, Any]]) -> int:
    # Prefer the design-strategy default unless it creates extreme decoy reuse.
    six = pack_options["6"]
    if isinstance(six["maximum_negative_case_reuse_for_positive_scenarios"], int) and six["maximum_negative_case_reuse_for_positive_scenarios"] <= 6:
        return 6
    return 5


def trial_scale(scenarios: int, trials: int, budget: int) -> dict[str, Any]:
    gpt_calls = scenarios * trials
    qwen_calls = scenarios * trials
    deterministic_rows = scenarios
    gpt_seconds = gpt_calls * 4.5
    qwen_seconds = qwen_calls * 82.8
    return {
        "llm_trials_per_scenario": trials,
        "deterministic_rows": deterministic_rows,
        "gpt_calls": gpt_calls,
        "qwen_calls": qwen_calls,
        "total_ranking_rows": deterministic_rows + gpt_calls + qwen_calls,
        "candidate_tests_deterministic": scenarios * budget,
        "candidate_tests_gpt": gpt_calls * budget,
        "candidate_tests_qwen": qwen_calls * budget,
        "projected_gpt_ranking_seconds_reference": gpt_seconds,
        "projected_gpt_ranking_hours_reference": round(gpt_seconds / 3600, 3),
        "projected_qwen_ranking_seconds_reference": qwen_seconds,
        "projected_qwen_ranking_hours_reference": round(qwen_seconds / 3600, 3),
        "projected_qwen_ranking_days_reference": round(qwen_seconds / 86400, 3),
    }


def recommend_trials(trial_options: dict[str, dict[str, Any]]) -> int:
    five = trial_options["5"]
    # Days of sequential local inference remains operationally possible as an
    # overnight or multi-day controlled run if the protocol records it.
    if five["projected_qwen_ranking_days_reference"] <= 3:
        return 5
    return 3


def validate_audit(audit_rows: list[dict[str, str]], expected_rows: list[ExpectedResult], benchmark_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    xss_expected = [row for row in expected_rows if row.category == "xss"]
    ids = [row["benchmark_case_id"] for row in audit_rows]
    expected_ids = [row.case_id for row in xss_expected]
    if len(audit_rows) != len(xss_expected):
        errors.append("case-audit row count does not match XSS expected-result count")
    if sorted(ids) != sorted(expected_ids):
        errors.append("case-audit IDs do not exactly match XSS expected-result IDs")
    duplicates = [item for item, count in Counter(ids).items() if count > 1]
    if duplicates:
        errors.append("duplicate original case IDs: " + ", ".join(duplicates))
    non_xss = [row for row in audit_rows if row["vulnerability_label"] != "xss"]
    if non_xss:
        errors.append("non-XSS rows appear in case audit")
    vulnerable = sum(row["expected_result"] == "vulnerable" for row in audit_rows)
    negative = sum(row["expected_result"] == "non_vulnerable" for row in audit_rows)
    if vulnerable + negative != len(audit_rows):
        errors.append("vulnerable + negative counts do not reconcile")
    compatibility_total = sum(1 for row in audit_rows if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED", "DERIVED_ADAPTED", "EXCLUDED"})
    if compatibility_total != len(audit_rows):
        errors.append("compatibility class count does not reconcile")
    for row in audit_rows:
        row.setdefault(
            "evaluation_role",
            "FINAL_CONFIRMATORY_ELIGIBLE" if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"} else "EXCLUDED",
        )
        if row["compatibility_class"] != "DIRECT" and not row["incompatibility_reason"]:
            errors.append(f"{row['benchmark_case_id']} is non-DIRECT without incompatibility_reason")
        if row["compatibility_class"] == "ADAPTER_SUPPORTED" and not row["required_adapter"]:
            errors.append(f"{row['benchmark_case_id']} is ADAPTER_SUPPORTED without required_adapter")
        if row["compatibility_class"] == "EXCLUDED" and not row["exclusion_reason"]:
            errors.append(f"{row['benchmark_case_id']} is EXCLUDED without exclusion_reason")
        if row["evaluation_role"] not in {"READINESS_ONLY", "FINAL_CONFIRMATORY_ELIGIBLE", "EXCLUDED"}:
            errors.append(f"{row['benchmark_case_id']} has invalid evaluation_role: {row['evaluation_role']}")
        if row["evaluation_role"] in {"READINESS_ONLY", "FINAL_CONFIRMATORY_ELIGIBLE"} and row["compatibility_class"] not in {"DIRECT", "ADAPTER_SUPPORTED"}:
            errors.append(f"{row['benchmark_case_id']} has eligible evaluation_role but is not compatible")
        if row["evaluation_role"] == "EXCLUDED" and row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}:
            errors.append(f"{row['benchmark_case_id']} is compatible but excluded without readiness/final role")
        source_path = benchmark_root / row["source_file"]
        if not source_path.exists():
            errors.append(f"{row['benchmark_case_id']} referenced source file does not exist: {row['source_file']}")
        model_fields = [
            row["sanitized_candidate_id"],
            row["sanitized_action_path"],
            row["sanitized_parameter_name"],
            row["retained_model_facing_fields"],
        ]
        forbidden_fragments = [row["benchmark_case_id"], row["expected_result"], row["vulnerability_label"], row["source_file"]]
        for field in model_fields:
            for forbidden in forbidden_fragments:
                if forbidden and forbidden in field:
                    errors.append(f"{row['benchmark_case_id']} leaks forbidden value in sanitized/model-facing field")
    if any(row.get("audit_status") == "needs_review" for row in audit_rows):
        warnings.append("some rows require manual review")
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "xss_expected_rows": len(xss_expected),
        "case_audit_rows": len(audit_rows),
        "vulnerable_rows": vulnerable,
        "negative_rows": negative,
    }


def write_outputs(audit_rows: list[dict[str, str]], expected_rows: list[ExpectedResult], summary: dict[str, Any], output_dir: Path, benchmark_root: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    case_audit_path = output_dir / "case-audit.csv"
    with case_audit_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_AUDIT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(audit_rows)
    validation = validate_audit(audit_rows, expected_rows, benchmark_root)
    write_json(output_dir / "validation-report.json", validation)
    write_json(output_dir / "audit-summary.json", summary)
    (output_dir / "audit-summary.md").write_text(render_summary_markdown(summary, validation), encoding="utf-8")
    write_json(output_dir / "provenance.json", summary["benchmark_provenance"])
    return validation


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def render_summary_markdown(summary: dict[str, Any], validation: dict[str, Any]) -> str:
    provenance = summary["benchmark_provenance"]
    lines = [
        "# OWASP Benchmark XSS v1.4 Compatibility Audit Summary",
        "",
        "Status: non-scored compatibility audit. No GPT, Qwen, browser verification or final ranking experiment was executed.",
        "",
        "## Benchmark Provenance",
        "",
        f"- Official remote: `{provenance['official_remote']}`",
        f"- Declared benchmark version: `{provenance['declared_benchmark_version']}`",
        f"- Pinned Git revision: `{provenance['pinned_git_revision']}`",
        f"- Repository status: `{provenance['repository_status']}`",
        f"- Expected-results file: `{provenance['expected_results_file']}`",
        f"- Expected-results SHA-256: `{provenance['expected_results_sha256']}`",
        "",
        "## XSS Population",
        "",
        f"- Total XSS cases: `{summary['total_xss']}`",
        f"- Vulnerable XSS cases: `{summary['vulnerable_xss']}`",
        f"- Non-vulnerable XSS cases: `{summary['negative_xss']}`",
        "",
        "## HTTP Method Distribution",
        "",
        markdown_counter(summary["http_method_distribution"]),
        "",
        "## Input Source Distribution",
        "",
        markdown_counter(summary["input_source_distribution"]),
        "",
        "## Compatibility Distribution",
        "",
        markdown_nested(summary["compatibility_distribution"]),
        "",
        "## Evaluation Role Distribution",
        "",
        markdown_nested(summary["evaluation_role_distribution"]),
        "",
        "## Projected Compatibility",
        "",
        f"- Currently usable original cases: `{summary['currently_usable_original_cases']}`",
        f"- Projected usable original cases after justified deterministic adapters: `{summary['projected_usable_original_cases_after_justified_adapters']}`",
        f"- Projected usable vulnerable cases after adapters: `{summary['projected_usable_vulnerable_after_adapters']}`",
        f"- Projected usable negative cases after adapters: `{summary['projected_usable_negative_after_adapters']}`",
        f"- READINESS_ONLY cases: `{summary['readiness_only_count']}`",
        f"- FINAL_CONFIRMATORY_ELIGIBLE cases: `{summary['final_confirmatory_eligible_count']}`",
        f"- FINAL_CONFIRMATORY_ELIGIBLE vulnerable cases: `{summary['final_confirmatory_eligible_vulnerable']}`",
        f"- FINAL_CONFIRMATORY_ELIGIBLE negative cases: `{summary['final_confirmatory_eligible_negative']}`",
        "",
        "## Required Adapters",
        "",
        markdown_counter(summary["required_adapter_distribution"]),
        "",
        "## Candidate Representation Gaps",
        "",
        markdown_counter(summary["candidate_representation_gaps"]),
        "",
        "## Verifier and Payload Compatibility",
        "",
        markdown_counter(summary["verifier_compatibility_distribution"]),
        "",
        "## Ranking Scale Projections",
        "",
        render_pack_table(summary["ranking_scale_by_pack_size"]),
        "",
        f"Recommended candidate pack size: `{summary['recommended_pack_size']}`.",
        f"Recommended candidate-test budget: `k={summary['recommended_k']}`.",
        "",
        "## Trial Count and Runtime Projections",
        "",
        render_trial_table(summary["trial_count_feasibility"]),
        "",
        f"Recommended final LLM trial count: `{summary['recommended_trial_count']}`.",
        "",
        "## Direct External Execution",
        "",
        f"- Current direct execution cases: `{summary['direct_external_execution_case_count_current']}`",
        f"- Projected direct execution cases after adapters: `{summary['direct_external_execution_case_count_after_adapters']}`",
        "",
        "## Validation",
        "",
        f"- Valid: `{validation['valid']}`",
        f"- Errors: `{len(validation['errors'])}`",
        f"- Warnings: `{len(validation['warnings'])}`",
        "",
        "## Next Implementation Recommendation",
        "",
        "Implement deterministic v1.4 compatibility extensions for metadata-constructed OWASP XSS candidates, header/cookie/parameter-name transports, opaque sanitization, and non-scored runtime readiness probes before freezing an executable protocol.",
    ]
    return "\n".join(lines) + "\n"


def markdown_counter(counter: dict[str, int]) -> str:
    if not counter:
        return "_None._"
    lines = ["| Value | Count |", "| --- | ---: |"]
    for key, value in sorted(counter.items()):
        lines.append(f"| `{key}` | {value} |")
    return "\n".join(lines)


def markdown_nested(values: dict[str, dict[str, int]]) -> str:
    lines = ["| Class | Total | Vulnerable | Negative |", "| --- | ---: | ---: | ---: |"]
    for key, counts in sorted(values.items()):
        lines.append(f"| `{key}` | {counts['total']} | {counts['vulnerable']} | {counts['negative']} |")
    return "\n".join(lines)


def render_pack_table(pack_options: dict[str, dict[str, Any]]) -> str:
    lines = [
        "| Pack size | Positive scenarios | Negative scenarios | Mean decoy reuse | Max decoy reuse | Unique cases represented | Candidate tests/arm |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key in sorted(pack_options, key=int):
        item = pack_options[key]
        lines.append(
            f"| {key} | {item['positive_ranking_scenarios']} | {item['negative_ranking_scenarios_disjoint']} | "
            f"{item['mean_negative_case_reuse_for_positive_scenarios']} | {item['maximum_negative_case_reuse_for_positive_scenarios']} | "
            f"{item['unique_original_cases_represented']} | {item['candidate_tests_per_deterministic_arm']} |"
        )
    return "\n".join(lines)


def render_trial_table(trial_options: dict[str, dict[str, Any]]) -> str:
    lines = [
        "| LLM trials/scenario | GPT calls | Qwen calls | Total rows | GPT hours reference | Qwen hours reference | Qwen days reference |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key in sorted(trial_options, key=int):
        item = trial_options[key]
        lines.append(
            f"| {key} | {item['gpt_calls']} | {item['qwen_calls']} | {item['total_ranking_rows']} | "
            f"{item['projected_gpt_ranking_hours_reference']} | {item['projected_qwen_ranking_hours_reference']} | "
            f"{item['projected_qwen_ranking_days_reference']} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit OWASP Benchmark Java XSS compatibility for v1.4 planning.")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    audit_rows, context = build_case_audit(args.benchmark_root)
    summary = summarize(audit_rows, context["provenance"])
    validation = write_outputs(audit_rows, context["all_expected_results"], summary, args.output_dir, args.benchmark_root)
    print(f"OWASP XSS cases audited: {summary['total_xss']}")
    print(f"Vulnerable: {summary['vulnerable_xss']}")
    print(f"Negative: {summary['negative_xss']}")
    print(f"Validation valid: {validation['valid']}")
    print(f"Artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
