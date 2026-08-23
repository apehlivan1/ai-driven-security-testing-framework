from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BENCHMARK_ROOT = REPO_ROOT / ".external" / "owasp-benchmark-java"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-compatibility-audit"

AUDIT_VERSION = "owasp-sqli-v15-compatibility-audit-v1"
CANDIDATE_SCHEMA_VERSION = "owasp-sqli-v15-sanitized-candidate-schema-v1"
RANKING_DESIGN_VERSION = "owasp-sqli-v15-preliminary-ranking-design-v1"

COMPATIBILITY_CLASSES = {"DIRECT", "ADAPTER_SUPPORTED", "DERIVED_ADAPTED", "EXCLUDED", "MANUAL_REVIEW"}
MODEL_FACING_FIELDS = [
    "candidate_id",
    "sanitized_action_path",
    "http_method",
    "input_carrier",
    "input_count_category",
    "editable_input_count",
    "multiple_parameters",
    "transport_adapter_category",
    "request_shape",
]
FORBIDDEN_MODELFACING_KEYS = {
    "benchmark_case_id",
    "source_file",
    "expected_result",
    "vulnerability_label",
    "sql_operation_category",
    "sql_statement",
    "query_text",
    "ground_truth",
    "label",
}
FORBIDDEN_MODELFACING_FRAGMENTS = [
    "BenchmarkTest",
    ".java",
    "expected_result",
    "ground_truth",
    "non_vulnerable",
    "vulnerable",
    "sqli",
    "select",
    "insert",
    "update",
    "delete",
    "call",
]

CASE_AUDIT_FIELDS = [
    "benchmark_case_id",
    "benchmark_name",
    "benchmark_version",
    "benchmark_revision",
    "source_file",
    "label_source",
    "vulnerability_label",
    "expected_result",
    "cwe",
    "ground_truth_granularity",
    "endpoint",
    "crawler_url",
    "request_shape",
    "source_request_method",
    "input_carrier_shape",
    "primary_input_carrier",
    "controllable_input_count",
    "controllable_input_names",
    "content_type",
    "sql_operation_category",
    "sql_operation_markers",
    "read_write_category",
    "execution_api",
    "response_observability",
    "boolean_verifier_applicability",
    "transport_compatibility",
    "sql_verifier_compatibility",
    "compatibility_class",
    "eligible_original_external_evaluation",
    "eligible_candidate_ranking",
    "required_adapter",
    "adapter_requirements",
    "incompatibility_reason",
    "classification_reason",
    "candidate_representation_support",
    "candidate_representation_gap",
    "sanitization_required",
    "sanitized_candidate_id",
    "sanitized_action_path",
    "retained_model_facing_fields",
    "excluded_from_model_input_fields",
    "model_facing_preview",
    "audit_status",
    "auditor_notes",
]


@dataclass(frozen=True)
class ExpectedResult:
    case_id: str
    category: str
    expected_result: str
    cwe: str


@dataclass(frozen=True)
class CrawlerInfo:
    crawler_url: str
    input_elements: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class SourceInfo:
    source_file: str
    endpoint: str
    source_request_method: str
    content_type: str
    sql_operation_category: str
    sql_operation_markers: tuple[str, ...]
    read_write_category: str
    execution_api: str
    response_observability: str
    notes: tuple[str, ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run_git(args: list[str], cwd: Path) -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={cwd}", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        encoding="utf-8",
    )
    return completed.stdout.strip()


def safe_git(args: list[str], cwd: Path) -> str:
    try:
        return run_git(args, cwd)
    except Exception as exc:  # pragma: no cover - depends on local git metadata
        return f"unavailable: {type(exc).__name__}: {exc}"


def declared_version(pom_path: Path) -> str:
    tree = ElementTree.parse(pom_path)
    root = tree.getroot()
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    return root.findtext("m:version", namespaces=namespace) or "unknown"


def benchmark_provenance(benchmark_root: Path, expected_results: Path, crawler_xml: Path) -> dict[str, Any]:
    return {
        "official_remote": safe_git(["remote", "get-url", "origin"], benchmark_root),
        "current_branch": safe_git(["branch", "--show-current"], benchmark_root),
        "pinned_git_revision": safe_git(["rev-parse", "HEAD"], benchmark_root),
        "repository_status": safe_git(["status", "--short"], benchmark_root) or "clean",
        "declared_benchmark_version": declared_version(benchmark_root / "pom.xml"),
        "expected_results_file": str(expected_results.relative_to(benchmark_root)),
        "expected_results_sha256": sha256_file(expected_results),
        "crawler_xml_file": str(crawler_xml.relative_to(benchmark_root)),
        "crawler_xml_sha256": sha256_file(crawler_xml),
        "source_root": "src/main/java/org/owasp/benchmark/testcode",
    }


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


def parse_crawler_xml(path: Path) -> dict[str, CrawlerInfo]:
    tree = ElementTree.parse(path)
    output: dict[str, CrawlerInfo] = {}
    for element in tree.getroot().findall("benchmarkTest"):
        case_id = element.attrib["tcName"]
        inputs = tuple((child.tag, child.attrib.get("name", "")) for child in list(element))
        output[case_id] = CrawlerInfo(crawler_url=element.attrib.get("URL", ""), input_elements=inputs)
    return output


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


def first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text, flags=re.MULTILINE | re.DOTALL)
    return match.group(1) if match else None


def extract_source_info(benchmark_root: Path, case_id: str) -> SourceInfo:
    source_path = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode" / f"{case_id}.java"
    if not source_path.exists():
        return SourceInfo(
            source_file=str(source_path.relative_to(benchmark_root)),
            endpoint="unknown",
            source_request_method="unknown",
            content_type="unknown",
            sql_operation_category="unknown",
            sql_operation_markers=("source_file_missing",),
            read_write_category="unknown",
            execution_api="unknown",
            response_observability="unknown",
            notes=("source file missing",),
        )

    source = source_path.read_text(encoding="utf-8", errors="replace")
    do_get_body = method_body(source, "doGet")
    do_post_body = method_body(source, "doPost")
    has_get = do_get_body is not None
    has_post = do_post_body is not None
    get_calls_post = bool(do_get_body and "doPost(request, response)" in do_get_body)
    get_dispatches_form = bool(do_get_body and "getRequestDispatcher" in do_get_body)
    endpoint = first_match(r"@WebServlet\s*\(\s*value\s*=\s*\"([^\"]+)\"", source) or "unknown"
    content_type = first_match(r"setContentType\s*\(\s*\"([^\"]+)\"", source) or "unknown"
    source_method = classify_source_request_method(has_get, has_post, get_calls_post, get_dispatches_form)
    markers = sql_markers(source)
    operation = classify_sql_operation(markers)
    read_write = classify_read_write(markers, operation)
    execution_api = classify_execution_api(source)
    observability = classify_response_observability(source)
    notes = []
    if get_dispatches_form:
        notes.append("doGet dispatches to a form/template before doPost")
    if "{call " in source or "prepareCall" in source:
        notes.append("stored procedure call statically detected")
    if "executeUpdate(" in source:
        notes.append("executeUpdate call statically detected")
    if not notes:
        notes.append("static source inspection completed")
    return SourceInfo(
        source_file=str(source_path.relative_to(benchmark_root)),
        endpoint=endpoint,
        source_request_method=source_method,
        content_type=content_type,
        sql_operation_category=operation,
        sql_operation_markers=tuple(markers),
        read_write_category=read_write,
        execution_api=execution_api,
        response_observability=observability,
        notes=tuple(notes),
    )


def classify_source_request_method(has_get: bool, has_post: bool, get_calls_post: bool, get_dispatches_form: bool) -> str:
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


def sql_markers(source: str) -> list[str]:
    checks = [
        ("select", r"\bSELECT\b"),
        ("insert", r"\bINSERT\b"),
        ("update", r"\bUPDATE\b"),
        ("delete", r"\bDELETE\b"),
        ("stored_procedure", r"prepareCall|CallableStatement|\{call|\bCALL\b"),
        ("execute_query", r"executeQuery\s*\("),
        ("execute_update", r"executeUpdate\s*\("),
        ("prepared_statement", r"prepareStatement\s*\("),
        ("statement", r"createStatement\s*\("),
    ]
    return [name for name, pattern in checks if re.search(pattern, source, flags=re.IGNORECASE)]


def classify_sql_operation(markers: list[str]) -> str:
    has_write = any(item in markers for item in ("insert", "update", "delete", "execute_update"))
    if "stored_procedure" in markers and has_write:
        return "stored_procedure_with_write_api"
    if "stored_procedure" in markers:
        return "stored_procedure"
    write_markers = [item for item in ("insert", "update", "delete") if item in markers]
    if len(write_markers) > 1 or (write_markers and "select" in markers):
        return "mixed_sql_operation"
    if write_markers:
        return write_markers[0]
    if "select" in markers:
        return "select_like"
    return "unknown"


def classify_read_write(markers: list[str], operation: str) -> str:
    if operation == "select_like" and "execute_update" not in markers:
        return "read_like"
    if operation in {"insert", "update", "delete", "mixed_sql_operation", "stored_procedure_with_write_api"}:
        return "write_or_state_changing"
    if operation == "stored_procedure":
        return "stored_procedure_ambiguous"
    return "unknown"


def classify_execution_api(source: str) -> str:
    markers = []
    if "executeQuery(" in source:
        markers.append("executeQuery")
    if "executeUpdate(" in source:
        markers.append("executeUpdate")
    if "execute(" in source:
        markers.append("execute")
    if "prepareCall" in source:
        markers.append("prepareCall")
    if "prepareStatement" in source:
        markers.append("prepareStatement")
    if "createStatement" in source:
        markers.append("createStatement")
    return ";".join(markers) if markers else "unknown"


def classify_response_observability(source: str) -> str:
    if "DatabaseHelper.printResults" in source:
        return "result_rows_written"
    if "response.getWriter()" not in source:
        return "no_writer_detected"
    if re.search(r"while\s*\([^)]*results\.next", source) or "results.getString" in source:
        return "result_rows_written"
    if re.search(r"\.print(?:ln)?\s*\(", source):
        return "writer_output_detected"
    return "writer_detected"


def shape_for_crawler(info: CrawlerInfo | None) -> str:
    if info is None:
        return "unknown"
    return "+".join(tag for tag, _name in info.input_elements) or "no_inputs"


def primary_carrier(info: CrawlerInfo | None) -> str:
    if info is None:
        return "unknown"
    tags = {tag for tag, _name in info.input_elements}
    if not tags:
        return "no_inputs"
    if len(tags) == 1:
        return next(iter(tags))
    return "mixed"


def request_shape(info: CrawlerInfo | None) -> str:
    carrier = primary_carrier(info)
    if carrier == "getparam":
        return "GET_query"
    if carrier == "formparam":
        return "POST_form"
    if carrier == "header":
        return "header"
    if carrier == "cookie":
        return "cookie"
    return carrier


def adapter_requirement(info: CrawlerInfo | None, source: SourceInfo) -> tuple[str, str]:
    if info is None:
        return "manual_static_review", "crawler_metadata_missing"
    carriers = [tag for tag, _name in info.input_elements]
    carrier_counts = Counter(carriers)
    adapters: list[str] = []
    requirements: list[str] = []
    if carrier_counts.get("getparam", 0) > 1:
        adapters.append("multi_query_parameter_adapter")
        requirements.append("preserve original query parameter set and replace only the audited controllable value")
    elif carrier_counts.get("getparam", 0) == 1:
        requirements.append("single query parameter can be represented by existing URL mutation semantics")
    if carrier_counts.get("formparam", 0):
        adapters.append("form_parameter_adapter")
        requirements.append("submit original form parameters with deterministic values")
        if carrier_counts["formparam"] > 1:
            adapters.append("multi_form_parameter_adapter")
            requirements.append("preserve companion form parameters")
    if carrier_counts.get("header", 0):
        adapters.append("header_adapter")
        requirements.append("set deterministic request headers without exposing original BenchmarkTest names to the ranker")
    if carrier_counts.get("cookie", 0):
        adapters.append("cookie_adapter")
        requirements.append("set deterministic cookies without exposing original BenchmarkTest names to the ranker")
    unknown = [carrier for carrier in carriers if carrier not in {"getparam", "formparam", "header", "cookie"}]
    if unknown:
        adapters.append("manual_transport_adapter")
        requirements.append(f"unsupported crawler input carrier(s): {','.join(sorted(set(unknown)))}")
    if source.source_request_method == "POST_with_GET_form_setup":
        requirements.append("preserve original POST flow after deterministic setup")
    return ";".join(dict.fromkeys(adapters)), ";".join(dict.fromkeys(requirements))


def transport_compatibility(info: CrawlerInfo | None) -> str:
    if info is None:
        return "manual_review_required"
    carriers = {tag for tag, _name in info.input_elements}
    if not carriers:
        return "incompatible_no_external_input"
    if carriers <= {"getparam", "formparam", "header", "cookie"}:
        return "adapter_feasible"
    return "manual_review_required"


def verifier_applicability(source: SourceInfo) -> tuple[str, str]:
    if source.read_write_category == "read_like" and source.response_observability == "result_rows_written":
        return "plausible_runtime_validation_required", "static read-like query with response row output"
    if source.read_write_category == "read_like":
        return "manual_review_required", "read-like SQL detected but static response oracle is insufficient"
    if source.read_write_category == "write_or_state_changing":
        return "not_applicable_non_destructive_conflict", "write/state-changing SQL conflicts with non-destructive verifier philosophy"
    if source.read_write_category == "stored_procedure_ambiguous":
        return "not_applicable_stored_procedure_ambiguous", "stored procedure behavior cannot be assumed read-only by static audit"
    return "manual_review_required", "SQL operation could not be classified statically"


def classify_case(
    expected: ExpectedResult,
    crawler: CrawlerInfo | None,
    source: SourceInfo,
    index: int,
    version: str,
    revision: str,
) -> dict[str, str]:
    adapter, adapter_requirements = adapter_requirement(crawler, source)
    transport = transport_compatibility(crawler)
    verifier, verifier_reason = verifier_applicability(source)
    source_exists = not source.sql_operation_markers or "source_file_missing" not in source.sql_operation_markers
    input_count = len(crawler.input_elements) if crawler else 0
    carrier_shape = shape_for_crawler(crawler)
    primary = primary_carrier(crawler)

    if not source_exists or transport == "manual_review_required" or verifier == "manual_review_required":
        compatibility_class = "MANUAL_REVIEW"
        reason = ";".join(
            item
            for item in [
                "static_source_or_transport_insufficient" if not source_exists or transport == "manual_review_required" else "",
                verifier_reason if verifier == "manual_review_required" else "",
            ]
            if item
        )
    elif verifier.startswith("not_applicable"):
        compatibility_class = "EXCLUDED"
        reason = verifier_reason
    elif transport == "incompatible_no_external_input":
        compatibility_class = "EXCLUDED"
        reason = "crawler metadata exposes no controllable input"
    elif verifier == "plausible_runtime_validation_required":
        if primary == "getparam" and input_count == 1 and not adapter:
            compatibility_class = "DIRECT"
            reason = "single query-parameter read-like case appears transport-compatible without new adapter"
        else:
            compatibility_class = "ADAPTER_SUPPORTED"
            reason = "original case may be preserved with deterministic transport adapter; runtime boolean validation still required"
    else:
        compatibility_class = "MANUAL_REVIEW"
        reason = "classification fell through conservative static rules"

    eligible_original = compatibility_class in {"DIRECT", "ADAPTER_SUPPORTED"}
    eligible_ranking = eligible_original
    candidate_id = f"os15-c{index:06d}" if eligible_ranking else ""
    model_preview = model_facing_preview(candidate_id, index, crawler, source, adapter) if eligible_ranking else {}
    preview_text = json.dumps(model_preview, sort_keys=True)
    if eligible_ranking:
        assert_no_model_facing_leak(preview_text, expected)

    return {
        "benchmark_case_id": expected.case_id,
        "benchmark_name": "OWASP Benchmark Java",
        "benchmark_version": version,
        "benchmark_revision": revision,
        "source_file": source.source_file,
        "label_source": "expectedresults-1.2.csv",
        "vulnerability_label": expected.category,
        "expected_result": "vulnerable" if expected.expected_result == "true" else "non_vulnerable",
        "cwe": expected.cwe,
        "ground_truth_granularity": "case_level",
        "endpoint": source.endpoint,
        "crawler_url": crawler.crawler_url if crawler else "",
        "request_shape": request_shape(crawler),
        "source_request_method": source.source_request_method,
        "input_carrier_shape": carrier_shape,
        "primary_input_carrier": primary,
        "controllable_input_count": str(input_count),
        "controllable_input_names": ";".join(name for _tag, name in crawler.input_elements) if crawler else "",
        "content_type": source.content_type,
        "sql_operation_category": source.sql_operation_category,
        "sql_operation_markers": ";".join(source.sql_operation_markers),
        "read_write_category": source.read_write_category,
        "execution_api": source.execution_api,
        "response_observability": source.response_observability,
        "boolean_verifier_applicability": verifier,
        "transport_compatibility": transport,
        "sql_verifier_compatibility": verifier,
        "compatibility_class": compatibility_class,
        "eligible_original_external_evaluation": str(eligible_original).lower(),
        "eligible_candidate_ranking": str(eligible_ranking).lower(),
        "required_adapter": adapter,
        "adapter_requirements": adapter_requirements,
        "incompatibility_reason": "" if eligible_original else reason,
        "classification_reason": reason,
        "candidate_representation_support": "proposed_schema" if eligible_ranking else "not_applicable",
        "candidate_representation_gap": "" if eligible_ranking else "no_ranker_candidate_for_incompatible_case",
        "sanitization_required": "true" if eligible_ranking else "not_applicable",
        "sanitized_candidate_id": candidate_id,
        "sanitized_action_path": f"/external-v15/case-{index:06d}" if eligible_ranking else "",
        "retained_model_facing_fields": ";".join(MODEL_FACING_FIELDS) if eligible_ranking else "",
        "excluded_from_model_input_fields": ";".join(sorted(FORBIDDEN_MODELFACING_KEYS)),
        "model_facing_preview": preview_text if eligible_ranking else "",
        "audit_status": "audited",
        "auditor_notes": ";".join(source.notes),
    }


def model_facing_preview(
    candidate_id: str,
    index: int,
    crawler: CrawlerInfo | None,
    source: SourceInfo,
    adapter: str,
) -> dict[str, Any]:
    input_count = len(crawler.input_elements) if crawler else 0
    return {
        "candidate_id": candidate_id,
        "sanitized_action_path": f"/external-v15/case-{index:06d}",
        "http_method": "GET" if primary_carrier(crawler) == "getparam" else "POST_or_request_metadata",
        "input_carrier": sanitized_carrier(primary_carrier(crawler)),
        "input_count_category": input_count_category(input_count),
        "editable_input_count": input_count,
        "multiple_parameters": input_count > 1,
        "transport_adapter_category": sanitized_adapter_category(adapter),
        "request_shape": sanitized_request_shape(request_shape(crawler)),
    }


def sanitized_carrier(carrier: str) -> str:
    return {
        "getparam": "query_parameter",
        "formparam": "form_parameter",
        "header": "header",
        "cookie": "cookie",
        "mixed": "mixed",
    }.get(carrier, "unknown")


def input_count_category(count: int) -> str:
    if count <= 0:
        return "none"
    if count == 1:
        return "single"
    if count <= 3:
        return "small_multi"
    return "larger_multi"


def sanitized_adapter_category(adapter: str) -> str:
    if not adapter:
        return "none"
    parts = adapter.split(";")
    if "form_parameter_adapter" in parts:
        return "form"
    if "header_adapter" in parts:
        return "header"
    if "cookie_adapter" in parts:
        return "cookie"
    if "multi_query_parameter_adapter" in parts:
        return "query_multi"
    return "other"


def sanitized_request_shape(shape: str) -> str:
    return {
        "GET_query": "query",
        "POST_form": "form",
        "header": "header",
        "cookie": "cookie",
    }.get(shape, "other")


def assert_no_model_facing_leak(serialized: str, expected: ExpectedResult) -> None:
    for fragment in [expected.case_id, expected.category, *FORBIDDEN_MODELFACING_FRAGMENTS]:
        if fragment and fragment in serialized:
            raise ValueError(f"model-facing preview leaks forbidden fragment: {fragment}")


def build_case_audit(benchmark_root: Path = DEFAULT_BENCHMARK_ROOT) -> tuple[list[dict[str, str]], dict[str, Any]]:
    expected_path = benchmark_root / "expectedresults-1.2.csv"
    crawler_path = benchmark_root / "data" / "benchmark-crawler-http.xml"
    expected_rows = parse_expected_results(expected_path)
    crawler_rows = parse_crawler_xml(crawler_path)
    provenance = benchmark_provenance(benchmark_root, expected_path, crawler_path)
    sqli_rows = [row for row in expected_rows if row.category == "sqli"]
    audit_rows = [
        classify_case(
            expected=row,
            crawler=crawler_rows.get(row.case_id),
            source=extract_source_info(benchmark_root, row.case_id),
            index=index,
            version=provenance["declared_benchmark_version"],
            revision=provenance["pinned_git_revision"],
        )
        for index, row in enumerate(sqli_rows, start=1)
    ]
    return audit_rows, {
        "provenance": provenance,
        "all_expected_results": expected_rows,
        "crawler_rows": crawler_rows,
    }


def count_rows(rows: Iterable[dict[str, str]], compatibility: str, expected: str) -> int:
    return sum(row["compatibility_class"] == compatibility and row["expected_result"] == expected for row in rows)


def nested_counts(rows: list[dict[str, str]], field: str, expected_values: set[str] | None = None) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    values = sorted({row[field] for row in rows} | (expected_values or set()))
    for value in values:
        selected = [row for row in rows if row[field] == value]
        output[value] = {
            "total": len(selected),
            "vulnerable": sum(row["expected_result"] == "vulnerable" for row in selected),
            "non_vulnerable": sum(row["expected_result"] == "non_vulnerable" for row in selected),
        }
    return output


def split_field(value: str) -> list[str]:
    return [item for item in value.split(";") if item]


def ranking_scale(*, vulnerable_count: int, negative_count: int, pack_size: int, budget: int) -> dict[str, Any]:
    decoys_per_positive = max(pack_size - 1, 0)
    positive_scenarios = vulnerable_count if vulnerable_count and negative_count >= decoys_per_positive else 0
    negative_decoy_assignments = positive_scenarios * decoys_per_positive
    negative_scenarios_disjoint = negative_count // pack_size if pack_size else 0
    return {
        "pack_size": pack_size,
        "candidate_test_budget_k": budget,
        "positive_scenarios": positive_scenarios,
        "negative_only_scenarios_disjoint": negative_scenarios_disjoint,
        "core_ranking_scenarios": positive_scenarios + negative_scenarios_disjoint,
        "required_negative_decoy_assignments": negative_decoy_assignments,
        "mean_negative_case_reuse_for_positive_scenarios": (
            round(negative_decoy_assignments / negative_count, 3) if negative_count else "not_applicable"
        ),
        "maximum_negative_case_reuse_for_positive_scenarios": (
            math.ceil(negative_decoy_assignments / negative_count) if negative_count else "not_applicable"
        ),
        "candidate_placements": positive_scenarios * pack_size + negative_scenarios_disjoint * pack_size,
        "candidate_tests_per_arm_or_trial_set": (positive_scenarios + negative_scenarios_disjoint) * budget,
    }


def summarize(audit_rows: list[dict[str, str]], provenance: dict[str, Any]) -> dict[str, Any]:
    compatible = [row for row in audit_rows if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}]
    compatible_vulnerable = [row for row in compatible if row["expected_result"] == "vulnerable"]
    compatible_negative = [row for row in compatible if row["expected_result"] == "non_vulnerable"]
    pack_options = {
        str(pack): ranking_scale(
            vulnerable_count=len(compatible_vulnerable),
            negative_count=len(compatible_negative),
            pack_size=pack,
            budget=4,
        )
        for pack in (4, 5, 6)
    }
    recommended_pack = recommend_pack(pack_options)
    return {
        "schema_version": AUDIT_VERSION,
        "artifact_status": "non_scored_static_audit",
        "benchmark_provenance": provenance,
        "total_sqli": len(audit_rows),
        "vulnerable_sqli": sum(row["expected_result"] == "vulnerable" for row in audit_rows),
        "non_vulnerable_sqli": sum(row["expected_result"] == "non_vulnerable" for row in audit_rows),
        "compatibility_distribution": nested_counts(audit_rows, "compatibility_class", COMPATIBILITY_CLASSES),
        "input_carrier_distribution": nested_counts(audit_rows, "input_carrier_shape"),
        "primary_input_carrier_distribution": nested_counts(audit_rows, "primary_input_carrier"),
        "request_shape_distribution": nested_counts(audit_rows, "request_shape"),
        "sql_operation_distribution": nested_counts(audit_rows, "sql_operation_category"),
        "read_write_distribution": nested_counts(audit_rows, "read_write_category"),
        "boolean_verifier_applicability_distribution": nested_counts(audit_rows, "boolean_verifier_applicability"),
        "required_adapter_distribution": dict(Counter(adapter for row in audit_rows for adapter in split_field(row["required_adapter"]))),
        "compatible_required_adapter_distribution": dict(
            Counter(adapter for row in compatible for adapter in split_field(row["required_adapter"]))
        ),
        "compatible_input_carrier_distribution": nested_counts(compatible, "input_carrier_shape"),
        "compatible_primary_input_carrier_distribution": nested_counts(compatible, "primary_input_carrier"),
        "major_incompatibility_reasons": dict(Counter(row["incompatibility_reason"] for row in audit_rows if row["incompatibility_reason"])),
        "eligible_original_external_evaluation": len(compatible),
        "eligible_original_external_evaluation_vulnerable": len(compatible_vulnerable),
        "eligible_original_external_evaluation_non_vulnerable": len(compatible_negative),
        "eligible_candidate_ranking": sum(row["eligible_candidate_ranking"] == "true" for row in audit_rows),
        "ranking_scale_by_pack_size": pack_options,
        "recommended_pack_size": recommended_pack,
        "recommended_candidate_test_budget_k": 4,
        "recommended_trial_count_future_llm": 5,
        "direct_execution_layer_recommended": True,
        "candidate_ranking_layer_recommended": True,
        "runtime_execution_counts": {
            "sqli_runtime_executions": 0,
            "gpt_calls": 0,
            "qwen_calls": 0,
            "scored_rankings": 0,
        },
    }


def recommend_pack(pack_options: dict[str, dict[str, Any]]) -> int:
    five = pack_options["5"]
    if isinstance(five["maximum_negative_case_reuse_for_positive_scenarios"], int) and five[
        "maximum_negative_case_reuse_for_positive_scenarios"
    ] <= 5:
        return 5
    return 4


def validate_audit(audit_rows: list[dict[str, str]], expected_rows: list[ExpectedResult], benchmark_root: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    sqli_expected = [row for row in expected_rows if row.category == "sqli"]
    ids = [row["benchmark_case_id"] for row in audit_rows]
    expected_ids = [row.case_id for row in sqli_expected]
    if len(audit_rows) != len(sqli_expected):
        errors.append("case-audit row count does not match SQLi expected-result count")
    if sorted(ids) != sorted(expected_ids):
        errors.append("case-audit IDs do not exactly match SQLi expected-result IDs")
    duplicates = [item for item, count in Counter(ids).items() if count > 1]
    if duplicates:
        errors.append("duplicate original case IDs: " + ", ".join(duplicates))
    if any(row["vulnerability_label"] != "sqli" for row in audit_rows):
        errors.append("non-SQLi rows appear in SQLi audit")
    if sum(row["expected_result"] == "vulnerable" for row in audit_rows) + sum(
        row["expected_result"] == "non_vulnerable" for row in audit_rows
    ) != len(audit_rows):
        errors.append("vulnerable + non-vulnerable counts do not reconcile")
    class_count = sum(row["compatibility_class"] in COMPATIBILITY_CLASSES for row in audit_rows)
    if class_count != len(audit_rows):
        errors.append("compatibility classes do not reconcile")
    if not any(row["compatibility_class"] == "ADAPTER_SUPPORTED" for row in audit_rows):
        errors.append("audit unexpectedly found no adapter-supported cases")

    for row in audit_rows:
        source_path = benchmark_root / row["source_file"]
        if not source_path.exists():
            errors.append(f"{row['benchmark_case_id']} source file does not exist: {row['source_file']}")
        if row["compatibility_class"] == "ADAPTER_SUPPORTED" and not row["required_adapter"]:
            errors.append(f"{row['benchmark_case_id']} is adapter-supported without required_adapter")
        if row["compatibility_class"] in {"EXCLUDED", "MANUAL_REVIEW"} and not row["incompatibility_reason"]:
            errors.append(f"{row['benchmark_case_id']} is {row['compatibility_class']} without incompatibility_reason")
        if row["read_write_category"] == "write_or_state_changing" and row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}:
            errors.append(f"{row['benchmark_case_id']} write/state-changing case classified as original-compatible")
        if row["read_write_category"] == "stored_procedure_ambiguous" and row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}:
            errors.append(f"{row['benchmark_case_id']} stored procedure case classified as original-compatible")
        if row["eligible_candidate_ranking"] == "true":
            preview = row["model_facing_preview"]
            for forbidden in [
                row["benchmark_case_id"],
                row["source_file"],
                row["expected_result"],
                row["vulnerability_label"],
                row["sql_operation_category"],
                *FORBIDDEN_MODELFACING_FRAGMENTS,
            ]:
                if forbidden and forbidden in preview:
                    errors.append(f"{row['benchmark_case_id']} model-facing preview leaks {forbidden}")
    if any(row["compatibility_class"] == "MANUAL_REVIEW" for row in audit_rows):
        warnings.append("some cases require manual review before a scored protocol")
    return {
        "schema_version": "owasp-sqli-v15-compatibility-validation-v1",
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "expected_sqli_rows": len(sqli_expected),
        "case_audit_rows": len(audit_rows),
        "runtime_execution_counts": {
            "sqli_runtime_executions": 0,
            "gpt_calls": 0,
            "qwen_calls": 0,
            "scored_rankings": 0,
        },
    }


def candidate_schema() -> dict[str, Any]:
    return {
        "schema_version": CANDIDATE_SCHEMA_VERSION,
        "status": "proposed_not_frozen",
        "authority_boundary": "Rankers may order existing sanitized candidate IDs only. They do not receive payloads, SQL source, expected results, BenchmarkTest IDs, execution tools or verifier authority.",
        "fields": [
            {
                "name": "candidate_id",
                "purpose": "Opaque stable identifier used for ordering only.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "sanitized_action_path",
                "purpose": "Neutral path-like placeholder so structural path depth can be represented without exposing OWASP routes.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "http_method",
                "purpose": "Transport-level method category available before testing.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "input_carrier",
                "purpose": "Structural carrier type such as query parameter, form parameter, header or cookie.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "input_count_category",
                "purpose": "Coarse parameter-count category used for prioritization without exposing original names.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "editable_input_count",
                "purpose": "Count of controllable inputs visible to the deterministic adapter.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "multiple_parameters",
                "purpose": "Boolean structural signal for multi-input requests.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
            {
                "name": "transport_adapter_category",
                "purpose": "Coarse adapter class needed to construct the request deterministically.",
                "allowed": True,
                "ground_truth_risk": "low",
            },
        ],
        "excluded_fields": sorted(FORBIDDEN_MODELFACING_KEYS),
        "excluded_fragments": FORBIDDEN_MODELFACING_FRAGMENTS,
    }


def adapter_requirements(audit_rows: list[dict[str, str]]) -> dict[str, Any]:
    carriers = nested_counts(audit_rows, "primary_input_carrier")
    return {
        "schema_version": "owasp-sqli-v15-adapter-requirements-v1",
        "status": "design_only_not_implemented",
        "transport_compatibility_is_not_verifier_compatibility": True,
        "required_adapters": {
            "query_parameters": {
                "needed": any("multi_query_parameter_adapter" in row["required_adapter"] for row in audit_rows),
                "requirement": "Construct original query-parameter sets and mutate only the audited controllable value.",
            },
            "form_parameters": {
                "needed": any("form_parameter_adapter" in row["required_adapter"] for row in audit_rows),
                "requirement": "Submit original form parameters with deterministic companion values and preserve original method shape.",
            },
            "headers": {
                "needed": any("header_adapter" in row["required_adapter"] for row in audit_rows),
                "requirement": "Set deterministic request headers while keeping original header names out of model-facing records.",
            },
            "cookies": {
                "needed": any("cookie_adapter" in row["required_adapter"] for row in audit_rows),
                "requirement": "Set deterministic cookies while keeping original cookie names out of model-facing records.",
            },
        },
        "carrier_distribution": carriers,
    }


def ranking_design(summary: dict[str, Any]) -> dict[str, Any]:
    pack_size = summary["recommended_pack_size"]
    compatible = summary["eligible_candidate_ranking"]
    vulnerable = summary["eligible_original_external_evaluation_vulnerable"]
    negative = summary["eligible_original_external_evaluation_non_vulnerable"]
    return {
        "schema_version": RANKING_DESIGN_VERSION,
        "status": "recommendation_not_frozen",
        "independent_scenario_unit": "candidate pack derived from original OWASP SQLi cases after compatibility filtering",
        "candidate_pack_size": pack_size,
        "candidate_test_budget_k": summary["recommended_candidate_test_budget_k"],
        "top_k_definition": "min(candidate_test_budget_k, candidate_count)",
        "positive_scenario_construction": "one compatible vulnerable focal candidate plus structurally varied compatible non-vulnerable decoys",
        "negative_only_scenario_construction": "compatible non-vulnerable candidates only; vulnerable-candidate ranking metrics not applicable",
        "decoy_assignment_strategy": "deterministic stratified assignment by carrier/request shape where possible; reuse negatives only by predeclared balanced rule",
        "negative_reuse_recommendation": "allowed for positive decoy placement if recorded, balanced, and separated from negative-only scenario denominators",
        "candidate_counts": {
            "compatible_total": compatible,
            "compatible_vulnerable": vulnerable,
            "compatible_non_vulnerable": negative,
        },
        "scale_options": summary["ranking_scale_by_pack_size"],
        "separate_layers_required": True,
        "ranking_layer_proves": "whether rankers prioritize sanitized compatible SQLi candidates under a fixed budget",
        "direct_execution_layer_proves": "whether deterministic execution and verifier criteria can confirm or reject compatible original OWASP cases",
    }


def decision_log(summary: dict[str, Any]) -> str:
    lines = [
        "# SQLi v1.5 Methodological Decision Log",
        "",
        "- Preserve the existing non-destructive boolean-SQLi verifier philosophy.",
        "- Do not classify write/state-changing SQL operations as direct or adapter-supported original cases.",
        "- Treat stored procedures as incompatible unless a later protocol explicitly audits and proves read-only semantics.",
        "- Separate deterministic transport compatibility from SQL/verifier compatibility.",
        "- Keep OWASP ground truth only in offline audit and future post-run scoring data.",
        "- Exclude BenchmarkTest IDs, Java paths, SQL operation names, payloads and labels from ranker-facing candidates.",
        "- Keep SQLi candidate ranking and direct verifier validation as separate study layers with separate denominators.",
        "",
        f"Recommended pack size: `{summary['recommended_pack_size']}`.",
        f"Recommended candidate-test budget: `k={summary['recommended_candidate_test_budget_k']}`.",
        "",
    ]
    return "\n".join(lines)


def render_summary_markdown(summary: dict[str, Any], validation: dict[str, Any]) -> str:
    lines = [
        "# OWASP Benchmark SQLi v1.5 Compatibility Audit Summary",
        "",
        "Status: non-scored static compatibility audit and protocol-design preparation. No SQLi runtime execution, GPT call, Qwen call or scored ranking was performed.",
        "",
        "## Corpus Counts",
        "",
        f"- Total SQLi cases: `{summary['total_sqli']}`",
        f"- Vulnerable SQLi cases: `{summary['vulnerable_sqli']}`",
        f"- Non-vulnerable SQLi cases: `{summary['non_vulnerable_sqli']}`",
        "",
        "## Compatibility Distribution",
        "",
        markdown_nested(summary["compatibility_distribution"]),
        "",
        "## Input Carrier Distribution",
        "",
        markdown_nested(summary["input_carrier_distribution"]),
        "",
        "## SQL Operation Distribution",
        "",
        markdown_nested(summary["sql_operation_distribution"]),
        "",
        "## Read-vs-Write Distribution",
        "",
        markdown_nested(summary["read_write_distribution"]),
        "",
        "## Original-Case Eligibility",
        "",
        f"- Original OWASP cases potentially usable for direct external evaluation after deterministic adapters: `{summary['eligible_original_external_evaluation']}`",
        f"- Vulnerable among potentially usable original cases: `{summary['eligible_original_external_evaluation_vulnerable']}`",
        f"- Non-vulnerable among potentially usable original cases: `{summary['eligible_original_external_evaluation_non_vulnerable']}`",
        f"- Cases potentially usable for candidate-ranking evaluation: `{summary['eligible_candidate_ranking']}`",
        "",
        "## Major Incompatibility Reasons",
        "",
        markdown_counter(summary["major_incompatibility_reasons"]),
        "",
        "## Required Adapters",
        "",
        markdown_counter(summary["required_adapter_distribution"]),
        "",
        "## Required Adapters Among Potentially Compatible Original Cases",
        "",
        markdown_counter(summary["compatible_required_adapter_distribution"]),
        "",
        "## Preliminary Ranking Scale",
        "",
        render_pack_table(summary["ranking_scale_by_pack_size"]),
        "",
        f"Recommended candidate pack size: `{summary['recommended_pack_size']}`.",
        f"Recommended candidate-test budget: `k={summary['recommended_candidate_test_budget_k']}`.",
        "",
        "## Validation",
        "",
        f"- Valid: `{validation['valid']}`",
        f"- Errors: `{len(validation['errors'])}`",
        f"- Warnings: `{len(validation['warnings'])}`",
        f"- SQLi runtime executions: `{validation['runtime_execution_counts']['sqli_runtime_executions']}`",
        f"- GPT calls: `{validation['runtime_execution_counts']['gpt_calls']}`",
        f"- Qwen calls: `{validation['runtime_execution_counts']['qwen_calls']}`",
        "",
        "## Recommended Next Milestone",
        "",
        "Proceed to `v1.5 SQLi deterministic adapter + READINESS_ONLY validation` only after reviewing this audit. The readiness milestone should implement deterministic transport adapters and dry/runtime-readiness validation on a small stratified non-scored subset, without consuming the final confirmatory corpus.",
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
    lines = ["| Value | Total | Vulnerable | Non-vulnerable |", "| --- | ---: | ---: | ---: |"]
    for key, counts in sorted(values.items()):
        lines.append(f"| `{key}` | {counts['total']} | {counts['vulnerable']} | {counts['non_vulnerable']} |")
    return "\n".join(lines)


def render_pack_table(pack_options: dict[str, dict[str, Any]]) -> str:
    lines = [
        "| Pack size | Positive scenarios | Negative-only scenarios | Mean decoy reuse | Max decoy reuse | Candidate tests per arm/trial set |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for key in sorted(pack_options, key=int):
        item = pack_options[key]
        lines.append(
            f"| {key} | {item['positive_scenarios']} | {item['negative_only_scenarios_disjoint']} | "
            f"{item['mean_negative_case_reuse_for_positive_scenarios']} | {item['maximum_negative_case_reuse_for_positive_scenarios']} | "
            f"{item['candidate_tests_per_arm_or_trial_set']} |"
        )
    return "\n".join(lines)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_AUDIT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def render_checksums(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "checksums.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksums(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    root = path.parent
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        actual = sha256_file(root / rel)
        if expected != actual:
            errors.append(f"{rel}: expected {expected}, got {actual}")
    return {
        "schema_version": "owasp-sqli-v15-checksum-validation-v1",
        "valid": not errors,
        "errors": errors,
    }


def write_outputs(
    audit_rows: list[dict[str, str]],
    expected_rows: list[ExpectedResult],
    summary: dict[str, Any],
    output_dir: Path,
    benchmark_root: Path,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    validation = validate_audit(audit_rows, expected_rows, benchmark_root)
    write_csv(output_dir / "case-audit.csv", audit_rows)
    write_json(output_dir / "audit-summary.json", summary)
    write_json(output_dir / "validation-report.json", validation)
    write_json(output_dir / "provenance.json", summary["benchmark_provenance"])
    write_json(output_dir / "adapter-requirements.json", adapter_requirements(audit_rows))
    write_json(output_dir / "candidate-schema.json", candidate_schema())
    write_json(output_dir / "ranking-design-recommendation.json", ranking_design(summary))
    write_json(output_dir / "compatibility-rules.json", compatibility_rules())
    (output_dir / "audit-summary.md").write_text(render_summary_markdown(summary, validation), encoding="utf-8")
    (output_dir / "methodological-decision-log.md").write_text(decision_log(summary), encoding="utf-8")
    (output_dir / "checksums.sha256").write_text(render_checksums(output_dir), encoding="utf-8")
    checksum_validation = validate_checksums(output_dir / "checksums.sha256")
    write_json(output_dir / "checksum-validation-report.json", checksum_validation)
    if not validation["valid"] or not checksum_validation["valid"]:
        raise RuntimeError("SQLi v1.5 compatibility audit validation failed")
    return validation


def compatibility_rules() -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-compatibility-rules-v1",
        "status": "audit_rules_not_final_scored_protocol",
        "classes": {
            "DIRECT": "Original read-like case appears usable without a new deterministic transport adapter and still requires runtime verifier validation.",
            "ADAPTER_SUPPORTED": "Original read-like case may remain semantically intact but requires deterministic transport adapter support before execution.",
            "DERIVED_ADAPTED": "Original case is not directly usable without changing semantics; no such cases are selected by this first audit.",
            "EXCLUDED": "Original case conflicts with the non-destructive verifier philosophy or lacks controllable input.",
            "MANUAL_REVIEW": "Static evidence is insufficient to decide compatibility.",
        },
        "non_destructive_rule": "Write/state-changing operations and ambiguous stored procedures are excluded from original direct/adapter-supported eligibility.",
        "transport_rule": "Transport compatibility does not imply SQL/verifier compatibility.",
        "verifier_rule": "Read-like cases require later runtime validation of stable baseline behavior and reproducible true/false differences.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit OWASP Benchmark Java SQLi compatibility for v1.5 planning.")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    audit_rows, context = build_case_audit(args.benchmark_root)
    summary = summarize(audit_rows, context["provenance"])
    validation = write_outputs(audit_rows, context["all_expected_results"], summary, args.output_dir, args.benchmark_root)
    print(f"OWASP SQLi cases audited: {summary['total_sqli']}")
    print(f"Vulnerable: {summary['vulnerable_sqli']}")
    print(f"Non-vulnerable: {summary['non_vulnerable_sqli']}")
    print(f"Validation valid: {validation['valid']}")
    print(f"Artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
