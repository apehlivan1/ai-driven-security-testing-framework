from __future__ import annotations

import argparse
import csv
import hashlib
import json
import ssl
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree

from adstf.contracts import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
)
from adstf.execution import HttpExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier

from scripts.audit_owasp_benchmark_sqli import (
    DEFAULT_BENCHMARK_ROOT,
    DEFAULT_OUTPUT_DIR as DEFAULT_AUDIT_DIR,
    CASE_AUDIT_FIELDS,
    FORBIDDEN_MODELFACING_FRAGMENTS,
    MODEL_FACING_FIELDS,
    build_case_audit,
    parse_expected_results,
    summarize,
    validate_audit,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-readiness"
DEFAULT_BASE_URL = "https://127.0.0.1:8443/benchmark"

READINESS_SELECTION_SEED = "owasp-sqli-v15-readiness-selection-v1"
READINESS_CLASSES = ("form", "multi_form", "multi_query", "header", "cookie")
READINESS_PER_CLASS_PER_LABEL = 2
BASELINE_VALUE_POLICY = "original_owasp_crawler_value"
TRUE_PROBE_VALUE = "missing' OR '1'='1' -- "
FALSE_PROBE_VALUE = "missing' AND '1'='2' -- "


@dataclass(frozen=True)
class OwaspInput:
    carrier: str
    name: str
    value: str


@dataclass(frozen=True)
class OriginalBenchmarkProvenance:
    opaque_candidate_id: str
    benchmark_case_id: str
    benchmark_name: str
    benchmark_version: str
    benchmark_revision: str
    source_file: str
    endpoint: str
    input_carrier_shape: str
    compatibility_class: str
    evaluation_role: str
    expected_result: str


@dataclass(frozen=True)
class ExecutionSpecification:
    opaque_candidate_id: str
    endpoint: str
    method: str
    adapter_class: str
    target_input_name: str
    target_input_carrier: str
    inputs: list[OwaspInput]
    content_type: str
    baseline_value: str
    true_value: str
    false_value: str


@dataclass(frozen=True)
class RankerFacingCandidate:
    candidate_id: str
    sanitized_action_path: str
    http_method: str
    input_carrier: str
    input_count_category: str
    editable_input_count: int
    multiple_parameters: bool
    transport_adapter_category: str
    request_shape: str


@dataclass(frozen=True)
class OwaspSqliCandidate:
    provenance: OriginalBenchmarkProvenance
    execution: ExecutionSpecification
    ranker_candidate: RankerFacingCandidate


def load_case_audit(path: Path = DEFAULT_AUDIT_DIR / "case-audit.csv") -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_case_audit(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_AUDIT_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_crawler_inputs(benchmark_root: Path = DEFAULT_BENCHMARK_ROOT) -> dict[str, list[OwaspInput]]:
    tree = ElementTree.parse(benchmark_root / "data" / "benchmark-crawler-http.xml")
    output: dict[str, list[OwaspInput]] = {}
    for element in tree.getroot().findall("benchmarkTest"):
        output[element.attrib["tcName"]] = [
            OwaspInput(
                carrier=child.tag,
                name=child.attrib.get("name", ""),
                value=child.attrib.get("value", ""),
            )
            for child in list(element)
        ]
    return output


def readiness_adapter_class(row: dict[str, str]) -> str:
    shape = row["input_carrier_shape"]
    if shape == "formparam":
        return "form"
    if shape.startswith("formparam+"):
        return "multi_form"
    if shape == "getparam+getparam+getparam":
        return "multi_query"
    if shape == "header":
        return "header"
    if shape == "cookie":
        return "cookie"
    return "unsupported"


def select_readiness_rows(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[str]]:
    selected: list[dict[str, str]] = []
    notes: list[str] = []
    for adapter_class in READINESS_CLASSES:
        for expected_result in ("vulnerable", "non_vulnerable"):
            pool = [
                row
                for row in rows
                if row["compatibility_class"] == "ADAPTER_SUPPORTED"
                and readiness_adapter_class(row) == adapter_class
                and row["expected_result"] == expected_result
            ]
            ordered = sorted(pool, key=lambda row: stable_selection_key(row, adapter_class, expected_result))
            chosen = ordered[:READINESS_PER_CLASS_PER_LABEL]
            if len(chosen) < READINESS_PER_CLASS_PER_LABEL:
                notes.append(
                    f"{adapter_class}/{expected_result}: requested {READINESS_PER_CLASS_PER_LABEL}, selected {len(chosen)}"
                )
            selected.extend(chosen)
    return selected, notes


def stable_selection_key(row: dict[str, str], adapter_class: str, expected_result: str) -> str:
    text = "|".join(
        [
            READINESS_SELECTION_SEED,
            adapter_class,
            expected_result,
            row["benchmark_case_id"],
            row["benchmark_revision"],
        ]
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def assign_evaluation_roles(rows: list[dict[str, str]], readiness_case_ids: set[str]) -> list[dict[str, str]]:
    assigned: list[dict[str, str]] = []
    for row in rows:
        item = dict(row)
        if item["benchmark_case_id"] in readiness_case_ids:
            item["evaluation_role"] = "READINESS_ONLY"
        elif item["compatibility_class"] == "ADAPTER_SUPPORTED":
            item["evaluation_role"] = "FINAL_CONFIRMATORY_ELIGIBLE"
        else:
            item["evaluation_role"] = "EXCLUDED"
        assigned.append(item)
    return assigned


def construct_candidate(row: dict[str, str], crawler_inputs: list[OwaspInput]) -> OwaspSqliCandidate:
    if row["compatibility_class"] != "ADAPTER_SUPPORTED":
        raise ValueError(f"{row['benchmark_case_id']} is not adapter-supported")
    target_input = target_input_for(row["benchmark_case_id"], crawler_inputs)
    adapter_class = readiness_adapter_class(row)
    candidate_id = row["sanitized_candidate_id"]
    execution = ExecutionSpecification(
        opaque_candidate_id=candidate_id,
        endpoint=row["endpoint"],
        method="GET" if adapter_class == "multi_query" else "POST" if adapter_class in {"form", "multi_form"} else "GET",
        adapter_class=adapter_class,
        target_input_name=target_input.name,
        target_input_carrier=target_input.carrier,
        inputs=crawler_inputs,
        content_type="application/x-www-form-urlencoded" if adapter_class in {"form", "multi_form"} else "not_applicable",
        baseline_value=target_input.value,
        true_value=TRUE_PROBE_VALUE,
        false_value=FALSE_PROBE_VALUE,
    )
    provenance = OriginalBenchmarkProvenance(
        opaque_candidate_id=candidate_id,
        benchmark_case_id=row["benchmark_case_id"],
        benchmark_name=row["benchmark_name"],
        benchmark_version=row["benchmark_version"],
        benchmark_revision=row["benchmark_revision"],
        source_file=row["source_file"],
        endpoint=row["endpoint"],
        input_carrier_shape=row["input_carrier_shape"],
        compatibility_class=row["compatibility_class"],
        evaluation_role=row["evaluation_role"],
        expected_result=row["expected_result"],
    )
    ranker_candidate = RankerFacingCandidate(
        candidate_id=candidate_id,
        sanitized_action_path=row["sanitized_action_path"],
        http_method=sanitized_http_method(execution),
        input_carrier=sanitized_carrier(row["primary_input_carrier"]),
        input_count_category=input_count_category(len(crawler_inputs)),
        editable_input_count=len(crawler_inputs),
        multiple_parameters=len(crawler_inputs) > 1,
        transport_adapter_category=adapter_class,
        request_shape=sanitized_request_shape(row["request_shape"]),
    )
    validate_model_facing_candidate(ranker_candidate)
    return OwaspSqliCandidate(provenance=provenance, execution=execution, ranker_candidate=ranker_candidate)


def target_input_for(case_id: str, inputs: list[OwaspInput]) -> OwaspInput:
    for item in inputs:
        if item.name == case_id:
            return item
    if inputs:
        return inputs[-1]
    raise ValueError(f"{case_id} has no crawler input metadata")


def sanitized_http_method(execution: ExecutionSpecification) -> str:
    if execution.adapter_class == "multi_query":
        return "GET"
    if execution.adapter_class in {"form", "multi_form"}:
        return "POST"
    return "GET_with_request_metadata"


def sanitized_carrier(carrier: str) -> str:
    return {
        "getparam": "query_parameter",
        "formparam": "form_parameter",
        "header": "header",
        "cookie": "cookie",
    }.get(carrier, "unknown")


def input_count_category(count: int) -> str:
    if count <= 0:
        return "none"
    if count == 1:
        return "single"
    if count <= 3:
        return "small_multi"
    return "larger_multi"


def sanitized_request_shape(shape: str) -> str:
    return {
        "GET_query": "query",
        "POST_form": "form",
        "header": "header",
        "cookie": "cookie",
    }.get(shape, "other")


def validate_model_facing_candidate(candidate: RankerFacingCandidate) -> None:
    serialized = json.dumps(asdict(candidate), sort_keys=True)
    for fragment in FORBIDDEN_MODELFACING_FRAGMENTS:
        if fragment in serialized:
            raise ValueError(f"model-facing candidate leaks forbidden fragment: {fragment}")


def build_request(
    base_url: str,
    spec: ExecutionSpecification,
    value: str,
) -> tuple[str, str, dict[str, str], str | None]:
    url = urljoin(ensure_trailing_slash(base_url), spec.endpoint.lstrip("/"))
    headers: dict[str, str] = {}
    body: str | None = None
    if spec.adapter_class == "multi_query":
        return add_query_parameters(url, replace_input_values(spec.inputs, spec.target_input_name, value)), "GET", headers, None
    if spec.adapter_class in {"form", "multi_form"}:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        body = urlencode(replace_input_values(spec.inputs, spec.target_input_name, value))
        return url, "POST", headers, body
    if spec.adapter_class == "header":
        headers[spec.target_input_name] = value
        return url, "GET", headers, None
    if spec.adapter_class == "cookie":
        headers["Cookie"] = f"{spec.target_input_name}={value}"
        return url, "GET", headers, None
    raise ValueError(f"unsupported adapter class: {spec.adapter_class}")


def replace_input_values(inputs: list[OwaspInput], target_name: str, value: str) -> list[tuple[str, str]]:
    return [(item.name, value if item.name == target_name else item.value) for item in inputs]


def add_query_parameters(url: str, pairs: list[tuple[str, str]]) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(pairs)
    return urlunparse(parsed._replace(query=urlencode(query)))


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"


def target_config_for_url(base_url: str) -> TargetConfig:
    parsed = urlparse(base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return TargetConfig(
        name="OWASP Benchmark Java SQLi v1.5 readiness",
        base_url=base_url,
        allowed_hosts=[parsed.hostname or "127.0.0.1"],
        allowed_ports=[port],
        allowed_schemes=[parsed.scheme],
        enabled_modules=["sqli.boolean"],
        max_actions=200,
        metadata={"evaluation": "owasp-sqli-v15-readiness", "local_only": True},
    )


def health_check(base_url: str, timeout_seconds: float = 8.0) -> dict[str, Any]:
    context = ssl._create_unverified_context() if base_url.startswith("https://") else None
    started = datetime.now(UTC).isoformat()
    try:
        request = Request(base_url, headers={"User-Agent": "adstf-v15-sqli-readiness"})
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            return {
                "reachable": 200 <= int(response.status) < 500,
                "status": int(response.status),
                "url": response.geturl(),
                "started_at": started,
                "completed_at": datetime.now(UTC).isoformat(),
                "error": None,
            }
    except Exception as exc:
        return {
            "reachable": False,
            "status": None,
            "url": base_url,
            "started_at": started,
            "completed_at": datetime.now(UTC).isoformat(),
            "error": str(exc),
        }


def run_readiness(
    *,
    benchmark_root: Path = DEFAULT_BENCHMARK_ROOT,
    audit_dir: Path = DEFAULT_AUDIT_DIR,
    output_dir: Path = DEFAULT_READINESS_DIR,
    base_url: str = DEFAULT_BASE_URL,
) -> dict[str, Any]:
    rows = load_case_audit(audit_dir / "case-audit.csv")
    selected_rows, selection_notes = select_readiness_rows(rows)
    selected_case_ids = {row["benchmark_case_id"] for row in selected_rows}
    assigned_rows = assign_evaluation_roles(rows, selected_case_ids)
    selected_rows = [row for row in assigned_rows if row["benchmark_case_id"] in selected_case_ids]
    output_dir.mkdir(parents=True, exist_ok=True)

    crawler_inputs = parse_crawler_inputs(benchmark_root)
    candidates = [construct_candidate(row, crawler_inputs[row["benchmark_case_id"]]) for row in selected_rows]
    selection_manifest = build_selection_manifest(selected_rows, selection_notes)
    write_json(output_dir / "selection-manifest.json", selection_manifest)
    write_json(output_dir / "sanitized-candidate-preview.json", [asdict(candidate.ranker_candidate) for candidate in candidates])
    write_json(output_dir / "internal-provenance.json", [asdict(candidate.provenance) for candidate in candidates])
    write_json(output_dir / "execution-specifications.json", [asdict(candidate.execution) for candidate in candidates])

    audit_context_rows, context = build_case_audit(benchmark_root)
    reconciled_audit_rows = assign_reconciled_rows(audit_context_rows, assigned_rows)
    summary = summarize(reconciled_audit_rows, context["provenance"])
    expected_rows = parse_expected_results(benchmark_root / "expectedresults-1.2.csv")
    audit_validation = validate_audit(reconciled_audit_rows, expected_rows, benchmark_root)
    write_case_audit(output_dir / "updated-compatibility-inventory.csv", reconciled_audit_rows)
    write_json(output_dir / "reconciled-audit-summary.json", summary)
    write_json(output_dir / "reconciled-audit-validation.json", audit_validation)
    write_json(output_dir / "reconciled-corpus-summary.json", reconciled_corpus_summary(reconciled_audit_rows))
    write_json(output_dir / "manual-review-reconciliation.json", manual_review_reconciliation(reconciled_audit_rows))
    write_json(output_dir / "preliminary-final-ranking-scale.json", final_ranking_scale(reconciled_audit_rows))
    write_text(output_dir / "adapter-implementation.md", adapter_implementation_document())
    write_text(output_dir / "methodological-decision-log.md", methodological_decision_log())

    target = target_config_for_url(base_url)
    safety = SafetyBoundary(target)
    health = health_check(base_url)
    run_id = f"owasp-sqli-v15-readiness-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_dir / "runs", run_id)
    store.initialize(target)

    runtime_results: list[dict[str, Any]] = []
    if health["reachable"]:
        runtime_results = attach_post_execution_ground_truth(
            candidates,
            execute_readiness_cases(candidates, target, safety, store, base_url),
        )

    readiness = {
        "schema_version": "owasp-sqli-v15-readiness-results-v1",
        "status": classify_readiness_status(candidates, health, runtime_results),
        "base_url": base_url,
        "health": health,
        "run_id": run_id,
        "run_dir": str(store.run_dir),
        "selected_case_count": len(candidates),
        "selected_case_ids": [candidate.provenance.benchmark_case_id for candidate in candidates],
        "readiness_results": runtime_results,
        "summary": readiness_runtime_summary(candidates, runtime_results),
        "selection_manifest": "selection-manifest.json",
        "ground_truth_loaded_only_after_execution": True,
        "final_confirmatory_cases_executed": False,
        "gpt_calls_executed": False,
        "qwen_calls_executed": False,
        "audit_validation": audit_validation,
    }
    write_json(output_dir / "readiness-results.json", readiness)
    validation_report = validate_readiness_package(output_dir, candidates, readiness, reconciled_audit_rows)
    write_json(output_dir / "validation-report.json", validation_report)
    write_text(output_dir / "readiness-report.md", render_readiness_report(readiness, validation_report))
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_validation = validate_checksums(output_dir / "checksums.sha256")
    write_json(output_dir / "checksum-validation-report.json", checksum_validation)
    if not validation_report["valid"] or not checksum_validation["valid"]:
        raise RuntimeError("SQLi v1.5 readiness package validation failed")
    return readiness


def assign_reconciled_rows(static_rows: list[dict[str, str]], assigned_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    roles = {row["benchmark_case_id"]: row["evaluation_role"] for row in assigned_rows}
    output = []
    for row in static_rows:
        item = dict(row)
        item["evaluation_role"] = roles.get(
            item["benchmark_case_id"],
            "FINAL_CONFIRMATORY_ELIGIBLE" if item["compatibility_class"] == "ADAPTER_SUPPORTED" else "EXCLUDED",
        )
        output.append(item)
    return output


def execute_readiness_cases(
    candidates: list[OwaspSqliCandidate],
    target: TargetConfig,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    base_url: str,
) -> list[dict[str, Any]]:
    executor = HttpExecutor(safety, verify_tls=False, timeout_seconds=8.0)
    modules = mvp_modules()
    results: list[dict[str, Any]] = []
    for candidate in candidates:
        results.append(execute_one_candidate(candidate, target, executor, store, base_url, modules))
    store.save_report(render_placeholder_report(target, [], placeholder=False))
    return results


def execute_one_candidate(
    candidate: OwaspSqliCandidate,
    target: TargetConfig,
    executor: HttpExecutor,
    store: RunArtifactStore,
    base_url: str,
    modules: dict[str, Any],
) -> dict[str, Any]:
    phases = {
        "baseline_1": candidate.execution.baseline_value,
        "baseline_2": candidate.execution.baseline_value,
        "true_1": candidate.execution.true_value,
        "true_2": candidate.execution.true_value,
        "false_1": candidate.execution.false_value,
        "false_2": candidate.execution.false_value,
    }
    observations: dict[str, tuple[ActionResult, list[EvidenceRecord]]] = {}
    for phase, value in phases.items():
        action = build_http_action(store.run_id, target, candidate, base_url, value, phase)
        store.save_action_request(action)
        result, evidence = executor.execute(action)
        store.save_action_result(result)
        for item in evidence:
            store.save_evidence(item)
        observations[phase] = (result, evidence)
    comparison = comparison_evidence(store.run_id, candidate, observations)
    store.save_evidence(comparison)
    finding = verify_candidate(store, target, modules, candidate, comparison, [item for _, evidence in observations.values() for item in evidence])
    expected_vulnerable = candidate.provenance.expected_result == "vulnerable"
    return {
        "candidate_id": candidate.ranker_candidate.candidate_id,
        "benchmark_case_id": candidate.provenance.benchmark_case_id,
        "evaluation_role": candidate.provenance.evaluation_role,
        "adapter_class": candidate.execution.adapter_class,
        "action_statuses": {phase: result.status.value for phase, (result, _evidence) in observations.items()},
        "comparison_evidence_id": comparison.evidence_id,
        "baseline_stable": comparison.attributes["baseline_stable"],
        "true_false_difference_reproducible": comparison.attributes["true_false_difference_reproducible"],
        "server_error_observed": comparison.attributes["server_error_observed"],
        "finding_state": finding.state.value,
        "ground_truth_used_phase": "not_loaded_during_runtime_execution",
    }


def attach_post_execution_ground_truth(
    candidates: list[OwaspSqliCandidate],
    runtime_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {candidate.ranker_candidate.candidate_id: candidate for candidate in candidates}
    enriched: list[dict[str, Any]] = []
    for result in runtime_results:
        candidate = by_id[str(result["candidate_id"])]
        expected_vulnerable = candidate.provenance.expected_result == "vulnerable"
        item = dict(result)
        item["expected_result_loaded_after_execution"] = candidate.provenance.expected_result
        item["ground_truth_match_for_readiness_only"] = (item["finding_state"] == "verified") == expected_vulnerable
        item["ground_truth_used_phase"] = "post_execution_readiness_report_only"
        enriched.append(item)
    return enriched


def build_http_action(
    run_id: str,
    target: TargetConfig,
    candidate: OwaspSqliCandidate,
    base_url: str,
    value: str,
    phase: str,
) -> ActionRequest:
    url, method, headers, body = build_request(base_url, candidate.execution, value)
    parameters: dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": headers,
        "capture_body_text": True,
        "body_text_limit": 4096,
    }
    if body is not None:
        parameters["body"] = body
        parameters["body_encoding"] = "utf-8"
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="owasp_sqli_v15_readiness",
        module_id="sqli.boolean",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=url,
        scope_context={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "evaluation_role": candidate.provenance.evaluation_role,
            "phase": phase,
            "ground_truth_loaded": False,
        },
        parameters=parameters,
        preconditions=["owasp_benchmark_java_running_locally", "readiness_only_case", "non_destructive_boolean_probe"],
        safety_class=SafetyClass.LOW,
        rationale="Execute deterministic OWASP SQLi readiness request.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def comparison_evidence(
    run_id: str,
    candidate: OwaspSqliCandidate,
    observations: dict[str, tuple[ActionResult, list[EvidenceRecord]]],
) -> EvidenceRecord:
    evidence_by_phase = {phase: evidence[0] for phase, (_, evidence) in observations.items()}
    fingerprints = {phase: fingerprint(evidence) for phase, evidence in evidence_by_phase.items()}
    statuses = {phase: evidence.attributes.get("status_code") for phase, evidence in evidence_by_phase.items()}
    baseline_stable = fingerprints["baseline_1"] == fingerprints["baseline_2"]
    true_stable = fingerprints["true_1"] == fingerprints["true_2"]
    false_stable = fingerprints["false_1"] == fingerprints["false_2"]
    true_false_difference = fingerprints["true_1"] != fingerprints["false_1"]
    all_status_ok = all(status == 200 for status in statuses.values())
    server_error_observed = any(isinstance(status, int) and status >= 500 for status in statuses.values())
    reflected_payload_only = payload_reflected(candidate.execution.true_value, evidence_by_phase["true_1"]) or payload_reflected(
        candidate.execution.false_value,
        evidence_by_phase["false_1"],
    )
    true_false_difference_reproducible = (
        baseline_stable
        and true_stable
        and false_stable
        and true_false_difference
        and all_status_ok
        and not server_error_observed
        and not reflected_payload_only
    )
    control_case_passed = baseline_stable and true_stable and false_stable and all_status_ok and not server_error_observed
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="owasp_sqli_v15_readiness",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=evidence_by_phase["true_1"].target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary=f"Compared baseline, boolean-true, and boolean-false responses for {candidate.ranker_candidate.candidate_id}.",
        data_ref=None,
        redaction_status=RedactionStatus.REDACTED,
        related_action_ids=[result.action_id for result, _ in observations.values()],
        attributes={
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "adapter_class": candidate.execution.adapter_class,
            "payload_family": "bounded_boolean_condition",
            "baseline_stable": baseline_stable,
            "true_condition_stable": true_stable,
            "false_condition_stable": false_stable,
            "true_false_difference": true_false_difference,
            "true_false_difference_reproducible": true_false_difference_reproducible,
            "all_status_ok": all_status_ok,
            "server_error_observed": server_error_observed,
            "reflected_payload_only": reflected_payload_only,
            "is_control_case": True,
            "control_case_passed": control_case_passed,
            "rejects_hypothesis": False,
            "fingerprints": fingerprints,
            "status_codes": statuses,
            "ground_truth_used": False,
        },
    )


def verify_candidate(
    store: RunArtifactStore,
    target: TargetConfig,
    modules: dict[str, Any],
    candidate: OwaspSqliCandidate,
    comparison: EvidenceRecord,
    http_evidence: list[EvidenceRecord],
) -> FindingRecord:
    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=store.run_id,
        module_id="sqli.boolean",
        title=f"Boolean SQL injection readiness candidate {candidate.ranker_candidate.candidate_id}",
        category=modules["sqli.boolean"].category,
        affected_target=target.base_url,
        state=FindingState.SUSPECTED,
        hypothesis="A request input may alter database query logic through deterministic boolean conditions.",
        created_by="owasp_sqli_v15_readiness",
        supporting_evidence_refs=[*[evidence.evidence_id for evidence in http_evidence], comparison.evidence_id],
        report_fields={
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "input_carrier": candidate.ranker_candidate.input_carrier,
            "baseline": "[original crawler value]",
            "true_condition": "[bounded boolean true condition]",
            "false_condition": "[bounded boolean false condition]",
        },
        severity="medium",
        confidence="readiness_only_deterministic_verifier",
    )
    store.save_finding(finding)
    requested = request_verification(finding)
    store.save_finding(requested)
    result = FindingVerifier(modules).verify(requested, [*http_evidence, comparison])
    store.save_verifier_result(result)
    updated = apply_verifier_result(requested, result)
    store.save_finding(updated)
    return updated


def fingerprint(evidence: EvidenceRecord) -> dict[str, Any]:
    return {
        "status_code": evidence.attributes.get("status_code"),
        "body_sha256": evidence.attributes.get("body_sha256"),
        "body_length": evidence.attributes.get("body_length"),
    }


def payload_reflected(payload: str, evidence: EvidenceRecord) -> bool:
    body_text = evidence.attributes.get("body_text")
    return isinstance(body_text, str) and payload in body_text


def build_selection_manifest(rows: list[dict[str, str]], notes: list[str]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-readiness-selection-v1",
        "selection_seed": READINESS_SELECTION_SEED,
        "selection_policy": f"{READINESS_PER_CLASS_PER_LABEL} cases per adapter class and expected-result label where available",
        "readiness_case_count": len(rows),
        "expected_result_distribution": dict(Counter(row["expected_result"] for row in rows)),
        "adapter_class_distribution": dict(Counter(readiness_adapter_class(row) for row in rows)),
        "notes": notes,
        "selected_cases": [
            {
                "opaque_candidate_id": row["sanitized_candidate_id"],
                "benchmark_case_id": row["benchmark_case_id"],
                "adapter_class": readiness_adapter_class(row),
                "expected_result": row["expected_result"],
                "selection_hash": stable_selection_key(row, readiness_adapter_class(row), row["expected_result"]),
            }
            for row in rows
        ],
        "final_confirmatory_exclusion_policy": "READINESS_ONLY cases must not enter future final confirmatory denominators.",
    }


def reconciled_corpus_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    by_role = Counter(row["evaluation_role"] for row in rows)
    final = [row for row in rows if row["evaluation_role"] == "FINAL_CONFIRMATORY_ELIGIBLE"]
    return {
        "schema_version": "owasp-sqli-v15-reconciled-corpus-summary-v1",
        "original_total": len(rows),
        "readiness_only_count": by_role.get("READINESS_ONLY", 0),
        "final_confirmatory_eligible_count": len(final),
        "final_confirmatory_eligible_vulnerable": sum(row["expected_result"] == "vulnerable" for row in final),
        "final_confirmatory_eligible_non_vulnerable": sum(row["expected_result"] == "non_vulnerable" for row in final),
        "excluded_count": by_role.get("EXCLUDED", 0),
        "manual_review_count": sum(row["compatibility_class"] == "MANUAL_REVIEW" for row in rows),
        "compatibility_distribution": nested_counts(rows, "compatibility_class"),
        "evaluation_role_distribution": nested_counts(rows, "evaluation_role"),
    }


def manual_review_reconciliation(rows: list[dict[str, str]]) -> dict[str, Any]:
    manual = [row for row in rows if row["compatibility_class"] == "MANUAL_REVIEW"]
    return {
        "schema_version": "owasp-sqli-v15-manual-review-reconciliation-v1",
        "review_method": "offline_static_only",
        "manual_review_before": len(manual),
        "manual_review_after": len(manual),
        "reclassified_cases": 0,
        "reason": "Manual-review cases remain unresolved because static source evidence shows writer output but not a sufficient deterministic boolean response oracle.",
        "distribution_by_response_observability": dict(Counter(row["response_observability"] for row in manual)),
        "distribution_by_input_carrier": dict(Counter(row["input_carrier_shape"] for row in manual)),
        "runtime_executions": 0,
    }


def final_ranking_scale(rows: list[dict[str, str]]) -> dict[str, Any]:
    final = [row for row in rows if row["evaluation_role"] == "FINAL_CONFIRMATORY_ELIGIBLE"]
    vulnerable = [row for row in final if row["expected_result"] == "vulnerable"]
    negative = [row for row in final if row["expected_result"] == "non_vulnerable"]
    pack_size = 5
    budget = 4
    positive_scenarios = len(vulnerable)
    negative_only = len(negative) // pack_size
    decoy_assignments = positive_scenarios * (pack_size - 1)
    max_reuse = (decoy_assignments + len(negative) - 1) // len(negative) if negative else 0
    core = positive_scenarios + negative_only
    return {
        "schema_version": "owasp-sqli-v15-preliminary-final-ranking-scale-v1",
        "status": "preliminary_not_frozen",
        "pack_size": pack_size,
        "candidate_test_budget_k": budget,
        "positive_scenarios": positive_scenarios,
        "negative_only_scenarios": negative_only,
        "total_core_ranking_scenarios": core,
        "unique_original_cases_represented": len(final),
        "required_negative_decoy_assignments": decoy_assignments,
        "maximum_negative_decoy_reuse": max_reuse,
        "deterministic_rows": core,
        "projected_gpt_rows_at_five_trials": core * 5,
        "projected_qwen_rows_at_five_trials": core * 5,
        "total_projected_ranking_rows": core + (core * 5) + (core * 5),
        "readiness_cases_excluded_from_final": sum(row["evaluation_role"] == "READINESS_ONLY" for row in rows),
    }


def readiness_runtime_summary(candidates: list[OwaspSqliCandidate], runtime_results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "selected_cases": len(candidates),
        "runtime_cases_executed": len(runtime_results),
        "verified": sum(result.get("finding_state") == "verified" for result in runtime_results),
        "rejected": sum(result.get("finding_state") == "rejected" for result in runtime_results),
        "inconclusive": sum(result.get("finding_state") == "inconclusive" for result in runtime_results),
        "baseline_stable": sum(result.get("baseline_stable") is True for result in runtime_results),
        "boolean_difference_reproducible": sum(result.get("true_false_difference_reproducible") is True for result in runtime_results),
        "adapter_class_distribution": dict(Counter(candidate.execution.adapter_class for candidate in candidates)),
        "expected_result_distribution": dict(Counter(candidate.provenance.expected_result for candidate in candidates)),
    }


def classify_readiness_status(
    candidates: list[OwaspSqliCandidate],
    health: dict[str, Any],
    runtime_results: list[dict[str, Any]],
) -> str:
    if not health["reachable"]:
        return "FAIL"
    if len(runtime_results) != len(candidates):
        return "FAIL"
    adapter_coverage = set(READINESS_CLASSES) <= {candidate.execution.adapter_class for candidate in candidates}
    all_actions_executed = all(
        all(status == "executed" for status in result.get("action_statuses", {}).values())
        for result in runtime_results
    )
    verifier_completed = all(result.get("finding_state") in {"verified", "rejected", "inconclusive"} for result in runtime_results)
    no_server_errors = all(result.get("server_error_observed") is False for result in runtime_results)
    all_baselines_stable = all(result.get("baseline_stable") is True for result in runtime_results)
    if adapter_coverage and all_actions_executed and verifier_completed and no_server_errors and all_baselines_stable:
        return "PASS"
    if adapter_coverage and all_actions_executed and verifier_completed:
        return "PARTIAL_PASS"
    return "FAIL"


def validate_readiness_package(
    output_dir: Path,
    candidates: list[OwaspSqliCandidate],
    readiness: dict[str, Any],
    rows: list[dict[str, str]],
) -> dict[str, Any]:
    errors: list[str] = []
    if len(candidates) != len({candidate.ranker_candidate.candidate_id for candidate in candidates}):
        errors.append("readiness candidate IDs are not unique")
    if len(candidates) != READINESS_PER_CLASS_PER_LABEL * len(READINESS_CLASSES) * 2:
        errors.append("readiness selection size does not match expected stratified design")
    final_runtime = [row for row in readiness["readiness_results"] if row.get("evaluation_role") != "READINESS_ONLY"]
    if final_runtime:
        errors.append("non-readiness runtime result found")
    serialized_preview = (output_dir / "sanitized-candidate-preview.json").read_text(encoding="utf-8")
    for fragment in FORBIDDEN_MODELFACING_FRAGMENTS:
        if fragment in serialized_preview:
            errors.append(f"sanitized candidate preview leaks forbidden fragment: {fragment}")
    role_counts = Counter(row["evaluation_role"] for row in rows)
    if role_counts.get("READINESS_ONLY", 0) != len(candidates):
        errors.append("reconciled inventory readiness count does not match selected candidates")
    if readiness["gpt_calls_executed"] or readiness["qwen_calls_executed"]:
        errors.append("model calls were recorded during readiness")
    if readiness["final_confirmatory_cases_executed"]:
        errors.append("final-confirmatory cases were executed during readiness")
    return {
        "schema_version": "owasp-sqli-v15-readiness-validation-v1",
        "valid": not errors,
        "errors": errors,
        "readiness_status": readiness["status"],
        "expected_readiness_count": READINESS_PER_CLASS_PER_LABEL * len(READINESS_CLASSES) * 2,
        "selected_readiness_count": len(candidates),
        "final_eligible_runtime_executions": 0,
        "gpt_calls": 0,
        "qwen_calls": 0,
    }


def nested_counts(rows: list[dict[str, str]], field: str) -> dict[str, dict[str, int]]:
    output: dict[str, dict[str, int]] = {}
    for value in sorted({row[field] for row in rows}):
        selected = [row for row in rows if row[field] == value]
        output[value] = {
            "total": len(selected),
            "vulnerable": sum(row["expected_result"] == "vulnerable" for row in selected),
            "non_vulnerable": sum(row["expected_result"] == "non_vulnerable" for row in selected),
        }
    return output


def adapter_implementation_document() -> str:
    return """# OWASP SQLi v1.5 Adapter Implementation

Status: READINESS_ONLY support. The adapters construct deterministic requests from pinned OWASP crawler metadata. They do not modify OWASP Benchmark source, choose payloads dynamically, expose ground truth to rankers, or change SQLi verifier criteria.

- `form`: submits one form parameter using `application/x-www-form-urlencoded`.
- `multi_form`: submits all original form parameters and mutates only the audited target input.
- `multi_query`: preserves all original query parameters and mutates only the audited target input.
- `header`: sets the audited request header deterministically.
- `cookie`: sets the audited cookie deterministically.

Transport compatibility remains separate from SQL/verifier compatibility. Runtime readiness still requires stable baseline behavior and reproducible true/false response differences for verification.
"""


def methodological_decision_log() -> str:
    return """# OWASP SQLi v1.5 Readiness Decision Log

- READINESS_ONLY cases are selected before runtime execution using seed `owasp-sqli-v15-readiness-selection-v1`.
- READINESS_ONLY cases are permanently excluded from later final confirmatory denominators.
- SQLi payload values are deterministic framework-owned probes derived from the existing boolean-SQLi verifier philosophy.
- The LLM authority boundary remains unchanged: future rankers may order sanitized candidate IDs only.
- Ground truth is used only after readiness execution to summarize readiness behavior.
- Manual-review cases are revisited by offline static inspection only and remain unresolved when static evidence does not establish a sufficient boolean response oracle.
"""


def render_readiness_report(readiness: dict[str, Any], validation: dict[str, Any]) -> str:
    summary = readiness["summary"]
    lines = [
        "# OWASP SQLi v1.5 READINESS_ONLY Report",
        "",
        f"- Status: `{readiness['status']}`",
        f"- Selected READINESS_ONLY cases: `{readiness['selected_case_count']}`",
        f"- Runtime cases executed: `{summary['runtime_cases_executed']}`",
        f"- Verified: `{summary['verified']}`",
        f"- Rejected: `{summary['rejected']}`",
        f"- Inconclusive: `{summary['inconclusive']}`",
        f"- Baseline stable cases: `{summary['baseline_stable']}`",
        f"- Reproducible boolean differences: `{summary['boolean_difference_reproducible']}`",
        f"- Health reachable: `{readiness['health']['reachable']}`",
        f"- Final-confirmatory cases executed: `{readiness['final_confirmatory_cases_executed']}`",
        f"- GPT calls: `{readiness['gpt_calls_executed']}`",
        f"- Qwen calls: `{readiness['qwen_calls_executed']}`",
        "",
        "## Adapter Coverage",
        "",
        markdown_counter(summary["adapter_class_distribution"]),
        "",
        "## Expected-Result Split",
        "",
        markdown_counter(summary["expected_result_distribution"]),
        "",
        "## Validation",
        "",
        f"- Valid: `{validation['valid']}`",
        f"- Errors: `{len(validation['errors'])}`",
    ]
    return "\n".join(lines) + "\n"


def markdown_counter(values: dict[str, Any]) -> str:
    if not values:
        return "_None._"
    lines = ["| Value | Count |", "| --- | ---: |"]
    for key, value in sorted(values.items()):
        lines.append(f"| `{key}` | {value} |")
    return "\n".join(lines)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "checksums.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksums(path: Path) -> dict[str, Any]:
    errors = []
    root = path.parent
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        actual = sha256_file(root / rel)
        if expected != actual:
            errors.append(f"{rel}: expected {expected}, got {actual}")
    return {
        "schema_version": "owasp-sqli-v15-readiness-checksum-validation-v1",
        "valid": not errors,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OWASP SQLi v1.5 READINESS_ONLY validation.")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--audit-dir", type=Path, default=DEFAULT_AUDIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args()
    try:
        readiness = run_readiness(
            benchmark_root=args.benchmark_root,
            audit_dir=args.audit_dir,
            output_dir=args.output_dir,
            base_url=args.base_url,
        )
    except Exception as exc:
        print(f"OWASP SQLi v1.5 readiness failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"OWASP SQLi v1.5 readiness status: {readiness['status']}")
    print(f"Artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
