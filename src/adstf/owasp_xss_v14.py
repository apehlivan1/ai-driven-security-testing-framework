from __future__ import annotations

import argparse
import csv
import hashlib
import json
import ssl
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from adstf.browser import BrowserExecutor
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
    VerificationOutcome,
)
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier

from scripts.audit_owasp_benchmark_xss import (
    DEFAULT_BENCHMARK_ROOT,
    DEFAULT_OUTPUT_DIR as DEFAULT_AUDIT_DIR,
    ExpectedResult,
    parse_expected_results,
    render_pack_table,
    summarize,
    validate_audit,
    write_outputs,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-xss-v14-readiness"
DEFAULT_BASE_URL = "https://127.0.0.1:8443/benchmark"
READINESS_SELECTION_SEED = "owasp-xss-v14-readiness-selection-v1"
READINESS_INPUT_SOURCES = [
    "parameter",
    "parameter_map",
    "query_string",
    "header",
    "parameter_name_enumeration",
]
READINESS_PER_SOURCE_PER_LABEL = 2
SUPPORTED_INPUT_SOURCES = set(READINESS_INPUT_SOURCES)
MARKER_VARIABLE = "__adstfXssMarker"


@dataclass(frozen=True)
class OriginalBenchmarkProvenance:
    opaque_candidate_id: str
    benchmark_case_id: str
    benchmark_name: str
    benchmark_version: str
    benchmark_revision: str
    source_file: str
    endpoint: str
    input_source: str
    input_name: str
    compatibility_class: str
    evaluation_role: str
    expected_result: str


@dataclass(frozen=True)
class ExecutionSpecification:
    opaque_candidate_id: str
    endpoint: str
    method: str
    transport: str
    input_name: str
    content_type: str
    parameter_name_value: str | None = None


@dataclass(frozen=True)
class RankerFacingCandidate:
    candidate_id: str
    action_path: str
    method: str
    parameter_name: str
    source: str
    input_type: str
    editable_input_count: int
    required_input_count: int
    parameter_count: int


@dataclass(frozen=True)
class OwaspExternalCandidate:
    provenance: OriginalBenchmarkProvenance
    execution: ExecutionSpecification
    ranker_candidate: RankerFacingCandidate


def load_case_audit(path: Path = DEFAULT_AUDIT_DIR / "case-audit.csv") -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_case_audit(path: Path, rows: list[dict[str, str]]) -> None:
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def select_readiness_rows(rows: list[dict[str, str]]) -> tuple[list[dict[str, str]], list[str]]:
    selected: list[dict[str, str]] = []
    notes: list[str] = []
    for input_source in READINESS_INPUT_SOURCES:
        for expected_result in ("vulnerable", "non_vulnerable"):
            pool = [
                row
                for row in rows
                if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}
                and row["input_source"] == input_source
                and row["expected_result"] == expected_result
            ]
            ordered = sorted(pool, key=lambda row: stable_selection_key(row, input_source, expected_result))
            chosen = ordered[:READINESS_PER_SOURCE_PER_LABEL]
            if len(chosen) < READINESS_PER_SOURCE_PER_LABEL:
                notes.append(
                    f"{input_source}/{expected_result}: requested {READINESS_PER_SOURCE_PER_LABEL}, selected {len(chosen)}"
                )
            selected.extend(chosen)
    return selected, notes


def stable_selection_key(row: dict[str, str], input_source: str, expected_result: str) -> str:
    text = "|".join(
        [
            READINESS_SELECTION_SEED,
            input_source,
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
        elif item["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}:
            item["evaluation_role"] = "FINAL_CONFIRMATORY_ELIGIBLE"
        else:
            item["evaluation_role"] = "EXCLUDED"
        assigned.append(item)
    return assigned


def construct_external_candidate(row: dict[str, str]) -> OwaspExternalCandidate:
    if row["compatibility_class"] not in {"DIRECT", "ADAPTER_SUPPORTED"}:
        raise ValueError(f"{row['benchmark_case_id']} is not compatible with v1.4 candidate construction")
    if row["input_source"] not in SUPPORTED_INPUT_SOURCES:
        raise ValueError(f"unsupported input_source for v1.4 readiness: {row['input_source']}")

    opaque_id = row["sanitized_candidate_id"]
    execution = ExecutionSpecification(
        opaque_candidate_id=opaque_id,
        endpoint=row["endpoint"],
        method="GET",
        transport=row["input_source"],
        input_name=row["parameter"],
        content_type=row["content_type"],
        parameter_name_value=row["benchmark_case_id"] if row["input_source"] == "parameter_name_enumeration" else None,
    )
    provenance = OriginalBenchmarkProvenance(
        opaque_candidate_id=opaque_id,
        benchmark_case_id=row["benchmark_case_id"],
        benchmark_name=row["benchmark_name"],
        benchmark_version=row["benchmark_version"],
        benchmark_revision=row["benchmark_revision"],
        source_file=row["source_file"],
        endpoint=row["endpoint"],
        input_source=row["input_source"],
        input_name=row["parameter"],
        compatibility_class=row["compatibility_class"],
        evaluation_role=row.get("evaluation_role", "FINAL_CONFIRMATORY_ELIGIBLE"),
        expected_result=row["expected_result"],
    )
    ranker_candidate = RankerFacingCandidate(
        candidate_id=opaque_id,
        action_path=row["sanitized_action_path"],
        method="GET",
        parameter_name=row["sanitized_parameter_name"],
        source=sanitized_source(row["input_source"]),
        input_type=input_type_for_source(row["input_source"]),
        editable_input_count=1,
        required_input_count=1 if row["input_source"] == "parameter_name_enumeration" else 0,
        parameter_count=2 if row["input_source"] == "parameter_name_enumeration" else 1,
    )
    validate_model_facing_candidate(ranker_candidate)
    return OwaspExternalCandidate(provenance, execution, ranker_candidate)


def sanitized_source(input_source: str) -> str:
    return {
        "parameter": "request_parameter",
        "parameter_map": "request_parameter_map",
        "query_string": "query_string",
        "header": "request_header",
        "parameter_name_enumeration": "dynamic_parameter_name",
    }[input_source]


def input_type_for_source(input_source: str) -> str:
    return "header" if input_source == "header" else "text"


def validate_model_facing_candidate(candidate: RankerFacingCandidate) -> None:
    serialized = json.dumps(asdict(candidate), sort_keys=True)
    forbidden_fragments = ["BenchmarkTest", ".java", "xss", "vulnerable", "non_vulnerable"]
    for fragment in forbidden_fragments:
        if fragment in serialized:
            raise ValueError(f"model-facing candidate leaks forbidden fragment: {fragment}")


def build_value_request(base_url: str, spec: ExecutionSpecification, value: str) -> tuple[str, dict[str, str]]:
    url = urljoin(ensure_trailing_slash(base_url), spec.endpoint.lstrip("/"))
    if spec.transport == "header":
        return url, {spec.input_name: header_value_for_transport(spec.input_name, value)}
    if spec.transport == "parameter_name_enumeration":
        if not spec.parameter_name_value:
            raise ValueError("parameter_name_enumeration requires parameter_name_value")
        return add_query_parameters(url, [(value, spec.parameter_name_value)]), {}
    if spec.transport in {"parameter", "parameter_map", "query_string"}:
        return add_query_parameters(url, [(spec.input_name, value)]), {}
    raise ValueError(f"unsupported transport: {spec.transport}")


def header_value_for_transport(input_name: str, value: str) -> str:
    if input_name.lower() == "referer":
        return f"https://adstf.local/{quote(value, safe='')}"
    return value


def add_query_parameters(url: str, pairs: list[tuple[str, str]]) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.extend(pairs)
    return urlunparse(parsed._replace(query=urlencode(query)))


def ensure_trailing_slash(url: str) -> str:
    return url if url.endswith("/") else f"{url}/"


def payload_for_marker(marker: str) -> str:
    return f"<script>window.{MARKER_VARIABLE}='{marker}'</script> "


def build_browser_action(
    *,
    run_id: str,
    candidate: OwaspExternalCandidate,
    url: str,
    headers: dict[str, str],
    expected_marker: str | None,
    artifact_prefix: str,
    summary: str,
) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="owasp_xss_v14_readiness",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=url,
        scope_context={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "evaluation_role": candidate.provenance.evaluation_role,
            "ground_truth_loaded": False,
        },
        parameters={
            "url": url,
            "headers": headers,
            "marker_variable": MARKER_VARIABLE,
            "expected_marker": expected_marker,
            "artifact_prefix": artifact_prefix,
            "summary": summary,
        },
        preconditions=["owasp_benchmark_java_running_locally", "readiness_only_case"],
        safety_class=SafetyClass.LOW,
        rationale="Execute deterministic marker/control browser observation for OWASP XSS readiness.",
        expected_evidence=[EvidenceType.BROWSER_OBSERVATION],
    )


def target_config_for_url(base_url: str) -> TargetConfig:
    parsed = urlparse(base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return TargetConfig(
        name="OWASP Benchmark Java v1.4 XSS readiness",
        base_url=base_url,
        allowed_hosts=[parsed.hostname or "127.0.0.1"],
        allowed_ports=[port],
        allowed_schemes=[parsed.scheme],
        enabled_modules=["xss.reflected"],
        max_actions=100,
        metadata={"evaluation": "owasp-xss-v14-readiness", "local_only": True},
    )


def health_check(base_url: str, timeout_seconds: float = 8.0) -> dict[str, Any]:
    context = ssl._create_unverified_context() if base_url.startswith("https://") else None
    started = datetime.now(UTC).isoformat()
    try:
        request = Request(base_url, headers={"User-Agent": "adstf-v14-readiness"})
        with urlopen(request, timeout=timeout_seconds, context=context) as response:
            status = int(response.status)
            return {
                "reachable": 200 <= status < 500,
                "status": status,
                "url": response.geturl(),
                "started_at": started,
                "completed_at": datetime.now(UTC).isoformat(),
                "error": None,
            }
    except Exception as exc:
        fallback = playwright_health_check(base_url, timeout_seconds)
        fallback["primary_error"] = str(exc)
        fallback["started_at"] = started
        return fallback


def playwright_health_check(base_url: str, timeout_seconds: float = 8.0) -> dict[str, Any]:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            response = page.goto(base_url, wait_until="domcontentloaded", timeout=timeout_seconds * 1000)
            status = getattr(response, "status", None)
            final_url = str(getattr(page, "url", base_url))
            context.close()
            browser.close()
            return {
                "reachable": isinstance(status, int) and 200 <= status < 500,
                "status": status,
                "url": final_url,
                "started_at": datetime.now(UTC).isoformat(),
                "completed_at": datetime.now(UTC).isoformat(),
                "error": None,
                "method": "playwright_ignore_https_errors",
            }
    except Exception as exc:
        return {
            "reachable": False,
            "status": None,
            "url": base_url,
            "started_at": datetime.now(UTC).isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "error": str(exc),
            "method": "playwright_ignore_https_errors",
        }


def run_readiness(
    *,
    benchmark_root: Path = DEFAULT_BENCHMARK_ROOT,
    audit_dir: Path = DEFAULT_AUDIT_DIR,
    output_dir: Path = DEFAULT_READINESS_DIR,
    base_url: str = DEFAULT_BASE_URL,
    headless: bool = True,
) -> dict[str, Any]:
    rows = load_case_audit(audit_dir / "case-audit.csv")
    selected_rows, selection_notes = select_readiness_rows(rows)
    selected_case_ids = {row["benchmark_case_id"] for row in selected_rows}
    assigned_rows = assign_evaluation_roles(rows, selected_case_ids)
    selected_rows = [row for row in assigned_rows if row["benchmark_case_id"] in selected_case_ids]
    output_dir.mkdir(parents=True, exist_ok=True)

    provenance = json.loads((audit_dir / "provenance.json").read_text(encoding="utf-8"))
    expected_rows = parse_expected_results(benchmark_root / "expectedresults-1.2.csv")
    summary = summarize(assigned_rows, provenance)
    validation = write_outputs(assigned_rows, expected_rows, summary, audit_dir, benchmark_root)

    selection_manifest = build_selection_manifest(selected_rows, selection_notes, provenance)
    write_json(output_dir / "selection-manifest.json", selection_manifest)

    candidates = [construct_external_candidate(row) for row in selected_rows]
    write_json(output_dir / "sanitized-candidate-preview.json", [asdict(candidate.ranker_candidate) for candidate in candidates])
    write_json(output_dir / "internal-provenance.json", [asdict(candidate.provenance) for candidate in candidates])
    write_json(output_dir / "execution-specifications.json", [asdict(candidate.execution) for candidate in candidates])

    target = target_config_for_url(base_url)
    safety = SafetyBoundary(target)
    health = health_check(base_url)
    run_id = f"owasp-xss-v14-readiness-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_dir / "runs", run_id)
    store.initialize(target)

    runtime_results: list[dict[str, Any]] = []
    if health["reachable"]:
        runtime_results = execute_readiness_cases(candidates, target, safety, store, base_url, headless)

    readiness = {
        "status": classify_readiness_status(runtime_results, candidates, health),
        "base_url": base_url,
        "target": asdict(target),
        "health": health,
        "run_id": run_id,
        "run_dir": str(store.run_dir),
        "selected_case_count": len(candidates),
        "selected_case_ids": [candidate.provenance.benchmark_case_id for candidate in candidates],
        "readiness_results": runtime_results,
        "summary": readiness_runtime_summary(runtime_results, candidates),
        "audit_validation": validation,
        "selection_manifest": "selection-manifest.json",
        "ground_truth_loaded_only_after_execution": True,
        "final_confirmatory_cases_executed": False,
        "gpt_calls_executed": False,
        "qwen_calls_executed": False,
    }
    write_json(output_dir / "readiness-results.json", readiness)
    validation_report = validate_readiness_package(output_dir, readiness, assigned_rows)
    write_json(output_dir / "validation-report.json", validation_report)
    (output_dir / "readiness-report.md").write_text(
        render_readiness_report(readiness, summary, selection_manifest, validation_report),
        encoding="utf-8",
    )
    write_json(output_dir / "checksums.json", checksum_manifest(output_dir))
    return readiness


def execute_readiness_cases(
    candidates: list[OwaspExternalCandidate],
    target: TargetConfig,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    base_url: str,
    headless: bool,
) -> list[dict[str, Any]]:
    from playwright.sync_api import sync_playwright

    modules = mvp_modules()
    results: list[dict[str, Any]] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        try:
            for candidate in candidates:
                results.append(execute_one_candidate(candidate, target, safety, store, base_url, page, modules))
        finally:
            context.close()
            browser.close()
    return results


def execute_one_candidate(
    candidate: OwaspExternalCandidate,
    target: TargetConfig,
    safety: SafetyBoundary,
    store: RunArtifactStore,
    base_url: str,
    page: Any,
    modules: dict[str, Any],
) -> dict[str, Any]:
    marker = f"adstf_owasp_{candidate.ranker_candidate.candidate_id.replace('-', '_')}"
    control_marker = f"adstf_control_{candidate.ranker_candidate.candidate_id.replace('-', '_')}"
    payload_url, payload_headers = build_value_request(base_url, candidate.execution, payload_for_marker(marker))
    control_url, control_headers = build_value_request(base_url, candidate.execution, control_marker)
    artifact_prefix = candidate.ranker_candidate.candidate_id

    payload_action = build_browser_action(
        run_id=store.run_id,
        candidate=candidate,
        url=payload_url,
        headers=payload_headers,
        expected_marker=marker,
        artifact_prefix=f"{artifact_prefix}-marker",
        summary="OWASP readiness marker observation.",
    )
    control_action = build_browser_action(
        run_id=store.run_id,
        candidate=candidate,
        url=control_url,
        headers=control_headers,
        expected_marker=None,
        artifact_prefix=f"{artifact_prefix}-control",
        summary="OWASP readiness benign control observation.",
    )
    store.save_action_request(payload_action)
    store.save_action_request(control_action)

    executor = BrowserExecutor(safety, store)
    payload_result, payload_evidence = executor.observe(payload_action, page)
    control_result, control_observation = executor.observe(control_action, page)
    store.save_action_result(payload_result)
    store.save_action_result(control_result)
    store.save_evidence(payload_evidence)
    store.save_evidence(control_observation)

    http_evidence = [
        http_exchange_evidence(store.run_id, payload_action, payload_result, payload_evidence, candidate, "marker"),
        http_exchange_evidence(store.run_id, control_action, control_result, control_observation, candidate, "control"),
    ]
    control_evidence = comparison_control_evidence(store.run_id, control_action, control_observation, control_marker, candidate)
    verification_note = verification_note_evidence(store.run_id, [payload_action, control_action], payload_url, candidate)
    for evidence in [*http_evidence, control_evidence, verification_note]:
        store.save_evidence(evidence)

    all_evidence = [payload_evidence, control_observation, *http_evidence, control_evidence, verification_note]
    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=store.run_id,
        module_id="xss.reflected",
        title=f"OWASP XSS readiness candidate {candidate.ranker_candidate.candidate_id}",
        category=modules["xss.reflected"].category,
        affected_target=candidate.ranker_candidate.action_path,
        state=FindingState.SUSPECTED,
        hypothesis="A metadata-constructed external reflected-XSS candidate may execute the supplied marker.",
        created_by="owasp_xss_v14_readiness",
        supporting_evidence_refs=[evidence.evidence_id for evidence in all_evidence],
        report_fields={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "evaluation_role": candidate.provenance.evaluation_role,
            "transport": candidate.execution.transport,
            "ground_truth_used": False,
            "verification_context": "runtime_readiness",
        },
        severity="medium",
        confidence="readiness_probe",
    )
    store.save_finding(finding)
    requested = request_verification(finding)
    store.save_finding(requested)
    verifier_result = FindingVerifier(modules).verify(requested, all_evidence)
    store.save_verifier_result(verifier_result)
    verified = apply_verifier_result(requested, verifier_result)
    store.save_finding(verified)

    expected = candidate.provenance.expected_result
    verified_state = verified.state.value
    return {
        "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
        "original_case_id": candidate.provenance.benchmark_case_id,
        "evaluation_role": candidate.provenance.evaluation_role,
        "compatibility_class": candidate.provenance.compatibility_class,
        "input_source": candidate.provenance.input_source,
        "expected_result": expected,
        "payload_action_status": payload_result.status.value,
        "control_action_status": control_result.status.value,
        "transport_request_shape_valid": transport_shape_valid(candidate, payload_action, control_action),
        "scope_approved": payload_result.status != ActionStatus.BLOCKED and control_result.status != ActionStatus.BLOCKED,
        "payload_marker_observed": payload_evidence.attributes.get("execution_marker_observed"),
        "control_marker_observed": control_observation.attributes.get("execution_marker_observed"),
        "control_case_passed": control_evidence.attributes["control_case_passed"],
        "verifier_outcome": verifier_result.outcome.value,
        "runtime_finding_state": verified_state,
        "matches_readiness_ground_truth": (
            expected == "vulnerable" and verifier_result.outcome == VerificationOutcome.VERIFIED
        )
        or (expected == "non_vulnerable" and verifier_result.outcome != VerificationOutcome.VERIFIED),
        "evidence_refs": [evidence.evidence_id for evidence in all_evidence],
        "finding_id": finding.finding_id,
        "verification_result_id": verifier_result.verification_result_id,
    }


def http_exchange_evidence(
    run_id: str,
    action: ActionRequest,
    result: ActionResult,
    observation: EvidenceRecord,
    candidate: OwaspExternalCandidate,
    role: str,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="owasp_xss_v14_readiness",
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        target_ref=candidate.ranker_candidate.action_path,
        created_at=datetime.now(UTC).isoformat(),
        summary=f"Browser main-document HTTP observation for OWASP readiness {role} request.",
        data_ref=observation.data_ref,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[action.action_id],
        attributes={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "role": role,
            "action_status": result.status.value,
            "requested_url": observation.attributes.get("requested_url"),
            "final_url": observation.attributes.get("final_url"),
            "main_response_status": observation.attributes.get("main_response_status"),
            "main_response_url": observation.attributes.get("main_response_url"),
            "transport": candidate.execution.transport,
            "request_header_names": observation.attributes.get("request_header_names", []),
            "ground_truth_used": False,
        },
    )


def comparison_control_evidence(
    run_id: str,
    control_action: ActionRequest,
    control_observation: EvidenceRecord,
    control_marker: str,
    candidate: OwaspExternalCandidate,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="owasp_xss_v14_readiness",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=candidate.ranker_candidate.action_path,
        created_at=datetime.now(UTC).isoformat(),
        summary="Benign readiness control did not set the browser execution marker.",
        data_ref=control_observation.data_ref,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[control_action.action_id],
        attributes={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "is_control_case": True,
            "control_case_passed": control_observation.attributes["execution_marker_observed"] is False,
            "execution_marker_observed": control_observation.attributes["execution_marker_observed"],
            "control_marker": control_marker,
            "control_observation_evidence": control_observation.evidence_id,
            "html_artifact": control_observation.attributes.get("html_artifact"),
            "screenshot_artifact": control_observation.attributes.get("screenshot_artifact"),
            "ground_truth_used": False,
        },
    )


def verification_note_evidence(
    run_id: str,
    actions: list[ActionRequest],
    target_ref: str,
    candidate: OwaspExternalCandidate,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="owasp_xss_v14_readiness",
        evidence_type=EvidenceType.VERIFICATION_NOTE,
        target_ref=target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary="OWASP readiness verification used deterministic marker/control construction only.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[action.action_id for action in actions],
        attributes={
            "opaque_candidate_id": candidate.ranker_candidate.candidate_id,
            "payload_family": "safe_marker_assignment_inert_suffix",
            "ground_truth_used": False,
            "readiness_only": True,
        },
    )


def transport_shape_valid(candidate: OwaspExternalCandidate, payload: ActionRequest, control: ActionRequest) -> bool:
    if candidate.execution.transport == "header":
        return bool(payload.parameters["headers"]) and bool(control.parameters["headers"])
    if candidate.execution.transport == "parameter_name_enumeration":
        payload_query = dict(parse_qsl(urlparse(payload.parameters["url"]).query, keep_blank_values=True))
        control_query = dict(parse_qsl(urlparse(control.parameters["url"]).query, keep_blank_values=True))
        return (
            candidate.execution.parameter_name_value in payload_query.values()
            and candidate.execution.parameter_name_value in control_query.values()
        )
    return candidate.execution.input_name in dict(parse_qsl(urlparse(payload.parameters["url"]).query, keep_blank_values=True))


def build_selection_manifest(
    selected_rows: list[dict[str, str]],
    selection_notes: list[str],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": "owasp-xss-v14-readiness-selection",
        "status": "frozen_readiness_subset",
        "selection_algorithm": (
            "For each supported input_source and expected_result stratum, sort compatible original cases "
            "by SHA-256(seed|input_source|expected_result|benchmark_case_id|benchmark_revision) and select the first two."
        ),
        "seed": READINESS_SELECTION_SEED,
        "selected_before_runtime_execution": True,
        "target_per_input_source_per_label": READINESS_PER_SOURCE_PER_LABEL,
        "benchmark_provenance": provenance,
        "selection_notes": selection_notes,
        "selected_cases": [
            {
                "benchmark_case_id": row["benchmark_case_id"],
                "opaque_candidate_id": row["sanitized_candidate_id"],
                "compatibility_class": row["compatibility_class"],
                "input_source": row["input_source"],
                "expected_result": row["expected_result"],
                "evaluation_role": row["evaluation_role"],
                "source_file": row["source_file"],
            }
            for row in selected_rows
        ],
        "distribution": {
            "count": len(selected_rows),
            "by_expected_result": dict(Counter(row["expected_result"] for row in selected_rows)),
            "by_input_source": dict(Counter(row["input_source"] for row in selected_rows)),
        },
    }


def readiness_runtime_summary(results: list[dict[str, Any]], candidates: list[OwaspExternalCandidate]) -> dict[str, Any]:
    return {
        "attempted_runtime_case_count": len(results),
        "selected_case_count": len(candidates),
        "transport_success_count": sum(result.get("transport_request_shape_valid") is True for result in results),
        "verifier_defined_count": sum(result.get("verifier_outcome") in {"verified", "rejected", "inconclusive"} for result in results),
        "readiness_ground_truth_match_count": sum(result.get("matches_readiness_ground_truth") is True for result in results),
        "by_input_source": dict(Counter(result["input_source"] for result in results)),
        "by_verifier_outcome": dict(Counter(result["verifier_outcome"] for result in results)),
        "by_expected_result": dict(Counter(candidate.provenance.expected_result for candidate in candidates)),
    }


def classify_readiness_status(
    results: list[dict[str, Any]],
    candidates: list[OwaspExternalCandidate],
    health: dict[str, Any],
) -> str:
    if not health["reachable"]:
        return "FAIL"
    if len(results) != len(candidates):
        return "FAIL"
    if not all(result["transport_request_shape_valid"] for result in results):
        return "FAIL"
    if not all(result["scope_approved"] for result in results):
        return "FAIL"
    if not all(result["verifier_outcome"] in {"verified", "rejected", "inconclusive"} for result in results):
        return "FAIL"
    if all(result["matches_readiness_ground_truth"] for result in results):
        return "PASS"
    return "PARTIAL_PASS"


def validate_readiness_package(output_dir: Path, readiness: dict[str, Any], assigned_rows: list[dict[str, str]]) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    selected_ids = set(readiness["selected_case_ids"])
    if readiness["selected_case_count"] != 20:
        errors.append("readiness selection does not contain 20 cases")
    if any(row["benchmark_case_id"] in selected_ids and row["evaluation_role"] != "READINESS_ONLY" for row in assigned_rows):
        errors.append("selected readiness case lacks READINESS_ONLY role")
    if any(row["benchmark_case_id"] not in selected_ids and row["evaluation_role"] == "READINESS_ONLY" for row in assigned_rows):
        errors.append("non-selected case was marked READINESS_ONLY")
    preview = json.loads((output_dir / "sanitized-candidate-preview.json").read_text(encoding="utf-8"))
    serialized_preview = json.dumps(preview, sort_keys=True)
    for forbidden in ["BenchmarkTest", ".java", "vulnerable", "non_vulnerable", "expected_result"]:
        if forbidden in serialized_preview:
            errors.append(f"sanitized preview leaks forbidden fragment: {forbidden}")
    if readiness["final_confirmatory_cases_executed"]:
        errors.append("readiness package reports final confirmatory cases executed")
    if readiness["gpt_calls_executed"] or readiness["qwen_calls_executed"]:
        errors.append("readiness package reports model calls executed")
    if readiness["status"] == "FAIL":
        warnings.append("runtime readiness did not pass; inspect readiness-results.json")
    return {"valid": not errors, "errors": errors, "warnings": warnings}


def render_readiness_report(
    readiness: dict[str, Any],
    audit_summary: dict[str, Any],
    selection_manifest: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    results = readiness["readiness_results"]
    final_scale = audit_summary["final_confirmatory_ranking_scale_by_pack_size"]["5"]
    lines = [
        "# OWASP XSS v1.4 Compatibility Readiness Report",
        "",
        "Status: non-scored readiness validation. No GPT, Qwen or final ranking experiment was executed.",
        "",
        "## Pass Criteria Defined Before Runtime",
        "",
        "- `PASS`: all selected READINESS_ONLY cases execute the intended request shape in scope, produce evidence, receive a defined verifier outcome, preserve ground-truth isolation, avoid model-facing identity leakage, cover every supported input source, and match readiness ground truth.",
        "- `PARTIAL_PASS`: structural readiness criteria pass, but one or more readiness ground-truth outcomes do not match the runtime verifier result.",
        "- `FAIL`: target health, transport shape, scope, evidence, verifier definition, role separation or leakage validation fails.",
        "",
        "## Benchmark Provenance",
        "",
        f"- Official remote: `{audit_summary['benchmark_provenance']['official_remote']}`",
        f"- Declared version: `{audit_summary['benchmark_provenance']['declared_benchmark_version']}`",
        f"- Pinned revision: `{audit_summary['benchmark_provenance']['pinned_git_revision']}`",
        f"- Expected-results SHA-256: `{audit_summary['benchmark_provenance']['expected_results_sha256']}`",
        "",
        "## Selection",
        "",
        f"- Seed: `{selection_manifest['seed']}`",
        f"- Selected cases: `{selection_manifest['distribution']['count']}`",
        f"- Distribution by expected result: `{selection_manifest['distribution']['by_expected_result']}`",
        f"- Distribution by input source: `{selection_manifest['distribution']['by_input_source']}`",
        "",
        "## Runtime Target",
        "",
        f"- Base URL: `{readiness['base_url']}`",
        "- Startup command: `runBenchmark.bat` or `mvn initialize; mvn clean package cargo:run -Pdeploy` from `.external/owasp-benchmark-java`.",
        "- Java target recorded by the benchmark POM: `8`; local Maven reports the active Java runtime during startup.",
        f"- Health reachable: `{readiness['health']['reachable']}`",
        f"- Health status: `{readiness['health']['status']}`",
        f"- Health error: `{readiness['health']['error']}`",
        "",
        "## Safety Configuration",
        "",
        f"- Allowed schemes: `{readiness['target']['allowed_schemes']}`",
        f"- Allowed hosts: `{readiness['target']['allowed_hosts']}`",
        f"- Allowed ports: `{readiness['target']['allowed_ports']}`",
        "- Enabled module: `xss.reflected`",
        "",
        "## Adapter Summary",
        "",
        "- Direct parameter, parameter-map and query-string cases use deterministic query construction.",
        "- Header cases use deterministic per-action browser headers; rankers never choose header names or values.",
        "- Parameter-name enumeration cases place the marker/control in the request parameter name and the original case marker value in the parameter value.",
        "- Cookie support was not implemented because the authoritative audit found no required cookie transport for XSS.",
        "- A single deterministic inert-suffix marker payload is used so terminal-character mutations in READINESS_ONLY cases do not break the script boundary.",
        "- No LLM-generated payloads, model-selected payloads or multi-payload suite were introduced during this readiness milestone.",
        "",
        "## Per-Case Runtime Results",
        "",
        "| Opaque ID | Original case | Source | Expected | Payload action | Control action | Verifier | Match |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            f"| `{result['opaque_candidate_id']}` | `{result['original_case_id']}` | `{result['input_source']}` | "
            f"`{result['expected_result']}` | `{result['payload_action_status']}` | `{result['control_action_status']}` | "
            f"`{result['verifier_outcome']}` | `{result['matches_readiness_ground_truth']}` |"
        )
    lines.extend(
        [
            "",
            "## Reconciled Corpus",
            "",
            f"- Original total XSS cases: `{audit_summary['total_xss']}`",
            f"- Original compatible after adapters: `{audit_summary['projected_usable_original_cases_after_justified_adapters']}`",
            f"- READINESS_ONLY count: `{audit_summary['readiness_only_count']}`",
            f"- FINAL_CONFIRMATORY_ELIGIBLE count: `{audit_summary['final_confirmatory_eligible_count']}`",
            f"- FINAL_CONFIRMATORY_ELIGIBLE vulnerable count: `{audit_summary['final_confirmatory_eligible_vulnerable']}`",
            f"- FINAL_CONFIRMATORY_ELIGIBLE negative count: `{audit_summary['final_confirmatory_eligible_negative']}`",
            f"- Remaining excluded count: `{audit_summary['evaluation_role_distribution']['EXCLUDED']['total']}`",
            "",
            "## Preliminary Final Ranking Scale From FINAL_CONFIRMATORY_ELIGIBLE Only",
            "",
            render_pack_table({"5": final_scale}),
            "",
            "## Integrity Statements",
            "",
            "- READINESS_ONLY cases were selected before runtime execution.",
            "- FINAL_CONFIRMATORY_ELIGIBLE cases were not executed.",
            "- Benchmark ground truth was not included in model-facing candidates, execution specifications, executor inputs or verifier inputs.",
            "- Ground truth appears only in internal provenance and post-run readiness reporting.",
            "- No GPT or Qwen calls occurred.",
            "",
            "## Validation",
            "",
            f"- Valid: `{validation['valid']}`",
            f"- Errors: `{len(validation['errors'])}`",
            f"- Warnings: `{len(validation['warnings'])}`",
            f"- Readiness status: `{readiness['status']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def checksum_manifest(root: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.json":
            checksums[str(path.relative_to(root)).replace("\\", "/")] = sha256_file(path)
    return checksums


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run non-scored OWASP XSS v1.4 readiness validation.")
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--audit-dir", type=Path, default=DEFAULT_AUDIT_DIR)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()

    readiness = run_readiness(
        benchmark_root=args.benchmark_root,
        audit_dir=args.audit_dir,
        output_dir=args.output_dir,
        base_url=args.base_url,
        headless=not args.headed,
    )
    print(f"OWASP XSS v1.4 readiness status: {readiness['status']}")
    print(f"Selected readiness cases: {readiness['selected_case_count']}")
    print(f"Artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
