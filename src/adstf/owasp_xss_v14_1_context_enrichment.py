from __future__ import annotations

import hashlib
import json
import re
import subprocess
import argparse
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from html import unescape
from pathlib import Path
from typing import Any
from urllib.parse import quote

from adstf.contracts import ActionRequest, ActionStatus, ActionType, EvidenceType, SafetyClass
from adstf.execution import HttpExecutor
from adstf.lifecycle import new_id
from adstf.owasp_xss_v14 import DEFAULT_BASE_URL, ExecutionSpecification, build_value_request, target_config_for_url
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
V14_PROTOCOL_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
DEFAULT_READINESS_DIR = REPO_ROOT / "results" / "owasp-xss-v14-1-context-enrichment-readiness"
DEFAULT_COLLECTION_ROOT = REPO_ROOT / "results" / "owasp-xss-v14-1-context-collection"
DEFAULT_COLLECTION_AUDIT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-1-context-collection-audit"

CONTEXT_ENRICHMENT_VERSION = "owasp-xss-v14-1-context-enrichment-v1"
MINIMAL_SNAPSHOT_SCHEMA = "ow14-1-minimal-candidate-snapshot-v1"
ENRICHED_SNAPSHOT_SCHEMA = "ow14-1-enriched-candidate-snapshot-v1"
ENRICHED_RANKING_RULESET_VERSION = "deterministic-enriched-context-v1"
CONTEXT_ENRICHMENT_MARKER = "ADSTF_CTX_V141/SAFE"

REFLECTION_CONTEXT_CATEGORIES = ("none", "html_text", "html_attribute", "script_like", "url_like", "other")
MARKER_PRESERVATION_CATEGORIES = ("not_reflected", "unchanged", "encoded", "transformed", "stripped")
REFLECTION_COUNT_CATEGORIES = ("0", "1", "2", "3_or_more")
CONTENT_TYPE_CATEGORIES = ("html", "json", "text", "redirect", "other", "not_available")
UNAVAILABLE_CONTEXT_VALUE = "not_available"
CONTEXT_SELECTION_PRECEDENCE = ("script_like", "url_like", "html_attribute", "html_text", "other", "none")
RANKING_CONTEXT_ORDER = ("script_like", "html_attribute", "url_like", "html_text", "other", "none")
RANKING_PRESERVATION_ORDER = ("unchanged", "encoded", "transformed", "stripped", "not_reflected")
RANKING_COUNT_ORDER = ("3_or_more", "2", "1", "0")
RANKING_CONTENT_TYPE_ORDER = ("html", "text", "json", "redirect", "other", "not_available")

PERMITTED_MINIMAL_FIELDS = {
    "candidate_id",
    "http_method",
    "input_carrier_category",
    "input_type_category",
    "editable_input_count",
    "required_input_count",
    "parameter_count",
    "multiple_parameters",
    "request_shape_category",
}
PERMITTED_ENRICHED_FIELDS = PERMITTED_MINIMAL_FIELDS | {
    "reflection_detected",
    "reflection_count_category",
    "reflection_context_category",
    "marker_preservation_category",
    "response_content_type_category",
    "collection_status",
    "failure_state",
}
FORBIDDEN_KEYS = {
    "action_path",
    "parameter_name",
    "ground_truth",
    "expected_result",
    "expected",
    "label",
    "source_file",
    "source_path",
    "endpoint",
    "servlet",
    "servlet_identity",
    "raw_html",
    "raw_body",
    "body",
    "html",
    "payload",
    "verification_payload",
    "verifier_state",
    "verifier_outcome",
    "finding_state",
    "tp_fp_fn_tn",
}
FORBIDDEN_FRAGMENTS = (
    "BenchmarkTest",
    ".java",
    "ground_truth",
    "expected_result",
    "vulnerable",
    "non_vulnerable",
    "verified",
    "inconclusive",
    "rejected",
    "<html",
    "<body",
)
CASE_DERIVED_PATTERNS = (
    re.compile(r"/external-v14/case-\d+", re.IGNORECASE),
    re.compile(r"\bcase-\d+\b", re.IGNORECASE),
    re.compile(r"\binput_\d+\b", re.IGNORECASE),
    re.compile(r"\bheader_\d+\b", re.IGNORECASE),
)


class EnrichmentLeakageError(ValueError):
    pass


@dataclass(frozen=True)
class ContextObservation:
    candidate_id: str
    reflection_detected: bool
    reflection_count_category: str
    reflection_context_category: str
    marker_preservation_category: str
    response_content_type_category: str

    def as_ranker_fields(self) -> dict[str, Any]:
        return {
            "reflection_detected": self.reflection_detected,
            "reflection_count_category": self.reflection_count_category,
            "reflection_context_category": self.reflection_context_category,
            "marker_preservation_category": self.marker_preservation_category,
            "response_content_type_category": self.response_content_type_category,
        }


def marker_policy() -> dict[str, Any]:
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.marker-policy",
        "marker": CONTEXT_ENRICHMENT_MARKER,
        "marker_policy": "fixed_inert_non_executing_marker",
        "slash_delimiter_policy": "The slash is intentional: it is non-executable and safely encodable, allowing deterministic observation of transport or encoding transformations.",
        "executable_syntax": False,
        "forbidden_characters": ["<", ">", "'", '"', "control_characters"],
        "payload_status": "not_an_xss_payload",
    }


def validate_marker(marker: str) -> bool:
    if not marker:
        return False
    if any(char in marker for char in ["<", ">", "'", '"']):
        return False
    return not any(ord(char) < 32 or ord(char) == 127 for char in marker)


def categorize_reflection_count(count: int) -> str:
    if count <= 0:
        return "0"
    if count == 1:
        return "1"
    if count == 2:
        return "2"
    return "3_or_more"


def categorize_content_type(content_type: str | None, *, status_code: int | None = None) -> str:
    if status_code is not None and 300 <= status_code < 400:
        return "redirect"
    normalized = (content_type or "").split(";", 1)[0].strip().lower()
    if not normalized:
        return "not_available"
    if normalized in {"text/html", "application/xhtml+xml"}:
        return "html"
    if normalized in {"application/json", "text/json"} or normalized.endswith("+json"):
        return "json"
    if normalized.startswith("text/"):
        return "text"
    return "other"


def classify_marker_preservation(body: str, marker: str = CONTEXT_ENRICHMENT_MARKER, *, reflected: bool | None = None) -> str:
    encoded = quote(marker, safe="")
    if marker in body:
        return "unchanged"
    if encoded != marker and encoded in body:
        return "encoded"
    if unescape(body) != body and marker in unescape(body):
        return "encoded"
    if _marker_tokens_present(body, marker):
        return "transformed"
    if reflected is False:
        return "not_reflected"
    return "stripped" if reflected is not False else "not_reflected"


def classify_reflection_context(body: str, marker: str = CONTEXT_ENRICHMENT_MARKER) -> str:
    observed_contexts = [
        _classify_reflection_position(body, position, observed_marker)
        for position, observed_marker in _recognized_reflection_occurrences(body, marker)
    ]
    if not observed_contexts:
        return "none"
    return min(observed_contexts, key=lambda context: CONTEXT_SELECTION_PRECEDENCE.index(context))


def _classify_reflection_position(body: str, position: int, observed_marker: str) -> str:
    lower = body.lower()
    if _inside_tag(lower, position, "script"):
        return "script_like"
    surrounding_tag = _surrounding_open_tag(body, position)
    if surrounding_tag:
        if re.search(r"\b(?:href|src|action|data)\s*=\s*['\"][^'\"]*" + re.escape(observed_marker), surrounding_tag, re.IGNORECASE):
            return "url_like"
        if re.search(r"\w[\w:-]*\s*=\s*['\"][^'\"]*" + re.escape(observed_marker), surrounding_tag, re.IGNORECASE):
            return "html_attribute"
    if _between_tags(body, position):
        return "html_text"
    return "other"


def observation_from_http_response(
    body: str,
    content_type: str | None,
    *,
    candidate_id: str = "synthetic-candidate",
    marker: str = CONTEXT_ENRICHMENT_MARKER,
    status_code: int | None = None,
) -> dict[str, Any]:
    encoded = quote(marker, safe="")
    exact_count = body.count(marker)
    encoded_count = 0 if encoded == marker else body.count(encoded)
    reflection_count = exact_count + encoded_count
    reflected = reflection_count > 0
    preservation = classify_marker_preservation(body, marker, reflected=reflected)
    if not reflected and preservation == "transformed":
        reflected = True
        reflection_count = 1
    context = classify_reflection_context(body, marker)
    if context == "none" and reflected:
        context = "other"
    observation = ContextObservation(
        candidate_id=candidate_id,
        reflection_detected=reflected,
        reflection_count_category=categorize_reflection_count(reflection_count),
        reflection_context_category=context,
        marker_preservation_category=preservation,
        response_content_type_category=categorize_content_type(content_type, status_code=status_code),
    )
    return {"candidate_id": candidate_id, **observation.as_ranker_fields()}


def abstract_minimal_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    candidate_input = [_abstract_candidate(candidate) for candidate in snapshot["candidate_input"]]
    abstracted = {
        "schema_version": MINIMAL_SNAPSHOT_SCHEMA,
        "artifact_status": "pre_execution_v14_1_abstracted_ranker_input",
        "scenario_id": snapshot["scenario_id"],
        "candidate_count": snapshot.get("candidate_count", len(candidate_input)),
        "candidate_test_budget": snapshot.get("candidate_test_budget", 4),
        "top_k": snapshot.get("top_k", min(4, len(candidate_input))),
        "candidate_input_schema": "llm-candidate-ranking-v1.4.1.abstracted_candidate_input",
        "candidate_input": candidate_input,
    }
    validate_ranker_facing_snapshot(abstracted)
    return abstracted


def enrich_snapshot(minimal_snapshot: dict[str, Any], observations_by_candidate_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidate_input: list[dict[str, Any]] = []
    for candidate in minimal_snapshot["candidate_input"]:
        observation = observations_by_candidate_id[candidate["candidate_id"]]
        candidate_input.append({**candidate, **_observation_fields(observation)})
    enriched = {
        **{key: value for key, value in minimal_snapshot.items() if key != "candidate_input"},
        "schema_version": ENRICHED_SNAPSHOT_SCHEMA,
        "candidate_input_schema": "llm-candidate-ranking-v1.4.1.enriched_candidate_input",
        "candidate_input": candidate_input,
    }
    validate_ranker_facing_snapshot(enriched)
    return enriched


def validate_ranker_facing_snapshot(snapshot: dict[str, Any]) -> None:
    _validate_no_leakage(snapshot)
    schema = snapshot.get("schema_version")
    allowed = PERMITTED_ENRICHED_FIELDS if schema == ENRICHED_SNAPSHOT_SCHEMA else PERMITTED_MINIMAL_FIELDS
    for candidate in snapshot.get("candidate_input", []):
        extra = set(candidate) - allowed
        if extra:
            raise EnrichmentLeakageError(f"ranker-facing candidate contains unsupported fields: {sorted(extra)}")
        if not str(candidate.get("candidate_id", "")).startswith("ox14-c"):
            raise EnrichmentLeakageError("candidate_id is not an expected opaque v1.4 candidate identifier")


def validate_v14_structural_equality(protocol_package_dir: Path = V14_PROTOCOL_PACKAGE_DIR) -> dict[str, Any]:
    scenario_manifest = _load_json(protocol_package_dir / "scenario-manifest.json")
    snapshot_index = _load_json(protocol_package_dir / "model-facing" / "candidate-snapshot-index.json")
    scoring = _load_json(protocol_package_dir / "ground-truth" / "scoring-data.json")
    errors: list[str] = []
    candidate_counts: dict[str, int] = {}
    unique_ids: set[str] = set()
    candidate_reference_count = 0
    for item in snapshot_index["snapshot_paths"]:
        snapshot = _load_json(protocol_package_dir / item["path"])
        abstracted = abstract_minimal_snapshot(snapshot)
        original_ids = [candidate["candidate_id"] for candidate in snapshot["candidate_input"]]
        abstracted_ids = [candidate["candidate_id"] for candidate in abstracted["candidate_input"]]
        if original_ids != abstracted_ids:
            errors.append(f"candidate order changed for {snapshot['scenario_id']}")
        candidate_counts[str(len(original_ids))] = candidate_counts.get(str(len(original_ids)), 0) + 1
        unique_ids.update(original_ids)
        candidate_reference_count += len(original_ids)
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.structural-equality-validation",
        "valid": not errors,
        "errors": errors,
        "scenario_count": scenario_manifest["scenario_count"],
        "candidate_reference_count": candidate_reference_count,
        "unique_candidate_count": len(unique_ids),
        "positive_scenario_count": scoring["positive_scenarios"],
        "negative_only_scenario_count": scoring["negative_only_scenarios"],
        "candidate_count_distribution": candidate_counts,
        "scenario_membership_and_order_preserved": not errors,
        "ground_truth_used_for_snapshot_construction": False,
    }


def enriched_rankings(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = [_rank_key_for_enriched_candidate(candidate) for candidate in candidates]
    ordered = sorted(scored, key=lambda item: (tuple(-part for part in item["sort_key"]), item["candidate_id"]))
    rankings = []
    for index, item in enumerate(ordered, start=1):
        rankings.append({**item, "rank": index, "selected": index == 1})
    return rankings


def deterministic_enriched_ranking_specification() -> dict[str, Any]:
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.deterministic-enriched-ranking-specification",
        "ruleset_version": ENRICHED_RANKING_RULESET_VERSION,
        "status": "pre_scored_execution_generic_rule",
        "policy": "lexicographic_ordinal",
        "label_independent": True,
        "lexicographic_priority": [
            {"feature": "reflection_detected", "order": [True, False]},
            {"feature": "reflection_context_category", "order": list(RANKING_CONTEXT_ORDER)},
            {"feature": "marker_preservation_category", "order": list(RANKING_PRESERVATION_ORDER)},
            {"feature": "reflection_count_category", "order": list(RANKING_COUNT_ORDER)},
            {"feature": "response_content_type_category", "order": list(RANKING_CONTENT_TYPE_ORDER)},
            {
                "feature": "abstract_structural_fallback",
                "order": [
                    "GET before non-GET",
                    "text/header-like categories before other",
                    "single editable input before many",
                    "fewer required inputs",
                    "fewer parameters",
                    "single-parameter request shape before multi-parameter",
                ],
            },
        ],
        "tie_breaking": ["lexicographic priority tuple", "ascending candidate_id"],
        "rationale": (
            "The rule uses generic reflected-XSS context signals observed with a benign marker and does not inspect "
            "benchmark labels or verifier outcomes. The original deterministic structural ranker depends on URL and "
            "parameter-name fields that v1.4.1 deliberately removes from ranker-facing records, so the final fallback "
            "uses only the permitted abstract structural fields that correspond to the same generic structural signals."
        ),
    }


def prepare_collection_plan_without_ground_truth(protocol_package_dir: Path = V14_PROTOCOL_PACKAGE_DIR) -> dict[str, Any]:
    snapshot_index_path = protocol_package_dir / "model-facing" / "candidate-snapshot-index.json"
    execution_specs_path = protocol_package_dir / "execution" / "execution-specifications.json"
    snapshot_index = _load_json(snapshot_index_path)
    execution_specs = _load_json(execution_specs_path)
    files_read = [
        (snapshot_index_path.relative_to(protocol_package_dir)).as_posix(),
        (execution_specs_path.relative_to(protocol_package_dir)).as_posix(),
    ]
    snapshot_candidate_ids: set[str] = set()
    for item in snapshot_index["snapshot_paths"]:
        snapshot_path = protocol_package_dir / item["path"]
        snapshot = _load_json(snapshot_path)
        files_read.append(Path(item["path"]).as_posix())
        for candidate in snapshot["candidate_input"]:
            snapshot_candidate_ids.add(candidate["candidate_id"])
    specs_by_id = {spec["opaque_candidate_id"]: spec for spec in execution_specs}
    missing_specs = sorted(snapshot_candidate_ids - set(specs_by_id))
    plan_items = [
        {
            "candidate_id": candidate_id,
            "execution_spec_available": candidate_id in specs_by_id,
            "marker": CONTEXT_ENRICHMENT_MARKER,
            "ground_truth_loaded": False,
        }
        for candidate_id in sorted(snapshot_candidate_ids)
    ]
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.collection-plan-without-ground-truth",
        "valid": not missing_specs,
        "errors": [f"missing execution specification for {candidate_id}" for candidate_id in missing_specs],
        "unique_candidate_count": len(snapshot_candidate_ids),
        "benign_marker_request_limit": len(snapshot_candidate_ids),
        "files_read": files_read,
        "ground_truth_scoring_data_loaded": False,
        "model_calls": 0,
        "http_requests_executed_by_plan_preparation": 0,
        "plan_item_count": len(plan_items),
        "plan_items_preview": plan_items[:5],
    }


def projected_denominators(protocol_package_dir: Path = V14_PROTOCOL_PACKAGE_DIR) -> dict[str, Any]:
    structural = validate_v14_structural_equality(protocol_package_dir)
    scenarios = structural["scenario_count"]
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.projected-denominators",
        "scenario_count": scenarios,
        "positive_scenarios": structural["positive_scenario_count"],
        "negative_only_scenarios": structural["negative_only_scenario_count"],
        "candidate_references": structural["candidate_reference_count"],
        "unique_candidates": structural["unique_candidate_count"],
        "benign_marker_request_denominator": structural["unique_candidate_count"],
        "ranking_rows": {
            "deterministic_minimal": scenarios,
            "gpt_minimal": scenarios * 5,
            "qwen_minimal": scenarios * 5,
            "deterministic_enriched": scenarios,
            "gpt_enriched": scenarios * 5,
            "qwen_enriched": scenarios * 5,
            "total": scenarios * 22,
        },
        "model_call_denominator": {
            "gpt_calls": scenarios * 10,
            "qwen_calls": scenarios * 10,
        },
    }


def build_context_enrichment_readiness_package(
    *,
    output_dir: Path = DEFAULT_READINESS_DIR,
    protocol_package_dir: Path = V14_PROTOCOL_PACKAGE_DIR,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    structural = validate_v14_structural_equality(protocol_package_dir)
    denominators = projected_denominators(protocol_package_dir)
    category_definitions = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.category-definitions",
        "reflection_context_categories": list(REFLECTION_CONTEXT_CATEGORIES),
        "marker_preservation_categories": list(MARKER_PRESERVATION_CATEGORIES),
        "reflection_count_categories": list(REFLECTION_COUNT_CATEGORIES),
        "response_content_type_categories": list(CONTENT_TYPE_CATEGORIES),
        "ambiguous_context_precedence": list(CONTEXT_SELECTION_PRECEDENCE),
        "ranking_context_order": list(RANKING_CONTEXT_ORDER),
        "ranking_preservation_order": list(RANKING_PRESERVATION_ORDER),
        "ranking_count_order": list(RANKING_COUNT_ORDER),
        "ranking_content_type_order": list(RANKING_CONTENT_TYPE_ORDER),
    }
    collection_plan = prepare_collection_plan_without_ground_truth(protocol_package_dir)
    leakage_report = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.leakage-validation",
        "valid": structural["valid"] and collection_plan["valid"],
        "forbidden_keys": sorted(FORBIDDEN_KEYS),
        "forbidden_fragments": list(FORBIDDEN_FRAGMENTS),
        "case_derived_patterns_rejected": [pattern.pattern for pattern in CASE_DERIVED_PATTERNS],
        "ground_truth_loaded_for_ranker_facing_snapshot_construction": False,
        "ground_truth_loaded_for_collection_plan_preparation": collection_plan["ground_truth_scoring_data_loaded"],
    }
    cost_plan = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.cost-measurement-plan",
        "status": "prospective_plan_only",
        "provider_model_identifier": "gpt-5.6-luna",
        "billing_evidence_policy": "retain provider usage metadata per call and separately retain dated billing/pricing evidence if available before protocol freeze",
        "timezone_policy": "record UTC timestamps for calls and billing evidence capture",
        "per_call_cost_policy": "use provider-reported cost only if directly available; otherwise derive only from frozen numeric pricing evidence captured before execution",
        "unavailable_policy": "if monetary cost cannot be isolated reliably, report not_available rather than zero",
    }
    validation = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.readiness-validation",
        "valid": structural["valid"] and collection_plan["valid"],
        "errors": [*structural["errors"], *collection_plan["errors"]],
        "no_gpt_calls": True,
        "no_qwen_calls": True,
        "no_http_benchmark_requests": True,
        "no_scored_ranking_rows": True,
        "no_ground_truth_loaded_for_snapshot_construction": True,
        "collection_plan_prepared_without_ground_truth": not collection_plan["ground_truth_scoring_data_loaded"],
    }
    manifest = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.readiness-manifest",
        "created_at": datetime.now(UTC).isoformat(),
        "status": "offline_implementation_readiness_no_scored_execution",
        "source_protocol_package": _display_path(protocol_package_dir),
        "structural_equality_valid": structural["valid"],
        "collection_plan_valid": collection_plan["valid"],
        "denominators": denominators,
        "external_activity": {
            "gpt_calls": 0,
            "qwen_calls": 0,
            "http_benchmark_requests": 0,
            "browser_verification_runs": 0,
            "scored_ranking_rows": 0,
        },
        "decision": "OFFLINE IMPLEMENTATION READY - LIVE BENIGN COLLECTION REQUIRED",
    }
    _write_json(output_dir / "marker-policy.json", marker_policy())
    _write_json(output_dir / "category-definitions.json", category_definitions)
    _write_json(output_dir / "deterministic-enriched-ranking-specification.json", deterministic_enriched_ranking_specification())
    _write_json(output_dir / "collection-plan-preparation.json", collection_plan)
    _write_json(output_dir / "leakage-validation-report.json", leakage_report)
    _write_json(output_dir / "frozen-v14-structural-equality-validation.json", structural)
    _write_json(output_dir / "projected-denominators.json", denominators)
    _write_json(output_dir / "cost-measurement-plan.json", cost_plan)
    _write_json(output_dir / "validation-report.json", validation)
    _write_text(output_dir / "README.md", _readiness_readme(manifest, denominators))
    _write_json(output_dir / "manifest.json", manifest)
    _write_text(output_dir / "checksums.sha256", _render_checksums(output_dir))
    return manifest


def collect_benign_context_observations(
    *,
    base_url: str = DEFAULT_BASE_URL,
    output_root: Path = DEFAULT_COLLECTION_ROOT,
    protocol_package_dir: Path = V14_PROTOCOL_PACKAGE_DIR,
    audit_dir: Path = DEFAULT_COLLECTION_AUDIT_DIR,
    executor: Any | None = None,
    timeout_seconds: float = 8.0,
) -> Path:
    collection_plan = prepare_collection_plan_without_ground_truth(protocol_package_dir)
    if not collection_plan["valid"]:
        raise RuntimeError("ground-truth-free collection plan is invalid")
    run_id = f"owasp-xss-v14-1-context-collection-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    if run_dir.exists():
        raise RuntimeError(f"collection run directory already exists: {run_dir}")
    for subdir in ["raw/actions", "raw/results", "raw/evidence", "sanitized-observations", "draft-snapshots"]:
        (run_dir / subdir).mkdir(parents=True, exist_ok=True)

    target = target_config_for_url(base_url)
    safety = SafetyBoundary(target)
    http_executor = executor or HttpExecutor(safety, timeout_seconds=timeout_seconds, verify_tls=False)
    schedule = _collection_schedule(protocol_package_dir, base_url)
    if len(schedule) != 388:
        raise RuntimeError(f"expected 388 unique collection candidates, got {len(schedule)}")

    manifest = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.collection-manifest",
        "run_id": run_id,
        "created_at": datetime.now(UTC).isoformat(),
        "pre_run_commit_sha": _git_head(),
        "target": asdict(target),
        "base_url": base_url,
        "marker_policy": marker_policy(),
        "failure_policy": {
            "silent_retry": False,
            "scheduled_attempts_per_candidate": 1,
            "failure_representation": "explicit not_available fields; transport failure is not treated as not reflected",
        },
        "scheduled_candidates": len(schedule),
        "ground_truth_scoring_data_loaded": False,
        "gpt_calls": 0,
        "qwen_calls": 0,
        "verification_runs": 0,
        "scored_ranking_rows": 0,
    }
    observations: list[dict[str, Any]] = []
    request_sequence = 0
    actual_candidate_http_requests = 0
    actual_http_exchanges_including_redirects = 0
    for item in schedule:
        request_sequence += 1
        actual_candidate_http_requests += 1
        candidate_id = item["candidate_id"]
        action = _collection_action(
            run_id=run_id,
            request_sequence=request_sequence,
            base_url=base_url,
            spec=item["execution_specification"],
        )
        _write_json(run_dir / "raw" / "actions" / f"{candidate_id}.json", to_json_value(action))
        result, evidence = http_executor.execute(action)
        result_json = to_json_value(result)
        evidence_json = [to_json_value(record) for record in evidence]
        _write_json(run_dir / "raw" / "results" / f"{candidate_id}.json", result_json)
        _write_json(run_dir / "raw" / "evidence" / f"{candidate_id}.json", evidence_json)
        normalized = _observation_from_execution_result(candidate_id, result_json)
        observations.append(
            {
                "candidate_id": candidate_id,
                "request_sequence": request_sequence,
                "action_id": action.action_id,
                "started_at": result.started_at,
                "completed_at": result.completed_at,
                "collection_status": normalized["collection_status"],
                "failure_state": normalized["failure_state"],
                "status_code": result.normalized_observations.get("status_code"),
                "response_content_type": result.normalized_observations.get("content_type"),
                "response_body_sha256": result.normalized_observations.get("body_sha256"),
                "raw_result_ref": f"raw/results/{candidate_id}.json",
                "raw_evidence_ref": f"raw/evidence/{candidate_id}.json",
                **_ranker_observation_fields(normalized),
            }
        )
        redirect_chain = result.normalized_observations.get("redirect_chain", [])
        actual_http_exchanges_including_redirects += 1 + (len(redirect_chain) if isinstance(redirect_chain, list) else 0)

    observation_index = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.candidate-observations",
        "artifact_status": "sanitized_candidate_level_context_observations",
        "run_id": run_id,
        "marker": CONTEXT_ENRICHMENT_MARKER,
        "ground_truth_loaded": False,
        "observations": observations,
    }
    _write_json(run_dir / "sanitized-observations" / "candidate-observations.json", observation_index)
    draft_validation = _write_draft_enriched_snapshots(run_dir, protocol_package_dir, observations)
    accounting = _collection_accounting(schedule, observations, actual_candidate_http_requests, actual_http_exchanges_including_redirects)
    manifest.update(
        {
            **accounting,
            "completed_at": datetime.now(UTC).isoformat(),
            "raw_body_retention_policy": "raw body text may exist only inside raw executor artifacts; sanitized observations and draft snapshots contain normalized fields only",
        }
    )
    _write_json(run_dir / "collection-manifest.json", manifest)
    audit = _post_collection_audit(run_dir, protocol_package_dir, observation_index, accounting, draft_validation)
    _write_json(run_dir / "post-collection-audit.json", audit)
    _write_text(run_dir / "checksums.sha256", _render_checksums(run_dir))
    _write_collection_audit_package(audit_dir, run_dir, manifest, audit)
    return run_dir


def _abstract_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    source = candidate["source"]
    parameter_count = int(candidate["parameter_count"])
    return {
        "candidate_id": candidate["candidate_id"],
        "http_method": candidate["method"].upper(),
        "input_carrier_category": _carrier_category(source),
        "input_type_category": _input_type_category(candidate["input_type"]),
        "editable_input_count": int(candidate["editable_input_count"]),
        "required_input_count": int(candidate["required_input_count"]),
        "parameter_count": parameter_count,
        "multiple_parameters": parameter_count > 1,
        "request_shape_category": _request_shape_category(source, parameter_count),
    }


def _collection_schedule(protocol_package_dir: Path, base_url: str) -> list[dict[str, Any]]:
    plan = prepare_collection_plan_without_ground_truth(protocol_package_dir)
    execution_specs = {
        spec["opaque_candidate_id"]: ExecutionSpecification(**spec)
        for spec in _load_json(protocol_package_dir / "execution" / "execution-specifications.json")
    }
    schedule = [
        {
            "sequence": index,
            "candidate_id": candidate_id,
            "execution_specification": spec,
            "base_url": base_url,
            "marker": CONTEXT_ENRICHMENT_MARKER,
        }
        for index, (candidate_id, spec) in enumerate(sorted(execution_specs.items()), start=1)
        if candidate_id in _candidate_ids_from_snapshots(protocol_package_dir)
    ]
    return sorted(schedule, key=lambda item: item["candidate_id"])


def _candidate_ids_from_snapshots(protocol_package_dir: Path) -> set[str]:
    snapshot_index = _load_json(protocol_package_dir / "model-facing" / "candidate-snapshot-index.json")
    ids: set[str] = set()
    for item in snapshot_index["snapshot_paths"]:
        snapshot = _load_json(protocol_package_dir / item["path"])
        ids.update(candidate["candidate_id"] for candidate in snapshot["candidate_input"])
    return ids


def _collection_action(
    *,
    run_id: str,
    request_sequence: int,
    base_url: str,
    spec: ExecutionSpecification,
) -> ActionRequest:
    url, headers = build_value_request(base_url, spec, CONTEXT_ENRICHMENT_MARKER)
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="owasp_xss_v14_1_context_collector",
        module_id="xss.reflected",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=url,
        scope_context={
            "candidate_id": spec.opaque_candidate_id,
            "request_sequence": request_sequence,
            "ground_truth_loaded": False,
            "marker_policy": "fixed_inert_non_executing_marker",
        },
        parameters={
            "url": url,
            "method": spec.method,
            "headers": headers,
            "capture_body_text": True,
            "body_text_limit": 1048576,
            "max_redirects": 3,
        },
        preconditions=["owasp_benchmark_java_running_locally", "final_confirmatory_candidate_context_collection"],
        safety_class=SafetyClass.LOW,
        rationale="Collect one benign inert-marker context observation for v1.4.1 candidate enrichment.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def _observation_from_execution_result(candidate_id: str, result: dict[str, Any]) -> dict[str, Any]:
    if result.get("status") != ActionStatus.EXECUTED:
        return _unavailable_observation(candidate_id, str(result.get("error") or result.get("status")))
    normalized = result.get("normalized_observations", {})
    body_text = normalized.get("body_text")
    if not isinstance(body_text, str):
        return _unavailable_observation(candidate_id, "response body text not available")
    observation = observation_from_http_response(
        body_text,
        normalized.get("content_type"),
        candidate_id=candidate_id,
        status_code=normalized.get("status_code"),
    )
    return {"collection_status": "success", "failure_state": None, **observation}


def _unavailable_observation(candidate_id: str, failure_state: str) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "collection_status": "failure",
        "failure_state": failure_state,
        "reflection_detected": UNAVAILABLE_CONTEXT_VALUE,
        "reflection_count_category": UNAVAILABLE_CONTEXT_VALUE,
        "reflection_context_category": UNAVAILABLE_CONTEXT_VALUE,
        "marker_preservation_category": UNAVAILABLE_CONTEXT_VALUE,
        "response_content_type_category": UNAVAILABLE_CONTEXT_VALUE,
    }


def _ranker_observation_fields(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "reflection_detected": observation["reflection_detected"],
        "reflection_count_category": observation["reflection_count_category"],
        "reflection_context_category": observation["reflection_context_category"],
        "marker_preservation_category": observation["marker_preservation_category"],
        "response_content_type_category": observation["response_content_type_category"],
        "collection_status": observation["collection_status"],
        "failure_state": observation["failure_state"],
    }


def _write_draft_enriched_snapshots(
    run_dir: Path,
    protocol_package_dir: Path,
    observations: list[dict[str, Any]],
) -> dict[str, Any]:
    observations_by_id = {item["candidate_id"]: item for item in observations}
    snapshot_index = _load_json(protocol_package_dir / "model-facing" / "candidate-snapshot-index.json")
    errors: list[str] = []
    snapshot_paths: list[dict[str, Any]] = []
    for item in snapshot_index["snapshot_paths"]:
        original = _load_json(protocol_package_dir / item["path"])
        minimal = abstract_minimal_snapshot(original)
        try:
            enriched = enrich_snapshot(minimal, observations_by_id)
        except Exception as exc:
            errors.append(f"{original['scenario_id']}: {exc}")
            continue
        enriched["artifact_status"] = "draft_pre_freeze_enriched_ranker_input"
        out_path = run_dir / "draft-snapshots" / f"{original['scenario_id']}.json"
        _write_json(out_path, enriched)
        snapshot_paths.append(
            {
                "scenario_id": original["scenario_id"],
                "path": out_path.relative_to(run_dir).as_posix(),
                "candidate_input_sha256": sha256_json(enriched["candidate_input"]),
            }
        )
    validation = {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.draft-enriched-snapshot-validation",
        "valid": not errors and len(snapshot_paths) == 266,
        "errors": errors,
        "snapshot_count": len(snapshot_paths),
        "candidate_references": 1330 if len(snapshot_paths) == 266 else "not_available",
        "candidate_order_preserved": not errors,
        "ground_truth_loaded": False,
        "artifact_status": "draft_pre_freeze",
    }
    _write_json(
        run_dir / "draft-snapshots" / "candidate-snapshot-index.json",
        {
            "schema_version": f"{ENRICHED_SNAPSHOT_SCHEMA}-draft-index",
            "artifact_status": "draft_pre_freeze_enriched_ranker_input_index",
            "scenario_count": len(snapshot_paths),
            "snapshot_paths": snapshot_paths,
        },
    )
    _write_json(run_dir / "draft-snapshots" / "validation-report.json", validation)
    return validation


def _collection_accounting(
    schedule: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    actual_candidate_http_requests: int,
    actual_http_exchanges_including_redirects: int,
) -> dict[str, Any]:
    scheduled = [item["candidate_id"] for item in schedule]
    observed = [item["candidate_id"] for item in observations]
    scheduled_set = set(scheduled)
    observed_set = set(observed)
    duplicate_attempts = len(observed) - len(observed_set)
    failures = [item for item in observations if item["collection_status"] != "success"]
    successes = [item for item in observations if item["collection_status"] == "success"]
    return {
        "attempted_requests": len(observations),
        "actual_candidate_http_requests": actual_candidate_http_requests,
        "actual_http_exchanges_including_redirects": actual_http_exchanges_including_redirects,
        "successful_responses": len(successes),
        "failures_or_timeouts": len(failures),
        "duplicate_attempts": duplicate_attempts,
        "missing_candidate_ids": sorted(scheduled_set - observed_set),
        "unexpected_candidate_ids": sorted(observed_set - scheduled_set),
        "context_distribution": {
            "reflection_detected": dict(Counter(str(item["reflection_detected"]) for item in observations)),
            "reflection_context_category": dict(Counter(str(item["reflection_context_category"]) for item in observations)),
            "marker_preservation_category": dict(Counter(str(item["marker_preservation_category"]) for item in observations)),
            "reflection_count_category": dict(Counter(str(item["reflection_count_category"]) for item in observations)),
            "response_content_type_category": dict(Counter(str(item["response_content_type_category"]) for item in observations)),
            "collection_status": dict(Counter(str(item["collection_status"]) for item in observations)),
        },
    }


def _post_collection_audit(
    run_dir: Path,
    protocol_package_dir: Path,
    observation_index: dict[str, Any],
    accounting: dict[str, Any],
    draft_validation: dict[str, Any],
) -> dict[str, Any]:
    leakage_errors: list[str] = []
    try:
        for path in (run_dir / "draft-snapshots").glob("ow14-s*.json"):
            validate_ranker_facing_snapshot(_load_json(path))
    except EnrichmentLeakageError as exc:
        leakage_errors.append(str(exc))
    structural = validate_v14_structural_equality(protocol_package_dir)
    return {
        "schema_version": f"{CONTEXT_ENRICHMENT_VERSION}.post-collection-audit",
        "valid": (
            accounting["attempted_requests"] == 388
            and accounting["actual_candidate_http_requests"] <= 388
            and accounting["duplicate_attempts"] == 0
            and not accounting["missing_candidate_ids"]
            and not accounting["unexpected_candidate_ids"]
            and not leakage_errors
            and structural["valid"]
            and draft_validation["valid"]
        ),
        "collection_denominator_report": accounting,
        "ground_truth_separation_validation": {
            "ground_truth_loaded_in_collector_path": False,
            "observation_index_ground_truth_loaded": observation_index["ground_truth_loaded"],
        },
        "leakage_validation": {"valid": not leakage_errors, "errors": leakage_errors},
        "structural_equality_validation": structural,
        "draft_enriched_snapshot_validation": draft_validation,
        "raw_evidence_checksum_validation": "available_after_checksums_written",
        "gpt_calls": 0,
        "qwen_calls": 0,
        "verification_runs": 0,
        "scored_ranking_rows": 0,
    }


def _write_collection_audit_package(audit_dir: Path, run_dir: Path, manifest: dict[str, Any], audit: dict[str, Any]) -> None:
    audit_dir.mkdir(parents=True, exist_ok=True)
    _write_json(audit_dir / "execution-manifest.json", manifest)
    _write_json(audit_dir / "collection-denominator-report.json", audit["collection_denominator_report"])
    _write_json(audit_dir / "context-category-distribution.json", audit["collection_denominator_report"]["context_distribution"])
    _write_json(audit_dir / "ground-truth-separation-validation.json", audit["ground_truth_separation_validation"])
    _write_json(audit_dir / "leakage-validation.json", audit["leakage_validation"])
    _write_json(audit_dir / "scenario-candidate-order-equality-validation.json", audit["structural_equality_validation"])
    _write_json(audit_dir / "draft-enriched-snapshot-validation.json", audit["draft_enriched_snapshot_validation"])
    _write_json(audit_dir / "post-collection-audit.json", audit)
    _write_text(
        audit_dir / "README.md",
        "\n".join(
            [
                "# v1.4.1 Context Collection Audit",
                "",
                f"Raw collection run: `{_display_path(run_dir)}`",
                "",
                "This package contains collection-quality diagnostics only. It does not contain ranking results, vulnerability verification, ground-truth scoring or effectiveness metrics.",
                "",
            ]
        ),
    )
    _write_text(audit_dir / "checksums.sha256", _render_checksums(audit_dir))


def _carrier_category(source: str) -> str:
    return {
        "request_parameter": "query_parameter",
        "request_parameter_map": "query_parameter_map",
        "query_string": "query_string",
        "request_header": "header",
        "dynamic_parameter_name": "dynamic_parameter_name",
    }.get(source, "other")


def _input_type_category(input_type: str) -> str:
    return "header" if input_type.lower() == "header" else "text"


def _request_shape_category(source: str, parameter_count: int) -> str:
    if source == "request_header":
        return "header_value"
    if source == "dynamic_parameter_name":
        return "dynamic_parameter_name"
    if source == "query_string":
        return "whole_query_string"
    return "multi_query_parameter" if parameter_count > 1 else "single_query_parameter"


def _observation_fields(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "reflection_detected": bool(observation["reflection_detected"]),
        "reflection_count_category": observation["reflection_count_category"],
        "reflection_context_category": observation["reflection_context_category"],
        "marker_preservation_category": observation["marker_preservation_category"],
        "response_content_type_category": observation["response_content_type_category"],
    }


def _rank_key_for_enriched_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    rationale: list[str] = []
    reflection_value = 1 if candidate.get("reflection_detected") is True else 0
    rationale.append(f"reflection_detected={candidate.get('reflection_detected') is True}")
    context = candidate.get("reflection_context_category", "none")
    rationale.append(f"context={context}")
    preservation = candidate.get("marker_preservation_category", "not_reflected")
    rationale.append(f"preservation={preservation}")
    count_category = candidate.get("reflection_count_category", "0")
    rationale.append(f"count={count_category}")
    content_type = candidate.get("response_content_type_category", "not_available")
    rationale.append(f"content_type={content_type}")
    structural_key, structural_rationale = _abstract_structural_fallback_key(candidate)
    rationale.extend(structural_rationale)
    return {
        "candidate_id": candidate["candidate_id"],
        "policy": "lexicographic_ordinal",
        "sort_key": [
            reflection_value,
            _ordinal(context, RANKING_CONTEXT_ORDER),
            _ordinal(preservation, RANKING_PRESERVATION_ORDER),
            _ordinal(count_category, RANKING_COUNT_ORDER),
            _ordinal(content_type, RANKING_CONTENT_TYPE_ORDER),
            *structural_key,
        ],
        "rationale": rationale,
    }


def _ordinal(value: Any, ordered_values: tuple[Any, ...]) -> int:
    try:
        return len(ordered_values) - ordered_values.index(value)
    except ValueError:
        return 0


def _abstract_structural_fallback_key(candidate: dict[str, Any]) -> tuple[list[int], list[str]]:
    editable_count = int(candidate.get("editable_input_count", 99))
    required_count = int(candidate.get("required_input_count", 99))
    parameter_count = int(candidate.get("parameter_count", 99))
    single_editable = 1 if editable_count == 1 else 0
    few_editable = 1 if editable_count <= 3 else 0
    no_required = 1 if required_count == 0 else 0
    few_required_rank = max(0, 9 - min(required_count, 9))
    few_parameter_rank = max(0, 9 - min(parameter_count, 9))
    single_parameter = 1 if candidate.get("multiple_parameters") is False else 0
    method_get = 1 if str(candidate.get("http_method", "")).upper() == "GET" else 0
    text_like = 1 if candidate.get("input_type_category") in {"text", "header"} else 0
    key = [
        method_get,
        text_like,
        single_editable,
        few_editable,
        no_required,
        few_required_rank,
        few_parameter_rank,
        single_parameter,
    ]
    rationale = [
        "abstract structural fallback: method, input type, editable count, required count, parameter count and request shape",
        f"structural fallback key={key}",
    ]
    return key, rationale


def _validate_no_leakage(value: Any, *, current_key: str | None = None) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in FORBIDDEN_KEYS:
                raise EnrichmentLeakageError(f"forbidden ranker-facing key: {key}")
            _validate_no_leakage(item, current_key=key)
    elif isinstance(value, list):
        for item in value:
            _validate_no_leakage(item, current_key=current_key)
    elif isinstance(value, str):
        if current_key in {"candidate_id", "scenario_id", "schema_version", "candidate_input_schema", "artifact_status"}:
            return
        for fragment in FORBIDDEN_FRAGMENTS:
            if fragment in value:
                raise EnrichmentLeakageError(f"forbidden ranker-facing fragment: {fragment}")
        for pattern in CASE_DERIVED_PATTERNS:
            if pattern.search(value):
                raise EnrichmentLeakageError(f"case-derived identity fragment: {pattern.pattern}")


def _marker_tokens_present(body: str, marker: str) -> bool:
    tokens = [token for token in re.split(r"[^A-Za-z0-9]+", marker) if len(token) >= 4]
    return bool(tokens) and all(token in body for token in tokens)


def _recognized_reflection_occurrences(body: str, marker: str) -> list[tuple[int, str]]:
    occurrences = [(position, marker) for position in _find_all(body, marker)]
    encoded = quote(marker, safe="")
    if encoded != marker:
        occurrences.extend((position, encoded) for position in _find_all(body, encoded))
    return sorted(occurrences, key=lambda item: item[0])


def _find_all(body: str, needle: str) -> list[int]:
    if not needle:
        return []
    positions: list[int] = []
    start = 0
    while True:
        position = body.find(needle, start)
        if position == -1:
            return positions
        positions.append(position)
        start = position + len(needle)


def _inside_tag(lower_body: str, position: int, tag_name: str) -> bool:
    open_tag = lower_body.rfind(f"<{tag_name}", 0, position)
    close_tag = lower_body.rfind(f"</{tag_name}", 0, position)
    end_tag = lower_body.find(f"</{tag_name}", position)
    return open_tag != -1 and open_tag > close_tag and end_tag != -1


def _surrounding_open_tag(body: str, position: int) -> str | None:
    start = body.rfind("<", 0, position)
    end = body.find(">", position)
    previous_end = body.rfind(">", 0, position)
    if start == -1 or end == -1 or previous_end > start:
        return None
    return body[start : end + 1]


def _between_tags(body: str, position: int) -> bool:
    previous_gt = body.rfind(">", 0, position)
    previous_lt = body.rfind("<", 0, position)
    next_lt = body.find("<", position)
    return previous_gt > previous_lt and next_lt != -1


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{_sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
    except Exception:
        return "not_available"


def _readiness_readme(manifest: dict[str, Any], denominators: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# v1.4.1 Context-Enrichment Readiness Package",
            "",
            "Status: offline implementation readiness only.",
            "",
            "No GPT calls, Qwen calls, benchmark HTTP requests, browser verification runs or scored ranking rows were executed.",
            "",
            f"Decision: {manifest['decision']}.",
            "",
            "Projected denominators:",
            "",
            f"- Scenarios: {denominators['scenario_count']}",
            f"- Positive scenarios: {denominators['positive_scenarios']}",
            f"- Negative-only scenarios: {denominators['negative_only_scenarios']}",
            f"- Unique candidates requiring benign observation: {denominators['unique_candidates']}",
            f"- Projected total ranking rows: {denominators['ranking_rows']['total']}",
            "",
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="v1.4.1 OWASP XSS context-enrichment utilities")
    subparsers = parser.add_subparsers(dest="command", required=True)
    readiness = subparsers.add_parser("readiness", help="Regenerate offline readiness package")
    readiness.add_argument("--output-dir", type=Path, default=DEFAULT_READINESS_DIR)
    collect = subparsers.add_parser("collect", help="Run benign context observation collection")
    collect.add_argument("--base-url", default=DEFAULT_BASE_URL)
    collect.add_argument("--output-root", type=Path, default=DEFAULT_COLLECTION_ROOT)
    collect.add_argument("--audit-dir", type=Path, default=DEFAULT_COLLECTION_AUDIT_DIR)
    collect.add_argument("--timeout-seconds", type=float, default=8.0)
    args = parser.parse_args()

    if args.command == "readiness":
        manifest = build_context_enrichment_readiness_package(output_dir=args.output_dir)
        print(f"v1.4.1 context-enrichment readiness package: {args.output_dir}")
        print(f"Decision: {manifest['decision']}")
    elif args.command == "collect":
        run_dir = collect_benign_context_observations(
            base_url=args.base_url,
            output_root=args.output_root,
            audit_dir=args.audit_dir,
            timeout_seconds=args.timeout_seconds,
        )
        print(f"v1.4.1 benign context collection written to: {run_dir}")


if __name__ == "__main__":
    main()
