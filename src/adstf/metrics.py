from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any


NOT_AVAILABLE = "not_available"
NOT_APPLICABLE = "not_applicable"
MEASUREMENT_SCHEMA_VERSION = "measurement-summary-v1.3"

HTTP_ACTION_TYPES = {
    "replay_request",
    "mutate_parameter",
    "authenticate_test_user",
    "submit_form",
}
BROWSER_ACTION_TYPES = {
    "navigate",
    "observe_browser",
    "submit_form",
}


def derive_measurements_from_run_dir(
    run_dir: Path,
    *,
    model_artifact_paths: list[Path] | None = None,
    case_rows: list[dict[str, Any]] | None = None,
    arm_type: str = "framework",
    candidate_based: bool = False,
) -> dict[str, Any]:
    """Derive v1.3 measurements from a stored run directory."""
    return derive_measurements(
        action_requests=_load_json_dir(run_dir / "actions"),
        action_results=_load_json_dir(run_dir / "results"),
        evidence_records=_load_json_dir(run_dir / "evidence"),
        findings=_load_json_dir(run_dir / "findings"),
        verifier_results=_load_json_dir(run_dir / "verification"),
        model_artifacts=[_load_json(path) for path in model_artifact_paths or []],
        case_rows=case_rows or [],
        arm_type=arm_type,
        candidate_based=candidate_based,
    )


def derive_measurements(
    *,
    action_requests: list[dict[str, Any]] | None = None,
    action_results: list[dict[str, Any]] | None = None,
    evidence_records: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    verifier_results: list[dict[str, Any]] | None = None,
    model_artifacts: list[dict[str, Any]] | None = None,
    case_rows: list[dict[str, Any]] | None = None,
    arm_type: str = "framework",
    candidate_based: bool = False,
) -> dict[str, Any]:
    """Return derived v1.3 measurements without changing evaluation outcomes."""
    actions = action_requests or []
    results = action_results or []
    evidence = evidence_records or []
    finding_records = findings or []
    verification = verifier_results or []
    model_records = model_artifacts or []
    cases = case_rows or []
    actions_by_id = {str(action.get("action_id")): action for action in actions}
    first_verified_at = _first_verified_timestamp(finding_records)
    run_started_at = _run_started_at(results, evidence, model_records)
    verified_finding_count = sum(1 for item in finding_records if item.get("state") == "verified")

    return {
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
        "undefined_values": {
            "not_available": "The artifact set does not contain the data required to derive the metric.",
            "not_applicable": "The metric has no meaningful denominator or does not apply to this arm/run.",
        },
        "action_counts": _action_counts(actions, results),
        "request_counts": _request_counts(results, actions_by_id),
        "first_verified_finding": _first_verified_metrics(
            action_results=results,
            actions_by_id=actions_by_id,
            run_started_at=run_started_at,
            first_verified_at=first_verified_at,
            has_verified_finding=verified_finding_count > 0,
            candidate_based=candidate_based,
        ),
        "verifier_decisions": _verifier_decisions(verification, finding_records),
        "model_provider": _model_provider_metrics(
            model_records,
            arm_type=arm_type,
            verified_finding_count=verified_finding_count,
        ),
        "classification_counts": classification_counts(cases),
        "case_accounting": {
            "case_count": len(cases),
            "model_trial_count": len(model_records),
            "independent_model_scenario_count": len(
                {str(item.get("scenario_id")) for item in model_records if item.get("scenario_id")}
            ),
            "note": "Repeated LLM trials are counted as model trials, not independent benchmark cases.",
        },
    }


def classification_counts(case_rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(row.get("classification")) for row in case_rows)
    return {key: counts.get(key, 0) for key in ("TP", "FP", "FN", "TN")}


def _action_counts(actions: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = Counter(str(result.get("status")) for result in results)
    result_count = len(results)
    blocked = statuses.get("blocked", 0)
    return {
        "requested": len(actions),
        "approved": result_count - blocked,
        "blocked": blocked,
        "executed": statuses.get("executed", 0),
        "failed": statuses.get("failed", 0),
        "skipped": statuses.get("skipped", 0),
        "result_record_count": result_count,
    }


def _request_counts(results: list[dict[str, Any]], actions_by_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    http_total = 0
    browser_total = 0
    inferred_total = 0
    for result in results:
        action = actions_by_id.get(str(result.get("action_id")), {})
        http_count, http_inferred = _http_request_count(result, action)
        browser_count, browser_inferred = _browser_navigation_count(result, action)
        http_total += http_count
        browser_total += browser_count
        inferred_total += int(http_inferred) + int(browser_inferred)
    return {
        "http_requests": http_total,
        "browser_navigations": browser_total,
        "inferred_count_fields": inferred_total,
    }


def _first_verified_metrics(
    *,
    action_results: list[dict[str, Any]],
    actions_by_id: dict[str, dict[str, Any]],
    run_started_at: datetime | None,
    first_verified_at: datetime | None,
    has_verified_finding: bool,
    candidate_based: bool,
) -> dict[str, Any]:
    if not has_verified_finding:
        return {
            "timestamp": NOT_APPLICABLE,
            "time_to_first_verified_finding_ms": NOT_APPLICABLE,
            "requests_to_first_verified_finding": NOT_APPLICABLE,
            "candidates_tested_before_first_verification": NOT_APPLICABLE,
        }
    if first_verified_at is None:
        return {
            "timestamp": NOT_AVAILABLE,
            "time_to_first_verified_finding_ms": NOT_AVAILABLE,
            "requests_to_first_verified_finding": NOT_AVAILABLE,
            "candidates_tested_before_first_verification": NOT_AVAILABLE if candidate_based else NOT_APPLICABLE,
        }

    eligible_results = [
        result
        for result in action_results
        if _parse_timestamp(str(result.get("completed_at") or "")) is not None
        and _parse_timestamp(str(result.get("completed_at") or "")) <= first_verified_at
    ]
    requests_before = 0
    candidate_ids: set[str] = set()
    for result in eligible_results:
        action = actions_by_id.get(str(result.get("action_id")), {})
        http_count, _ = _http_request_count(result, action)
        browser_count, _ = _browser_navigation_count(result, action)
        requests_before += http_count + browser_count
        candidate_id = _candidate_id(result) or _candidate_id(action)
        if candidate_id:
            candidate_ids.add(candidate_id)

    elapsed_ms: Any = NOT_AVAILABLE
    if run_started_at is not None:
        elapsed_ms = int((first_verified_at - run_started_at).total_seconds() * 1000)

    if candidate_based:
        candidates_before: Any = len(candidate_ids) if candidate_ids else NOT_AVAILABLE
    else:
        candidates_before = NOT_APPLICABLE

    return {
        "timestamp": first_verified_at.isoformat(),
        "time_to_first_verified_finding_ms": elapsed_ms,
        "requests_to_first_verified_finding": requests_before,
        "candidates_tested_before_first_verification": candidates_before,
    }


def _verifier_decisions(
    verifier_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    outcomes = Counter(str(item.get("outcome")) for item in verifier_results if item.get("outcome"))
    if not verifier_results:
        outcomes = Counter(str(item.get("state")) for item in findings if item.get("state"))
    return {
        "total": sum(outcomes.get(name, 0) for name in ("verified", "rejected", "inconclusive")),
        "verified": outcomes.get("verified", 0),
        "rejected": outcomes.get("rejected", 0),
        "inconclusive": outcomes.get("inconclusive", 0),
    }


def _model_provider_metrics(
    model_artifacts: list[dict[str, Any]],
    *,
    arm_type: str,
    verified_finding_count: int,
) -> dict[str, Any]:
    provider_applicable = arm_type in {"llm", "proprietary_llm", "local_llm"}
    if not provider_applicable:
        return {
            "provider_applicable": False,
            "trial_count": NOT_APPLICABLE,
            "valid_trial_count": NOT_APPLICABLE,
            "malformed_output_count": NOT_APPLICABLE,
            "malformed_output_rate": NOT_APPLICABLE,
            "timeout_count": NOT_APPLICABLE,
            "timeout_rate": NOT_APPLICABLE,
            "provider_failure_count": NOT_APPLICABLE,
            "provider_failure_rate": NOT_APPLICABLE,
            "latency_ms": NOT_APPLICABLE,
            "tokens": NOT_APPLICABLE,
            "cost_availability": NOT_APPLICABLE,
            "cost_per_ranking_trial_usd": NOT_APPLICABLE,
            "cost_per_verified_finding_usd": NOT_APPLICABLE,
        }

    trial_count = len(model_artifacts)
    valid_count = sum(1 for item in model_artifacts if not item.get("validation_errors") and not item.get("provider_failed"))
    malformed_count = sum(1 for item in model_artifacts if _has_malformed_output(item))
    timeout_count = sum(1 for item in model_artifacts if _is_timeout(item))
    provider_failure_count = sum(1 for item in model_artifacts if item.get("provider_failed") and not _is_timeout(item))
    usage = [_token_usage(item.get("usage")) for item in model_artifacts]
    latencies = [int(item["latency_ms"]) for item in model_artifacts if isinstance(item.get("latency_ms"), int)]
    cost_values = [_cost_usd(item.get("cost")) for item in model_artifacts]
    numeric_costs = [value for value in cost_values if isinstance(value, (int, float))]
    total_cost = sum(numeric_costs) if numeric_costs else None

    return {
        "provider_applicable": True,
        "trial_count": trial_count,
        "valid_trial_count": valid_count,
        "malformed_output_count": malformed_count,
        "malformed_output_rate": _rate(malformed_count, trial_count),
        "timeout_count": timeout_count,
        "timeout_rate": _rate(timeout_count, trial_count),
        "provider_failure_count": provider_failure_count,
        "provider_failure_rate": _rate(provider_failure_count, trial_count),
        "latency_ms": _latency_summary(latencies),
        "tokens": {
            "input": _sum_known([item["input"] for item in usage]),
            "output": _sum_known([item["output"] for item in usage]),
            "total": _sum_known([item["total"] for item in usage]),
        },
        "cost_availability": "available" if numeric_costs else NOT_AVAILABLE,
        "cost_total_usd": total_cost if total_cost is not None else NOT_AVAILABLE,
        "cost_per_ranking_trial_usd": (
            total_cost / trial_count if total_cost is not None and trial_count else NOT_AVAILABLE
        ),
        "cost_per_verified_finding_usd": _cost_per_verified_finding(total_cost, verified_finding_count),
    }


def _http_request_count(result: dict[str, Any], action: dict[str, Any]) -> tuple[int, bool]:
    observations = result.get("normalized_observations") or {}
    for key in ("http_request_count", "request_count"):
        value = observations.get(key)
        if isinstance(value, int):
            return value, False
    if str(result.get("status")) == "executed" and str(action.get("action_type")) in HTTP_ACTION_TYPES:
        return 1, True
    return 0, False


def _browser_navigation_count(result: dict[str, Any], action: dict[str, Any]) -> tuple[int, bool]:
    observations = result.get("normalized_observations") or {}
    value = observations.get("browser_navigation_count")
    if isinstance(value, int):
        return value, False
    if str(result.get("status")) == "executed" and str(action.get("action_type")) in BROWSER_ACTION_TYPES:
        return 1, True
    return 0, False


def _first_verified_timestamp(findings: list[dict[str, Any]]) -> datetime | None:
    timestamps = []
    for finding in findings:
        if finding.get("state") != "verified":
            continue
        report_fields = finding.get("report_fields") or {}
        for key in ("verified_at", "verification_completed_at", "first_verified_at"):
            parsed = _parse_timestamp(str(report_fields.get(key) or ""))
            if parsed is not None:
                timestamps.append(parsed)
                break
    return min(timestamps) if timestamps else None


def _run_started_at(
    results: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    model_artifacts: list[dict[str, Any]],
) -> datetime | None:
    timestamps = []
    for result in results:
        parsed = _parse_timestamp(str(result.get("started_at") or ""))
        if parsed is not None:
            timestamps.append(parsed)
    for item in evidence:
        parsed = _parse_timestamp(str(item.get("created_at") or ""))
        if parsed is not None:
            timestamps.append(parsed)
    for item in model_artifacts:
        parsed = _parse_timestamp(str(item.get("timestamp") or ""))
        if parsed is not None:
            timestamps.append(parsed)
    return min(timestamps) if timestamps else None


def _candidate_id(record: dict[str, Any]) -> str | None:
    for container_name in ("scope_context", "parameters", "normalized_observations", "attributes"):
        container = record.get(container_name)
        if isinstance(container, dict):
            value = container.get("candidate_id")
            if value:
                return str(value)
    return None


def _token_usage(usage: Any) -> dict[str, Any]:
    if not isinstance(usage, dict):
        return {"input": NOT_AVAILABLE, "output": NOT_AVAILABLE, "total": NOT_AVAILABLE}
    input_tokens = _first_int(usage, "input_tokens", "prompt_tokens")
    output_tokens = _first_int(usage, "output_tokens", "completion_tokens")
    total_tokens = _first_int(usage, "total_tokens")
    if total_tokens is None and input_tokens is not None and output_tokens is not None:
        total_tokens = input_tokens + output_tokens
    return {
        "input": input_tokens if input_tokens is not None else NOT_AVAILABLE,
        "output": output_tokens if output_tokens is not None else NOT_AVAILABLE,
        "total": total_tokens if total_tokens is not None else NOT_AVAILABLE,
    }


def _first_int(data: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, int):
            return value
    return None


def _sum_known(values: list[Any]) -> Any:
    numeric_values = [value for value in values if isinstance(value, int)]
    return sum(numeric_values) if numeric_values else NOT_AVAILABLE


def _latency_summary(latencies: list[int]) -> Any:
    if not latencies:
        return NOT_AVAILABLE
    return {
        "count": len(latencies),
        "min": min(latencies),
        "max": max(latencies),
        "mean": mean(latencies),
        "total": sum(latencies),
    }


def _cost_usd(cost: Any) -> float | None:
    if not isinstance(cost, dict):
        return None
    for key in ("estimated_cost_usd", "total_cost_usd", "amount_usd", "usd"):
        value = cost.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return None


def _cost_per_verified_finding(total_cost: float | None, verified_finding_count: int) -> Any:
    if verified_finding_count <= 0:
        return NOT_APPLICABLE
    if total_cost is None:
        return NOT_AVAILABLE
    return total_cost / verified_finding_count


def _has_malformed_output(item: dict[str, Any]) -> bool:
    return any("malformed" in str(error).lower() for error in item.get("validation_errors") or [])


def _is_timeout(item: dict[str, Any]) -> bool:
    errors = " ".join(str(error).lower() for error in item.get("validation_errors") or [])
    metadata = item.get("provider_metadata") or {}
    return bool(item.get("provider_failed")) and (
        "timeout" in errors
        or "timed out" in errors
        or str(metadata.get("error_type", "")).lower() == "timeout"
    )


def _rate(count: int, denominator: int) -> Any:
    return count / denominator if denominator else NOT_APPLICABLE


def _parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_json_dir(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [_load_json(item) for item in sorted(path.glob("*.json"))]
