from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from adstf.owasp_xss_v14_1_resumable_runner import (
    EXPECTED_DENOMINATORS,
    PROTOCOL_COMMIT,
    PROTOCOL_PACKAGE_DIR,
    PROTOCOL_PATH,
    PROTOCOL_TAG,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
FINAL_ROOT = REPO_ROOT / "results" / "owasp-xss-v14-1-confirmatory-final"
ANALYSIS_ROOT = FINAL_ROOT / "canonical-analysis"
NOT_APPLICABLE = "not_applicable"
NOT_AVAILABLE = "not_available"
ARM_ORDER = (
    "deterministic_minimal",
    "deterministic_enriched",
    "gpt_minimal",
    "gpt_enriched",
    "qwen_minimal",
    "qwen_enriched",
)
PRIMARY_COMPARISONS = (
    ("gpt_enriched", "gpt_minimal"),
    ("qwen_enriched", "qwen_minimal"),
    ("gpt_enriched", "deterministic_enriched"),
    ("qwen_enriched", "deterministic_enriched"),
)
BOOTSTRAP_ITERATIONS = 10_000
PERMUTATION_ITERATIONS = 10_000
STATISTICAL_SEED = 14101


def build_analysis_package(
    *,
    final_root: Path = FINAL_ROOT,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    output_dir = output_dir or timestamped_output_dir(ANALYSIS_ROOT)
    output_dir.mkdir(parents=True, exist_ok=False)

    protocol = load_protocol_artifacts(protocol_package_dir)
    raw_rows = load_raw_rows(final_root)
    pre_scoring = audit_pre_scoring_integrity(raw_rows, protocol, final_root, protocol_package_dir)
    if not pre_scoring["valid"]:
        write_json(output_dir / "validation-report.json", pre_scoring)
        raise RuntimeError("pre-scoring integrity failed; refusing to load ground truth")

    scoring = load_json(protocol_package_dir / "ground-truth" / "scoring-data.json")
    scenarios = {scenario["scenario_id"]: scenario for scenario in scoring["scenarios"]}
    scored_rows = [score_ranking_row(row, scenarios[row["summary"]["scenario_id"]]) for row in raw_rows]

    scenario_metrics = scenario_level_results(scored_rows)
    arm_summaries = {arm: aggregate_arm_metrics([row for row in scored_rows if row["arm_id"] == arm]) for arm in ARM_ORDER}
    reliability = {arm: reliability_summary([row for row in scored_rows if row["arm_id"] == arm]) for arm in ARM_ORDER}
    efficiency = {arm: efficiency_summary([row for row in scored_rows if row["arm_id"] == arm], arm) for arm in ARM_ORDER}
    stability = {arm: ranking_stability([row for row in scored_rows if row["arm_id"] == arm]) for arm in ARM_ORDER}
    negative = negative_scenario_behavior(scored_rows, protocol)
    decomposition = minimal_vs_enriched_decomposition(arm_summaries)
    comparisons = primary_mrr_comparisons(scenario_metrics)
    proxy_risk = proxy_risk_interpretation(decomposition, comparisons, arm_summaries)
    validation = validate_analysis_outputs(scored_rows, scenario_metrics, arm_summaries, reliability, pre_scoring)

    package = {
        "manifest": manifest(output_dir, final_root, protocol_package_dir, pre_scoring, validation),
        "pre_scoring_integrity": pre_scoring,
        "scored_rows": scored_rows,
        "scenario_metrics": scenario_metrics,
        "arm_summaries": arm_summaries,
        "reliability": reliability,
        "efficiency": efficiency,
        "stability": stability,
        "negative_scenario_behavior": negative,
        "minimal_vs_enriched": decomposition,
        "statistical_analysis": {
            "schema_version": "owasp-xss-v14-1-statistical-analysis-v1",
            "primary_outcome": "scenario-level MRR on positive scenarios",
            "inferential_unit": "scenario",
            "llm_trial_handling": "repeated trials are nested under scenario and arm; they are not independent benchmark scenarios",
            "bootstrap_iterations": BOOTSTRAP_ITERATIONS,
            "permutation_iterations": PERMUTATION_ITERATIONS,
            "seed": STATISTICAL_SEED,
            "multiple_comparison_policy": "Holm correction across the four primary paired MRR comparisons",
            "primary_mrr_comparisons": comparisons,
        },
        "proxy_risk_interpretation": proxy_risk,
        "validation": validation,
    }
    write_package(output_dir, package)
    checksum_errors = validate_checksum_file(output_dir / "checksums.sha256", output_dir)
    checksum_report = {
        "schema_version": "owasp-xss-v14-1-analysis-checksum-validation-v1",
        "valid": not checksum_errors,
        "errors": checksum_errors,
        "checked_at": now_utc(),
    }
    write_json(output_dir / "checksum-validation-report.json", checksum_report)
    package["checksum_validation"] = checksum_report
    write_json(output_dir / "manifest.json", {**package["manifest"], "checksum_validation_valid": checksum_report["valid"]})
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    return package


def load_protocol_artifacts(root: Path) -> dict[str, Any]:
    minimal_index = load_json(root / "model-facing" / "minimal-candidate-snapshot-index.json")
    enriched_index = load_json(root / "model-facing" / "enriched-candidate-snapshot-index.json")
    return {
        "root": root,
        "manifest": load_json(root / "manifest.json"),
        "schedule": load_json(root / "trial-schedule.json"),
        "metric_spec": load_json(root / "metric-scoring-specification.json"),
        "statistical_plan": load_json(root / "statistical-analysis-plan.json"),
        "minimal_index": minimal_index,
        "enriched_index": enriched_index,
        "minimal_snapshots": {item["scenario_id"]: load_json(root / item["path"]) for item in minimal_index["snapshot_paths"]},
        "enriched_snapshots": {item["scenario_id"]: load_json(root / item["path"]) for item in enriched_index["snapshot_paths"]},
    }


def load_raw_rows(final_root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(final_root.glob("*/raw/ranking-rows/sequence-*.json")):
        row = load_json(path)
        row["_artifact_path"] = display_path(path)
        row["_artifact_sha256"] = sha256_file(path)
        rows.append(row)
    return sorted(rows, key=lambda item: int(item["summary"]["sequence"]))


def audit_pre_scoring_integrity(
    rows: list[dict[str, Any]],
    protocol: dict[str, Any],
    final_root: Path,
    protocol_package_dir: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    schedule_rows = protocol["schedule"]["rows"]
    by_sequence = {int(row["sequence"]): row for row in schedule_rows}
    seen_sequences: Counter[int] = Counter()
    row_ids: Counter[str] = Counter()
    candidate_checksum_errors = []
    gt_leaks = []
    artifact_status = Counter()
    arm_counts = Counter()
    empty_or_nonfinal_dirs = []

    for path in sorted(final_root.glob("*")):
        if path.is_dir() and not list(path.glob("raw/ranking-rows/sequence-*.json")):
            empty_or_nonfinal_dirs.append(display_path(path))

    for row in rows:
        summary = row.get("summary", {})
        sequence = int(summary.get("sequence", -1))
        seen_sequences[sequence] += 1
        row_ids[str(summary.get("row_id"))] += 1
        arm_counts[str(summary.get("arm_id"))] += 1
        artifact_status[str(summary.get("status"))] += 1
        scheduled = by_sequence.get(sequence)
        if scheduled is None:
            errors.append(f"unscheduled_sequence:{sequence}")
            continue
        for key in ("row_id", "arm_id", "scenario_id", "trial_number", "representation_condition", "snapshot_path"):
            if summary.get(key) != scheduled.get(key):
                errors.append(f"schedule_identity_mismatch:{sequence}:{key}")
        snapshot = snapshot_for_scheduled_row(protocol, scheduled)
        if summary.get("candidate_input_sha256") != sha256_json(snapshot["candidate_input"]):
            candidate_checksum_errors.append(sequence)
        if row.get("ground_truth_included") is not False:
            gt_leaks.append(sequence)
        model_facing_content = {
            "summary": {key: value for key, value in summary.items() if key != "ground_truth_included"},
            "ranking_result": row.get("ranking_result", {}),
        }
        serialized_model_facing = json.dumps(model_facing_content, sort_keys=True).lower()
        if any(fragment in serialized_model_facing for fragment in ("expected_result", "focal_vulnerable_candidate_id", "ground_truth_exposed")):
            gt_leaks.append(sequence)

    missing_sequences = [seq for seq in range(1, EXPECTED_DENOMINATORS["total_ranking_rows"] + 1) if seen_sequences[seq] == 0]
    duplicate_sequences = [seq for seq, count in seen_sequences.items() if count > 1]
    duplicate_row_ids = [rid for rid, count in row_ids.items() if count > 1]
    checksum_errors = validate_checksum_file(protocol_package_dir / "checksums.sha256", protocol_package_dir)
    protocol_hash = sha256_file(PROTOCOL_PATH)
    expected_arm_counts = {arm: EXPECTED_DENOMINATORS[arm] for arm in ARM_ORDER}

    if dict(arm_counts) != expected_arm_counts:
        errors.append(f"arm_denominator_mismatch:{dict(arm_counts)}")
    if len(rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append(f"total_denominator_mismatch:{len(rows)}")
    if missing_sequences:
        errors.append(f"missing_sequences:{len(missing_sequences)}")
    if duplicate_sequences:
        errors.append(f"duplicate_sequences:{len(duplicate_sequences)}")
    if duplicate_row_ids:
        errors.append(f"duplicate_row_ids:{len(duplicate_row_ids)}")
    if candidate_checksum_errors:
        errors.append(f"candidate_snapshot_checksum_mismatch:{len(candidate_checksum_errors)}")
    if gt_leaks:
        errors.append(f"ground_truth_present_before_scoring:{len(set(gt_leaks))}")
    if checksum_errors:
        errors.append(f"protocol_package_checksum_errors:{len(checksum_errors)}")
    if protocol["manifest"].get("denominators") != EXPECTED_DENOMINATORS:
        errors.append("protocol_manifest_denominator_mismatch")
    if protocol["schedule"].get("denominators") != EXPECTED_DENOMINATORS:
        errors.append("trial_schedule_denominator_mismatch")
    return {
        "schema_version": "owasp-xss-v14-1-pre-scoring-integrity-v1",
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "total_rows": len(rows),
        "expected_total_rows": EXPECTED_DENOMINATORS["total_ranking_rows"],
        "per_arm_counts": dict(arm_counts),
        "expected_per_arm_counts": expected_arm_counts,
        "status_counts": dict(artifact_status),
        "missing_sequences": missing_sequences[:25],
        "missing_sequence_count": len(missing_sequences),
        "duplicate_sequences": duplicate_sequences[:25],
        "duplicate_sequence_count": len(duplicate_sequences),
        "duplicate_row_ids": duplicate_row_ids[:25],
        "duplicate_row_id_count": len(duplicate_row_ids),
        "candidate_snapshot_checksum_error_count": len(candidate_checksum_errors),
        "ground_truth_leak_count": len(set(gt_leaks)),
        "protocol_package_checksum_error_count": len(checksum_errors),
        "protocol_package_checksum_errors": checksum_errors[:10],
        "protocol_sha256": protocol_hash,
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": PROTOCOL_COMMIT,
        "empty_or_nonfinal_run_dirs": empty_or_nonfinal_dirs,
        "deterministic_resume_incident": {
            "first_attempt_terminal_rows": "1-131",
            "incident": "Windows replace of completion-index.json failed during deterministic execution",
            "operator_action": "removed stale completion-index.json.tmp only",
            "resume_start_sequence": 132,
            "completed_sequence_rerun_detected": False,
            "validity_effect": "operational_provenance_only",
        },
        "git_state": git_state(),
    }


def snapshot_for_scheduled_row(protocol: dict[str, Any], scheduled: dict[str, Any]) -> dict[str, Any]:
    snapshots = protocol["enriched_snapshots"] if scheduled["representation_condition"] == "enriched" else protocol["minimal_snapshots"]
    return snapshots[scheduled["scenario_id"]]


def score_ranking_row(row: dict[str, Any], scenario: dict[str, Any]) -> dict[str, Any]:
    summary = row["summary"]
    result = row.get("ranking_result", {})
    parsed = result.get("parsed_ranking") or result.get("ordered_candidate_ids") or []
    scenario_type = scenario["scenario_type"]
    focal_id = scenario.get("focal_vulnerable_candidate_id")
    contract_valid = bool(summary.get("contract_valid"))
    rank: int | str = NOT_APPLICABLE
    top1: bool | str = NOT_APPLICABLE
    top2: bool | str = NOT_APPLICABLE
    top4: bool | str = NOT_APPLICABLE
    reciprocal: float | str = NOT_APPLICABLE
    if scenario_type == "positive":
        if contract_valid and focal_id in parsed:
            rank = parsed.index(focal_id) + 1
            top1 = rank == 1
            top2 = rank <= 2
            top4 = rank <= 4
            reciprocal = 1.0 / rank
        else:
            rank = NOT_AVAILABLE
            top1 = NOT_AVAILABLE
            top2 = NOT_AVAILABLE
            top4 = NOT_AVAILABLE
            reciprocal = NOT_AVAILABLE
    return {
        "sequence": int(summary["sequence"]),
        "row_id": summary.get("row_id"),
        "scenario_id": summary["scenario_id"],
        "scenario_type": scenario_type,
        "arm_id": summary["arm_id"],
        "arm_family": summary.get("arm_family"),
        "representation_condition": summary.get("representation_condition"),
        "trial_number": int(summary["trial_number"]),
        "candidate_test_budget": int(summary.get("candidate_test_budget", 4)),
        "top_k": int(summary.get("top_k", 4)),
        "candidate_input_sha256": summary.get("candidate_input_sha256"),
        "contract_valid": contract_valid,
        "status": summary.get("status"),
        "provider_failed": bool(summary.get("provider_failed")),
        "runtime_failed": summary.get("status") == "runtime_failed",
        "timeout": summary.get("status") == "timeout",
        "validation_error_count": len(summary.get("validation_errors", [])),
        "validation_errors": summary.get("validation_errors", []),
        "latency_ms": summary.get("latency_ms"),
        "model_identifier": summary.get("model_identifier"),
        "provider": summary.get("provider"),
        "prompt_version": summary.get("prompt_version"),
        "focal_vulnerable_candidate_id": focal_id if scenario_type == "positive" else NOT_APPLICABLE,
        "vulnerable_rank": rank,
        "top1": top1,
        "top2": top2,
        "top4": top4,
        "reciprocal_rank": reciprocal,
        "parsed_ranking": parsed,
        "raw_artifact_path": row.get("_artifact_path"),
        "raw_artifact_sha256": row.get("_artifact_sha256"),
        "usage": result.get("usage"),
        "cost": result.get("cost"),
        "provider_metadata": scrub_provider_metadata(result.get("provider_metadata")),
    }


def aggregate_arm_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive = [row for row in rows if row["scenario_type"] == "positive"]
    negative = [row for row in rows if row["scenario_type"] == "negative_only"]
    valid_positive = [row for row in positive if row["contract_valid"] and isinstance(row["reciprocal_rank"], float)]
    scenario_metrics = [row for row in scenario_level_results(rows) if row["scenario_type"] == "positive"]
    applicable_scenarios = [row for row in scenario_metrics if isinstance(row["scenario_level_mrr"], float)]
    rank_distribution = Counter(str(row["vulnerable_rank"]) for row in valid_positive)
    return {
        "scheduled_rows": len(rows),
        "eligible_positive_scenarios": len({row["scenario_id"] for row in positive}),
        "negative_scenarios": len({row["scenario_id"] for row in negative}),
        "positive_expected_trials": len(positive),
        "positive_valid_trials": len(valid_positive),
        "positive_invalid_trials": len(positive) - len(valid_positive),
        "negative_expected_trials": len(negative),
        "negative_valid_trials": sum(1 for row in negative if row["contract_valid"]),
        "top1": mean_float([row["scenario_top1_rate"] for row in applicable_scenarios]),
        "top2": mean_float([row["scenario_top2_rate"] for row in applicable_scenarios]),
        "top4": mean_float([row["scenario_top4_rate"] for row in applicable_scenarios]),
        "scenario_level_mrr": mean_float([row["scenario_level_mrr"] for row in applicable_scenarios]),
        "valid_trial_top1": safe_ratio(sum(1 for row in valid_positive if row["top1"] is True), len(valid_positive)),
        "valid_trial_top2": safe_ratio(sum(1 for row in valid_positive if row["top2"] is True), len(valid_positive)),
        "valid_trial_top4": safe_ratio(sum(1 for row in valid_positive if row["top4"] is True), len(valid_positive)),
        "valid_trial_mrr": mean_float([row["reciprocal_rank"] for row in valid_positive]),
        "rank_distribution": {str(rank): rank_distribution.get(str(rank), 0) for rank in range(1, 6)},
        "negative_top1_top2_top4_mrr": NOT_APPLICABLE,
    }


def scenario_level_results(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_key[(row["arm_id"], row["scenario_id"])].append(row)
    metrics = []
    for (arm, scenario_id), scenario_rows in sorted(by_key.items()):
        scenario_type = scenario_rows[0]["scenario_type"]
        valid_positive = [
            row for row in scenario_rows
            if row["scenario_type"] == "positive" and row["contract_valid"] and isinstance(row["reciprocal_rank"], float)
        ]
        metrics.append({
            "arm_id": arm,
            "scenario_id": scenario_id,
            "scenario_type": scenario_type,
            "scheduled_trials": len(scenario_rows),
            "valid_trials": sum(1 for row in scenario_rows if row["contract_valid"]),
            "invalid_trials": sum(1 for row in scenario_rows if not row["contract_valid"]),
            "scenario_top1_rate": safe_ratio(sum(1 for row in valid_positive if row["top1"] is True), len(valid_positive)) if scenario_type == "positive" else NOT_APPLICABLE,
            "scenario_top2_rate": safe_ratio(sum(1 for row in valid_positive if row["top2"] is True), len(valid_positive)) if scenario_type == "positive" else NOT_APPLICABLE,
            "scenario_top4_rate": safe_ratio(sum(1 for row in valid_positive if row["top4"] is True), len(valid_positive)) if scenario_type == "positive" else NOT_APPLICABLE,
            "scenario_level_mrr": mean_float([row["reciprocal_rank"] for row in valid_positive]) if scenario_type == "positive" else NOT_APPLICABLE,
            "valid_positive_trials": len(valid_positive),
        })
    return metrics


def reliability_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(row["status"] for row in rows)
    valid = sum(1 for row in rows if row["contract_valid"])
    return {
        "scheduled_rows": len(rows),
        "completed_artifacts": len(rows),
        "valid": valid,
        "contract_invalid": len(rows) - valid,
        "malformed": status_counts.get("malformed", 0),
        "provider_failed": status_counts.get("provider_failed", 0) + sum(1 for row in rows if row["provider_failed"] and row["status"] != "provider_failed"),
        "runtime_failed": status_counts.get("runtime_failed", 0),
        "timeout": status_counts.get("timeout", 0),
        "other_terminal": sum(count for status, count in status_counts.items() if status not in {"valid", "malformed", "provider_failed", "runtime_failed", "timeout"}),
        "retry_count": 0,
        "contract_validity_rate": safe_ratio(valid, len(rows)),
        "status_counts": dict(status_counts),
    }


def efficiency_summary(rows: list[dict[str, Any]], arm: str) -> dict[str, Any]:
    latencies = [int(row["latency_ms"]) for row in rows if isinstance(row.get("latency_ms"), int)]
    return {
        "latency_ms": describe_numeric(latencies),
        "token_usage": token_summary(rows),
        "cost": cost_summary(rows, arm),
        "cost_per_finding": NOT_AVAILABLE,
        "cost_per_finding_reason": "no frozen numeric pricing basis exists for this evaluation",
        "time_to_first_verified_finding": NOT_APPLICABLE,
        "requests_to_first_verified_finding": NOT_APPLICABLE,
    }


def ranking_stability(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows or rows[0]["arm_family"] == "deterministic":
        return {"applicable": False, "reason": "single deterministic trial per scenario"}
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario_id"]].append(row)
    unique_rankings = []
    unique_top1 = []
    fully_valid_unanimous_top1 = 0
    scenario_count = 0
    for scenario_rows in by_scenario.values():
        valid = [row for row in scenario_rows if row["contract_valid"] and row["parsed_ranking"]]
        if not valid:
            continue
        scenario_count += 1
        rankings = {tuple(row["parsed_ranking"]) for row in valid}
        top_ids = {row["parsed_ranking"][0] for row in valid}
        unique_rankings.append(len(rankings))
        unique_top1.append(len(top_ids))
        if len(valid) == len(scenario_rows) and len(top_ids) == 1:
            fully_valid_unanimous_top1 += 1
    return {
        "applicable": True,
        "scenario_count_with_valid_trials": scenario_count,
        "mean_unique_rankings_per_scenario": mean_float(unique_rankings),
        "median_unique_rankings_per_scenario": median_value(unique_rankings),
        "mean_unique_top1_per_scenario": mean_float(unique_top1),
        "scenarios_with_unanimous_top1_and_all_trials_valid": fully_valid_unanimous_top1,
    }


def negative_scenario_behavior(scored_rows: list[dict[str, Any]], protocol: dict[str, Any]) -> dict[str, Any]:
    enriched_context_by_candidate: dict[str, dict[str, Any]] = {}
    for snapshot in protocol["enriched_snapshots"].values():
        for candidate in snapshot["candidate_input"]:
            enriched_context_by_candidate[candidate["candidate_id"]] = candidate
    by_arm = {}
    for arm in ARM_ORDER:
        rows = [row for row in scored_rows if row["arm_id"] == arm and row["scenario_type"] == "negative_only"]
        valid = [row for row in rows if row["contract_valid"] and row["parsed_ranking"]]
        top_candidates = [row["parsed_ranking"][0] for row in valid]
        contexts = [enriched_context_by_candidate.get(candidate_id, {}) for candidate_id in top_candidates]
        by_arm[arm] = {
            "negative_scenarios": len({row["scenario_id"] for row in rows}),
            "scheduled_negative_rows": len(rows),
            "valid_negative_rows": len(valid),
            "ranking_metrics": NOT_APPLICABLE,
            "top1_reflection_detected_counts": dict(Counter(str(item.get("reflection_detected", NOT_AVAILABLE)) for item in contexts)),
            "top1_marker_preservation_counts": dict(Counter(str(item.get("marker_preservation_category", NOT_AVAILABLE)) for item in contexts)),
            "top1_reflection_context_counts": dict(Counter(str(item.get("reflection_context_category", NOT_AVAILABLE)) for item in contexts)),
        }
    return {
        "schema_version": "owasp-xss-v14-1-negative-scenario-behavior-v1",
        "policy": "negative-only scenarios have no vulnerable-candidate rank, Top-k, reciprocal-rank or MRR denominator",
        "arms": by_arm,
    }


def minimal_vs_enriched_decomposition(arm_summaries: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for family in ("deterministic", "gpt", "qwen"):
        minimal = arm_summaries[f"{family}_minimal"]
        enriched = arm_summaries[f"{family}_enriched"]
        item = {"family": family}
        for metric in ("scenario_level_mrr", "top1", "top2", "top4"):
            item[f"minimal_{metric}"] = minimal[metric]
            item[f"enriched_{metric}"] = enriched[metric]
            item[f"delta_{metric}"] = numeric_delta(enriched[metric], minimal[metric])
        rows.append(item)
    return rows


def primary_mrr_comparisons(
    scenario_metrics: list[dict[str, Any]],
    *,
    bootstrap_iterations: int = BOOTSTRAP_ITERATIONS,
    permutation_iterations: int = PERMUTATION_ITERATIONS,
    seed: int = STATISTICAL_SEED,
) -> list[dict[str, Any]]:
    values: dict[tuple[str, str], float] = {}
    for row in scenario_metrics:
        value = row.get("scenario_level_mrr")
        if isinstance(value, float):
            values[(row["arm_id"], row["scenario_id"])] = value
    comparisons = []
    for index, (treatment, control) in enumerate(PRIMARY_COMPARISONS):
        scenario_ids = sorted({scenario_id for arm, scenario_id in values if arm == treatment} & {scenario_id for arm, scenario_id in values if arm == control})
        deltas = [values[(treatment, scenario_id)] - values[(control, scenario_id)] for scenario_id in scenario_ids]
        rng = random.Random(seed + index)
        ci_low, ci_high = bootstrap_ci(deltas, bootstrap_iterations, rng)
        p_value = paired_sign_permutation_p_value(deltas, permutation_iterations, random.Random(seed + 100 + index))
        comparisons.append({
            "comparison": f"{treatment} vs {control}",
            "treatment_arm": treatment,
            "control_arm": control,
            "effect": "scenario_level_mrr_difference_treatment_minus_control",
            "observed_difference": mean_float(deltas),
            "paired_scenarios": len(deltas),
            "bootstrap_ci_95": [ci_low, ci_high],
            "raw_p_value": p_value,
            "method": "scenario-level paired bootstrap CI and paired sign-flip permutation test",
        })
    adjusted = holm_adjust_pvalues([float(item["raw_p_value"]) for item in comparisons])
    for item, adjusted_p in zip(comparisons, adjusted, strict=True):
        item["holm_adjusted_p_value"] = adjusted_p
        item["holm_family_size"] = len(comparisons)
        item["statistical_evidence_alpha_0_05_after_holm"] = adjusted_p < 0.05
    return comparisons


def bootstrap_ci(deltas: list[float], iterations: int, rng: random.Random) -> tuple[float | str, float | str]:
    if not deltas:
        return NOT_AVAILABLE, NOT_AVAILABLE
    samples = []
    n = len(deltas)
    for _ in range(iterations):
        samples.append(statistics.mean(deltas[rng.randrange(n)] for _ in range(n)))
    samples.sort()
    return percentile(samples, 0.025), percentile(samples, 0.975)


def paired_sign_permutation_p_value(deltas: list[float], iterations: int, rng: random.Random) -> float | str:
    nonzero = [delta for delta in deltas if delta != 0]
    if not nonzero:
        return 1.0
    observed = abs(statistics.mean(nonzero))
    n = len(nonzero)
    if n <= 18:
        total = 2 ** n
        extreme = 0
        for mask in range(total):
            value = statistics.mean(nonzero[i] if (mask >> i) & 1 else -nonzero[i] for i in range(n))
            if abs(value) >= observed - 1e-15:
                extreme += 1
        return extreme / total
    extreme = 0
    for _ in range(iterations):
        value = statistics.mean(delta if rng.random() < 0.5 else -delta for delta in nonzero)
        if abs(value) >= observed - 1e-15:
            extreme += 1
    return (extreme + 1) / (iterations + 1)


def holm_adjust_pvalues(p_values: list[float]) -> list[float]:
    indexed = sorted(enumerate(p_values), key=lambda item: item[1])
    adjusted = [0.0] * len(p_values)
    running_max = 0.0
    m = len(p_values)
    for rank, (index, p_value) in enumerate(indexed):
        value = min(1.0, (m - rank) * p_value)
        running_max = max(running_max, value)
        adjusted[index] = running_max
    return adjusted


def proxy_risk_interpretation(
    decomposition: list[dict[str, Any]],
    comparisons: list[dict[str, Any]],
    arm_summaries: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    by_family = {row["family"]: row for row in decomposition}
    comp = {row["comparison"]: row for row in comparisons}
    return {
        "schema_version": "owasp-xss-v14-1-proxy-risk-interpretation-v1",
        "supervisor_concern": "reflection-derived enriched variables may be close proxies for reflected-XSS susceptibility",
        "deterministic_enrichment_mrr_delta": by_family["deterministic"]["delta_scenario_level_mrr"],
        "gpt_enrichment_mrr_delta": by_family["gpt"]["delta_scenario_level_mrr"],
        "qwen_enrichment_mrr_delta": by_family["qwen"]["delta_scenario_level_mrr"],
        "gpt_enriched_minus_deterministic_enriched_mrr": comp.get("gpt_enriched vs deterministic_enriched", {}).get("observed_difference"),
        "qwen_enriched_minus_deterministic_enriched_mrr": comp.get("qwen_enriched vs deterministic_enriched", {}).get("observed_difference"),
        "interpretation_rules": [
            "Primary analysis is unchanged by this post-run caution.",
            "If deterministic enrichment improves over deterministic minimal, the added context itself carries ranking-relevant signal.",
            "If enriched LLM arms do not improve substantially beyond deterministic enriched, the evidence should not be interpreted as model-specific reasoning beyond the enriched features.",
            "Claims that reflection-derived enrichment independently demonstrates LLM reasoning would be unsafe without an additional restricted-context sensitivity analysis.",
        ],
        "summary": proxy_summary(by_family, arm_summaries),
        "future_sensitivity_analysis": "methodologically_warranted_if_the_thesis_wants_to_isolate_model_reasoning_from_reflection_proxy_features",
    }


def proxy_summary(by_family: dict[str, dict[str, Any]], arm_summaries: dict[str, dict[str, Any]]) -> str:
    det_delta = by_family["deterministic"]["delta_scenario_level_mrr"]
    gpt_delta = by_family["gpt"]["delta_scenario_level_mrr"]
    qwen_delta = by_family["qwen"]["delta_scenario_level_mrr"]
    return (
        "The proxy-risk interpretation should compare the deterministic enriched gain "
        f"({fmt(det_delta)}) with the GPT enriched gain ({fmt(gpt_delta)}) and Qwen enriched gain ({fmt(qwen_delta)}), "
        "then interpret any additional LLM effect relative to deterministic_enriched rather than treating enrichment alone as model-specific reasoning."
    )


def validate_analysis_outputs(
    scored_rows: list[dict[str, Any]],
    scenario_metrics: list[dict[str, Any]],
    arm_summaries: dict[str, dict[str, Any]],
    reliability: dict[str, dict[str, Any]],
    pre_scoring: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    if not pre_scoring["valid"]:
        errors.append("pre_scoring_integrity_invalid")
    if len(scored_rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("scored_row_total_mismatch")
    if len({row["scenario_id"] for row in scored_rows}) != 266:
        errors.append("scenario_denominator_mismatch")
    for arm in ARM_ORDER:
        expected = EXPECTED_DENOMINATORS[arm]
        if arm_summaries[arm]["scheduled_rows"] != expected:
            errors.append(f"arm_summary_denominator_mismatch:{arm}")
        if reliability[arm]["scheduled_rows"] != expected:
            errors.append(f"reliability_denominator_mismatch:{arm}")
    positive_scenario_counts = {
        arm: len({row["scenario_id"] for row in scenario_metrics if row["arm_id"] == arm and row["scenario_type"] == "positive"})
        for arm in ARM_ORDER
    }
    if any(count != 236 for count in positive_scenario_counts.values()):
        errors.append(f"positive_scenario_metric_denominator_mismatch:{positive_scenario_counts}")
    return {
        "schema_version": "owasp-xss-v14-1-analysis-validation-v1",
        "valid": not errors,
        "errors": errors,
        "expected_total_rows": EXPECTED_DENOMINATORS["total_ranking_rows"],
        "actual_total_rows": len(scored_rows),
        "expected_positive_scenarios_per_arm": 236,
        "positive_scenarios_per_arm": positive_scenario_counts,
        "expected_negative_scenarios_per_arm": 30,
        "ground_truth_loaded_only_after_pre_scoring_integrity": True,
        "new_experimental_calls": {
            "gpt": 0,
            "qwen": 0,
            "http": 0,
            "browser": 0,
            "deterministic_ranking": 0,
        },
    }


def write_package(output_dir: Path, package: dict[str, Any]) -> None:
    write_json(output_dir / "manifest.json", package["manifest"])
    write_json(output_dir / "pre-scoring-integrity-report.json", package["pre_scoring_integrity"])
    write_json(output_dir / "validation-report.json", package["validation"])
    write_json(output_dir / "normalized" / "scored-rows.json", package["scored_rows"])
    write_csv(output_dir / "normalized" / "scored-rows.csv", package["scored_rows"])
    write_json(output_dir / "normalized" / "scenario-level-results.json", package["scenario_metrics"])
    write_csv(output_dir / "normalized" / "scenario-level-results.csv", package["scenario_metrics"])
    write_json(output_dir / "normalized" / "arm-ranking-summary.json", package["arm_summaries"])
    write_csv(output_dir / "normalized" / "arm-ranking-summary.csv", arm_summary_rows(package))
    write_json(output_dir / "normalized" / "reliability-summary.json", package["reliability"])
    write_csv(output_dir / "normalized" / "reliability-summary.csv", dict_table_rows(package["reliability"], "arm_id"))
    write_json(output_dir / "normalized" / "efficiency-summary.json", package["efficiency"])
    write_csv(output_dir / "normalized" / "efficiency-summary.csv", efficiency_rows(package["efficiency"]))
    write_json(output_dir / "normalized" / "ranking-stability.json", package["stability"])
    write_csv(output_dir / "normalized" / "ranking-stability.csv", dict_table_rows(package["stability"], "arm_id"))
    write_json(output_dir / "normalized" / "negative-scenario-behavior.json", package["negative_scenario_behavior"])
    write_csv(output_dir / "normalized" / "minimal-vs-enriched-decomposition.csv", package["minimal_vs_enriched"])
    write_json(output_dir / "statistical-analysis.json", package["statistical_analysis"])
    write_csv(output_dir / "statistical-comparisons.csv", package["statistical_analysis"]["primary_mrr_comparisons"])
    write_json(output_dir / "proxy-risk-interpretation.json", package["proxy_risk_interpretation"])
    write_text(output_dir / "analysis-report.md", render_analysis_report(package))
    write_text(output_dir / "thesis-tables.md", render_thesis_tables_md(package))
    write_text(output_dir / "thesis-tables.tex", render_thesis_tables_tex(package))
    write_text(output_dir / "methodology-provenance-note.md", render_methodology_note(package))
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))


def manifest(
    output_dir: Path,
    final_root: Path,
    protocol_package_dir: Path,
    pre_scoring: dict[str, Any],
    validation: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-1-analysis-manifest-v1",
        "created_at": now_utc(),
        "artifact_status": "derived_post_run_ground_truth_scoring_and_statistical_analysis",
        "output_dir": display_path(output_dir),
        "raw_execution_root": display_path(final_root),
        "protocol_document": display_path(PROTOCOL_PATH),
        "protocol_tag": PROTOCOL_TAG,
        "protocol_commit": PROTOCOL_COMMIT,
        "protocol_package": display_path(protocol_package_dir),
        "protocol_sha256": pre_scoring["protocol_sha256"],
        "raw_artifacts_modified": False,
        "ground_truth_loaded_for_post_run_scoring": True,
        "ground_truth_available_during_ranking": False,
        "new_experimental_calls": validation["new_experimental_calls"],
        "denominators": EXPECTED_DENOMINATORS,
        "validation_valid": validation["valid"],
        "git_state": git_state(),
    }


def render_analysis_report(package: dict[str, Any]) -> str:
    lines = [
        "# v1.4.1 OWASP XSS Context-Enrichment Post-Run Analysis",
        "",
        "This package contains derived post-run scoring and statistical analysis only. It was produced after the complete pre-scoring integrity audit passed and after ground truth was authorized for post-run scoring. No ranking call, HTTP request, browser action, retry, repair or scored-artifact modification was performed by this analysis step.",
        "",
        "## Integrity",
        "",
        f"- Total ranking rows: `{package['pre_scoring_integrity']['total_rows']}` / `{EXPECTED_DENOMINATORS['total_ranking_rows']}`",
        f"- Missing sequences: `{package['pre_scoring_integrity']['missing_sequence_count']}`",
        f"- Duplicate sequences: `{package['pre_scoring_integrity']['duplicate_sequence_count']}`",
        f"- Candidate snapshot checksum errors: `{package['pre_scoring_integrity']['candidate_snapshot_checksum_error_count']}`",
        f"- Ground-truth leak count before scoring: `{package['pre_scoring_integrity']['ground_truth_leak_count']}`",
        f"- Package validation: `{package['validation']['valid']}`",
        "",
        "## Ranking Effectiveness",
        "",
        "| Arm | Positive scenarios | Valid positive trials | Top-1 | Top-2 | Top-4 | Scenario-level MRR |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_ORDER:
        a = package["arm_summaries"][arm]
        lines.append(
            f"| `{arm}` | {a['eligible_positive_scenarios']} | {a['positive_valid_trials']} / {a['positive_expected_trials']} | "
            f"{fmt(a['top1'])} | {fmt(a['top2'])} | {fmt(a['top4'])} | {fmt(a['scenario_level_mrr'])} |"
        )
    lines.extend([
        "",
        "## Primary Paired MRR Comparisons",
        "",
        "| Comparison | Difference | 95% bootstrap CI | raw p | Holm-adjusted p | Evidence after Holm |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ])
    for item in package["statistical_analysis"]["primary_mrr_comparisons"]:
        ci = item["bootstrap_ci_95"]
        lines.append(
            f"| `{item['comparison']}` | {fmt(item['observed_difference'])} | [{fmt(ci[0])}, {fmt(ci[1])}] | "
            f"{fmt(item['raw_p_value'])} | {fmt(item['holm_adjusted_p_value'])} | {item['statistical_evidence_alpha_0_05_after_holm']} |"
        )
    lines.extend([
        "",
        "## Minimal vs. Enriched Decomposition",
        "",
        "| Family | Minimal MRR | Enriched MRR | Delta MRR | Minimal Top-1 | Enriched Top-1 | Delta Top-1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for row in package["minimal_vs_enriched"]:
        lines.append(
            f"| `{row['family']}` | {fmt(row['minimal_scenario_level_mrr'])} | {fmt(row['enriched_scenario_level_mrr'])} | "
            f"{fmt(row['delta_scenario_level_mrr'])} | {fmt(row['minimal_top1'])} | {fmt(row['enriched_top1'])} | {fmt(row['delta_top1'])} |"
        )
    lines.extend([
        "",
        "## Proxy-Risk Interpretation",
        "",
        package["proxy_risk_interpretation"]["summary"],
        "",
        "The enriched variables include reflection-derived observations. The primary analysis is therefore valid as a comparison of the frozen minimal and enriched task representations, but enrichment effects should not be interpreted by themselves as evidence of independent model reasoning. A restricted-context sensitivity analysis would be needed for that narrower claim.",
        "",
        "## Negative/Control Scenarios",
        "",
        "Negative-only scenarios are reported separately. They do not contribute to vulnerable-candidate rank, Top-1, Top-2, Top-4 or MRR denominators.",
        "",
        "## Cost",
        "",
        "Cost per finding remains `not_available` because no frozen numeric pricing basis exists for this evaluation.",
    ])
    return "\n".join(lines) + "\n"


def render_thesis_tables_md(package: dict[str, Any]) -> str:
    lines = [
        "# Thesis-Ready Tables: v1.4.1 OWASP XSS Context Enrichment",
        "",
        "## Candidate-Ranking Effectiveness",
        "",
        "| Arm | Representation | Positive scenarios | Valid/expected positive trials | Top-1 | Top-2 | Top-4 | MRR |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_ORDER:
        a = package["arm_summaries"][arm]
        lines.append(
            f"| {family_label(arm)} | {condition_label(arm)} | {a['eligible_positive_scenarios']} | "
            f"{a['positive_valid_trials']}/{a['positive_expected_trials']} | {fmt(a['top1'])} | {fmt(a['top2'])} | {fmt(a['top4'])} | {fmt(a['scenario_level_mrr'])} |"
        )
    lines.extend([
        "",
        "## Minimal-to-Enriched Decomposition",
        "",
        "| Family | MRR minimal | MRR enriched | Delta | Top-1 minimal | Top-1 enriched | Delta | Top-2 minimal | Top-2 enriched | Delta | Top-4 minimal | Top-4 enriched | Delta |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for row in package["minimal_vs_enriched"]:
        lines.append(
            f"| {row['family']} | {fmt(row['minimal_scenario_level_mrr'])} | {fmt(row['enriched_scenario_level_mrr'])} | {fmt(row['delta_scenario_level_mrr'])} | "
            f"{fmt(row['minimal_top1'])} | {fmt(row['enriched_top1'])} | {fmt(row['delta_top1'])} | "
            f"{fmt(row['minimal_top2'])} | {fmt(row['enriched_top2'])} | {fmt(row['delta_top2'])} | "
            f"{fmt(row['minimal_top4'])} | {fmt(row['enriched_top4'])} | {fmt(row['delta_top4'])} |"
        )
    lines.extend([
        "",
        "## Primary Paired MRR Comparisons",
        "",
        "| Comparison | Paired scenarios | MRR difference | 95% CI | Raw p | Holm p |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ])
    for row in package["statistical_analysis"]["primary_mrr_comparisons"]:
        ci = row["bootstrap_ci_95"]
        lines.append(
            f"| {row['comparison']} | {row['paired_scenarios']} | {fmt(row['observed_difference'])} | "
            f"[{fmt(ci[0])}, {fmt(ci[1])}] | {fmt(row['raw_p_value'])} | {fmt(row['holm_adjusted_p_value'])} |"
        )
    return "\n".join(lines) + "\n"


def render_thesis_tables_tex(package: dict[str, Any]) -> str:
    rows = []
    for arm in ARM_ORDER:
        a = package["arm_summaries"][arm]
        rows.append(
            f"{latex_escape(family_label(arm))} & {latex_escape(condition_label(arm))} & "
            f"{a['positive_valid_trials']}/{a['positive_expected_trials']} & {fmt(a['top1'])} & {fmt(a['top2'])} & {fmt(a['top4'])} & {fmt(a['scenario_level_mrr'])} \\\\"
        )
    comparisons = []
    for row in package["statistical_analysis"]["primary_mrr_comparisons"]:
        ci = row["bootstrap_ci_95"]
        comparisons.append(
            f"{latex_escape(row['comparison'])} & {row['paired_scenarios']} & {fmt(row['observed_difference'])} & "
            f"[{fmt(ci[0])}, {fmt(ci[1])}] & {fmt(row['raw_p_value'])} & {fmt(row['holm_adjusted_p_value'])} \\\\"
        )
    return "\n".join([
        "% Generated from v1.4.1 canonical post-run analysis artifacts.",
        "\\begin{table}[ht]",
        "\\centering",
        "\\caption{v1.4.1 OWASP XSS candidate-ranking effectiveness.}",
        "\\begin{tabular}{llrrrrr}",
        "\\hline",
        "Family & Representation & Valid/expected positive trials & Top-1 & Top-2 & Top-4 & MRR \\\\",
        "\\hline",
        *rows,
        "\\hline",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\begin{table}[ht]",
        "\\centering",
        "\\caption{Primary paired MRR comparisons for v1.4.1 OWASP XSS.}",
        "\\begin{tabular}{lrrrrr}",
        "\\hline",
        "Comparison & Scenarios & Difference & 95\\% CI & Raw $p$ & Holm $p$ \\\\",
        "\\hline",
        *comparisons,
        "\\hline",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]) + "\n"


def render_methodology_note(package: dict[str, Any]) -> str:
    return "\n".join([
        "# v1.4.1 Methodology and Provenance Note",
        "",
        f"- Frozen protocol tag: `{PROTOCOL_TAG}`",
        f"- Frozen protocol commit: `{PROTOCOL_COMMIT}`",
        f"- Protocol package: `{package['manifest']['protocol_package']}`",
        "- Ground truth was loaded only after pre-scoring integrity validation.",
        "- Repeated LLM trials are nested under scenario and arm and are not treated as independent benchmark scenarios.",
        "- Invalid or malformed model outputs are retained in reliability denominators and excluded from valid ranking-performance aggregates.",
        "- Negative-only scenarios are excluded from vulnerable-candidate rank, Top-1, Top-2, Top-4 and MRR denominators.",
        "- Cost per finding is not available because no frozen numeric pricing basis exists.",
        "- The deterministic resume-index incident is recorded as operational provenance only; no completed sequence was rerun.",
        "- No new GPT, Qwen, HTTP, browser, discovery, deterministic-ranking or scoring execution calls were made by this post-run analysis.",
    ]) + "\n"


def arm_summary_rows(package: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for arm in ARM_ORDER:
        rows.append({
            "arm_id": arm,
            **package["arm_summaries"][arm],
            "contract_validity_rate": package["reliability"][arm]["contract_validity_rate"],
            "malformed": package["reliability"][arm]["malformed"],
            "provider_failed": package["reliability"][arm]["provider_failed"],
            "runtime_failed": package["reliability"][arm]["runtime_failed"],
            "timeout": package["reliability"][arm]["timeout"],
            "latency_median_ms": package["efficiency"][arm]["latency_ms"]["median"],
            "latency_mean_ms": package["efficiency"][arm]["latency_ms"]["mean"],
            "tokens_total": package["efficiency"][arm]["token_usage"].get("total_tokens", NOT_AVAILABLE)
            if isinstance(package["efficiency"][arm]["token_usage"], dict)
            else NOT_AVAILABLE,
        })
    return rows


def efficiency_rows(efficiency: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for arm, value in efficiency.items():
        rows.append({
            "arm_id": arm,
            **{f"latency_{key}": item for key, item in value["latency_ms"].items()},
            "input_tokens": token_value(value, "input_tokens"),
            "output_tokens": token_value(value, "output_tokens"),
            "total_tokens": token_value(value, "total_tokens"),
            "cost_availability": value["cost"]["availability"] if isinstance(value["cost"], dict) else value["cost"],
            "cost_per_finding": value["cost_per_finding"],
        })
    return rows


def dict_table_rows(mapping: dict[str, Any], key_name: str) -> list[dict[str, Any]]:
    return [{key_name: key, **value} for key, value in mapping.items()]


def scrub_provider_metadata(metadata: Any) -> Any:
    if not isinstance(metadata, dict):
        return metadata
    scrubbed = dict(metadata)
    if "api_key" in json.dumps(scrubbed).lower():
        scrubbed = {"redacted": "provider metadata contained secret-like key text"}
    return scrubbed


def token_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    totals = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}
    rows_with_usage = 0
    for row in rows:
        usage = row.get("usage")
        if not isinstance(usage, dict):
            continue
        present = False
        for key in totals:
            value = usage.get(key)
            if isinstance(value, int):
                totals[key] += value
                present = True
        if present:
            rows_with_usage += 1
    if rows_with_usage == 0:
        return {"availability": NOT_AVAILABLE, "input_tokens": NOT_AVAILABLE, "output_tokens": NOT_AVAILABLE, "total_tokens": NOT_AVAILABLE, "rows_with_usage": 0}
    return {"availability": "available", **totals, "rows_with_usage": rows_with_usage}


def cost_summary(rows: list[dict[str, Any]], arm: str) -> dict[str, Any] | str:
    if arm.startswith("deterministic_"):
        return NOT_APPLICABLE
    numeric_costs = []
    for row in rows:
        cost = row.get("cost")
        if isinstance(cost, dict):
            numeric_costs.extend(value for value in cost.values() if isinstance(value, (int, float)) and not isinstance(value, bool))
    if numeric_costs:
        return {"availability": "available", "observed_numeric_values": numeric_costs, "total_observed_numeric_cost": sum(numeric_costs)}
    return {"availability": NOT_AVAILABLE, "reason": "no frozen numeric pricing/cost artifact retained"}


def describe_numeric(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": NOT_AVAILABLE, "median": NOT_AVAILABLE, "mean": NOT_AVAILABLE, "p95": NOT_AVAILABLE, "max": NOT_AVAILABLE}
    ordered = sorted(values)
    return {
        "count": len(values),
        "min": min(ordered),
        "median": statistics.median(ordered),
        "mean": statistics.mean(ordered),
        "p95": percentile(ordered, 0.95),
        "max": max(ordered),
    }


def percentile(values: list[float] | list[int], q: float) -> float:
    if len(values) == 1:
        return float(values[0])
    pos = (len(values) - 1) * q
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return float(values[int(pos)])
    return float(values[lower] * (upper - pos) + values[upper] * (pos - lower))


def mean_float(values: Iterable[Any]) -> float | str:
    numeric = [float(value) for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
    return statistics.mean(numeric) if numeric else NOT_APPLICABLE


def median_value(values: Iterable[Any]) -> float | str:
    numeric = [float(value) for value in values if isinstance(value, (int, float)) and not isinstance(value, bool)]
    return statistics.median(numeric) if numeric else NOT_APPLICABLE


def safe_ratio(numerator: int, denominator: int) -> float | str:
    return numerator / denominator if denominator else NOT_APPLICABLE


def numeric_delta(new: Any, old: Any) -> float | str:
    if isinstance(new, (int, float)) and isinstance(old, (int, float)):
        return float(new) - float(old)
    return NOT_AVAILABLE


def token_value(summary: dict[str, Any], key: str) -> Any:
    token_usage = summary["token_usage"]
    if not isinstance(token_usage, dict):
        return NOT_AVAILABLE
    return token_usage.get(key, NOT_AVAILABLE)


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def family_label(arm: str) -> str:
    return arm.split("_", 1)[0]


def condition_label(arm: str) -> str:
    return arm.split("_", 1)[1]


def latex_escape(text: str) -> str:
    return text.replace("_", "\\_")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(to_json_value(value), sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksum_file(checksum_path: Path, base_dir: Path) -> list[str]:
    if not checksum_path.exists():
        return [f"missing checksum file:{display_path(checksum_path)}"]
    errors = []
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = base_dir / relative
        if not path.exists():
            errors.append(f"missing:{relative}")
        elif sha256_file(path) != expected:
            errors.append(f"mismatch:{relative}")
    return errors


def timestamped_output_dir(root: Path) -> Path:
    return root / f"owasp-xss-v14-1-context-enrichment-analysis-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()
    except ValueError:
        return str(path)


def git_state() -> dict[str, Any]:
    return {
        "branch": git_output(["branch", "--show-current"]),
        "commit": git_output(["rev-parse", "HEAD"]),
        "status_short": git_output(["status", "--short"]).splitlines(),
        "dirty": bool(git_output(["status", "--porcelain"])),
    }


def git_output(args: list[str]) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    return completed.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the v1.4.1 OWASP XSS post-run scoring and statistical analysis package.")
    parser.add_argument("--final-root", type=Path, default=FINAL_ROOT)
    parser.add_argument("--protocol-package", type=Path, default=PROTOCOL_PACKAGE_DIR)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    package = build_analysis_package(final_root=args.final_root, protocol_package_dir=args.protocol_package, output_dir=args.output_dir)
    print(f"v1.4.1 analysis valid: {package['validation']['valid']}")
    print(f"checksum validation valid: {package['checksum_validation']['valid']}")
    print(f"analysis package: {package['manifest']['output_dir']}")


if __name__ == "__main__":
    main()
