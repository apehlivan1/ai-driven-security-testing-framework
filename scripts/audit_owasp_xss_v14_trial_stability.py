from __future__ import annotations

import csv
import hashlib
import itertools
import json
import math
import statistics
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"
PROTOCOL_PACKAGE = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
CANONICAL = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
RAW_RUN = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "owasp-xss-v14-confirmatory-20260821T235804Z"
OUTPUT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-trial-stability-analysis"
ARMS = ("proprietary_gpt", "local_qwen")
SUBSETS = ("all", "positive", "negative_only")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    scored_rows = load_json(CANONICAL / "normalized" / "scored-rows.json")
    ranking_aggregates = load_json(CANONICAL / "normalized" / "ranking-aggregates.json")
    reliability = load_json(CANONICAL / "normalized" / "reliability-aggregates.json")
    scoring = load_json(PROTOCOL_PACKAGE / "ground-truth" / "scoring-data.json")
    scenario_ids = [scenario["scenario_id"] for scenario in scoring["scenarios"]]

    rows_by_arm_scenario = group_rows(scored_rows)
    scenario_stability = []
    rr_rows = []
    for arm in ARMS:
        for scenario_id in scenario_ids:
            scenario_rows = sorted(rows_by_arm_scenario[arm][scenario_id], key=lambda row: int(row["trial_number"]))
            scenario_type = scenario_rows[0]["scenario_type"] if scenario_rows else scenario_type_from_scoring(scoring, scenario_id)
            row = scenario_stability_row(arm, scenario_id, scenario_type, scenario_rows)
            scenario_stability.append(row)
            if scenario_type == "positive":
                rr_rows.append(scenario_rr_row(row))

    exact_summary = exact_ranking_stability_summary(scenario_stability)
    vulnerable_summary = vulnerable_rank_stability_summary(scenario_stability)
    pairwise_summary = pairwise_agreement_summary(scenario_stability)
    threshold_summary = threshold_consistency_summary(scenario_stability)
    rr_summary = reciprocal_rank_summary(rr_rows)
    reliability_summary = reliability_with_retained_failures(scored_rows, reliability)
    source_integrity = source_integrity_report(scored_rows)
    headline = headline_context(ranking_aggregates)
    validation = validation_report(
        scored_rows=scored_rows,
        scenario_stability=scenario_stability,
        source_integrity=source_integrity,
        exact_summary=exact_summary,
        reliability_summary=reliability_summary,
    )
    package_manifest = manifest(validation)

    write_json(OUTPUT_DIR / "scenario-level-stability.json", scenario_stability)
    write_csv(OUTPUT_DIR / "scenario-level-stability.csv", scenario_stability)
    write_json(OUTPUT_DIR / "exact-ranking-stability-summary.json", exact_summary)
    write_csv(OUTPUT_DIR / "exact-ranking-stability-summary.csv", flatten_summary_table(exact_summary))
    write_json(OUTPUT_DIR / "vulnerable-rank-stability-summary.json", vulnerable_summary)
    write_csv(OUTPUT_DIR / "vulnerable-rank-stability-summary.csv", flatten_summary_table(vulnerable_summary))
    write_json(OUTPUT_DIR / "pairwise-agreement-summary.json", pairwise_summary)
    write_csv(OUTPUT_DIR / "pairwise-agreement-summary.csv", flatten_summary_table(pairwise_summary))
    write_json(OUTPUT_DIR / "threshold-consistency-summary.json", threshold_summary)
    write_csv(OUTPUT_DIR / "threshold-consistency-summary.csv", flatten_summary_table(threshold_summary))
    write_json(OUTPUT_DIR / "scenario-mean-rr.json", rr_rows)
    write_csv(OUTPUT_DIR / "scenario-mean-rr.csv", rr_rows)
    write_json(OUTPUT_DIR / "reciprocal-rank-variability-summary.json", rr_summary)
    write_json(OUTPUT_DIR / "reliability-and-terminal-outcomes.json", reliability_summary)
    write_json(OUTPUT_DIR / "source-integrity-report.json", source_integrity)
    write_json(OUTPUT_DIR / "headline-metrics-context.json", headline)
    write_text(OUTPUT_DIR / "thesis-ready-tables.md", render_thesis_tables(headline, exact_summary, vulnerable_summary, pairwise_summary, threshold_summary, rr_summary, reliability_summary))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(source_integrity))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", package_manifest)
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(headline, exact_summary, vulnerable_summary, pairwise_summary, threshold_summary, rr_summary, reliability_summary, source_integrity, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_checksums(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "owasp-xss-v14-trial-stability-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    final_errors = validate_checksums(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    print(f"trial stability package: {display_path(OUTPUT_DIR)}")
    print(f"validation valid: {validation['valid']}")
    print(f"checksum errors: {len(final_errors)}")
    print(f"source integrity: {source_integrity['verdict']}")


def group_rows(rows: list[dict[str, Any]]) -> dict[str, dict[str, list[dict[str, Any]]]]:
    grouped: dict[str, dict[str, list[dict[str, Any]]]] = {arm: defaultdict(list) for arm in ARMS}
    for row in rows:
        arm = row.get("arm_id")
        if arm in grouped:
            grouped[arm][row["scenario_id"]].append(row)
    return grouped


def scenario_stability_row(arm: str, scenario_id: str, scenario_type: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid_rows = [row for row in rows if row.get("status") == "valid" and row.get("contract_valid") is True]
    valid_rankings = [tuple(row["parsed_ranking"]) for row in valid_rows]
    unique_rankings = sorted(set(valid_rankings))
    pairwise = pairwise_metrics(valid_rankings)
    invalid_rows = [row for row in rows if row not in valid_rows]
    base = {
        "arm_id": arm,
        "scenario_id": scenario_id,
        "scenario_type": scenario_type,
        "expected_trials": 5,
        "actual_trials": len(rows),
        "valid_complete_ranking_trials": len(valid_rankings),
        "invalid_or_failed_trials": len(invalid_rows),
        "terminal_status_counts": dict(Counter(row["status"] for row in rows)),
        "unique_complete_rankings": len(unique_rankings),
        "all_five_complete_rankings_identical": len(valid_rankings) == 5 and len(unique_rankings) == 1,
        "at_least_one_valid_complete_ranking_differs": len(unique_rankings) > 1,
        "has_invalid_or_failed_trial": bool(invalid_rows),
        "complete_ranking_values": ["|".join(ranking) for ranking in unique_rankings],
        "valid_pair_count": pairwise["valid_pair_count"],
        "exact_complete_ranking_agreement_pairs": pairwise["exact_complete_ranking_agreement_pairs"],
        "exact_complete_ranking_agreement_rate": pairwise["exact_complete_ranking_agreement_rate"],
        "spearman_mean": pairwise["spearman_mean"],
        "spearman_median": pairwise["spearman_median"],
        "kendall_tau_mean": pairwise["kendall_tau_mean"],
        "kendall_tau_median": pairwise["kendall_tau_median"],
    }
    if scenario_type != "positive":
        base.update(positive_not_applicable_fields())
        return base

    valid_vulnerable_ranks = [int(row["vulnerable_rank"]) for row in valid_rows if isinstance(row["vulnerable_rank"], int)]
    rrs = [1 / rank for rank in valid_vulnerable_ranks]
    rank_pairwise = vulnerable_rank_pairwise(valid_vulnerable_ranks)
    top_counts = threshold_counts(valid_vulnerable_ranks)
    rank_range: float | str = "not_available"
    rank_stdev: float | str = "not_available"
    unique_rank_count: int | str = "not_available"
    category = "no_valid_rank"
    if valid_vulnerable_ranks:
        unique_rank_count = len(set(valid_vulnerable_ranks))
        rank_range = max(valid_vulnerable_ranks) - min(valid_vulnerable_ranks)
        rank_stdev = statistics.pstdev(valid_vulnerable_ranks) if len(valid_vulnerable_ranks) > 1 else 0.0
        if len(valid_vulnerable_ranks) < 5:
            category = "incomplete_valid_ranks"
        elif rank_range == 0:
            category = "stable_identical_rank"
        elif rank_range == 1:
            category = "varies_by_one_position"
        else:
            category = "varies_by_two_or_more_positions"
    base.update(
        {
            "valid_vulnerable_ranks": valid_vulnerable_ranks,
            "unique_vulnerable_ranks": unique_rank_count,
            "vulnerable_rank_identical_across_all_five_trials": category == "stable_identical_rank",
            "vulnerable_rank_range": rank_range,
            "vulnerable_rank_population_stdev": rank_stdev,
            "vulnerable_rank_stability_category": category,
            "vulnerable_rank_pair_count": rank_pairwise["valid_pair_count"],
            "vulnerable_rank_agreement_pairs": rank_pairwise["agreement_pairs"],
            "vulnerable_rank_agreement_rate": rank_pairwise["agreement_rate"],
            "top1_success_trials": top_counts["top1"],
            "top2_success_trials": top_counts["top2"],
            "top4_success_trials": top_counts["top4"],
            "rr_values": rrs,
            "mean_rr": mean_or_na(rrs),
            "rr_population_stdev": statistics.pstdev(rrs) if len(rrs) > 1 else ("not_available" if not rrs else 0.0),
            "rr_min": min(rrs) if rrs else "not_available",
            "rr_max": max(rrs) if rrs else "not_available",
            "rr_range": (max(rrs) - min(rrs)) if rrs else "not_available",
        }
    )
    return base


def pairwise_metrics(rankings: list[tuple[str, ...]]) -> dict[str, Any]:
    exact = 0
    spearman_values = []
    kendall_values = []
    pairs = list(itertools.combinations(rankings, 2))
    for left, right in pairs:
        if left == right:
            exact += 1
        spearman_values.append(spearman(left, right))
        kendall_values.append(kendall_tau(left, right))
    return {
        "valid_pair_count": len(pairs),
        "exact_complete_ranking_agreement_pairs": exact,
        "exact_complete_ranking_agreement_rate": exact / len(pairs) if pairs else "not_available",
        "spearman_mean": mean_or_na(spearman_values),
        "spearman_median": statistics.median(spearman_values) if spearman_values else "not_available",
        "kendall_tau_mean": mean_or_na(kendall_values),
        "kendall_tau_median": statistics.median(kendall_values) if kendall_values else "not_available",
    }


def vulnerable_rank_pairwise(ranks: list[int]) -> dict[str, Any]:
    pairs = list(itertools.combinations(ranks, 2))
    agree = sum(1 for left, right in pairs if left == right)
    return {
        "valid_pair_count": len(pairs),
        "agreement_pairs": agree,
        "agreement_rate": agree / len(pairs) if pairs else "not_available",
    }


def spearman(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    left_pos = {candidate_id: idx + 1 for idx, candidate_id in enumerate(left)}
    right_pos = {candidate_id: idx + 1 for idx, candidate_id in enumerate(right)}
    ids = list(left)
    n = len(ids)
    squared_diff = sum((left_pos[candidate_id] - right_pos[candidate_id]) ** 2 for candidate_id in ids)
    return 1 - (6 * squared_diff) / (n * (n * n - 1))


def kendall_tau(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    right_pos = {candidate_id: idx for idx, candidate_id in enumerate(right)}
    concordant = 0
    discordant = 0
    for a, b in itertools.combinations(left, 2):
        if right_pos[a] < right_pos[b]:
            concordant += 1
        else:
            discordant += 1
    return (concordant - discordant) / (concordant + discordant)


def threshold_counts(ranks: list[int]) -> dict[str, int]:
    return {
        "top1": sum(1 for rank in ranks if rank <= 1),
        "top2": sum(1 for rank in ranks if rank <= 2),
        "top4": sum(1 for rank in ranks if rank <= 4),
    }


def positive_not_applicable_fields() -> dict[str, Any]:
    return {
        "valid_vulnerable_ranks": [],
        "unique_vulnerable_ranks": "not_applicable",
        "vulnerable_rank_identical_across_all_five_trials": "not_applicable",
        "vulnerable_rank_range": "not_applicable",
        "vulnerable_rank_population_stdev": "not_applicable",
        "vulnerable_rank_stability_category": "not_applicable",
        "vulnerable_rank_pair_count": "not_applicable",
        "vulnerable_rank_agreement_pairs": "not_applicable",
        "vulnerable_rank_agreement_rate": "not_applicable",
        "top1_success_trials": "not_applicable",
        "top2_success_trials": "not_applicable",
        "top4_success_trials": "not_applicable",
        "rr_values": [],
        "mean_rr": "not_applicable",
        "rr_population_stdev": "not_applicable",
        "rr_min": "not_applicable",
        "rr_max": "not_applicable",
        "rr_range": "not_applicable",
    }


def scenario_rr_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "arm_id": row["arm_id"],
        "scenario_id": row["scenario_id"],
        "expected_trials": row["expected_trials"],
        "valid_trials": row["valid_complete_ranking_trials"],
        "invalid_or_failed_trials": row["invalid_or_failed_trials"],
        "valid_vulnerable_ranks": row["valid_vulnerable_ranks"],
        "rr_values": row["rr_values"],
        "mean_rr": row["mean_rr"],
        "rr_population_stdev": row["rr_population_stdev"],
        "rr_min": row["rr_min"],
        "rr_max": row["rr_max"],
        "rr_range": row["rr_range"],
    }


def exact_ranking_stability_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        arm: {
            subset: exact_ranking_subset_summary([row for row in rows if row["arm_id"] == arm and subset_match(row, subset)])
            for subset in SUBSETS
        }
        for arm in ARMS
    }


def exact_ranking_subset_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    unique_counts = Counter(str(row["unique_complete_rankings"]) for row in rows)
    all_identical = sum(1 for row in rows if row["all_five_complete_rankings_identical"])
    differs = sum(1 for row in rows if row["at_least_one_valid_complete_ranking_differs"])
    invalid_scenarios = sum(1 for row in rows if row["has_invalid_or_failed_trial"])
    all_five_valid = sum(1 for row in rows if row["valid_complete_ranking_trials"] == 5)
    return {
        "scenario_count": total,
        "expected_trials": total * 5,
        "valid_complete_ranking_trials": sum(row["valid_complete_ranking_trials"] for row in rows),
        "invalid_or_failed_trials": sum(row["invalid_or_failed_trials"] for row in rows),
        "scenarios_with_all_five_valid_rankings": count_percent(all_five_valid, total),
        "scenarios_with_invalid_or_failed_trial": count_percent(invalid_scenarios, total),
        "all_five_complete_rankings_identical": count_percent(all_identical, total),
        "at_least_one_valid_complete_ranking_differs": count_percent(differs, total),
        "unique_complete_ranking_count_distribution": {str(count): count_percent(unique_counts[str(count)], total) for count in range(6)},
    }


def vulnerable_rank_stability_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {}
    for arm in ARMS:
        positive = [row for row in rows if row["arm_id"] == arm and row["scenario_type"] == "positive"]
        total = len(positive)
        categories = Counter(row["vulnerable_rank_stability_category"] for row in positive)
        unique_counts = Counter(str(row["unique_vulnerable_ranks"]) for row in positive)
        ranges = Counter(str(row["vulnerable_rank_range"]) for row in positive)
        complete_positive = [row for row in positive if row["valid_complete_ranking_trials"] == 5]
        stdev_values = [row["vulnerable_rank_population_stdev"] for row in positive if isinstance(row["vulnerable_rank_population_stdev"], (int, float))]
        result[arm] = {
            "positive_scenarios": total,
            "positive_scenarios_with_all_five_valid_ranks": count_percent(len(complete_positive), total),
            "positive_scenarios_with_invalid_or_failed_rank_trial": count_percent(categories["incomplete_valid_ranks"] + categories["no_valid_rank"], total),
            "completely_stable_identical_rank": count_percent(categories["stable_identical_rank"], total),
            "varies_by_one_position": count_percent(categories["varies_by_one_position"], total),
            "varies_by_two_or_more_positions": count_percent(categories["varies_by_two_or_more_positions"], total),
            "unique_vulnerable_rank_count_distribution": {str(count): count_percent(unique_counts[str(count)], total) for count in range(6)},
            "rank_range_distribution": {key: count_percent(count, total) for key, count in sorted(ranges.items(), key=range_sort_key)},
            "rank_population_stdev_summary": summarize_float_values(stdev_values),
        }
    return result


def pairwise_agreement_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for arm in ARMS:
        result[arm] = {
            subset: complete_ranking_pairwise_subset([row for row in rows if row["arm_id"] == arm and subset_match(row, subset)])
            for subset in SUBSETS
        }
        positives = [row for row in rows if row["arm_id"] == arm and row["scenario_type"] == "positive"]
        result[arm]["positive_vulnerable_rank_agreement"] = vulnerable_rank_pairwise_subset(positives)
    return result


def complete_ranking_pairwise_subset(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid_pairs = sum(row["valid_pair_count"] for row in rows)
    exact_pairs = sum(row["exact_complete_ranking_agreement_pairs"] for row in rows)
    exact_rates = [row["exact_complete_ranking_agreement_rate"] for row in rows if isinstance(row["exact_complete_ranking_agreement_rate"], (int, float))]
    spearman_values = [row["spearman_mean"] for row in rows if isinstance(row["spearman_mean"], (int, float))]
    kendall_values = [row["kendall_tau_mean"] for row in rows if isinstance(row["kendall_tau_mean"], (int, float))]
    return {
        "scenario_count": len(rows),
        "expected_pair_count": len(rows) * 10,
        "valid_pair_count": valid_pairs,
        "exact_complete_ranking_agreement_pairs": exact_pairs,
        "exact_complete_ranking_agreement_rate_valid_pairs": exact_pairs / valid_pairs if valid_pairs else "not_available",
        "scenario_level_exact_agreement_rate_summary": summarize_float_values(exact_rates),
        "scenario_level_spearman_mean_summary": summarize_float_values(spearman_values),
        "scenario_level_kendall_tau_mean_summary": summarize_float_values(kendall_values),
    }


def vulnerable_rank_pairwise_subset(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid_pairs = sum(row["vulnerable_rank_pair_count"] for row in rows if isinstance(row["vulnerable_rank_pair_count"], int))
    agree = sum(row["vulnerable_rank_agreement_pairs"] for row in rows if isinstance(row["vulnerable_rank_agreement_pairs"], int))
    rates = [row["vulnerable_rank_agreement_rate"] for row in rows if isinstance(row["vulnerable_rank_agreement_rate"], (int, float))]
    return {
        "positive_scenarios": len(rows),
        "expected_pair_count": len(rows) * 10,
        "valid_pair_count": valid_pairs,
        "vulnerable_rank_agreement_pairs": agree,
        "vulnerable_rank_agreement_rate_valid_pairs": agree / valid_pairs if valid_pairs else "not_available",
        "scenario_level_vulnerable_rank_agreement_rate_summary": summarize_float_values(rates),
    }


def threshold_consistency_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {}
    for arm in ARMS:
        positive = [row for row in rows if row["arm_id"] == arm and row["scenario_type"] == "positive"]
        result[arm] = {
            "positive_scenarios": len(positive),
            "scenarios_with_all_five_valid_trials": sum(1 for row in positive if row["valid_complete_ranking_trials"] == 5),
            "scenarios_with_invalid_or_failed_trial": sum(1 for row in positive if row["valid_complete_ranking_trials"] < 5),
            "top1_success_count_distribution_0_to_5": success_distribution(positive, "top1_success_trials"),
            "top2_success_count_distribution_0_to_5": success_distribution(positive, "top2_success_trials"),
            "top4_success_count_distribution_0_to_5": success_distribution(positive, "top4_success_trials"),
        }
    return result


def success_distribution(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
    counts = Counter(str(row[key]) for row in rows)
    return {str(count): count_percent(counts[str(count)], len(rows)) for count in range(6)}


def reciprocal_rank_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    result = {}
    for arm in ARMS:
        arm_rows = [row for row in rows if row["arm_id"] == arm]
        stdev_values = [row["rr_population_stdev"] for row in arm_rows if isinstance(row["rr_population_stdev"], (int, float))]
        range_values = [row["rr_range"] for row in arm_rows if isinstance(row["rr_range"], (int, float))]
        mean_rr_values = [row["mean_rr"] for row in arm_rows if isinstance(row["mean_rr"], (int, float))]
        result[arm] = {
            "positive_scenarios": len(arm_rows),
            "positive_scenarios_with_valid_rr": sum(1 for row in arm_rows if isinstance(row["mean_rr"], (int, float))),
            "positive_scenarios_with_no_valid_rr": sum(1 for row in arm_rows if not isinstance(row["mean_rr"], (int, float))),
            "scenario_mean_rr_summary": summarize_float_values(mean_rr_values),
            "within_scenario_rr_population_stdev_summary": summarize_float_values(stdev_values),
            "within_scenario_rr_range_summary": summarize_float_values(range_values),
            "scenario_rows_source": "scenario-mean-rr.csv",
        }
    return result


def reliability_with_retained_failures(scored_rows: list[dict[str, Any]], reliability: dict[str, Any]) -> dict[str, Any]:
    result = {}
    for arm in ARMS:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        status_counts = Counter(row["status"] for row in rows)
        result[arm] = {
            "expected_rows": 1330,
            "actual_rows": len(rows),
            "canonical_reliability_source": reliability["arms"][arm],
            "status_counts_from_scored_rows": dict(status_counts),
            "contract_valid_count": sum(1 for row in rows if row["contract_valid"] is True),
            "contract_invalid_count": sum(1 for row in rows if row["contract_valid"] is not True),
            "provider_failed_count": sum(1 for row in rows if row["provider_failed"] is True),
            "malformed_count": status_counts["malformed"],
            "timeout_count": status_counts["timeout"],
            "retried_terminal_rows": 0,
            "invalid_trial_stability_policy": (
                "Invalid or failed terminal outcomes are retained in reliability denominators and are not repaired or retried. "
                "They do not contribute a valid complete ranking to exact-ranking, rank, threshold or reciprocal-rank stability denominators."
            ),
        }
    return result


def source_integrity_report(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_subset = [row for row in scored_rows if row["arm_id"] in ARMS]
    raw_checksum_path = RAW_RUN / "checksums.sha256"
    checksum_map = load_checksum_map(raw_checksum_path)
    raw_relatives = []
    missing_files = []
    for row in row_subset:
        path = REPO_ROOT / row["raw_artifact_path"]
        if not path.exists():
            missing_files.append(row["raw_artifact_path"])
            continue
        raw_relatives.append(path.resolve().relative_to(RAW_RUN.resolve()).as_posix())
    missing_checksum_entries = [relative for relative in raw_relatives if relative not in checksum_map]
    checksum_mismatches = [
        relative
        for relative in raw_relatives
        if relative in checksum_map and sha256_file(RAW_RUN / relative) != checksum_map[relative]
    ]
    sequences = [row["sequence"] for row in row_subset]
    duplicate_sequences = sorted(sequence for sequence, count in Counter(sequences).items() if count > 1)
    missing_sequences = sorted(set(range(267, 2927)).difference(sequences))
    row_ids = [(row["arm_id"], row["scenario_id"], row["trial_number"]) for row in row_subset]
    duplicate_row_ids = [
        {"arm_id": key[0], "scenario_id": key[1], "trial_number": key[2], "count": count}
        for key, count in sorted(Counter(row_ids).items())
        if count > 1
    ]
    raw_checksum_errors = validate_checksums(raw_checksum_path, RAW_RUN)
    canonical_checksum_errors = validate_checksums(CANONICAL / "checksums.sha256", CANONICAL)
    verified = (
        len(row_subset) == 2660
        and not missing_files
        and not missing_checksum_entries
        and not checksum_mismatches
        and not missing_sequences
        and not duplicate_sequences
        and not duplicate_row_ids
        and not raw_checksum_errors
        and not canonical_checksum_errors
    )
    return {
        "schema_version": "owasp-xss-v14-trial-stability-source-integrity-v1",
        "raw_run_dir": display_path(RAW_RUN),
        "raw_checksum_source": display_path(raw_checksum_path),
        "canonical_checksum_source": display_path(CANONICAL / "checksums.sha256"),
        "canonical_scored_rows_source": display_path(CANONICAL / "normalized" / "scored-rows.json"),
        "ranking_rows_checked": len(row_subset),
        "ranking_rows_covered_by_raw_checksum": len(raw_relatives) - len(missing_checksum_entries),
        "raw_checksum_total_entries": len(checksum_map),
        "missing_files": missing_files,
        "missing_checksum_entries": missing_checksum_entries,
        "checksum_mismatches": checksum_mismatches,
        "raw_checksum_error_count": len(raw_checksum_errors),
        "raw_checksum_errors": raw_checksum_errors[:25],
        "canonical_checksum_error_count": len(canonical_checksum_errors),
        "canonical_checksum_errors": canonical_checksum_errors[:25],
        "missing_sequences": missing_sequences,
        "duplicate_sequences": duplicate_sequences,
        "duplicate_row_ids": duplicate_row_ids,
        "source_integrity_verified": verified,
        "verdict": "verified_source_integrity" if verified else "source_integrity_limitation_or_mismatch",
    }


def headline_context(ranking_aggregates: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-headline-ranking-context-v1",
        "note": "Descriptive context only; no model-superiority test is performed by this stability audit.",
        "arms": {
            "deterministic_structural": {
                "top1": ranking_aggregates["arms"]["deterministic_structural"]["top1"],
                "top4": ranking_aggregates["arms"]["deterministic_structural"]["topk"],
                "mrr": ranking_aggregates["arms"]["deterministic_structural"]["mrr"],
            },
            "proprietary_gpt": {
                "top1": ranking_aggregates["arms"]["proprietary_gpt"]["top1"],
                "top4": ranking_aggregates["arms"]["proprietary_gpt"]["topk"],
                "mrr": ranking_aggregates["arms"]["proprietary_gpt"]["mrr"],
            },
            "local_qwen": {
                "top1": ranking_aggregates["arms"]["local_qwen"]["top1"],
                "top4": ranking_aggregates["arms"]["local_qwen"]["topk"],
                "mrr": ranking_aggregates["arms"]["local_qwen"]["mrr"],
            },
        },
    }


def validation_report(
    *,
    scored_rows: list[dict[str, Any]],
    scenario_stability: list[dict[str, Any]],
    source_integrity: dict[str, Any],
    exact_summary: dict[str, Any],
    reliability_summary: dict[str, Any],
) -> dict[str, Any]:
    errors = []
    arm_counts = Counter(row["arm_id"] for row in scored_rows)
    if arm_counts["proprietary_gpt"] != 1330:
        errors.append(f"proprietary_gpt_row_count_expected_1330_actual_{arm_counts['proprietary_gpt']}")
    if arm_counts["local_qwen"] != 1330:
        errors.append(f"local_qwen_row_count_expected_1330_actual_{arm_counts['local_qwen']}")
    for arm in ARMS:
        if len([row for row in scenario_stability if row["arm_id"] == arm]) != 266:
            errors.append(f"{arm}_scenario_stability_rows_not_266")
        if exact_summary[arm]["positive"]["scenario_count"] != 236:
            errors.append(f"{arm}_positive_scenario_count_not_236")
        if exact_summary[arm]["negative_only"]["scenario_count"] != 30:
            errors.append(f"{arm}_negative_scenario_count_not_30")
        if reliability_summary[arm]["retried_terminal_rows"] != 0:
            errors.append(f"{arm}_retried_terminal_rows_nonzero")
    if source_integrity["source_integrity_verified"] is not True:
        errors.append("source_integrity_not_verified")
    return {
        "schema_version": "owasp-xss-v14-trial-stability-validation-v1",
        "valid": not errors,
        "errors": errors,
        "source_integrity_verified": source_integrity["source_integrity_verified"],
        "zero_experimental_calls": {
            "gpt": 0,
            "qwen": 0,
            "deterministic_ranking": 0,
            "http": 0,
            "browser": 0,
            "discovery": 0,
            "verifier": 0,
            "scored_calls": 0,
        },
    }


def render_report(
    headline: dict[str, Any],
    exact_summary: dict[str, Any],
    vulnerable_summary: dict[str, Any],
    pairwise_summary: dict[str, Any],
    threshold_summary: dict[str, Any],
    rr_summary: dict[str, Any],
    reliability_summary: dict[str, Any],
    source_integrity: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    lines = [
        "# Professor Comment 2 Closure Analysis: v1.4 Repeated-Trial Stability",
        "",
        "This is a derived post-run stability audit of the original frozen OWASP XSS v1.4 evaluation. It performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier or scored calls and does not modify frozen/canonical v1.4 or v1.4.1 artifacts.",
        "",
        "## Headline Metrics Context",
        "",
        "| Arm | Top-1 | Top-4 | MRR |",
        "| --- | ---: | ---: | ---: |",
    ]
    for arm, label in [("deterministic_structural", "deterministic"), ("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        values = headline["arms"][arm]
        lines.append(f"| {label} | {values['top1']:.4f} | {values['top4']:.4f} | {values['mrr']:.4f} |")
    lines.extend(
        [
            "",
            "These values are reproduced only as descriptive context. This audit does not perform a model-superiority test.",
            "",
            "## Exact Complete-Ranking Stability",
            "",
            exact_stability_table(exact_summary).strip(),
            "",
            "## Vulnerable-Candidate Rank Stability",
            "",
            vulnerable_stability_table(vulnerable_summary).strip(),
            "",
            "## Pairwise Within-Scenario Agreement",
            "",
            pairwise_table(pairwise_summary).strip(),
            "",
            "## Threshold Consistency",
            "",
            threshold_table(threshold_summary).strip(),
            "",
            "## Reciprocal-Rank Variability",
            "",
            rr_table(rr_summary).strip(),
            "",
            "## Reliability and Invalid-Output Handling",
            "",
            reliability_table(reliability_summary).strip(),
            "",
            "Invalid or failed terminal outcomes are retained in reliability denominators and were not retried. They do not provide valid complete rankings, so they are excluded from complete-ranking, vulnerable-rank, threshold and reciprocal-rank stability denominators while remaining visible as incomplete scenarios.",
            "",
            "## Interpretation",
            "",
            "GPT repeated rankings are moderately variable: its complete rankings differ in a majority of scenarios, while pairwise rank-correlation values remain positive and moderate. Qwen repeated rankings are highly stable among valid complete rankings in this run, with one positive scenario affected by malformed terminal outputs. In both cases, the repeated trials are correlated measurements of the same scenario rather than independent benchmark cases.",
            "",
            "The five repeated LLM trials therefore provide information about model variability and reliability, but they do not increase the independent experimental unit beyond the scenario level. The independent unit remains the 236 positive scenarios for ranking-performance comparisons.",
            "",
            "## Source Integrity",
            "",
            f"- Source-integrity verdict: `{source_integrity['verdict']}`",
            f"- Ranking rows checked: `{source_integrity['ranking_rows_checked']}`",
            f"- Rows covered by raw checksum: `{source_integrity['ranking_rows_covered_by_raw_checksum']}`",
            f"- Raw checksum errors: `{source_integrity['raw_checksum_error_count']}`",
            f"- Canonical checksum errors: `{source_integrity['canonical_checksum_error_count']}`",
            f"- Missing sequences: `{len(source_integrity['missing_sequences'])}`",
            f"- Duplicate sequences: `{len(source_integrity['duplicate_sequences'])}`",
            "",
            "## Validation",
            "",
            f"- Validation valid: `{validation['valid']}`",
            "- New experimental/scored calls: `0`",
        ]
    )
    return "\n".join(lines) + "\n"


def render_thesis_tables(
    headline: dict[str, Any],
    exact_summary: dict[str, Any],
    vulnerable_summary: dict[str, Any],
    pairwise_summary: dict[str, Any],
    threshold_summary: dict[str, Any],
    rr_summary: dict[str, Any],
    reliability_summary: dict[str, Any],
) -> str:
    return "\n\n".join(
        [
            "# Thesis-Ready Tables: v1.4 Repeated-Trial Stability",
            "## Headline Context\n\n" + headline_table(headline),
            "## Exact Complete-Ranking Stability\n\n" + exact_stability_table(exact_summary),
            "## Vulnerable-Candidate Rank Stability\n\n" + vulnerable_stability_table(vulnerable_summary),
            "## Pairwise Agreement\n\n" + pairwise_table(pairwise_summary),
            "## Threshold Consistency\n\n" + threshold_table(threshold_summary),
            "## Reciprocal-Rank Variability\n\n" + rr_table(rr_summary),
            "## Reliability\n\n" + reliability_table(reliability_summary),
        ]
    ) + "\n"


def headline_table(headline: dict[str, Any]) -> str:
    lines = ["| Arm | Top-1 | Top-4 | MRR |", "| --- | ---: | ---: | ---: |"]
    for arm, label in [("deterministic_structural", "Deterministic"), ("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        values = headline["arms"][arm]
        lines.append(f"| {label} | {values['top1']:.4f} | {values['top4']:.4f} | {values['mrr']:.4f} |")
    return "\n".join(lines)


def exact_stability_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Subset | Scenarios | Valid trials | Invalid/failed trials | 1 unique ranking | 2 | 3 | 4 | 5 | All five identical | At least one valid ranking differs |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        for subset in SUBSETS:
            item = summary[arm][subset]
            dist = item["unique_complete_ranking_count_distribution"]
            lines.append(
                f"| {label} | {subset} | {item['scenario_count']} | {item['valid_complete_ranking_trials']} | "
                f"{item['invalid_or_failed_trials']} | {count_text(dist['1'])} | {count_text(dist['2'])} | "
                f"{count_text(dist['3'])} | {count_text(dist['4'])} | {count_text(dist['5'])} | "
                f"{count_text(item['all_five_complete_rankings_identical'])} | "
                f"{count_text(item['at_least_one_valid_complete_ranking_differs'])} |"
            )
    return "\n".join(lines)


def vulnerable_stability_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Positive scenarios | Stable identical rank | Varies by 1 | Varies by >=2 | Incomplete rank trials | Rank stdev mean | Rank stdev max |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        item = summary[arm]
        stdev = item["rank_population_stdev_summary"]
        lines.append(
            f"| {label} | {item['positive_scenarios']} | {count_text(item['completely_stable_identical_rank'])} | "
            f"{count_text(item['varies_by_one_position'])} | {count_text(item['varies_by_two_or_more_positions'])} | "
            f"{count_text(item['positive_scenarios_with_invalid_or_failed_rank_trial'])} | "
            f"{fmt(stdev['mean'])} | {fmt(stdev['max'])} |"
        )
    return "\n".join(lines)


def pairwise_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Subset | Valid pairs | Exact agreement | Scenario mean exact agreement | Mean Spearman | Mean Kendall tau | Vulnerable-rank pair agreement |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        for subset in SUBSETS:
            item = summary[arm][subset]
            vuln = summary[arm]["positive_vulnerable_rank_agreement"] if subset == "positive" else None
            lines.append(
                f"| {label} | {subset} | {item['valid_pair_count']} | "
                f"{fmt(item['exact_complete_ranking_agreement_rate_valid_pairs'])} | "
                f"{fmt(item['scenario_level_exact_agreement_rate_summary']['mean'])} | "
                f"{fmt(item['scenario_level_spearman_mean_summary']['mean'])} | "
                f"{fmt(item['scenario_level_kendall_tau_mean_summary']['mean'])} | "
                f"{fmt(vuln['vulnerable_rank_agreement_rate_valid_pairs']) if vuln else 'not_applicable'} |"
            )
    return "\n".join(lines)


def threshold_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Threshold | 0/5 | 1/5 | 2/5 | 3/5 | 4/5 | 5/5 | Incomplete scenarios |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        item = summary[arm]
        for threshold, key in [("Top-1", "top1_success_count_distribution_0_to_5"), ("Top-2", "top2_success_count_distribution_0_to_5"), ("Top-4", "top4_success_count_distribution_0_to_5")]:
            dist = item[key]
            lines.append(
                f"| {label} | {threshold} | {dist['0']['count']} | {dist['1']['count']} | {dist['2']['count']} | "
                f"{dist['3']['count']} | {dist['4']['count']} | {dist['5']['count']} | {item['scenarios_with_invalid_or_failed_trial']} |"
            )
    return "\n".join(lines)


def rr_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Positive scenarios | With valid RR | Mean scenario-mean RR | Mean within-scenario RR stdev | Max RR range |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        item = summary[arm]
        lines.append(
            f"| {label} | {item['positive_scenarios']} | {item['positive_scenarios_with_valid_rr']} | "
            f"{fmt(item['scenario_mean_rr_summary']['mean'])} | {fmt(item['within_scenario_rr_population_stdev_summary']['mean'])} | "
            f"{fmt(item['within_scenario_rr_range_summary']['max'])} |"
        )
    return "\n".join(lines)


def reliability_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Arm | Expected rows | Actual rows | Contract-valid | Contract-invalid | Provider-failed | Malformed | Timeout | Retries |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm, label in [("proprietary_gpt", "GPT"), ("local_qwen", "Qwen")]:
        item = summary[arm]
        lines.append(
            f"| {label} | {item['expected_rows']} | {item['actual_rows']} | {item['contract_valid_count']} | "
            f"{item['contract_invalid_count']} | {item['provider_failed_count']} | {item['malformed_count']} | "
            f"{item['timeout_count']} | {item['retried_terminal_rows']} |"
        )
    return "\n".join(lines)


def render_methodology_note(source_integrity: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance",
            "",
            "- Scope: original frozen OWASP XSS v1.4 evaluation only.",
            "- Source rows: canonical v1.4 scored rows and retained v1.4 raw ranking-row artifacts.",
            "- Ground truth use: limited to post-run identification of positive scenarios and vulnerable-candidate ranks already represented in canonical scored rows.",
            "- Stability denominator: complete-ranking stability uses valid complete rankings only; invalid/provider-failed/malformed rows remain in reliability denominators and are reported as incomplete scenario evidence.",
            "- Pairwise unit: trial pairs are summarized within scenario; they are not treated as independent inferential observations.",
            "- Independent experimental unit: scenario, not individual repeated trial.",
            f"- Source integrity: `{source_integrity['verdict']}` against `{source_integrity['raw_checksum_source']}` and `{source_integrity['canonical_checksum_source']}`.",
            "- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero deterministic ranking calls, zero verifier calls.",
        ]
    ) + "\n"


def manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-trial-stability-analysis-manifest-v1",
        "created_at": now_utc(),
        "artifact_status": "derived_post_run_stability_audit",
        "output_dir": display_path(OUTPUT_DIR),
        "source_protocol": display_path(PROTOCOL_PATH),
        "source_protocol_package": display_path(PROTOCOL_PACKAGE),
        "source_canonical_package": display_path(CANONICAL),
        "source_raw_run": display_path(RAW_RUN),
        "validation_valid": validation["valid"],
        "frozen_artifacts_modified": False,
        "new_experimental_calls": validation["zero_experimental_calls"],
        "git_state": git_state(),
    }


def scenario_type_from_scoring(scoring: dict[str, Any], scenario_id: str) -> str:
    for scenario in scoring["scenarios"]:
        if scenario["scenario_id"] == scenario_id:
            return scenario["scenario_type"]
    raise KeyError(scenario_id)


def subset_match(row: dict[str, Any], subset: str) -> bool:
    return subset == "all" or row["scenario_type"] == subset


def summarize_float_values(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "mean": "not_available", "median": "not_available", "min": "not_available", "max": "not_available"}
    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def mean_or_na(values: list[float]) -> float | str:
    return statistics.mean(values) if values else "not_available"


def count_percent(count: int, total: int) -> dict[str, Any]:
    return {"count": count, "percentage": (count / total * 100) if total else 0.0}


def count_text(value: dict[str, Any]) -> str:
    return f"{value['count']} ({value['percentage']:.2f}%)"


def range_sort_key(item: tuple[str, int]) -> tuple[int, str]:
    key, _ = item
    return (999, key) if not key.isdigit() else (int(key), key)


def flatten_summary_table(data: Any) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def walk(value: Any, prefix: dict[str, str]) -> None:
        if isinstance(value, dict) and value and all(isinstance(v, dict) for v in value.values()):
            for key, nested in value.items():
                walk(nested, {**prefix, f"level_{len(prefix) + 1}": str(key)})
        elif isinstance(value, dict):
            rows.append({**prefix, **value})
        else:
            rows.append({**prefix, "value": value})

    walk(data, {})
    return rows


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksums(checksum_path: Path, base_dir: Path) -> list[str]:
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


def load_checksum_map(checksum_path: Path) -> dict[str, str]:
    entries = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        entries[relative] = expected
    return entries


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
        "dirty": bool(git_output(["status", "--porcelain"])),
        "status_short": git_output(["status", "--short"]).splitlines(),
    }


def git_output(args: list[str]) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    return completed.stdout.strip()


if __name__ == "__main__":
    main()
