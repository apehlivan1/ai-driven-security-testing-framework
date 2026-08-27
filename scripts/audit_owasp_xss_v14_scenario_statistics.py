from __future__ import annotations

import csv
import hashlib
import json
import math
import statistics
import subprocess
import sys
import warnings
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import scipy
from scipy.stats import wilcoxon


REPO_ROOT = Path(__file__).resolve().parents[1]
PLAN_DOC = REPO_ROOT / "docs" / "evaluation-v1.4-postrun-statistical-plan.md"
PLAN_PACKAGE = REPO_ROOT / "results" / "owasp-xss-v14-statistical-plan"
PLAN_JSON = PLAN_PACKAGE / "analysis-plan.json"
PROTOCOL = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"
PROTOCOL_PACKAGE = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
CANONICAL = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
RAW_RUN = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "owasp-xss-v14-confirmatory-20260821T235804Z"
COMMENT2 = REPO_ROOT / "results" / "owasp-xss-v14-trial-stability-analysis"
OUTPUT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-scenario-statistical-analysis"

DETERMINISTIC = "deterministic_structural"
GPT = "proprietary_gpt"
QWEN = "local_qwen"

BOOTSTRAP_SEED = 20260827
BOOTSTRAP_RESAMPLES = 20000
ALPHA = 0.05

EXPLORATORY_FAMILY = [
    "local_qwen_vs_proprietary_gpt_mrr",
    "proprietary_gpt_vs_deterministic_structural_mrr",
    "proprietary_gpt_vs_deterministic_structural_top1",
    "local_qwen_vs_deterministic_structural_top1",
    "local_qwen_vs_proprietary_gpt_top1",
    "proprietary_gpt_vs_deterministic_structural_top2",
    "local_qwen_vs_deterministic_structural_top2",
    "local_qwen_vs_proprietary_gpt_top2",
    "proprietary_gpt_vs_deterministic_structural_top4",
    "local_qwen_vs_deterministic_structural_top4",
    "local_qwen_vs_proprietary_gpt_top4",
]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    plan = load_json(PLAN_JSON)
    scored_rows = load_json(CANONICAL / "normalized" / "scored-rows.json")
    comment2_rr = load_csv(COMMENT2 / "scenario-mean-rr.csv")
    comment2_integrity = load_json(COMMENT2 / "source-integrity-report.json")

    source_validation = validate_sources(plan)
    scenario_rows = build_scenario_rows(scored_rows, comment2_rr)
    denominator_validation = validate_denominators(scored_rows, scenario_rows, comment2_integrity)
    validation_errors = [*source_validation["errors"], *denominator_validation["errors"]]
    if validation_errors:
        validation = validation_report(source_validation, denominator_validation, None, valid=False, errors=validation_errors)
        write_json(OUTPUT_DIR / "validation-report.json", validation)
        raise SystemExit("fail-closed: " + "; ".join(validation_errors))

    primary = paired_comparison(
        comparison_id="primary_local_qwen_vs_deterministic_structural_mrr",
        label="Qwen vs deterministic structural, scenario-level MRR",
        arm_a=QWEN,
        arm_b=DETERMINISTIC,
        metric="mrr",
        rows=scenario_rows,
        primary=True,
    )
    exploratory = build_exploratory_comparisons(scenario_rows)
    holm = holm_correction(exploratory)
    for comparison in exploratory:
        comparison["holm_adjusted_p_value"] = holm["adjusted_p_values"][comparison["comparison_id"]]
        comparison["holm_significant_at_alpha_0_05"] = comparison["holm_adjusted_p_value"] < ALPHA

    bootstrap = {
        "schema_version": "owasp-xss-v14-scenario-statistical-bootstrap-v1",
        "seed": BOOTSTRAP_SEED,
        "resample_count": BOOTSTRAP_RESAMPLES,
        "confidence_interval": "percentile_95",
        "resampling_unit": "paired_positive_scenario",
        "comparisons": {
            primary["comparison_id"]: primary["bootstrap"],
            **{comparison["comparison_id"]: comparison["bootstrap"] for comparison in exploratory},
        },
    }
    random_reference = {
        "schema_version": "owasp-xss-v14-random-reference-context-v1",
        "policy": "descriptive_context_only_no_new_random_baseline_hypothesis_test",
        "basis": "positive scenarios contain five candidates and one vulnerable candidate",
        "values": {
            "top1": 0.2,
            "top2": 0.4,
            "top4": 0.8,
            "mrr": 0.4566666667,
        },
    }
    implementation = implementation_metadata(plan, primary, exploratory)
    validation = validation_report(
        source_validation,
        denominator_validation,
        {"primary": primary, "exploratory": exploratory, "holm": holm},
        valid=True,
        errors=[],
    )
    manifest = build_manifest(validation)

    write_json(OUTPUT_DIR / "scenario-level-statistical-input.json", scenario_rows)
    write_csv(OUTPUT_DIR / "scenario-level-statistical-input.csv", scenario_rows)
    write_json(OUTPUT_DIR / "primary-comparison.json", primary)
    write_json(OUTPUT_DIR / "all-comparisons.json", exploratory)
    write_csv(OUTPUT_DIR / "all-comparisons.csv", comparison_csv_rows([primary, *exploratory]))
    write_json(OUTPUT_DIR / "bootstrap-results.json", bootstrap)
    write_json(OUTPUT_DIR / "holm-correction.json", holm)
    write_json(OUTPUT_DIR / "implementation-metadata.json", implementation)
    write_json(OUTPUT_DIR / "random-reference-context.json", random_reference)
    write_text(OUTPUT_DIR / "thesis-ready-table.md", render_thesis_markdown_table(primary, exploratory, holm))
    write_text(OUTPUT_DIR / "thesis-ready-table.tex", render_thesis_latex_table(primary, exploratory))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(source_validation, denominator_validation, implementation))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", manifest)
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(primary, exploratory, holm, denominator_validation, random_reference, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_checksums(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "owasp-xss-v14-scenario-statistical-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    final_checksum_errors = validate_checksums(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    if final_checksum_errors:
        raise SystemExit("checksum validation failed: " + "; ".join(final_checksum_errors))

    print(f"statistical analysis package: {display_path(OUTPUT_DIR)}")
    print(f"primary paired n: {primary['paired_n']}")
    print(f"primary mean paired difference: {primary['mean_paired_difference']:.10f}")
    print(f"primary bootstrap CI: [{primary['bootstrap']['ci_95_percentile'][0]:.10f}, {primary['bootstrap']['ci_95_percentile'][1]:.10f}]")
    print(f"primary wilcoxon statistic: {primary['wilcoxon']['statistic']:.10f}")
    print(f"primary raw p-value: {primary['wilcoxon']['p_value']:.10g}")
    print(f"primary rank-biserial: {primary['matched_pairs_rank_biserial_correlation']:.10f}")
    print(f"validation valid: {validation['valid']}")
    print(f"checksum errors: {len(final_checksum_errors)}")


def build_scenario_rows(scored_rows: list[dict[str, Any]], comment2_rr: list[dict[str, str]]) -> list[dict[str, Any]]:
    positive_scenarios = sorted({row["scenario_id"] for row in scored_rows if row["scenario_type"] == "positive"})
    rows_by_arm_scenario: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in scored_rows:
        rows_by_arm_scenario[row["arm_id"]][row["scenario_id"]].append(row)

    llm_rr = {(row["arm_id"], row["scenario_id"]): row for row in comment2_rr}
    result: list[dict[str, Any]] = []
    for scenario_id in positive_scenarios:
        det_rows = rows_by_arm_scenario[DETERMINISTIC][scenario_id]
        if len(det_rows) != 1:
            raise ValueError(f"expected one deterministic row for {scenario_id}, found {len(det_rows)}")
        det = det_rows[0]
        gpt_stats = llm_scenario_values(rows_by_arm_scenario[GPT][scenario_id])
        qwen_stats = llm_scenario_values(rows_by_arm_scenario[QWEN][scenario_id])
        gpt_rr_row = llm_rr.get((GPT, scenario_id))
        qwen_rr_row = llm_rr.get((QWEN, scenario_id))
        if gpt_rr_row is not None:
            assert_close(gpt_stats["mean_rr"], parse_number(gpt_rr_row["mean_rr"]), f"GPT mean_rr {scenario_id}")
        if qwen_rr_row is not None:
            assert_close(qwen_stats["mean_rr"], parse_number(qwen_rr_row["mean_rr"]), f"Qwen mean_rr {scenario_id}")
        result.append(
            {
                "scenario_id": scenario_id,
                "deterministic_rr": float(det["reciprocal_rank"]),
                "gpt_mean_rr": gpt_stats["mean_rr"],
                "qwen_mean_rr": qwen_stats["mean_rr"],
                "gpt_valid_trials": gpt_stats["valid_trials"],
                "qwen_valid_trials": qwen_stats["valid_trials"],
                "gpt_invalid_or_failed_trials": gpt_stats["invalid_or_failed_trials"],
                "qwen_invalid_or_failed_trials": qwen_stats["invalid_or_failed_trials"],
                "deterministic_top1": int(int(det["vulnerable_rank"]) <= 1),
                "deterministic_top2": int(int(det["vulnerable_rank"]) <= 2),
                "deterministic_top4": int(int(det["vulnerable_rank"]) <= 4),
                "gpt_top1_proportion": gpt_stats["top1_proportion"],
                "gpt_top2_proportion": gpt_stats["top2_proportion"],
                "gpt_top4_proportion": gpt_stats["top4_proportion"],
                "qwen_top1_proportion": qwen_stats["top1_proportion"],
                "qwen_top2_proportion": qwen_stats["top2_proportion"],
                "qwen_top4_proportion": qwen_stats["top4_proportion"],
            }
        )
    return result


def llm_scenario_values(rows: list[dict[str, Any]]) -> dict[str, Any]:
    valid_rows = [row for row in rows if row.get("status") == "valid" and row.get("contract_valid") is True]
    ranks = [int(row["vulnerable_rank"]) for row in valid_rows if isinstance(row.get("vulnerable_rank"), int)]
    if not ranks:
        return {
            "valid_trials": 0,
            "invalid_or_failed_trials": len(rows),
            "mean_rr": "missing",
            "top1_proportion": "missing",
            "top2_proportion": "missing",
            "top4_proportion": "missing",
        }
    return {
        "valid_trials": len(ranks),
        "invalid_or_failed_trials": len(rows) - len(ranks),
        "mean_rr": statistics.mean(1 / rank for rank in ranks),
        "top1_proportion": sum(1 for rank in ranks if rank <= 1) / len(ranks),
        "top2_proportion": sum(1 for rank in ranks if rank <= 2) / len(ranks),
        "top4_proportion": sum(1 for rank in ranks if rank <= 4) / len(ranks),
    }


def build_exploratory_comparisons(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    specs = [
        ("local_qwen_vs_proprietary_gpt_mrr", QWEN, GPT, "mrr"),
        ("proprietary_gpt_vs_deterministic_structural_mrr", GPT, DETERMINISTIC, "mrr"),
        ("proprietary_gpt_vs_deterministic_structural_top1", GPT, DETERMINISTIC, "top1"),
        ("local_qwen_vs_deterministic_structural_top1", QWEN, DETERMINISTIC, "top1"),
        ("local_qwen_vs_proprietary_gpt_top1", QWEN, GPT, "top1"),
        ("proprietary_gpt_vs_deterministic_structural_top2", GPT, DETERMINISTIC, "top2"),
        ("local_qwen_vs_deterministic_structural_top2", QWEN, DETERMINISTIC, "top2"),
        ("local_qwen_vs_proprietary_gpt_top2", QWEN, GPT, "top2"),
        ("proprietary_gpt_vs_deterministic_structural_top4", GPT, DETERMINISTIC, "top4"),
        ("local_qwen_vs_deterministic_structural_top4", QWEN, DETERMINISTIC, "top4"),
        ("local_qwen_vs_proprietary_gpt_top4", QWEN, GPT, "top4"),
    ]
    comparisons = [
        paired_comparison(
            comparison_id=comparison_id,
            label=f"{arm_label(arm_a)} vs {arm_label(arm_b)}, scenario-level {metric.upper()}",
            arm_a=arm_a,
            arm_b=arm_b,
            metric=metric,
            rows=rows,
            primary=False,
        )
        for comparison_id, arm_a, arm_b, metric in specs
    ]
    if [comparison["comparison_id"] for comparison in comparisons] != EXPLORATORY_FAMILY:
        raise ValueError("exploratory family order does not match frozen plan")
    return comparisons


def paired_comparison(
    *,
    comparison_id: str,
    label: str,
    arm_a: str,
    arm_b: str,
    metric: str,
    rows: list[dict[str, Any]],
    primary: bool,
) -> dict[str, Any]:
    paired = []
    for row in rows:
        a = metric_value(row, arm_a, metric)
        b = metric_value(row, arm_b, metric)
        if is_number(a) and is_number(b):
            paired.append({"scenario_id": row["scenario_id"], "arm_a": float(a), "arm_b": float(b), "difference": float(a) - float(b)})
    diffs = [item["difference"] for item in paired]
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        result = wilcoxon(diffs, alternative="two-sided", zero_method="pratt", method="auto")
    rank_sums = signed_rank_sums_pratt(diffs)
    ci = bootstrap_ci(diffs)
    return {
        "schema_version": "owasp-xss-v14-paired-comparison-v1",
        "comparison_id": comparison_id,
        "label": label,
        "comparison_role": "primary" if primary else "exploratory",
        "metric": metric,
        "arm_a": arm_a,
        "arm_b": arm_b,
        "difference_orientation": f"{arm_a} - {arm_b}",
        "paired_n": len(paired),
        "arm_a_mean": statistics.mean(item["arm_a"] for item in paired),
        "arm_b_mean": statistics.mean(item["arm_b"] for item in paired),
        "mean_paired_difference": statistics.mean(diffs),
        "median_paired_difference": statistics.median(diffs),
        "positive_difference_count": sum(1 for diff in diffs if diff > 0),
        "negative_difference_count": sum(1 for diff in diffs if diff < 0),
        "zero_difference_count": sum(1 for diff in diffs if diff == 0),
        "wilcoxon": {
            "implementation": "scipy.stats.wilcoxon",
            "scipy_version": scipy.__version__,
            "parameters": {
                "alternative": "two-sided",
                "zero_method": "pratt",
                "method": "auto",
            },
            "actual_computation_recorded": scipy_auto_computation_note(diffs),
            "statistic": float(result.statistic),
            "p_value": float(result.pvalue),
            "warnings": [str(item.message) for item in caught],
        },
        "signed_rank_sums_pratt": rank_sums,
        "matched_pairs_rank_biserial_correlation": rank_sums["rank_biserial_correlation"],
        "bootstrap": {
            "seed": BOOTSTRAP_SEED,
            "resample_count": BOOTSTRAP_RESAMPLES,
            "ci_95_percentile": ci,
            "resampling_unit": "paired_positive_scenario",
        },
        "scenario_ids": [item["scenario_id"] for item in paired],
    }


def metric_value(row: dict[str, Any], arm: str, metric: str) -> Any:
    prefix = "deterministic" if arm == DETERMINISTIC else ("gpt" if arm == GPT else "qwen")
    suffix = "mean_rr" if metric == "mrr" and arm != DETERMINISTIC else metric
    if arm == DETERMINISTIC and metric == "mrr":
        return row["deterministic_rr"]
    if arm == DETERMINISTIC:
        return row[f"deterministic_{metric}"]
    return row[f"{prefix}_{suffix}_proportion"] if metric.startswith("top") else row[f"{prefix}_{suffix}"]


def signed_rank_sums_pratt(diffs: list[float]) -> dict[str, Any]:
    ranks = rank_absolute_values([abs(diff) for diff in diffs])
    positive = sum(rank for rank, diff in zip(ranks, diffs, strict=True) if diff > 0)
    negative = sum(rank for rank, diff in zip(ranks, diffs, strict=True) if diff < 0)
    zero = sum(rank for rank, diff in zip(ranks, diffs, strict=True) if diff == 0)
    denominator = positive + negative
    rbc = (positive - negative) / denominator if denominator else 0.0
    return {
        "positive_rank_sum": positive,
        "negative_rank_sum": negative,
        "zero_rank_sum": zero,
        "rank_biserial_formula": "(positive_rank_sum - negative_rank_sum) / (positive_rank_sum + negative_rank_sum), with zero-difference ranks excluded from the denominator after Pratt ranking",
        "rank_biserial_correlation": rbc,
    }


def rank_absolute_values(values: list[float]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    index = 0
    while index < len(indexed):
        end = index + 1
        while end < len(indexed) and indexed[end][1] == indexed[index][1]:
            end += 1
        average_rank = (index + 1 + end) / 2
        for original_index, _ in indexed[index:end]:
            ranks[original_index] = average_rank
        index = end
    return ranks


def bootstrap_ci(diffs: list[float]) -> list[float]:
    try:
        import numpy as np
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("numpy is required for the frozen bootstrap implementation") from exc

    values = np.array(diffs, dtype=float)
    rng = np.random.default_rng(BOOTSTRAP_SEED)
    indices = rng.integers(0, len(values), size=(BOOTSTRAP_RESAMPLES, len(values)))
    means = values[indices].mean(axis=1)
    lower, upper = np.percentile(means, [2.5, 97.5])
    return [float(lower), float(upper)]


def holm_correction(comparisons: list[dict[str, Any]]) -> dict[str, Any]:
    if len(comparisons) != 11:
        raise ValueError(f"expected 11 exploratory tests, found {len(comparisons)}")
    ordered = sorted(((comparison["comparison_id"], comparison["wilcoxon"]["p_value"]) for comparison in comparisons), key=lambda item: item[1])
    adjusted: dict[str, float] = {}
    running_max = 0.0
    m = len(ordered)
    for index, (comparison_id, p_value) in enumerate(ordered):
        value = min((m - index) * p_value, 1.0)
        running_max = max(running_max, value)
        adjusted[comparison_id] = running_max
    return {
        "schema_version": "owasp-xss-v14-holm-correction-v1",
        "family": "exploratory_model_comparisons",
        "alpha": ALPHA,
        "p_value_count": len(comparisons),
        "expected_p_value_count": 11,
        "raw_p_values": {comparison["comparison_id"]: comparison["wilcoxon"]["p_value"] for comparison in comparisons},
        "ordered_raw_p_values": [{"comparison_id": comparison_id, "raw_p_value": p_value} for comparison_id, p_value in ordered],
        "adjusted_p_values": adjusted,
        "significant_after_holm": {comparison_id: value < ALPHA for comparison_id, value in adjusted.items()},
    }


def validate_sources(plan: dict[str, Any]) -> dict[str, Any]:
    errors = []
    plan_manifest = load_json(PLAN_PACKAGE / "manifest.json")
    doc_sha = sha256_file(PLAN_DOC)
    plan_sha = sha256_file(PLAN_JSON)
    if doc_sha != plan_manifest.get("source_plan_sha256"):
        errors.append("frozen_markdown_plan_hash_mismatch")
    if plan_sha != plan_manifest.get("analysis_plan_sha256"):
        errors.append("frozen_machine_plan_hash_mismatch")
    checks = {
        "statistical_plan_package": validate_checksums(PLAN_PACKAGE / "checksums.sha256", PLAN_PACKAGE),
        "canonical_v1_4": validate_checksums(CANONICAL / "checksums.sha256", CANONICAL),
        "raw_run_v1_4": validate_checksums(RAW_RUN / "checksums.sha256", RAW_RUN),
        "comment_2_trial_stability": validate_checksums(COMMENT2 / "checksums.sha256", COMMENT2),
    }
    for name, check_errors in checks.items():
        if check_errors:
            errors.append(f"{name}_checksum_errors_{len(check_errors)}")
    return {
        "schema_version": "owasp-xss-v14-statistical-source-validation-v1",
        "valid": not errors,
        "errors": errors,
        "checksums": {name: {"valid": not check_errors, "error_count": len(check_errors), "errors": check_errors[:25]} for name, check_errors in checks.items()},
        "plan_hashes": {
            "markdown_plan_sha256": doc_sha,
            "machine_plan_sha256": plan_sha,
            "manifest_markdown_plan_sha256": plan_manifest.get("source_plan_sha256"),
            "manifest_machine_plan_sha256": plan_manifest.get("analysis_plan_sha256"),
        },
        "frozen_plan_git_commit": git_output(["log", "-1", "--format=%H", "--", display_path(PLAN_DOC), display_path(PLAN_JSON)]),
        "current_git": git_state(),
        "plan_primary_paired_denominator": plan["primary_comparison"]["paired_denominator"],
        "plan_exploratory_family_size": plan["multiplicity"]["exploratory_family_size"],
    }


def validate_denominators(
    scored_rows: list[dict[str, Any]],
    scenario_rows: list[dict[str, Any]],
    comment2_integrity: dict[str, Any],
) -> dict[str, Any]:
    errors = []
    scenario_types = {row["scenario_id"]: row["scenario_type"] for row in scored_rows}
    positive = sorted(sid for sid, scenario_type in scenario_types.items() if scenario_type == "positive")
    negative = sorted(sid for sid, scenario_type in scenario_types.items() if scenario_type == "negative_only")
    counts = Counter((row["arm_id"], row["scenario_type"]) for row in scored_rows)
    terminal = Counter((row["arm_id"], row["status"]) for row in scored_rows)
    by_arm_scenario: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for row in scored_rows:
        by_arm_scenario[row["arm_id"]][row["scenario_id"]].append(row)
    qwen_missing = [row["scenario_id"] for row in scenario_rows if row["qwen_valid_trials"] == 0]
    malformed_missing = []
    for scenario_id in qwen_missing:
        rows = by_arm_scenario[QWEN][scenario_id]
        if len(rows) == 5 and all(row.get("status") == "malformed" for row in rows):
            malformed_missing.append(scenario_id)
    expected_checks = {
        "positive_scenario_count": (len(positive), 236),
        "negative_only_scenario_count": (len(negative), 30),
        "deterministic_positive_rr_count": (sum(1 for row in scenario_rows if is_number(row["deterministic_rr"])), 236),
        "gpt_positive_mean_rr_count": (sum(1 for row in scenario_rows if is_number(row["gpt_mean_rr"])), 236),
        "qwen_positive_mean_rr_count": (sum(1 for row in scenario_rows if is_number(row["qwen_mean_rr"])), 235),
        "primary_qwen_vs_deterministic_complete_pairs": (sum(1 for row in scenario_rows if is_number(row["qwen_mean_rr"]) and is_number(row["deterministic_rr"])), 235),
        "gpt_vs_deterministic_complete_pairs": (sum(1 for row in scenario_rows if is_number(row["gpt_mean_rr"]) and is_number(row["deterministic_rr"])), 236),
        "qwen_vs_gpt_complete_pairs": (sum(1 for row in scenario_rows if is_number(row["qwen_mean_rr"]) and is_number(row["gpt_mean_rr"])), 235),
    }
    for name, (actual, expected) in expected_checks.items():
        if actual != expected:
            errors.append(f"{name}_expected_{expected}_actual_{actual}")
    if len(qwen_missing) != 1 or qwen_missing != malformed_missing:
        errors.append(f"qwen_missing_scenario_not_exactly_five_malformed_terminal_outputs:{qwen_missing}")
    if comment2_integrity.get("source_integrity_verified") is not True:
        errors.append("comment_2_source_integrity_not_verified")
    return {
        "schema_version": "owasp-xss-v14-statistical-denominator-validation-v1",
        "valid": not errors,
        "errors": errors,
        "required_counts": expected_checks,
        "scored_row_counts_by_arm_and_scenario_type": {f"{arm}:{stype}": count for (arm, stype), count in sorted(counts.items())},
        "terminal_status_counts_by_arm": {f"{arm}:{status}": count for (arm, status), count in sorted(terminal.items())},
        "qwen_missing_positive_scenarios": qwen_missing,
        "qwen_missing_positive_scenarios_with_five_malformed_terminal_outputs": malformed_missing,
        "comment_2_source_integrity_verified": comment2_integrity.get("source_integrity_verified"),
    }


def implementation_metadata(plan: dict[str, Any], primary: dict[str, Any], exploratory: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-statistical-implementation-metadata-v1",
        "analysis_status": "derived_post_run_inferential_analysis",
        "python_executable": sys.executable,
        "python_version": sys.version,
        "analysis_pythonpath": [entry for entry in sys.path if "scipy-v14-stat" in entry],
        "scipy_version": scipy.__version__,
        "scipy_wilcoxon_parameters": {
            "alternative": "two-sided",
            "zero_method": "pratt",
            "method": "auto",
        },
        "scipy_computation_notes": sorted({comparison["wilcoxon"]["actual_computation_recorded"] for comparison in [primary, *exploratory]}),
        "rank_biserial_formula": primary["signed_rank_sums_pratt"]["rank_biserial_formula"],
        "bootstrap": {
            "resamples": BOOTSTRAP_RESAMPLES,
            "seed": BOOTSTRAP_SEED,
            "resampling_unit": "paired_positive_scenario",
            "confidence_interval": "percentile_95",
            "numpy_rng": "numpy.random.default_rng",
            "numpy_percentile": "np.percentile([2.5, 97.5])",
        },
        "plan_source": display_path(PLAN_DOC),
        "machine_plan_source": display_path(PLAN_JSON),
        "plan_primary_comparison": plan["primary_comparison"],
        "zero_experimental_calls": zero_experimental_calls(),
    }


def validation_report(
    source_validation: dict[str, Any],
    denominator_validation: dict[str, Any],
    comparison_validation: dict[str, Any] | None,
    *,
    valid: bool,
    errors: list[str],
) -> dict[str, Any]:
    comparison_errors = []
    if comparison_validation is not None:
        primary = comparison_validation["primary"]
        exploratory = comparison_validation["exploratory"]
        holm = comparison_validation["holm"]
        if primary["paired_n"] != 235:
            comparison_errors.append("primary_paired_n_not_235")
        if len(exploratory) != 11 or holm["p_value_count"] != 11:
            comparison_errors.append("exploratory_family_not_11")
    return {
        "schema_version": "owasp-xss-v14-scenario-statistical-validation-v1",
        "valid": valid and not comparison_errors,
        "errors": [*errors, *comparison_errors],
        "source_validation": source_validation,
        "denominator_validation": denominator_validation,
        "comparison_validation": comparison_validation,
        "zero_experimental_calls": zero_experimental_calls(),
        "validated_at": now_utc(),
    }


def build_manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-scenario-statistical-analysis-manifest-v1",
        "created_at": now_utc(),
        "artifact_status": "derived_post_run_inferential_analysis",
        "output_dir": display_path(OUTPUT_DIR),
        "source_plan": display_path(PLAN_DOC),
        "source_machine_plan": display_path(PLAN_JSON),
        "source_protocol": display_path(PROTOCOL),
        "source_protocol_package": display_path(PROTOCOL_PACKAGE),
        "source_canonical_package": display_path(CANONICAL),
        "source_raw_run": display_path(RAW_RUN),
        "source_comment_2_package": display_path(COMMENT2),
        "validation_valid": validation["valid"],
        "frozen_artifacts_modified": False,
        "new_experimental_calls": zero_experimental_calls(),
        "git_state": git_state(),
    }


def render_report(
    primary: dict[str, Any],
    exploratory: list[dict[str, Any]],
    holm: dict[str, Any],
    denominator_validation: dict[str, Any],
    random_reference: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    supported_exploratory = [comparison for comparison in exploratory if comparison["holm_significant_at_alpha_0_05"]]
    descriptive_only = [comparison for comparison in exploratory if not comparison["holm_significant_at_alpha_0_05"]]
    lines = [
        "# Professor Comment 3 Closure Analysis: v1.4 Scenario-Level Inference",
        "",
        "This is a derived post-run inferential analysis of the original frozen OWASP XSS v1.4 ranking evaluation. It follows the frozen post-run statistical plan and performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier, or scored experimental calls.",
        "",
        "## Source and Denominator Validation",
        "",
        f"- Validation valid: `{validation['valid']}`",
        f"- Positive scenarios: `236`",
        f"- Negative-only scenarios: `30`",
        f"- Primary paired denominator: `{primary['paired_n']}`",
        f"- Missing Qwen positive scenario: `{', '.join(denominator_validation['qwen_missing_positive_scenarios'])}`",
        "- Repeated LLM trials are aggregated within scenario; trial rows are not treated as independent observations.",
        "",
        "## Primary Comparison",
        "",
        comparison_table([primary]).strip(),
        "",
        f"The primary comparison is Qwen minus deterministic structural ranking on scenario-level mean reciprocal rank. Qwen mean RR over the paired scenarios is `{primary['arm_a_mean']:.4f}` and deterministic mean RR over the same paired scenarios is `{primary['arm_b_mean']:.4f}`. The mean paired difference is `{primary['mean_paired_difference']:+.4f}` with a 95% paired-bootstrap percentile CI of `[{primary['bootstrap']['ci_95_percentile'][0]:+.4f}, {primary['bootstrap']['ci_95_percentile'][1]:+.4f}]`. The two-sided Wilcoxon signed-rank p-value is `{primary['wilcoxon']['p_value']:.6g}`.",
        "",
        primary_interpretation(primary),
        "",
        "## Exploratory Comparisons",
        "",
        comparison_table(exploratory, include_holm=True).strip(),
        "",
        f"Exactly `{holm['p_value_count']}` exploratory p-values entered the Holm procedure.",
        "",
        f"Exploratory differences supported after Holm correction: `{len(supported_exploratory)}`.",
        "",
        "Differences without Holm-adjusted support should remain descriptive trends rather than statistically supported conclusions: "
        + ", ".join(comparison["comparison_id"] for comparison in descriptive_only)
        + ".",
        "",
        "## Random Reference Context",
        "",
        f"The analytic random reference from Professor Comment 1 is included only descriptively: Top-1 `{random_reference['values']['top1']:.4f}`, Top-2 `{random_reference['values']['top2']:.4f}`, Top-4 `{random_reference['values']['top4']:.4f}`, and MRR `{random_reference['values']['mrr']:.4f}`. No new random-baseline hypothesis test is performed in this package.",
        "",
        "## Reliability and Invalid Outputs",
        "",
        "GPT scenario-level values are available for all `236` positive scenarios, although one GPT positive scenario has four valid trials. Qwen scenario-level values are available for `235/236` positive scenarios; the omitted scenario contains five malformed terminal Qwen outputs and no valid Qwen ranking. These invalid/failure outcomes remain part of reliability reporting and are not repaired, retried, imputed, or counted as successful rankings.",
        "",
        "## Thesis Interpretation",
        "",
        thesis_interpretation(primary, supported_exploratory, descriptive_only),
        "",
        "## Claims to Avoid",
        "",
        "- Do not treat repeated GPT or Qwen trial rows as independent scenarios.",
        "- Do not describe non-significant comparisons as evidence of equivalence.",
        "- Do not claim broad LLM, GPT, or Qwen superiority beyond the frozen OWASP XSS v1.4 scenario class.",
        "- Do not report v1.4 ranking-only evidence as verifier-confirmed vulnerability findings.",
        "",
        "## Validation",
        "",
        f"- Source validation: `{validation['source_validation']['valid']}`",
        f"- Denominator validation: `{validation['denominator_validation']['valid']}`",
        "- New experimental/scored calls: `0`",
    ]
    return "\n".join(lines) + "\n"


def render_thesis_markdown_table(primary: dict[str, Any], exploratory: list[dict[str, Any]], holm: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Thesis-Ready Tables: v1.4 Scenario-Level Inference",
            "## Primary MRR Comparison\n\n" + comparison_table([primary]),
            "## Exploratory Comparisons\n\n" + comparison_table(exploratory, include_holm=True),
            f"Holm correction was applied to exactly {holm['p_value_count']} exploratory tests. The primary Qwen-vs-deterministic MRR test is reported unadjusted according to the frozen plan.",
        ]
    ) + "\n"


def render_thesis_latex_table(primary: dict[str, Any], exploratory: list[dict[str, Any]]) -> str:
    rows = [primary, *exploratory]
    lines = [
        "% Thesis-ready table generated from results/owasp-xss-v14-scenario-statistical-analysis.",
        "\\begin{tabular}{lrrrrrr}",
        "\\hline",
        "Comparison & $n$ & Mean $\\Delta$ & 95\\% CI & Wilcoxon $W$ & $p$ & Holm $p$ \\\\",
        "\\hline",
    ]
    for comparison in rows:
        ci = comparison["bootstrap"]["ci_95_percentile"]
        holm_value = comparison.get("holm_adjusted_p_value", "not_applicable")
        holm_text = "n/a" if holm_value == "not_applicable" else f"{holm_value:.4g}"
        lines.append(
            f"{latex_escape(short_label(comparison))} & {comparison['paired_n']} & {comparison['mean_paired_difference']:+.4f} & "
            f"[{ci[0]:+.4f}, {ci[1]:+.4f}] & {comparison['wilcoxon']['statistic']:.4f} & "
            f"{comparison['wilcoxon']['p_value']:.4g} & {holm_text} \\\\"
        )
    lines.extend(["\\hline", "\\end{tabular}", ""])
    return "\n".join(lines)


def render_methodology_note(source_validation: dict[str, Any], denominator_validation: dict[str, Any], implementation: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance",
            "",
            "- Scope: original frozen OWASP XSS v1.4 ranking-only evaluation.",
            "- Plan: `docs/evaluation-v1.4-postrun-statistical-plan.md` and `results/owasp-xss-v14-statistical-plan/analysis-plan.json`.",
            f"- Frozen plan commit: `{source_validation['frozen_plan_git_commit']}`.",
            "- Source data: v1.4 canonical scored rows and Comment 2 scenario-level mean reciprocal-rank data.",
            "- Independent unit: positive scenario.",
            "- Repeated trials: GPT and Qwen trials are averaged within scenario before inferential comparison.",
            "- Missing Qwen scenario: retained as a reliability outcome and not imputed.",
            "- Primary test: paired two-sided Wilcoxon signed-rank, Qwen minus deterministic structural scenario-level MRR, unadjusted.",
            "- Exploratory tests: paired scenario-level Wilcoxon with Holm correction across exactly 11 tests.",
            f"- SciPy version: `{implementation['scipy_version']}`.",
            f"- Wilcoxon parameters: `{json.dumps(implementation['scipy_wilcoxon_parameters'], sort_keys=True)}`.",
            f"- Bootstrap: `{BOOTSTRAP_RESAMPLES}` paired scenario resamples, seed `{BOOTSTRAP_SEED}`.",
            f"- Source checksums valid: `{source_validation['valid']}`.",
            f"- Denominators valid: `{denominator_validation['valid']}`.",
            "- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero discovery calls, zero verifier calls, zero scored calls.",
        ]
    ) + "\n"


def comparison_table(comparisons: list[dict[str, Any]], *, include_holm: bool = False) -> str:
    headers = ["Comparison", "n", "Arm A mean", "Arm B mean", "Mean diff", "Median diff", "95% bootstrap CI", "W", "raw p", "rank-biserial"]
    if include_holm:
        headers.extend(["Holm p", "Holm < 0.05"])
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] + ["---:"] * (len(headers) - 1)) + " |"]
    for comparison in comparisons:
        ci = comparison["bootstrap"]["ci_95_percentile"]
        row = [
            short_label(comparison),
            str(comparison["paired_n"]),
            f"{comparison['arm_a_mean']:.4f}",
            f"{comparison['arm_b_mean']:.4f}",
            f"{comparison['mean_paired_difference']:+.4f}",
            f"{comparison['median_paired_difference']:+.4f}",
            f"[{ci[0]:+.4f}, {ci[1]:+.4f}]",
            f"{comparison['wilcoxon']['statistic']:.4f}",
            f"{comparison['wilcoxon']['p_value']:.6g}",
            f"{comparison['matched_pairs_rank_biserial_correlation']:+.4f}",
        ]
        if include_holm:
            row.extend([f"{comparison['holm_adjusted_p_value']:.6g}", str(comparison["holm_significant_at_alpha_0_05"])])
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines) + "\n"


def comparison_csv_rows(comparisons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for comparison in comparisons:
        ci = comparison["bootstrap"]["ci_95_percentile"]
        rows.append(
            {
                "comparison_id": comparison["comparison_id"],
                "comparison_role": comparison["comparison_role"],
                "metric": comparison["metric"],
                "arm_a": comparison["arm_a"],
                "arm_b": comparison["arm_b"],
                "difference_orientation": comparison["difference_orientation"],
                "paired_n": comparison["paired_n"],
                "arm_a_mean": comparison["arm_a_mean"],
                "arm_b_mean": comparison["arm_b_mean"],
                "mean_paired_difference": comparison["mean_paired_difference"],
                "median_paired_difference": comparison["median_paired_difference"],
                "positive_difference_count": comparison["positive_difference_count"],
                "negative_difference_count": comparison["negative_difference_count"],
                "zero_difference_count": comparison["zero_difference_count"],
                "bootstrap_ci_lower": ci[0],
                "bootstrap_ci_upper": ci[1],
                "wilcoxon_statistic": comparison["wilcoxon"]["statistic"],
                "raw_p_value": comparison["wilcoxon"]["p_value"],
                "holm_adjusted_p_value": comparison.get("holm_adjusted_p_value", "not_applicable"),
                "holm_significant_at_alpha_0_05": comparison.get("holm_significant_at_alpha_0_05", "not_applicable"),
                "rank_biserial_correlation": comparison["matched_pairs_rank_biserial_correlation"],
            }
        )
    return rows


def primary_interpretation(primary: dict[str, Any]) -> str:
    if primary["wilcoxon"]["p_value"] < ALPHA:
        return "The primary Qwen-versus-deterministic MRR difference is statistically supported at alpha 0.05 under the frozen scenario-level paired test. The conclusion must still be limited to the frozen OWASP XSS v1.4 scenario class and the recorded ranking-only task."
    return "The primary Qwen-versus-deterministic MRR difference is not statistically supported at alpha 0.05 under the frozen scenario-level paired test. This does not prove equivalence, but it does mean the thesis should not claim that Qwen outperformed the deterministic structural baseline on the frozen OWASP XSS v1.4 scenario class."


def thesis_interpretation(primary: dict[str, Any], supported: list[dict[str, Any]], descriptive_only: list[dict[str, Any]]) -> str:
    primary_supported = primary["wilcoxon"]["p_value"] < ALPHA
    if primary_supported:
        primary_sentence = "The primary scenario-level MRR comparison supports a Qwen difference relative to the deterministic structural baseline under the frozen analysis plan."
    else:
        primary_sentence = "The primary scenario-level MRR comparison does not support a claim that Qwen outperformed the deterministic structural baseline under the frozen analysis plan."
    supported_ids = ", ".join(item["comparison_id"] for item in supported) if supported else "none"
    return (
        f"{primary_sentence} The estimated mean paired difference is {primary['mean_paired_difference']:+.4f}, "
        f"with a 95% paired-bootstrap CI of [{primary['bootstrap']['ci_95_percentile'][0]:+.4f}, "
        f"{primary['bootstrap']['ci_95_percentile'][1]:+.4f}]. Exploratory comparisons supported after Holm correction: {supported_ids}. "
        "All other exploratory differences should remain descriptive trends, and no non-significant comparison should be interpreted as equivalence."
    )


def short_label(comparison: dict[str, Any]) -> str:
    return f"{arm_label(comparison['arm_a'])} - {arm_label(comparison['arm_b'])} {comparison['metric'].upper()}"


def arm_label(arm: str) -> str:
    return {
        DETERMINISTIC: "Deterministic",
        GPT: "GPT",
        QWEN: "Qwen",
    }[arm]


def scipy_auto_computation_note(diffs: list[float]) -> str:
    abs_nonzero = [abs(diff) for diff in diffs if diff != 0]
    has_zero = any(diff == 0 for diff in diffs)
    has_ties = len(abs_nonzero) != len(set(abs_nonzero))
    if len(diffs) > 50 or has_zero or has_ties:
        return "method_auto_documented_as_asymptotic_for_this_input_size_or_zero_tie_structure"
    return "method_auto_documented_selection_exact_or_permutation_for_small_untied_inputs"


def parse_number(value: str) -> float:
    if value in {"missing", "not_available", ""}:
        return math.nan
    return float(value)


def assert_close(left: Any, right: float, context: str) -> None:
    if not is_number(left) and math.isnan(right):
        return
    if not is_number(left) or math.isnan(right) or abs(float(left) - right) > 1e-12:
        raise ValueError(f"{context} mismatch: {left} != {right}")


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not math.isnan(float(value))


def zero_experimental_calls() -> dict[str, int]:
    return {
        "gpt": 0,
        "qwen": 0,
        "deterministic_ranking": 0,
        "http": 0,
        "browser": 0,
        "discovery": 0,
        "verifier": 0,
        "scored_calls": 0,
    }


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


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


def latex_escape(value: str) -> str:
    return value.replace("_", "\\_")


if __name__ == "__main__":
    main()
