from __future__ import annotations

import csv
import hashlib
import json
import statistics
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "results" / "professor-comment-4-negative-sqli-analysis"

XSS14_CANONICAL = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
XSS14_RANDOM_AUDIT = REPO_ROOT / "results" / "owasp-xss-v14-random-baseline-audit"
XSS14_STABILITY = REPO_ROOT / "results" / "owasp-xss-v14-trial-stability-analysis"
XSS14_READINESS = REPO_ROOT / "results" / "owasp-xss-v14-readiness"
XSS13_CANONICAL = REPO_ROOT / "results" / "xss-v13-ablation-v1.3.1-final" / "canonical"
SQLI_CANONICAL = REPO_ROOT / "results" / "owasp-sqli-v15-1-confirmatory-final" / "canonical"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    evidence_inventory = build_evidence_inventory()
    xss_negative = build_xss_negative_control_summary()
    sqli_ranking = build_sqli_ranking_summary()
    sqli_classification = build_sqli_classification_summary()
    validation = build_validation_report(evidence_inventory, xss_negative, sqli_ranking, sqli_classification)

    write_json(OUTPUT_DIR / "evidence-inventory.json", evidence_inventory)
    write_json(OUTPUT_DIR / "xss-negative-control-summary.json", xss_negative)
    write_json(OUTPUT_DIR / "sqli-ranking-summary.json", sqli_ranking)
    write_json(OUTPUT_DIR / "sqli-classification-summary.json", sqli_classification)
    write_json(OUTPUT_DIR / "confusion-matrix.json", sqli_classification["confusion_matrix"])
    write_csv(OUTPUT_DIR / "sqli-confusion-matrix.csv", sqli_classification["confusion_matrix_table"])
    write_csv(OUTPUT_DIR / "sqli-classification-metrics.csv", sqli_classification["metrics_table"])
    write_csv(OUTPUT_DIR / "sqli-ranking-summary.csv", sqli_ranking["arm_table"])
    write_csv(OUTPUT_DIR / "xss-negative-control-summary.csv", xss_negative["arm_table"])
    write_text(OUTPUT_DIR / "thesis-tables.md", render_thesis_tables(xss_negative, sqli_ranking, sqli_classification))
    write_text(OUTPUT_DIR / "thesis-tables.tex", render_thesis_tables_tex(xss_negative, sqli_ranking, sqli_classification))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(evidence_inventory))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", build_manifest(validation))
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(evidence_inventory, xss_negative, sqli_ranking, sqli_classification, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "professor-comment-4-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    final_checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    if final_checksum_errors:
        raise SystemExit("checksum validation failed: " + "; ".join(final_checksum_errors))
    if not validation["valid"]:
        raise SystemExit("source validation failed: " + "; ".join(validation["errors"]))
    print(f"package: {display_path(OUTPUT_DIR)}")
    print(f"validation: {validation['valid']}")
    print(f"checksum_errors: {len(final_checksum_errors)}")
    print("zero_experimental_calls: true")


def build_evidence_inventory() -> dict[str, Any]:
    sources = [
        {
            "id": "owasp_xss_v14_canonical",
            "path": display_path(XSS14_CANONICAL),
            "evidence_type": "ranking-only evidence",
            "role": "original OWASP XSS v1.4 confirmatory ranking results, including 30 negative-only ranking scenarios",
            "checksum_source": display_path(XSS14_CANONICAL / "checksums.sha256"),
            "checksum_validation": validate_sha256_package(XSS14_CANONICAL),
        },
        {
            "id": "owasp_xss_v14_random_baseline_audit",
            "path": display_path(XSS14_RANDOM_AUDIT),
            "evidence_type": "derived candidate-construction and random-baseline audit",
            "role": "non-vulnerable candidate coverage, pack construction and deterministic-ranker discrimination evidence",
            "checksum_source": display_path(XSS14_RANDOM_AUDIT / "checksums.sha256"),
            "checksum_validation": validate_sha256_package(XSS14_RANDOM_AUDIT),
        },
        {
            "id": "owasp_xss_v14_trial_stability",
            "path": display_path(XSS14_STABILITY),
            "evidence_type": "derived ranking-only repeated-trial stability evidence",
            "role": "valid/invalid and stability behavior on positive and negative-only v1.4 ranking scenarios",
            "checksum_source": display_path(XSS14_STABILITY / "checksums.sha256"),
            "checksum_validation": validate_sha256_package(XSS14_STABILITY),
        },
        {
            "id": "owasp_xss_v14_readiness",
            "path": display_path(XSS14_READINESS),
            "evidence_type": "runtime verifier evidence, readiness-only",
            "role": "OWASP XSS transport/verifier readiness controls; not final confirmatory ranking evidence",
            "checksum_source": display_path(XSS14_READINESS / "checksums.json"),
            "checksum_validation": validate_json_checksum_package(XSS14_READINESS / "checksums.json", XSS14_READINESS),
        },
        {
            "id": "xss_v13_1_canonical",
            "path": display_path(XSS13_CANONICAL),
            "evidence_type": "runtime verifier and post-run ground-truth classification evidence",
            "role": "frozen 24-scenario XSS ablation with eight negative/control scenarios",
            "checksum_source": display_path(XSS13_CANONICAL / "checksums.sha256"),
            "checksum_validation": validate_sha256_selected(
                XSS13_CANONICAL / "checksums.sha256",
                XSS13_CANONICAL,
                [
                    "normalized/arm-level-metrics.csv",
                    "normalized/arm-level-metrics.json",
                    "validation-report.json",
                    "manifest.json",
                ],
            ),
            "full_package_checksum_validation": validate_sha256_package(XSS13_CANONICAL),
            "full_package_note": "The Comment 4 audit uses checksum-valid normalized/control files. The full v1.3.1 canonical package currently reports mismatches in non-input presentation artifacts and is therefore not treated as wholly checksum-clean here.",
        },
        {
            "id": "sqli_v15_1_canonical",
            "path": display_path(SQLI_CANONICAL),
            "evidence_type": "ranking-only evidence, runtime verifier evidence and post-run ground-truth classification evidence",
            "role": "final OWASP SQLi v1.5.1 ranking and direct verifier/classification evidence",
            "checksum_source": display_path(SQLI_CANONICAL / "checksums.sha256"),
            "checksum_validation": validate_sha256_package(SQLI_CANONICAL),
        },
    ]
    return {
        "schema_version": "professor-comment-4-evidence-inventory-v1",
        "created_at": now_utc(),
        "sources": sources,
        "all_checksum_sources_valid": all(source["checksum_validation"]["valid"] for source in sources),
        "activity_boundaries": {
            "new_model_calls": 0,
            "new_http_requests": 0,
            "new_browser_tests": 0,
            "new_ranking_calls": 0,
            "new_verifier_calls": 0,
            "ground_truth_used_only_for_post_run_derived_classification": True,
        },
    }


def build_xss_negative_control_summary() -> dict[str, Any]:
    negative_aggregates = load_json(XSS14_CANONICAL / "normalized" / "negative-scenario-aggregates.json")["arms"]
    reliability = load_json(XSS14_CANONICAL / "normalized" / "reliability-aggregates.json")["arms"]
    ranking = load_json(XSS14_CANONICAL / "normalized" / "ranking-aggregates.json")["arms"]
    reuse = load_json(XSS14_RANDOM_AUDIT / "candidate-reuse-summary.json")
    stability = load_json(XSS14_STABILITY / "exact-ranking-stability-summary.json")
    v13_metrics = load_csv(XSS13_CANONICAL / "normalized" / "arm-level-metrics.csv")
    readiness = load_json(XSS14_READINESS / "readiness-results.json")

    v14_arm_rows = []
    for arm in ["deterministic_structural", "proprietary_gpt", "local_qwen"]:
        neg = negative_aggregates[arm]
        rel = reliability[arm]
        stab = stability.get(arm, {}).get("negative_only", {})
        v14_arm_rows.append(
            {
                "source": "owasp_xss_v14_negative_only_ranking",
                "arm_id": arm,
                "negative_only_scenarios": neg["negative_scenarios"],
                "negative_ranking_rows": neg["negative_rows"],
                "contract_valid_rows": neg["contract_valid_rows"],
                "scheduled_rows_all_scenarios": rel["scheduled_rows"],
                "contract_invalid_outputs_all_scenarios": rel["contract_invalid_outputs"],
                "provider_or_runtime_failures_all_scenarios": rel["provider_or_runtime_failures"],
                "top1_topk_mrr": neg["top1_topk_mrr"],
                "verifier_false_positive_evidence": neg["verifier_false_positive_evidence"],
                "direct_execution_layer": neg["direct_execution_layer"],
                "negative_unique_complete_ranking_patterns": stab.get("unique_complete_ranking_count_distribution", "not_applicable"),
                "negative_scenarios_with_differing_repeated_rankings": stab.get("at_least_one_valid_complete_ranking_differs", "not_applicable"),
            }
        )

    v13_rows = [row for row in v13_metrics if row["aggregate_scope"] == "all_retained_trials"]
    v13_control_rows = []
    for row in v13_rows:
        neg_rows = int(row["negative_ranking_rows"])
        neg_verified = int(row["negative_verified_rows"])
        v13_control_rows.append(
            {
                "source": "xss_v13_1_eight_negative_controls",
                "arm_id": row["arm_id"],
                "negative_control_scenarios": 8,
                "negative_retained_trials": neg_rows,
                "negative_verified_rows": neg_verified,
                "negative_unverified_rows": neg_rows - neg_verified,
                "false_positive_rate": safe_div(neg_verified, neg_rows),
                "specificity": safe_div(neg_rows - neg_verified, neg_rows),
                "calculation_scope": "retained arm/trial rows; eight scenarios remain the independent control cases",
            }
        )

    readiness_results = readiness["readiness_results"]
    readiness_summary = {
        "source": "owasp_xss_v14_readiness_only_controls",
        "selected_case_count": readiness["selected_case_count"],
        "expected_counts": dict(Counter(item["expected_result"] for item in readiness_results)),
        "verifier_outcomes": dict(Counter(item["verifier_outcome"] for item in readiness_results)),
        "matches_readiness_ground_truth": sum(1 for item in readiness_results if item["matches_readiness_ground_truth"]),
        "non_vulnerable_controls": sum(1 for item in readiness_results if item["expected_result"] == "non_vulnerable"),
        "non_vulnerable_verified": sum(1 for item in readiness_results if item["expected_result"] == "non_vulnerable" and item["verifier_outcome"] == "verified"),
        "note": "READINESS_ONLY evidence; it verifies transport/verifier behavior and is not part of the final v1.4 ranking denominator.",
    }

    non_vulnerable = reuse["denominators"]
    return {
        "schema_version": "professor-comment-4-xss-negative-control-summary-v1",
        "owasp_v14_negative_only": {
            "scenario_count": 30,
            "ranking_contract_supports_abstention": False,
            "ranking_contract_interpretation": "Rankers return an ordering of supplied candidate IDs; negative-only scenarios therefore exercise candidate-selection behavior and reliability, but do not create true-positive, false-positive, false-negative or true-negative vulnerability-classification observations.",
            "false_positive_specificity_status": "not_meaningful_for_ranking_only_outputs",
            "arm_rows": v14_arm_rows,
            "positive_context": {
                arm: {
                    "positive_rows": ranking[arm]["positive_rows"],
                    "top1": ranking[arm].get("top1"),
                    "top4": ranking[arm].get("candidate_coverage_under_budget"),
                    "mrr": ranking[arm].get("mrr"),
                }
                for arm in ranking
            },
        },
        "non_vulnerable_candidate_coverage": {
            "unique_non_vulnerable_candidates": non_vulnerable["non_vulnerable_unique_candidates"],
            "negative_only_scenarios": non_vulnerable["negative_only_scenarios"],
            "negative_only_placements": non_vulnerable["negative_only_placements"],
            "positive_scenario_distractor_placements": non_vulnerable["positive_scenario_distractor_placements"],
            "total_non_vulnerable_candidate_placements_across_all_packs": non_vulnerable["total_non_vulnerable_candidate_placements_across_all_packs"],
            "unique_non_vulnerable_candidates_used": non_vulnerable["unique_non_vulnerable_candidates_used"],
            "unused_non_vulnerable_candidates": non_vulnerable["unused_non_vulnerable_candidates"],
            "reuse_counts": reuse["total_reuse_counts"],
            "reuse_count_distribution": reuse["total_reuse_count_distribution"],
            "reuse_balance_interpretation": reuse["reuse_balance_interpretation"],
        },
        "xss_v13_1_eight_controls": {
            "scenario_count": 8,
            "evidence_semantics": "runtime verifier plus post-run ground-truth classification evidence",
            "rows": v13_control_rows,
            "interpretation": "No verifier-confirmed false positives were observed in the eight negative XSS scenarios for any arm. This supports scoped negative-control reporting, but it is not OWASP v1.4 evidence and does not turn v1.4 ranking-only rows into classifier specificity observations.",
        },
        "owasp_v14_readiness_controls": readiness_summary,
        "arm_table": [
            *v14_arm_rows,
            *v13_control_rows,
        ],
    }


def build_sqli_ranking_summary() -> dict[str, Any]:
    metrics = load_json(SQLI_CANONICAL / "normalized" / "arm-ranking-metrics.json")
    reliability = {row["arm_id"]: row for row in load_json(SQLI_CANONICAL / "normalized" / "reliability-metrics.json")}
    latency = {row["arm_id"]: row for row in load_json(SQLI_CANONICAL / "normalized" / "latency-resource-aggregates.json")}
    arm_table = []
    for row in metrics:
        arm = row["arm_id"]
        rel = reliability[arm]
        lat = latency[arm]
        arm_table.append(
            {
                "arm_id": arm,
                "valid_positive_observations": row["valid_positive_observations"],
                "invalid_positive_observations": row["invalid_positive_observations"],
                "valid_negative_observations": row["valid_negative_observations"],
                "top1_success_count": row["top_1_success_count"],
                "top1_rate": row["top_1_rate"],
                "top4_success_count": row["top_4_success_count"],
                "top4_rate": row["top_4_rate"],
                "mrr": row["mrr"],
                "rank_distribution": json.dumps(row["rank_distribution"], sort_keys=True),
                "scheduled_rows": rel["scheduled_rows"],
                "valid_rows": rel["valid_rows"],
                "contract_valid_rows": rel["contract_valid_rows"],
                "malformed_rows": rel["malformed_rows"],
                "provider_failed_rows": rel["provider_failed_rows"],
                "timeout_rows": rel["timeout_rows"],
                "retry_count": rel["retry_count"],
                "mean_latency_ms": lat["mean_latency_ms"],
                "median_latency_ms": lat["median_latency_ms"],
                "input_tokens": lat["input_tokens"],
                "output_tokens": lat["output_tokens"],
                "total_tokens": lat["total_tokens"],
                "cost": lat["cost"],
            }
        )
    return {
        "schema_version": "professor-comment-4-sqli-ranking-summary-v1",
        "source": display_path(SQLI_CANONICAL / "normalized" / "arm-ranking-metrics.json"),
        "ranking_metric_scope": "valid positive-scenario observations only",
        "negative_scenario_ranking_metrics": "not_applicable; negative-only scenarios have no vulnerable candidate rank",
        "reliability_scope": "all scheduled rows, including invalid/provider-failed terminal outcomes",
        "arm_table": arm_table,
        "interpretation": "The SQLi ranking data do not show the same descriptive model-backed advantage observed in the OWASP XSS ranking study; this is a scoped descriptive observation, not an inferential claim of model inferiority.",
    }


def build_sqli_classification_summary() -> dict[str, Any]:
    summary = load_json(SQLI_CANONICAL / "normalized" / "direct-sqli-summary.json")
    gt_verifier = load_json(SQLI_CANONICAL / "normalized" / "ground-truth-verifier-outcomes.json")
    tp, fp, fn, tn = summary["tp"], summary["fp"], summary["fn"], summary["tn"]
    metrics = [
        metric_row("sensitivity_recall", tp, tp + fn),
        metric_row("specificity", tn, tn + fp),
        metric_row("false_positive_rate", fp, fp + tn),
        metric_row("false_negative_rate", fn, fn + tp),
        metric_row("precision_ppv", tp, tp + fp),
        metric_row("negative_predictive_value", tn, tn + fn),
        metric_row("accuracy", tp + tn, tp + fp + fn + tn),
        metric_row("f1_score", 2 * tp, 2 * tp + fp + fn),
        {
            "metric": "balanced_accuracy",
            "numerator": "mean(sensitivity,specificity)",
            "denominator": "not_applicable",
            "value": round((safe_div(tp, tp + fn) + safe_div(tn, tn + fp)) / 2, 6),
        },
    ]
    confusion = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "runtime_verifier_outcomes_by_ground_truth": gt_verifier,
        "post_run_mapping_note": "Under the frozen v1.5.1 post-run scoring, verified vulnerable cases are TP, inconclusive vulnerable cases are FN, verified non-vulnerable cases are FP and non-verified non-vulnerable cases are TN.",
    }
    return {
        "schema_version": "professor-comment-4-sqli-classification-summary-v1",
        "source": display_path(SQLI_CANONICAL / "normalized" / "direct-sqli-summary.json"),
        "confusion_matrix": confusion,
        "confusion_matrix_table": [
            {"ground_truth": "vulnerable", "verified": 84, "inconclusive": 21, "rejected": 0, "classification": "TP=84, FN=21"},
            {"ground_truth": "non_vulnerable", "verified": 0, "inconclusive": 95, "rejected": 0, "classification": "FP=0, TN=95"},
        ],
        "metrics_table": metrics,
        "direct_execution": {
            "cases": summary["total_cases"],
            "requests": summary["request_count"],
            "vulnerable_cases": summary["vulnerable_cases"],
            "non_vulnerable_cases": summary["non_vulnerable_cases"],
            "verified": summary["verified"],
            "inconclusive": summary["inconclusive"],
            "rejected": summary["rejected"],
        },
    }


def build_validation_report(evidence: dict[str, Any], xss: dict[str, Any], sqli_ranking: dict[str, Any], sqli_cls: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, details: dict[str, Any] | None = None) -> None:
        checks.append({"check": name, "passed": passed, "details": details or {}})
        if not passed:
            errors.append(name)

    check("all_source_checksums_valid", evidence["all_checksum_sources_valid"])
    check("xss_v14_negative_scenarios_30", xss["owasp_v14_negative_only"]["scenario_count"] == 30)
    check("xss_v14_unique_non_vulnerable_candidates_152", xss["non_vulnerable_candidate_coverage"]["unique_non_vulnerable_candidates"] == 152)
    check("xss_v13_1_negative_controls_8", xss["xss_v13_1_eight_controls"]["scenario_count"] == 8)
    check("sqli_ranking_arm_count_3", len(sqli_ranking["arm_table"]) == 3)
    expected_sqli = {
        "deterministic_structural": (105, 20, 91, 0.455238),
        "proprietary_gpt": (522, 99, 411, 0.444668),
        "local_qwen": (520, 75, 415, 0.427404),
    }
    for row in sqli_ranking["arm_table"]:
        exp = expected_sqli[row["arm_id"]]
        check(
            f"sqli_expected_ranking_values_{row['arm_id']}",
            row["valid_positive_observations"] == exp[0]
            and row["top1_success_count"] == exp[1]
            and row["top4_success_count"] == exp[2]
            and abs(row["mrr"] - exp[3]) < 0.000001,
            row,
        )
    cm = sqli_cls["confusion_matrix"]
    check("sqli_direct_confusion_matrix_84_0_21_95", (cm["tp"], cm["fp"], cm["fn"], cm["tn"]) == (84, 0, 21, 95), cm)
    check("zero_experimental_calls", evidence["activity_boundaries"]["new_model_calls"] == 0 and evidence["activity_boundaries"]["new_http_requests"] == 0)
    return {
        "schema_version": "professor-comment-4-validation-v1",
        "valid": not errors,
        "errors": errors,
        "checks": checks,
        "validated_at": now_utc(),
    }


def metric_row(metric: str, numerator: int, denominator: int) -> dict[str, Any]:
    return {
        "metric": metric,
        "numerator": numerator,
        "denominator": denominator,
        "value": safe_div(numerator, denominator) if denominator else "not_applicable",
    }


def render_report(evidence: dict[str, Any], xss: dict[str, Any], sqli_ranking: dict[str, Any], sqli_cls: dict[str, Any], validation: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Professor Comment 4 Closure Analysis: Negative/Control Evidence and SQLi Results",
            "",
            "This derived package synthesizes existing frozen evidence only. It performs zero model, HTTP, browser, discovery, verifier, ranking or scored experimental calls, and it does not modify frozen v1.4, v1.4.1 or v1.5.1 artifacts.",
            "",
            "## Evidence Semantics",
            "",
            "- Original OWASP XSS v1.4 negative-only evidence is ranking-only evidence. The rankers return ordered candidate IDs and do not make an abstention or vulnerability/no-vulnerability claim.",
            "- XSS verifier-backed negative/control evidence is available from the frozen v1.3.1 eight negative scenarios and from OWASP v1.4 readiness-only controls; these must not be merged with v1.4 ranking-only metrics.",
            "- SQLi v1.5.1 contains both ranking-only evidence and a separate direct deterministic runtime verifier/post-run classification layer.",
            "",
            "## XSS Negative and Control Evidence",
            "",
            render_xss_table(xss),
            "",
            "The 30 original OWASP XSS v1.4 negative-only packs exercise behavior when no candidate in the pack is vulnerable, but false-positive rate and specificity are not mathematically meaningful for those ranking-only outputs. The ranking contract requires an ordering rather than a binary finding or abstention decision.",
            "",
            "The 152 unique non-vulnerable OWASP XSS candidates contribute 944 distractor placements in positive scenarios and 150 placements in negative-only scenarios, for 1094 total non-vulnerable placements. All 152 non-vulnerable candidates are used at least once; total reuse is deterministic and balanced with counts ranging from 6 to 8 placements.",
            "",
            "The frozen v1.3.1 XSS ablation supplies the verifier-backed eight negative/control scenarios. Across retained arm/trial rows, no verifier-confirmed false positives were observed for deterministic, GPT or Qwen arms.",
            "",
            "## SQLi Ranking Evidence",
            "",
            render_sqli_ranking_table(sqli_ranking),
            "",
            sqli_ranking["interpretation"],
            "",
            "## SQLi Direct Verifier and Classification Evidence",
            "",
            render_sqli_confusion_table(sqli_cls),
            "",
            render_sqli_metrics_table(sqli_cls),
            "",
            "Runtime verifier states remain distinct from post-run classification. The direct SQLi layer produced 84 verified and 116 inconclusive outcomes; only after applying frozen ground truth did those map to TP=84, FP=0, FN=21 and TN=95.",
            "",
            "## Thesis Interpretation",
            "",
            "The thesis can present the evaluation symmetrically: XSS positive ranking effectiveness, XSS negative/control behavior, SQLi ranking effectiveness, and SQLi direct verifier/classification behavior. The evidence supports a cautious statement that the model-backed ranking benefit observed in the XSS ranking study is not universal across evaluated vulnerability categories: in SQLi, both GPT and Qwen have lower descriptive MRR than the deterministic structural ranker under the frozen valid-observation denominators. This remains a scoped descriptive conclusion, not a general model-quality or statistical-significance claim.",
            "",
            "## Claims to Avoid",
            "",
            "- Do not compute XSS v1.4 false-positive rate or specificity from ranking-only negative packs.",
            "- Do not treat repeated model trials as independent benchmark scenarios.",
            "- Do not equate SQLi runtime inconclusive outcomes with false negatives except under the frozen post-run classification mapping.",
            "- Do not claim broad superiority or inferiority of GPT, Qwen, or deterministic ranking beyond the frozen evaluation settings.",
            "",
            "## Validation",
            "",
            f"- Source checksum validation: `{'PASS' if evidence['all_checksum_sources_valid'] else 'FAIL'}`",
            f"- Derived package validation: `{'PASS' if validation['valid'] else 'FAIL'}`",
            "- New experimental calls: `0`",
            "",
        ]
    )


def render_xss_table(xss: dict[str, Any]) -> str:
    rows = ["| Evidence source | Arm | Scenarios | Rows | Valid rows | FP/specificity status |", "| --- | --- | ---: | ---: | ---: | --- |"]
    for row in xss["owasp_v14_negative_only"]["arm_rows"]:
        rows.append(
            f"| OWASP XSS v1.4 negative-only ranking | {row['arm_id']} | {row['negative_only_scenarios']} | {row['negative_ranking_rows']} | {row['contract_valid_rows']} | not applicable for ranking-only outputs |"
        )
    for row in xss["xss_v13_1_eight_controls"]["rows"]:
        rows.append(
            f"| XSS v1.3.1 eight negative controls | {row['arm_id']} | {row['negative_control_scenarios']} | {row['negative_retained_trials']} | not_applicable | FPR {fmt(row['false_positive_rate'])}; specificity {fmt(row['specificity'])} |"
        )
    return "\n".join(rows)


def render_sqli_ranking_table(sqli: dict[str, Any]) -> str:
    rows = ["| Arm | Valid positive n | Top-1 | Top-4 | MRR | Reliability |", "| --- | ---: | ---: | ---: | ---: | --- |"]
    for row in sqli["arm_table"]:
        rows.append(
            f"| {row['arm_id']} | {row['valid_positive_observations']} | {row['top1_success_count']}/{row['valid_positive_observations']} = {fmt(row['top1_rate'])} | {row['top4_success_count']}/{row['valid_positive_observations']} = {fmt(row['top4_rate'])} | {row['mrr']:.4f} | valid {row['valid_rows']}/{row['scheduled_rows']}; malformed {row['malformed_rows']}; provider-failed {row['provider_failed_rows']} |"
        )
    return "\n".join(rows)


def render_sqli_confusion_table(sqli: dict[str, Any]) -> str:
    return "\n".join(
        [
            "| Ground truth | Verified | Inconclusive | Rejected | Post-run classification |",
            "| --- | ---: | ---: | ---: | --- |",
            "| Vulnerable | 84 | 21 | 0 | TP=84, FN=21 |",
            "| Non-vulnerable | 0 | 95 | 0 | FP=0, TN=95 |",
        ]
    )


def render_sqli_metrics_table(sqli: dict[str, Any]) -> str:
    rows = ["| Metric | Numerator | Denominator | Value |", "| --- | ---: | ---: | ---: |"]
    for row in sqli["metrics_table"]:
        rows.append(f"| {row['metric']} | {row['numerator']} | {row['denominator']} | {fmt(row['value'])} |")
    return "\n".join(rows)


def render_thesis_tables(xss: dict[str, Any], sqli_ranking: dict[str, Any], sqli_cls: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Professor Comment 4 Thesis-Ready Tables",
            "## XSS Negative/Control Evidence",
            render_xss_table(xss),
            "## SQLi Ranking Results",
            render_sqli_ranking_table(sqli_ranking),
            "## SQLi Direct Classification",
            render_sqli_confusion_table(sqli_cls),
            "## SQLi Classification Metrics",
            render_sqli_metrics_table(sqli_cls),
        ]
    ) + "\n"


def render_thesis_tables_tex(xss: dict[str, Any], sqli_ranking: dict[str, Any], sqli_cls: dict[str, Any]) -> str:
    lines = [
        "% Professor Comment 4 thesis-ready tables.",
        "% Derived from frozen v1.4 XSS, v1.3.1 XSS control and v1.5.1 SQLi evidence.",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{SQL injection ranking results in the frozen v1.5.1 evaluation}",
        "\\begin{tabular}{lrrrr}",
        "\\hline",
        "Arm & Valid positive $n$ & Top-1 & Top-4 & MRR \\\\",
        "\\hline",
    ]
    labels = {
        "deterministic_structural": "Deterministic",
        "proprietary_gpt": "GPT",
        "local_qwen": "Qwen",
    }
    for row in sqli_ranking["arm_table"]:
        lines.append(
            f"{labels[row['arm_id']]} & {row['valid_positive_observations']} & {pct(row['top1_rate'])} & {pct(row['top4_rate'])} & {row['mrr']:.4f} \\\\"
        )
    lines += [
        "\\hline",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Direct SQL injection verifier outcomes and post-run classification}",
        "\\begin{tabular}{lrrrr}",
        "\\hline",
        "Ground truth & Verified & Inconclusive & Rejected & Classification \\\\",
        "\\hline",
        "Vulnerable & 84 & 21 & 0 & TP=84, FN=21 \\\\",
        "Non-vulnerable & 0 & 95 & 0 & FP=0, TN=95 \\\\",
        "\\hline",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Direct SQL injection classification metrics}",
        "\\begin{tabular}{lrrr}",
        "\\hline",
        "Metric & Numerator & Denominator & Value \\\\",
        "\\hline",
    ]
    for row in sqli_cls["metrics_table"]:
        lines.append(f"{row['metric'].replace('_', ' ')} & {row['numerator']} & {row['denominator']} & {fmt(row['value'])} \\\\")
    lines += ["\\hline", "\\end{tabular}", "\\end{table}", ""]
    return "\n".join(lines)


def render_methodology_note(evidence: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance Note",
            "",
            "This package is a derived evidence synthesis for Professor Comment 4. It reads existing frozen/canonical packages and readiness artifacts only.",
            "",
            "Ground truth is used only where the source package already defines post-run scoring or readiness validation. The v1.4 OWASP XSS negative-only ranking scenarios are not reinterpreted as binary vulnerability-classification evidence.",
            "",
            "Source packages checked:",
            *[f"- `{source['path']}`: {source['evidence_type']}; checksum valid = `{source['checksum_validation']['valid']}`" for source in evidence["sources"]],
            "",
            "No new experimental execution was performed: model calls, HTTP requests, browser tests, discovery, ranking calls and verifier calls are all zero.",
            "",
        ]
    )


def build_manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "professor-comment-4-negative-sqli-analysis-manifest-v1",
        "created_at": now_utc(),
        "package_dir": display_path(OUTPUT_DIR),
        "source_artifacts": [
            display_path(XSS14_CANONICAL),
            display_path(XSS14_RANDOM_AUDIT),
            display_path(XSS14_STABILITY),
            display_path(XSS14_READINESS),
            display_path(XSS13_CANONICAL),
            display_path(SQLI_CANONICAL),
        ],
        "validation_valid": validation["valid"],
        "experimental_calls_executed": 0,
        "generated_files": sorted(display_path(path) for path in OUTPUT_DIR.rglob("*") if path.is_file()),
    }


def validate_sha256_package(package_dir: Path) -> dict[str, Any]:
    checksum_path = package_dir / "checksums.sha256"
    errors = validate_sha256_file(checksum_path, package_dir) if checksum_path.exists() else [f"missing {display_path(checksum_path)}"]
    return {
        "valid": checksum_path.exists() and not errors,
        "errors": errors,
        "checked_file": display_path(checksum_path),
    }


def validate_sha256_file(checksum_path: Path, base_dir: Path) -> list[str]:
    errors: list[str] = []
    if not checksum_path.exists():
        return [f"missing checksum file {display_path(checksum_path)}"]
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split(maxsplit=1)
        target = base_dir / rel.strip()
        if not target.exists():
            repo_relative = REPO_ROOT / rel.strip()
            if repo_relative.exists():
                target = repo_relative
        if not target.exists():
            errors.append(f"missing {rel}")
            continue
        actual = sha256(target)
        if actual != expected:
            errors.append(f"hash mismatch {rel}")
    return errors


def validate_json_checksum_package(checksum_path: Path, base_dir: Path) -> dict[str, Any]:
    errors: list[str] = []
    if not checksum_path.exists():
        return {"valid": False, "errors": [f"missing {display_path(checksum_path)}"], "checked_file": display_path(checksum_path)}
    checksums = load_json(checksum_path)
    for rel, expected in checksums.items():
        target = base_dir / rel
        if not target.exists():
            errors.append(f"missing {rel}")
            continue
        if sha256(target) != expected:
            errors.append(f"hash mismatch {rel}")
    return {"valid": not errors, "errors": errors, "checked_file": display_path(checksum_path)}


def validate_sha256_selected(checksum_path: Path, base_dir: Path, selected_relative_paths: list[str]) -> dict[str, Any]:
    if not checksum_path.exists():
        return {"valid": False, "errors": [f"missing {display_path(checksum_path)}"], "checked_file": display_path(checksum_path)}
    ledger: dict[str, str] = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split(maxsplit=1)
        ledger[rel.strip().replace("\\", "/")] = expected
    errors: list[str] = []
    for selected in selected_relative_paths:
        selected_norm = selected.replace("\\", "/")
        target = base_dir / selected_norm
        repo_rel = display_path(target)
        expected = ledger.get(selected_norm) or ledger.get(repo_rel)
        if expected is None:
            errors.append(f"missing checksum entry {selected_norm}")
            continue
        if not target.exists():
            errors.append(f"missing {selected_norm}")
            continue
        actual = sha256(target)
        if actual != expected:
            errors.append(f"hash mismatch {selected_norm}")
    return {
        "valid": not errors,
        "errors": errors,
        "checked_file": display_path(checksum_path),
        "selected_files": selected_relative_paths,
    }


def render_checksums(directory: Path) -> str:
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "checksums.sha256"):
        lines.append(f"{sha256(path)}  {path.relative_to(directory).as_posix()}")
    return "\n".join(lines) + "\n"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def safe_div(numerator: int | float, denominator: int | float) -> float:
    return numerator / denominator if denominator else 0.0


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def pct(value: float) -> str:
    return f"{value * 100:.2f}\\%"


def now_utc() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def display_path(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


if __name__ == "__main__":
    main()
