from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "results" / "professor-comment-5-bespoke-contamination-analysis"

BESPOKE_CANONICAL = REPO_ROOT / "results" / "xss-v13-ablation-v1.3.1-final" / "canonical"
BESPOKE_PROTOCOL_PREP = REPO_ROOT / "results" / "xss-v13-protocol-prep"
BESPOKE_STRUCTURAL = REPO_ROOT / "results" / "xss-v13-structural-validation"
BESPOKE_GROUND_TRUTH = REPO_ROOT / "examples" / "benchmarks" / "xss-v13-ground-truth.json"
OWASP_CANONICAL = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
LOCAL_PROVISIONING = REPO_ROOT / "results" / "local-runtime-provisioning-v1.3"
LOCAL_OUTPUT_BOUNDARY = REPO_ROOT / "results" / "local-runtime-output-boundary-v1.3"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    evidence = build_evidence_inventory()
    scenario_structure = build_bespoke_scenario_structure()
    random_by_scenario, random_summary = build_random_references(scenario_structure)
    bespoke_ranking = build_bespoke_ranking_summary(scenario_structure, random_summary)
    metric_reconciliation = build_metric_reconciliation(bespoke_ranking, random_summary)
    comparison = build_owasp_vs_bespoke_comparison(bespoke_ranking, random_summary)
    reproducibility = build_reproducibility_summary()
    validation = build_validation_report(evidence, scenario_structure, random_summary, bespoke_ranking)

    write_json(OUTPUT_DIR / "evidence-inventory.json", evidence)
    write_csv(OUTPUT_DIR / "bespoke-scenario-structure.csv", scenario_structure)
    write_csv(OUTPUT_DIR / "bespoke-random-baseline-by-scenario.csv", random_by_scenario)
    write_json(OUTPUT_DIR / "bespoke-random-baseline-summary.json", random_summary)
    write_json(OUTPUT_DIR / "bespoke-ranking-summary.json", bespoke_ranking)
    write_json(OUTPUT_DIR / "bespoke-metric-reconciliation.json", metric_reconciliation)
    write_csv(OUTPUT_DIR / "owasp-vs-bespoke-comparison.csv", comparison)
    write_text(OUTPUT_DIR / "contamination-risk-note.md", render_contamination_note())
    write_json(OUTPUT_DIR / "reproducibility-summary.json", reproducibility)
    write_text(OUTPUT_DIR / "thesis-ready-tables.md", render_thesis_tables(random_summary, bespoke_ranking, comparison))
    write_text(OUTPUT_DIR / "thesis-ready-tables.tex", render_thesis_tables_tex(random_summary, bespoke_ranking, comparison))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(evidence, validation))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", build_manifest(validation))
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(evidence, scenario_structure, random_summary, bespoke_ranking, comparison, reproducibility, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "professor-comment-5-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    final_checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    if not validation["valid"]:
        raise SystemExit("validation failed: " + "; ".join(validation["errors"]))
    if final_checksum_errors:
        raise SystemExit("checksum validation failed: " + "; ".join(final_checksum_errors))
    print(f"package: {display_path(OUTPUT_DIR)}")
    print(f"validation: {validation['valid']}")
    print(f"checksum_errors: {len(final_checksum_errors)}")
    print("zero_experimental_calls: true")


def build_evidence_inventory() -> dict[str, Any]:
    sources = [
        source_entry(
            "bespoke_v13_1_canonical",
            BESPOKE_CANONICAL,
            "final canonical 24-scenario bespoke held-out XSS v1.3.1 package",
            validate_sha256_selected(
                BESPOKE_CANONICAL / "checksums.sha256",
                BESPOKE_CANONICAL,
                [
                    "manifest.json",
                    "normalized/arm-level-metrics.csv",
                    "normalized/arm-level-metrics.json",
                    "normalized/ranked-candidates.csv",
                    "normalized/ranking-trials.csv",
                    "normalized/reliability-summary.json",
                    "normalized/provider-metrics.json",
                    "validation-report.json",
                ],
            ),
            "runtime verifier and post-run ranking/classification evidence",
            extra={
                "full_package_checksum_validation": validate_sha256_package(BESPOKE_CANONICAL),
                "full_package_note": "The selected numerical inputs validate; the legacy v1.3.1 package has known presentation-artifact checksum mismatches unrelated to this analysis.",
            },
        ),
        source_entry(
            "bespoke_v13_protocol_prep",
            BESPOKE_PROTOCOL_PREP,
            "frozen v1.3 candidate snapshots and arm-input ledger",
            validate_sha256_package(BESPOKE_PROTOCOL_PREP),
            "ground-truth-free candidate snapshot provenance",
        ),
        source_entry(
            "bespoke_v13_structural_validation",
            BESPOKE_STRUCTURAL,
            "v1.3 structural validation package, including benchmark manifest and ground truth checksum coverage",
            validate_sha256_package(BESPOKE_STRUCTURAL),
            "scenario-design and ground-truth provenance",
        ),
        source_entry(
            "owasp_xss_v14_canonical",
            OWASP_CANONICAL,
            "public OWASP Benchmark v1.2 XSS v1.4 canonical ranking package",
            validate_sha256_package(OWASP_CANONICAL),
            "public-benchmark ranking evidence",
        ),
        source_entry(
            "local_runtime_provisioning",
            LOCAL_PROVISIONING,
            "local model artifact and runtime provisioning metadata",
            validate_sha256_selected(
                LOCAL_PROVISIONING / "checksums.sha256",
                LOCAL_PROVISIONING,
                [
                    "hardware-report.json",
                    "model-metadata/qwen2_5_7b_instruct_gguf_q4_k_m.json",
                    "runtime-metadata.json",
                ],
            ),
            "Qwen reproducibility metadata",
            extra={
                "full_package_checksum_validation": validate_sha256_package(LOCAL_PROVISIONING),
                "full_package_note": "The selected reproducibility metadata validate; the retained provisioning package has a legacy ledger checksum mismatch that is disclosed but not used for numerical findings.",
            },
        ),
        source_entry(
            "local_runtime_output_boundary",
            LOCAL_OUTPUT_BOUNDARY,
            "local llama.cpp output-boundary/readiness metadata",
            validate_sha256_package(LOCAL_OUTPUT_BOUNDARY),
            "Qwen execution transport metadata",
        ),
    ]
    return {
        "schema_version": "professor-comment-5-evidence-inventory-v1",
        "created_at": now_utc(),
        "authoritative_bespoke_package": display_path(BESPOKE_CANONICAL),
        "authoritative_bespoke_protocol": "evaluation-protocol-v1.3.1",
        "authoritative_bespoke_tag": "evaluation-protocol-v1.3.1",
        "sources": sources,
        "all_required_sources_valid": all(source["checksum_validation"]["valid"] for source in sources),
        "activity_boundaries": {
            "new_model_calls": 0,
            "new_http_requests": 0,
            "new_browser_tests": 0,
            "new_discovery_calls": 0,
            "new_verifier_calls": 0,
            "new_scored_experiments": 0,
            "ground_truth_use": "post-run derived analysis only",
        },
    }


def source_entry(id_: str, path: Path, role: str, checksum_validation: dict[str, Any], evidence_type: str, extra: dict[str, Any] | None = None) -> dict[str, Any]:
    entry = {
        "id": id_,
        "path": display_path(path),
        "role": role,
        "evidence_type": evidence_type,
        "checksum_validation": checksum_validation,
    }
    if extra:
        entry.update(extra)
    return entry


def build_bespoke_scenario_structure() -> list[dict[str, Any]]:
    gt = load_json(BESPOKE_GROUND_TRUTH)
    snapshots = {item["scenario_id"]: load_json(BESPOKE_PROTOCOL_PREP / item["snapshot_path"]) for item in load_json(BESPOKE_PROTOCOL_PREP / "candidate-snapshot-index.json")["snapshots"]}
    gt_by_scenario = {scenario["scenario_id"]: scenario for scenario in gt["scenarios"]}
    rows: list[dict[str, Any]] = []
    for scenario_id in sorted(snapshots):
        snapshot = snapshots[scenario_id]
        scenario_gt = gt_by_scenario[scenario_id]
        candidates = snapshot["candidate_input"]
        vulnerable_ids = []
        for candidate in candidates:
            case = find_gt_case(scenario_gt, candidate)
            if case and case["vulnerable"]:
                vulnerable_ids.append(candidate["candidate_id"])
        candidate_count = len(candidates)
        vulnerable_count = len(vulnerable_ids)
        rows.append(
            {
                "scenario_id": scenario_id,
                "candidate_count": candidate_count,
                "vulnerable_candidate_count": vulnerable_count,
                "scenario_type": "positive" if vulnerable_count > 0 else "negative",
                "ranking_budget_k": snapshot["test_budget"],
                "top1_meaningful": vulnerable_count == 1,
                "top2_meaningful": vulnerable_count == 1,
                "top4_meaningful": vulnerable_count == 1,
                "top4_automatic_under_random": vulnerable_count == 1 and min(snapshot["top_k"], candidate_count) >= candidate_count,
                "snapshot_path": display_path(BESPOKE_PROTOCOL_PREP / snapshot["scenario_id"].join(["candidate-snapshots/", ".json"])) if False else display_path(BESPOKE_PROTOCOL_PREP / "candidate-snapshots" / f"{scenario_id}.json"),
                "snapshot_candidate_ids_sha256": sha256_text("\n".join(candidate["candidate_id"] for candidate in candidates)),
                "ground_truth_source": display_path(BESPOKE_GROUND_TRUTH),
            }
        )
    return rows


def find_gt_case(scenario_gt: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any] | None:
    for case in scenario_gt["cases"]:
        if case["action_path"] == candidate["action_path"] and case["parameter_name"] == candidate["parameter_name"]:
            return case
    return None


def build_random_references(scenarios: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows = []
    strata: dict[int, list[dict[str, float]]] = defaultdict(list)
    eligible = []
    for scenario in scenarios:
        if scenario["scenario_type"] != "positive" or scenario["vulnerable_candidate_count"] != 1:
            rows.append(
                {
                    "scenario_id": scenario["scenario_id"],
                    "candidate_count": scenario["candidate_count"],
                    "eligible_for_one_vulnerable_random_reference": False,
                    "random_top1": "not_applicable",
                    "random_top2": "not_applicable",
                    "random_top4": "not_applicable",
                    "random_mrr": "not_applicable",
                    "diagnostic_full_order_random_mrr": "not_applicable",
                }
            )
            continue
        n = scenario["candidate_count"]
        top_k = min(4, n)
        values = {
            "top1": 1 / n,
            "top2": min(2 / n, 1.0),
            "top4": min(4 / n, 1.0),
            "mrr": sum(1 / rank for rank in range(1, top_k + 1)) / n,
            "full_order_mrr": sum(1 / rank for rank in range(1, n + 1)) / n,
        }
        rows.append(
            {
                "scenario_id": scenario["scenario_id"],
                "candidate_count": n,
                "eligible_for_one_vulnerable_random_reference": True,
                "random_top1": values["top1"],
                "random_top2": values["top2"],
                "random_top4": values["top4"],
                "random_mrr": values["mrr"],
                "diagnostic_full_order_random_mrr": values["full_order_mrr"],
            }
        )
        eligible.append(values)
        strata[n].append(values)
    summary = {
        "schema_version": "professor-comment-5-bespoke-random-baseline-summary-v2",
        "scenario_averaging": "each eligible positive scenario receives equal weight",
        "mrr_semantics": "budget-censored random MRR matching v1.3.1 canonical MRR: (1/n) * sum(1/r for r=1..min(4,n))",
        "diagnostic_full_order_mrr_semantics": "non-thesis-facing full-order random MRR retained only for reconciliation provenance",
        "eligible_positive_scenarios": len(eligible),
        "negative_scenarios": sum(1 for scenario in scenarios if scenario["scenario_type"] == "negative"),
        "candidate_count_distribution_all": dict(sorted(Counter(s["candidate_count"] for s in scenarios).items())),
        "candidate_count_distribution_positive": dict(sorted(Counter(s["candidate_count"] for s in scenarios if s["scenario_type"] == "positive").items())),
        "overall": average_metrics(eligible),
        "diagnostic_full_order_overall_mrr": mean([item["full_order_mrr"] for item in eligible]),
        "by_candidate_count": {
            str(n): {
                "scenario_count": len(values),
                **average_metrics(values),
                "diagnostic_full_order_mrr": mean([item["full_order_mrr"] for item in values]),
            }
            for n, values in sorted(strata.items())
        },
        "top4_candidate_count_gt4_subset": {
            "scenario_count": sum(len(v) for n, v in strata.items() if n > 4),
            "random_top4": mean([item["top4"] for n, v in strata.items() if n > 4 for item in v]),
            "note": "Scenarios with candidate_count=4 have random Top-4 = 1.0000 by definition under budget k=4 and are isolated from this subset.",
        },
    }
    return rows, summary


def build_bespoke_ranking_summary(scenarios: list[dict[str, Any]], random_summary: dict[str, Any]) -> dict[str, Any]:
    ranked = load_csv(BESPOKE_CANONICAL / "normalized" / "ranked-candidates.csv")
    ranking_trials = load_csv(BESPOKE_CANONICAL / "normalized" / "ranking-trials.csv")
    canonical_valid_metrics = {
        row["arm_id"]: row
        for row in load_json(BESPOKE_CANONICAL / "normalized" / "arm-level-metrics.json")["rows"]
        if row["aggregate_scope"] == "valid_rankings_only"
    }
    reliability = {row["arm_id"]: row for row in load_json(BESPOKE_CANONICAL / "normalized" / "reliability-summary.json")["rows"]}
    provider_metrics = {row["arm_id"]: row for row in load_json(BESPOKE_CANONICAL / "normalized" / "provider-metrics.json")["rows"]}
    candidate_to_vulnerable = build_bespoke_candidate_vulnerability_map()
    scenario_by_id = {row["scenario_id"]: row for row in scenarios}
    positive_ids = {row["scenario_id"] for row in scenarios if row["scenario_type"] == "positive" and row["vulnerable_candidate_count"] == 1}
    vulnerable_ranks_by_trial: dict[tuple[str, str, int], list[int]] = defaultdict(list)
    for row in ranked:
        if not parse_bool(row["valid_trial"]):
            continue
        if candidate_to_vulnerable.get((row["scenario_id"], row["candidate_id"])) is True:
            vulnerable_ranks_by_trial[(row["arm_id"], row["scenario_id"], int(row["trial_number"]))].append(int(row["rank"]))
    trial_metrics: list[dict[str, Any]] = []
    for trial_row in ranking_trials:
        arm = trial_row["arm_id"]
        scenario_id = trial_row["scenario_id"]
        trial = int(trial_row["trial_number"])
        if scenario_id not in positive_ids:
            continue
        if not parse_bool(trial_row["valid_ranking"]):
            continue
        vulnerable_ranks = sorted(vulnerable_ranks_by_trial.get((arm, scenario_id, trial), []))
        rank = vulnerable_ranks[0] if len(vulnerable_ranks) == 1 else None
        n = scenario_by_id[scenario_id]["candidate_count"]
        top_k = min(4, n)
        budget_visible_rank = rank if rank is not None and rank <= top_k else None
        trial_metrics.append(
            {
                "arm_id": arm,
                "scenario_id": scenario_id,
                "trial_number": trial,
                "candidate_count": n,
                "vulnerable_rank": budget_visible_rank,
                "full_order_vulnerable_rank": rank,
                "top1": 1.0 if rank is not None and rank <= 1 else 0.0,
                "top2": 1.0 if rank is not None and rank <= 2 else 0.0,
                "top4": 1.0 if budget_visible_rank is not None else 0.0,
                "mrr": 1.0 / budget_visible_rank if budget_visible_rank is not None else 0.0,
                "full_order_mrr": 1.0 / rank if rank is not None else 0.0,
            }
        )
    summary_rows = []
    subset_rows = []
    scenario_mean_rows = []
    for arm in ["deterministic_structural", "proprietary_gpt", "local_qwen"]:
        arm_trials = [row for row in trial_metrics if row["arm_id"] == arm]
        scenario_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in arm_trials:
            scenario_groups[row["scenario_id"]].append(row)
        scenario_means = []
        for scenario_id, items in scenario_groups.items():
            scenario_means.append(
                {
                    "arm_id": arm,
                    "scenario_id": scenario_id,
                    "candidate_count": scenario_by_id[scenario_id]["candidate_count"],
                    "valid_trials": len(items),
                    "top1": mean([item["top1"] for item in items]),
                    "top2": mean([item["top2"] for item in items]),
                    "top4": mean([item["top4"] for item in items]),
                    "mrr": mean([item["mrr"] for item in items]),
                    "full_order_mrr": mean([item["full_order_mrr"] for item in items]),
                }
            )
        scenario_mean_rows.extend(scenario_means)
        scenario_level = average_metrics(scenario_means)
        trial_level = average_metrics(arm_trials)
        scenario_level_full_order_mrr = mean([row["full_order_mrr"] for row in scenario_means])
        trial_level_full_order_mrr = mean([row["full_order_mrr"] for row in arm_trials])
        random_overall = random_summary["overall"]
        summary_rows.append(
            {
                "arm_id": arm,
                "canonical_valid_row_metrics": canonical_valid_metrics[arm],
                "positive_scenarios_with_valid_ranking": len(scenario_means),
                "valid_positive_trial_rows": len(arm_trials),
                "expected_positive_trial_rows": 16 if arm == "deterministic_structural" else 80,
                "scenario_mean_top1": scenario_level["top1"],
                "scenario_mean_top2": scenario_level["top2"],
                "scenario_mean_top4": scenario_level["top4"],
                "scenario_mean_mrr": scenario_level["mrr"],
                "trial_row_top1": trial_level["top1"],
                "trial_row_top2": trial_level["top2"],
                "trial_row_top4": trial_level["top4"],
                "trial_row_mrr": trial_level["mrr"],
                "scenario_mean_full_order_mrr": scenario_level_full_order_mrr,
                "trial_row_full_order_mrr": trial_level_full_order_mrr,
                "random_top1": random_overall["top1"],
                "observed_minus_random_top1": scenario_level["top1"] - random_overall["top1"],
                "random_top2": random_overall["top2"],
                "observed_minus_random_top2": scenario_level["top2"] - random_overall["top2"],
                "random_top4": random_overall["top4"],
                "observed_minus_random_top4": scenario_level["top4"] - random_overall["top4"],
                "random_mrr": random_overall["mrr"],
                "observed_minus_random_mrr": scenario_level["mrr"] - random_overall["mrr"],
                "observed_minus_random_full_order_mrr": scenario_level_full_order_mrr - random_summary["diagnostic_full_order_overall_mrr"],
                "rank_distribution": dict(sorted(Counter(str(item["vulnerable_rank"]) if item["vulnerable_rank"] is not None else "missing" for item in arm_trials).items())),
                "full_order_rank_distribution": dict(sorted(Counter(str(item["full_order_vulnerable_rank"]) if item["full_order_vulnerable_rank"] is not None else "missing" for item in arm_trials).items())),
                "reliability": reliability[arm],
                "provider_metrics": provider_metrics[arm],
            }
        )
        gt4_means = [row for row in scenario_means if row["candidate_count"] > 4]
        gt4_average = average_metrics(gt4_means)
        subset_rows.append(
            {
                "arm_id": arm,
                "candidate_count_subset": ">4",
                "positive_scenarios_with_valid_ranking": len(gt4_means),
                "observed_top4": gt4_average["top4"],
                "random_top4": random_summary["top4_candidate_count_gt4_subset"]["random_top4"],
                "observed_minus_random_top4": gt4_average["top4"] - random_summary["top4_candidate_count_gt4_subset"]["random_top4"],
            }
        )
    return {
        "schema_version": "professor-comment-5-bespoke-ranking-summary-v2",
        "mrr_semantics": "Budget-censored MRR: reciprocal-rank credit is assigned only when the vulnerable candidate is within top_k = min(test_budget, candidate_count); otherwise reciprocal rank is 0. Full-order MRR is retained only as diagnostic provenance.",
        "scenario_level_metrics": summary_rows,
        "top4_candidate_count_gt4_subset": subset_rows,
        "scenario_mean_rows": scenario_mean_rows,
        "reliability_summary": reliability,
        "provider_metrics": provider_metrics,
        "ranking_trials_checked": len(ranking_trials),
        "ranking_and_verifier_evidence_separate": True,
        "trial_interpretation": "Repeated GPT/Qwen trials are retained as trial-level variability evidence; scenario remains the independent benchmark unit.",
    }


def build_bespoke_candidate_vulnerability_map() -> dict[tuple[str, str], bool]:
    gt = load_json(BESPOKE_GROUND_TRUTH)
    snapshots = {item["scenario_id"]: load_json(BESPOKE_PROTOCOL_PREP / item["snapshot_path"]) for item in load_json(BESPOKE_PROTOCOL_PREP / "candidate-snapshot-index.json")["snapshots"]}
    gt_by_scenario = {scenario["scenario_id"]: scenario for scenario in gt["scenarios"]}
    result = {}
    for scenario_id, snapshot in snapshots.items():
        scenario_gt = gt_by_scenario[scenario_id]
        for candidate in snapshot["candidate_input"]:
            case = find_gt_case(scenario_gt, candidate)
            result[(scenario_id, candidate["candidate_id"])] = bool(case and case["vulnerable"])
    return result


def build_metric_reconciliation(bespoke: dict[str, Any], random_summary: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for row in bespoke["scenario_level_metrics"]:
        canonical = row["canonical_valid_row_metrics"]
        rows.append(
            {
                "arm_id": row["arm_id"],
                "canonical_valid_trial_row": {
                    "formula": "mean over valid positive ranking rows of reciprocal_rank, with reciprocal_rank = 1/rank only when the vulnerable candidate is within top_k; otherwise 0",
                    "positive_trial_row_denominator": canonical["vulnerable_ranking_rows"],
                    "top1": canonical["top1_accuracy"],
                    "top4": canonical["topk_recall"],
                    "mrr": canonical["mrr"],
                },
                "random_reference": {
                    "budget_censored_mrr": row["random_mrr"],
                    "diagnostic_full_order_mrr": random_summary["diagnostic_full_order_overall_mrr"],
                },
                "derived_equal_weight_scenario_budget_censored": {
                    "formula": "mean over positive scenarios of the mean valid-trial Top-k and budget-censored reciprocal rank for that scenario",
                    "positive_scenario_denominator": row["positive_scenarios_with_valid_ranking"],
                    "valid_positive_trial_rows": row["valid_positive_trial_rows"],
                    "top1": row["scenario_mean_top1"],
                    "top2": row["scenario_mean_top2"],
                    "top4": row["scenario_mean_top4"],
                    "mrr": row["scenario_mean_mrr"],
                },
                "diagnostic_full_order_not_thesis_metric": {
                    "formula": "mean reciprocal rank over the full returned candidate ordering, including vulnerable-candidate ranks below top_k; retained only to explain the earlier derived-report discrepancy",
                    "scenario_mean_full_order_mrr": row["scenario_mean_full_order_mrr"],
                    "trial_row_full_order_mrr": row["trial_row_full_order_mrr"],
                },
            }
        )
    return {
        "schema_version": "professor-comment-5-bespoke-metric-reconciliation-v1",
        "authoritative_canonical_metric_source": display_path(BESPOKE_CANONICAL / "normalized" / "arm-level-metrics.json"),
        "decision": "Canonical valid-row metrics remain authoritative. Derived scenario-level metrics are retained only when explicitly labelled and use the same budget-censored reciprocal-rank semantics.",
        "rows": rows,
    }


def build_owasp_vs_bespoke_comparison(bespoke: dict[str, Any], random_summary: dict[str, Any]) -> list[dict[str, Any]]:
    owasp_rows = load_csv(OWASP_CANONICAL / "normalized" / "scored-rows.csv")
    output: list[dict[str, Any]] = []
    owasp_random = {"top1": 0.2, "top2": 0.4, "top4": 0.8, "mrr": 0.4566666667}
    for arm in ["deterministic_structural", "proprietary_gpt", "local_qwen"]:
        rows = [
            row for row in owasp_rows
            if row["arm_id"] == arm and row["scenario_type"] == "positive" and parse_bool(row["contract_valid"])
        ]
        values = {
            "top1": mean([1.0 if parse_bool(row["top1"]) else 0.0 for row in rows]),
            "top2": mean([1.0 if int(row["vulnerable_rank"]) <= 2 else 0.0 for row in rows]),
            "top4": mean([1.0 if parse_bool(row["topk"]) else 0.0 for row in rows]),
            "mrr": mean([float(row["reciprocal_rank"]) for row in rows]),
        }
        output.append(
            comparison_row(
                "public_owasp_xss_v14",
                arm,
                "fixed_5",
                len({row["scenario_id"] for row in rows}),
                len(rows),
                "valid_trial_row_mean",
                "full_order_reciprocal_rank",
                values,
                owasp_random,
            )
        )
    for row in bespoke["scenario_level_metrics"]:
        values = {
            "top1": row["scenario_mean_top1"],
            "top2": row["scenario_mean_top2"],
            "top4": row["scenario_mean_top4"],
            "mrr": row["scenario_mean_mrr"],
        }
        random_values = random_summary["overall"]
        output.append(
            comparison_row(
                "bespoke_xss_v13_1_heldout",
                row["arm_id"],
                str(random_summary["candidate_count_distribution_all"]),
                row["positive_scenarios_with_valid_ranking"],
                row["valid_positive_trial_rows"],
                "equal_weight_scenario_mean",
                "budget_censored_reciprocal_rank",
                values,
                random_values,
            )
        )
    return output


def comparison_row(
    dataset: str,
    arm: str,
    candidate_count: str,
    positive_scenarios: int,
    valid_positive_ranking_rows: int,
    metric_aggregation: str,
    mrr_semantics: str,
    values: dict[str, float],
    random_values: dict[str, float],
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "dataset": dataset,
        "arm_id": arm,
        "candidate_count": candidate_count,
        "positive_scenarios": positive_scenarios,
        "valid_positive_ranking_rows": valid_positive_ranking_rows,
        "metric_aggregation": metric_aggregation,
        "mrr_semantics": mrr_semantics,
    }
    for metric in ["top1", "top2", "top4", "mrr"]:
        row[f"observed_{metric}"] = values[metric]
        row[f"random_{metric}"] = random_values[metric]
        row[f"observed_minus_random_{metric}"] = values[metric] - random_values[metric]
    return row


def build_reproducibility_summary() -> dict[str, Any]:
    qwen_model = load_json(LOCAL_PROVISIONING / "model-metadata" / "qwen2_5_7b_instruct_gguf_q4_k_m.json")
    runtime = load_json(LOCAL_PROVISIONING / "runtime-metadata.json")
    output_boundary = load_json(LOCAL_OUTPUT_BOUNDARY / "transport-settings.json")
    hardware = load_json(LOCAL_PROVISIONING / "hardware-report.json")
    provider_rows = load_json(BESPOKE_CANONICAL / "normalized" / "provider-metrics.json")["rows"]
    gpt = next(row for row in provider_rows if row["arm_id"] == "proprietary_gpt")
    qwen = next(row for row in provider_rows if row["arm_id"] == "local_qwen")
    return {
        "schema_version": "professor-comment-5-reproducibility-summary-v1",
        "gpt": {
            "model_identifier": gpt["model_identifier"],
            "provider": gpt["provider"],
            "prompt_version": "llm-candidate-ranking-v1",
            "temperature": "omitted/provider default",
            "cost_availability": gpt["cost_availability"],
            "note": "Historical frozen provider metadata only; no current provider configuration is introduced.",
        },
        "qwen": {
            "model": qwen_model["display_name"],
            "repository": qwen_model["repository"],
            "revision": qwen_model["revision"],
            "quantization": qwen_model["quantization"],
            "license": qwen_model["license"],
            "files": qwen_model["files"],
            "runtime": runtime["runtime_id"],
            "runtime_release": runtime["release_tag"],
            "runtime_executable_sha256": runtime["executable_sha256"],
            "backend": runtime["backend"],
            "transport_settings_version": output_boundary["transport_settings_version"],
            "transport_parser_rule_version": output_boundary["transport_parser_rule_version"],
            "json_schema_version": output_boundary["json_schema_version"],
            "context_size_tokens": output_boundary["context_size_tokens"],
            "max_output_tokens": output_boundary["max_output_tokens"],
            "temperature": output_boundary["temperature"],
            "top_p": output_boundary["top_p"],
            "seed": output_boundary["seed"],
            "threads": output_boundary["threads"],
            "timeout_seconds": output_boundary["timeout_seconds"],
            "hardware": hardware,
            "observed_latency_ms_mean": qwen["latency_ms_mean"],
            "observed_latency_ms_median": qwen["latency_ms_median"],
            "latency_interpretation": "Observed under the recorded CPU-only local runtime and hardware configuration; not an inherent property of local inference in general.",
        },
    }


def build_validation_report(evidence: dict[str, Any], scenarios: list[dict[str, Any]], random_summary: dict[str, Any], bespoke: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, details: dict[str, Any] | None = None) -> None:
        checks.append({"check": name, "passed": passed, "details": details or {}})
        if not passed:
            errors.append(name)

    check("required_source_integrity_valid", evidence["all_required_sources_valid"])
    check("authoritative_bespoke_scenario_count_24", len(scenarios) == 24)
    check("bespoke_positive_negative_16_8", (sum(s["scenario_type"] == "positive" for s in scenarios), sum(s["scenario_type"] == "negative" for s in scenarios)) == (16, 8))
    check("candidate_counts_between_4_and_8", all(4 <= int(s["candidate_count"]) <= 8 for s in scenarios), {"distribution": random_summary["candidate_count_distribution_all"]})
    check("all_positive_scenarios_have_one_vulnerable_candidate", all(s["vulnerable_candidate_count"] == 1 for s in scenarios if s["scenario_type"] == "positive"))
    manifest = load_json(BESPOKE_CANONICAL / "manifest.json")
    ranking_trials = load_csv(BESPOKE_CANONICAL / "normalized" / "ranking-trials.csv")
    expected_by_arm = {
        arm: count
        for arm, count in manifest["ranking_denominators"].items()
        if arm != "total"
    }
    actual_by_arm = Counter(row["arm_id"] for row in ranking_trials)
    check(
        "expected_bespoke_ranking_rows_264",
        manifest["ranking_denominators"]["total"] == 264
        and len(ranking_trials) == 264
        and all(actual_by_arm[arm] == int(expected) for arm, expected in expected_by_arm.items()),
        {
            "manifest_total": manifest["ranking_denominators"]["total"],
            "actual_total": len(ranking_trials),
            "manifest_by_arm": expected_by_arm,
            "actual_by_arm": dict(actual_by_arm),
        },
    )
    protocol_prep_manifest = load_json(BESPOKE_PROTOCOL_PREP / "manifest.json")
    check(
        "calibration_development_exclusion_recorded",
        protocol_prep_manifest["scenario_count"] == 24
        and protocol_prep_manifest["artifact_status"] == "dry_validation_only_no_scored_trials_no_vulnerability_testing"
        and load_json(BESPOKE_CANONICAL / "manifest.json")["scenario_count"] == 24,
        {
            "protocol_prep_scenario_count": protocol_prep_manifest["scenario_count"],
            "canonical_scenario_count": load_json(BESPOKE_CANONICAL / "manifest.json")["scenario_count"],
            "artifact_status": protocol_prep_manifest["artifact_status"],
        },
    )
    check("rank_verifier_separation_recorded", bespoke["ranking_and_verifier_evidence_separate"])
    for row in bespoke["scenario_level_metrics"]:
        canonical = row["canonical_valid_row_metrics"]
        if row["arm_id"] in {"deterministic_structural", "local_qwen"}:
            check(
                f"{row['arm_id']}_scenario_mrr_matches_canonical_when_trial_counts_equal",
                round(float(row["scenario_mean_mrr"]), 6) == round(float(canonical["mrr"]), 6),
                {"scenario_mean_mrr": row["scenario_mean_mrr"], "canonical_valid_row_mrr": canonical["mrr"]},
            )
    gpt = next(row for row in bespoke["scenario_level_metrics"] if row["arm_id"] == "proprietary_gpt")
    check(
        "gpt_scenario_mrr_differs_from_canonical_only_by_scenario_weighting",
        round(float(gpt["scenario_mean_mrr"]), 6) != round(float(gpt["scenario_mean_full_order_mrr"]), 6)
        and round(float(gpt["trial_row_mrr"]), 6) == round(float(gpt["canonical_valid_row_metrics"]["mrr"]), 6),
        {
            "scenario_mean_budget_censored_mrr": gpt["scenario_mean_mrr"],
            "scenario_mean_full_order_mrr": gpt["scenario_mean_full_order_mrr"],
            "canonical_valid_row_mrr": gpt["canonical_valid_row_metrics"]["mrr"],
        },
    )
    check("zero_experimental_calls", evidence["activity_boundaries"]["new_model_calls"] == 0 and evidence["activity_boundaries"]["new_http_requests"] == 0)
    return {
        "schema_version": "professor-comment-5-validation-v2",
        "valid": not errors,
        "errors": errors,
        "checks": checks,
        "validated_at": now_utc(),
    }


def average_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    if not rows:
        return {"top1": 0.0, "top2": 0.0, "top4": 0.0, "mrr": 0.0}
    return {metric: mean([float(row[metric]) for row in rows]) for metric in ["top1", "top2", "top4", "mrr"]}


def render_report(evidence: dict[str, Any], scenarios: list[dict[str, Any]], random_summary: dict[str, Any], bespoke: dict[str, Any], comparison: list[dict[str, Any]], reproducibility: dict[str, Any], validation: dict[str, Any]) -> str:
    gpt_model = strip_count_suffix(str(reproducibility["gpt"]["model_identifier"]))
    gpt_provider = strip_count_suffix(str(reproducibility["gpt"]["provider"]))
    gpt_cost = strip_count_suffix(str(reproducibility["gpt"]["cost_availability"]))
    return "\n".join(
        [
            "# Professor Comment 5 Closure Analysis: OWASP Contamination Caveat and Bespoke Held-Out XSS Evidence",
            "",
            "This package is a derived post-run evidence synthesis. It performs zero GPT, Qwen, deterministic ranking, HTTP/browser, discovery, verifier or scored experimental calls and does not modify frozen/canonical artifacts.",
            "",
            "## Authoritative Bespoke Held-Out Package",
            "",
            f"- Protocol/version: `evaluation-protocol-v1.3.1`",
            f"- Canonical result path: `{display_path(BESPOKE_CANONICAL)}`",
            "- Frozen tag: `evaluation-protocol-v1.3.1`",
            "- Tagged commit: `a6fca7e54a0bb3247d6329fd0532178192b51de5`",
            f"- Scenario count: `{len(scenarios)}`",
            f"- Positive/negative composition: `16` positive and `8` negative/control scenarios",
            f"- Candidate-count distribution: `{random_summary['candidate_count_distribution_all']}`",
            "- Ranking budget: `k = 4`",
            "- Arms: `deterministic_structural`, `proprietary_gpt`, `local_qwen`",
            "- Trials: deterministic has one ranking per scenario; GPT and Qwen have five trials per scenario.",
            "- Ranking evidence and runtime verifier evidence are retained separately; ground truth is applied only in post-run scoring.",
            "- Ranking MRR in this report follows the canonical budget-censored v1.3.1 semantics: reciprocal-rank credit is assigned only if the vulnerable candidate is within `top_k = min(test_budget, candidate_count)`. Full-order reciprocal rank is retained only as diagnostic provenance and is not used as the thesis-facing v1.3.1 ranking metric.",
            "",
            "## Scenario-Specific Random Reference",
            "",
            render_random_summary_table(random_summary),
            "",
            "Scenarios with exactly four candidates have random Top-4 = 1.0000 by definition under budget k=4. Observed Top-4 on those scenarios cannot demonstrate prioritization advantage, so the candidate-count >4 subset is reported separately.",
            "",
            render_bespoke_table(bespoke),
            "",
            "The corresponding canonical valid-row metrics from `normalized/arm-level-metrics.json` remain the authoritative v1.3.1 historical results: deterministic Top-1 0.2500, Top-4 0.6875 and MRR 0.3854; GPT Top-1 0.2179, Top-4 0.7179 and MRR 0.4060; Qwen Top-1 0.3125, Top-4 0.6875 and MRR 0.4427. The scenario-level table above gives each positive scenario equal weight; for GPT it differs slightly from the canonical valid-row table because two positive scenarios have four valid trials rather than five. Earlier derived full-order MRR values of 0.4604 for GPT and 0.4958 for Qwen credited vulnerable candidates below the fixed budget and are retained only in `bespoke-metric-reconciliation.json` as diagnostic provenance.",
            "",
            render_top4_gt4_table(bespoke),
            "",
            "## OWASP Versus Bespoke Comparison",
            "",
            render_comparison_table(comparison),
            "",
            "The OWASP v1.4 benchmark contains 236 positive scenarios in total. Qwen contributes valid ranking-performance values for 235/236 positive scenarios; the excluded scenario remains represented in reliability reporting through its five malformed terminal outputs.",
            "",
            "The public OWASP v1.4 and bespoke v1.3.1 metrics should not be compared by raw Top-k values alone because their candidate-set sizes differ. Observed-minus-random values are more interpretable within each dataset. MRR deltas should still be read with care across the two protocols because original v1.4 uses full-order reciprocal-rank semantics, while v1.3.1 uses budget-censored reciprocal rank.",
            "",
            "## Contamination-Risk Interpretation",
            "",
            render_contamination_body(),
            "",
            "## Reproducibility Metadata",
            "",
            f"- GPT model identifier: `{gpt_model}`; provider `{gpt_provider}`; prompt version `llm-candidate-ranking-v1`; temperature parameter omitted/provider default; cost `{gpt_cost}`.",
            f"- Qwen model: `{reproducibility['qwen']['model']}`; repository `{reproducibility['qwen']['repository']}`; revision `{reproducibility['qwen']['revision']}`; quantization `{reproducibility['qwen']['quantization']}`; runtime `{reproducibility['qwen']['runtime']}`; backend `{reproducibility['qwen']['backend']}`; seed `{reproducibility['qwen']['seed']}`; temperature `{reproducibility['qwen']['temperature']}`; top-p `{reproducibility['qwen']['top_p']}`; context `{reproducibility['qwen']['context_size_tokens']}`; output limit `{reproducibility['qwen']['max_output_tokens']}`; timeout `{reproducibility['qwen']['timeout_seconds']}` seconds; threads `{reproducibility['qwen']['threads']}`.",
            "- Qwen latency is an experimental-system measurement under the recorded CPU-only runtime and hardware configuration, not an inherent property of local inference.",
            "",
            "## Direct Answers",
            "",
            direct_answers(bespoke, random_summary, comparison),
            "",
            "## Validation",
            "",
            f"- Source-integrity verdict: `{'PASS' if validation['valid'] else 'FAIL'}`",
            "- New experimental calls: `0`",
            "",
        ]
    )


def render_random_summary_table(summary: dict[str, Any]) -> str:
    rows = [
        "| Scope | Scenarios | Random Top-1 | Random Top-2 | Random Top-4 | Random budget-censored MRR |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
        f"| All eligible positive bespoke scenarios | {summary['eligible_positive_scenarios']} | {fmt(summary['overall']['top1'])} | {fmt(summary['overall']['top2'])} | {fmt(summary['overall']['top4'])} | {fmt(summary['overall']['mrr'])} |",
    ]
    for n, values in summary["by_candidate_count"].items():
        rows.append(f"| n={n} | {values['scenario_count']} | {fmt(values['top1'])} | {fmt(values['top2'])} | {fmt(values['top4'])} | {fmt(values['mrr'])} |")
    return "\n".join(rows)


def render_bespoke_table(bespoke: dict[str, Any]) -> str:
    rows = [
        "| Arm | Valid positive scenario n | Top-1 | Delta vs random | Top-2 | Delta vs random | Top-4 | Delta vs random | Budget-censored MRR | Delta vs random |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in bespoke["scenario_level_metrics"]:
        rows.append(
            f"| {row['arm_id']} | {row['positive_scenarios_with_valid_ranking']} | {fmt(row['scenario_mean_top1'])} | {fmt(row['observed_minus_random_top1'])} | {fmt(row['scenario_mean_top2'])} | {fmt(row['observed_minus_random_top2'])} | {fmt(row['scenario_mean_top4'])} | {fmt(row['observed_minus_random_top4'])} | {fmt(row['scenario_mean_mrr'])} | {fmt(row['observed_minus_random_mrr'])} |"
        )
    return "\n".join(rows)


def render_top4_gt4_table(bespoke: dict[str, Any]) -> str:
    rows = [
        "### Top-4 on Positive Scenarios with Candidate Count >4",
        "",
        "| Arm | Scenario n | Observed Top-4 | Random Top-4 | Delta |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for row in bespoke["top4_candidate_count_gt4_subset"]:
        rows.append(f"| {row['arm_id']} | {row['positive_scenarios_with_valid_ranking']} | {fmt(row['observed_top4'])} | {fmt(row['random_top4'])} | {fmt(row['observed_minus_random_top4'])} |")
    return "\n".join(rows)


def render_comparison_table(rows_in: list[dict[str, Any]]) -> str:
    rows = [
        "| Dataset | Arm | Positive scenarios with valid ranking metric | Valid positive ranking rows | Metric aggregation | MRR semantics | Observed Top-1 | Random Top-1 | Delta MRR | Observed MRR | Random MRR |",
        "| --- | --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in rows_in:
        rows.append(
            f"| {row['dataset']} | {row['arm_id']} | {row['positive_scenarios']} | {row['valid_positive_ranking_rows']} | {row['metric_aggregation']} | {row['mrr_semantics']} | {fmt(row['observed_top1'])} | {fmt(row['random_top1'])} | {fmt(row['observed_minus_random_mrr'])} | {fmt(row['observed_mrr'])} | {fmt(row['random_mrr'])} |"
        )
    return "\n".join(rows)


def direct_answers(bespoke: dict[str, Any], random_summary: dict[str, Any], comparison: list[dict[str, Any]]) -> str:
    bespoke_rows = {row["arm_id"]: row for row in bespoke["scenario_level_metrics"]}
    best = max(bespoke_rows.values(), key=lambda row: row["scenario_mean_mrr"])["arm_id"]
    exceed = {
        arm: {
            metric: bespoke_rows[arm][f"observed_minus_random_{metric}"] > 0
            for metric in ["top1", "top2", "top4", "mrr"]
        }
        for arm in bespoke_rows
    }
    qwen_delta = bespoke_rows["local_qwen"]["observed_minus_random_mrr"]
    gpt_delta = bespoke_rows["proprietary_gpt"]["observed_minus_random_mrr"]
    det_delta = bespoke_rows["deterministic_structural"]["observed_minus_random_mrr"]
    lines = [
        "1. The model-backed trends from public OWASP data appear partially on the bespoke set: under metric-compatible budget-censored random MRR, all three arms are above the bespoke random MRR reference, Qwen remains descriptively strongest, and the small bespoke scenario count and mixed Top-k deltas require cautious interpretation.",
        f"2. The best descriptive bespoke arm by scenario-level budget-censored MRR is `{best}`.",
        f"3. Exceeding random by metric: `{exceed}`.",
        f"4. Relative to OWASP, bespoke effects are mixed: all three bespoke arms are above random by budget-censored MRR, with deltas of {fmt(det_delta)} for deterministic, {fmt(gpt_delta)} for GPT and {fmt(qwen_delta)} for Qwen. Cross-dataset MRR deltas remain only approximate because v1.4 uses full-order reciprocal-rank semantics and v1.3.1 uses budget-censored MRR.",
        "5. The bespoke evidence strengthens the thesis by adding lower-contamination-risk held-out evidence, but it also qualifies the central claim: bounded model-backed ranking can improve prioritization in some settings, yet the effect is model- and dataset-dependent and uncertain with only 24 bespoke scenarios.",
    ]
    return "\n".join(lines)


def render_contamination_body() -> str:
    return (
        "OWASP Benchmark v1.2 is a public benchmark corpus used as an external validation source in v1.4. "
        "Because it was publicly available before this thesis evaluation, potential training-data exposure cannot be ruled out for either the hosted proprietary GPT arm or the local Qwen model. "
        "This is a contamination-risk caveat, not evidence of actual contamination. "
        "The bespoke v1.3/v1.3.1 held-out scenarios were constructed for this project as local benchmark scenarios, frozen before final scored execution, and excluded from model-selection/calibration runs. "
        "Their candidate snapshots explicitly exclude ground truth, labels, raw HTML, browser state and source code from ranking inputs. "
        "This provenance makes them substantially lower-contamination-risk evidence than the public OWASP corpus, but it does not prove mathematically impossible contamination."
    )


def render_contamination_note() -> str:
    return "# Contamination-Risk Note\n\n" + render_contamination_body() + "\n"


def render_thesis_tables(random_summary: dict[str, Any], bespoke: dict[str, Any], comparison: list[dict[str, Any]]) -> str:
    return "\n\n".join(
        [
            "# Professor Comment 5 Thesis-Ready Tables",
            "## Bespoke Scenario-Specific Random Baseline",
            render_random_summary_table(random_summary),
            "## Bespoke Observed-minus-Random Ranking Metrics",
            render_bespoke_table(bespoke),
            render_top4_gt4_table(bespoke),
            "## Public OWASP v1.4 versus Bespoke v1.3.1",
            render_comparison_table(comparison),
            "Note: OWASP v1.4 contains 236 positive scenarios in total. Qwen has valid ranking-performance values for 235/236 positive scenarios; the excluded scenario is retained in reliability reporting through its five malformed terminal outputs.",
        ]
    ) + "\n"


def render_thesis_tables_tex(random_summary: dict[str, Any], bespoke: dict[str, Any], comparison: list[dict[str, Any]]) -> str:
    lines = [
        "% Professor Comment 5 thesis-ready tables.",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Bespoke v1.3.1 scenario-level observed-minus-random budget-censored ranking metrics}",
        "\\begin{tabular}{lrrrr}",
        "\\hline",
        "Arm & Top-1 $\\Delta$ & Top-2 $\\Delta$ & Top-4 $\\Delta$ & MRR $\\Delta$ \\\\",
        "\\hline",
    ]
    for row in bespoke["scenario_level_metrics"]:
        lines.append(f"{label(row['arm_id'])} & {fmt(row['observed_minus_random_top1'])} & {fmt(row['observed_minus_random_top2'])} & {fmt(row['observed_minus_random_top4'])} & {fmt(row['observed_minus_random_mrr'])} \\\\")
    lines += ["\\hline", "\\end{tabular}", "\\end{table}", ""]
    return "\n".join(lines)


def render_methodology_note(evidence: dict[str, Any], validation: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance Note",
            "",
            "This derived package reads frozen/canonical evidence only. It does not execute experiments, model calls, HTTP/browser requests, discovery, verifier logic, or scoring runs.",
            "",
            "The authoritative bespoke held-out package was resolved from the v1.3.1 protocol and canonical manifest, not filename recency. The six calibration/development scenarios and local-model bake-off packages are not used as held-out results.",
            "",
            "Source validation status:",
            *[f"- `{source['id']}`: required checksum validation `{source['checksum_validation']['valid']}`" for source in evidence["sources"]],
            "",
            "For the bespoke v1.3.1 package, the numerical evidence-bearing files used here validate. A legacy full-package mismatch in presentation artifacts is recorded in the evidence inventory and is not used to derive numerical findings.",
            "",
            f"Validation status: `{validation['valid']}`",
            "",
        ]
    )


def build_manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "professor-comment-5-bespoke-contamination-analysis-manifest-v1",
        "created_at": now_utc(),
        "package_dir": display_path(OUTPUT_DIR),
        "validation_valid": validation["valid"],
        "experimental_calls_executed": 0,
        "generated_files": sorted(display_path(path) for path in OUTPUT_DIR.rglob("*") if path.is_file()),
    }


def validate_sha256_package(package_dir: Path) -> dict[str, Any]:
    checksum_path = package_dir / "checksums.sha256"
    errors = validate_sha256_file(checksum_path, package_dir) if checksum_path.exists() else [f"missing {display_path(checksum_path)}"]
    return {"valid": checksum_path.exists() and not errors, "errors": errors, "checked_file": display_path(checksum_path)}


def validate_sha256_selected(checksum_path: Path, base_dir: Path, selected_relative_paths: list[str]) -> dict[str, Any]:
    if not checksum_path.exists():
        return {"valid": False, "errors": [f"missing {display_path(checksum_path)}"], "checked_file": display_path(checksum_path)}
    ledger = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split(maxsplit=1)
        ledger[rel.strip().replace("\\", "/")] = expected
    errors: list[str] = []
    for selected in selected_relative_paths:
        target = base_dir / selected
        repo_rel = display_path(target)
        expected = ledger.get(selected) or ledger.get(repo_rel)
        if expected is None:
            errors.append(f"missing checksum entry {selected}")
            continue
        if not target.exists():
            errors.append(f"missing {selected}")
            continue
        if sha256(target) != expected:
            errors.append(f"hash mismatch {selected}")
    return {"valid": not errors, "errors": errors, "checked_file": display_path(checksum_path), "selected_files": selected_relative_paths}


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
            repo_target = REPO_ROOT / rel.strip()
            if repo_target.exists():
                target = repo_target
        if not target.exists():
            errors.append(f"missing {rel}")
            continue
        if sha256(target) != expected:
            errors.append(f"hash mismatch {rel}")
    return errors


def render_checksums(directory: Path) -> str:
    lines = []
    for path in sorted(p for p in directory.rglob("*") if p.is_file() and p.name != "checksums.sha256"):
        lines.append(f"{sha256(path)}  {path.relative_to(directory).as_posix()}")
    return "\n".join(lines) + "\n"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
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
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_bool(value: Any) -> bool:
    return str(value).lower() == "true"


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def label(arm: str) -> str:
    return {
        "deterministic_structural": "Deterministic",
        "proprietary_gpt": "GPT",
        "local_qwen": "Qwen",
    }.get(arm, arm)


def strip_count_suffix(value: str) -> str:
    if value.endswith(")") and " (" in value:
        prefix, suffix = value.rsplit(" (", 1)
        if suffix[:-1].isdigit():
            return prefix
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def display_path(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def now_utc() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
