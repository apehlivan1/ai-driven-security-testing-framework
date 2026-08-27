from __future__ import annotations

import csv
import hashlib
import json
import statistics
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"
PROTOCOL_PACKAGE = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
CANONICAL = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
RAW_RUN = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "owasp-xss-v14-confirmatory-20260821T235804Z"
OUTPUT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-random-baseline-audit"
ARM = "deterministic_structural"


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    scoring = load_json(PROTOCOL_PACKAGE / "ground-truth" / "scoring-data.json")
    decoys = load_json(PROTOCOL_PACKAGE / "ground-truth" / "decoy-assignment-manifest.json")
    scenario_manifest = load_json(PROTOCOL_PACKAGE / "scenario-manifest.json")
    aggregates = load_json(CANONICAL / "normalized" / "ranking-aggregates.json")
    rows = load_deterministic_rows()

    scenario_audit = build_scenario_discrimination(rows, scoring)
    discrimination = summarize_discrimination(scenario_audit)
    alignment = summarize_vulnerable_alignment(scenario_audit)
    random_reference = build_random_reference(scoring, aggregates)
    reuse = build_reuse_summary(scoring, decoys)
    provenance = build_raw_source_provenance(rows)
    validation = validate_package_inputs(scoring, scenario_manifest, rows, random_reference, reuse, provenance)
    package_manifest = manifest(validation)

    write_json(OUTPUT_DIR / "scenario-discrimination-data.json", scenario_audit)
    write_csv(OUTPUT_DIR / "scenario-discrimination-data.csv", scenario_audit)
    write_json(OUTPUT_DIR / "distinct-score-tie-frequency-summary.json", discrimination)
    write_csv(OUTPUT_DIR / "distinct-score-tie-frequency-summary.csv", discrimination_table_rows(discrimination))
    write_json(OUTPUT_DIR / "vulnerable-score-alignment-summary.json", alignment)
    write_csv(OUTPUT_DIR / "vulnerable-score-alignment-by-scenario.csv", alignment["scenario_rows"])
    write_text(OUTPUT_DIR / "vulnerable-score-alignment-table.md", render_vulnerable_alignment_table(alignment))
    write_json(OUTPUT_DIR / "raw-deterministic-source-provenance.json", provenance)
    write_json(OUTPUT_DIR / "candidate-reuse-summary.json", reuse)
    write_csv(OUTPUT_DIR / "candidate-reuse-by-candidate.csv", reuse["reuse_by_candidate"])
    write_json(OUTPUT_DIR / "random-reference-vs-deterministic.json", random_reference)
    write_text(OUTPUT_DIR / "random-reference-vs-deterministic.md", render_random_reference_table(random_reference))
    write_text(OUTPUT_DIR / "distinct-score-tie-frequency-table.md", render_discrimination_table(discrimination))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(provenance))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", package_manifest)
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(random_reference, discrimination, alignment, reuse, provenance, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_checksums(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "owasp-xss-v14-random-baseline-audit-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    print(f"audit package: {display_path(OUTPUT_DIR)}")
    print(f"validation valid: {validation['valid']}")
    print(f"checksum errors: {len(validate_checksums(OUTPUT_DIR / 'checksums.sha256', OUTPUT_DIR))}")
    print(f"verdict: {discrimination['verdict']}")


def load_deterministic_rows() -> list[dict[str, Any]]:
    row_dir = RAW_RUN / "raw" / "ranking-rows"
    rows = []
    for path in sorted(row_dir.glob("sequence-*__deterministic_structural__*.json")):
        row = load_json(path)
        row["_artifact_path"] = display_path(path)
        rows.append(row)
    return sorted(rows, key=lambda item: int(item["summary"]["sequence"]))


def build_scenario_discrimination(rows: list[dict[str, Any]], scoring: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = {scenario["scenario_id"]: scenario for scenario in scoring["scenarios"]}
    result = []
    for row in rows:
        summary = row["summary"]
        scenario = scenarios[summary["scenario_id"]]
        scores = row["ranking_result"]["provider_metadata"]["scores"]
        ordered_candidate_ids = [item["candidate"]["candidate_id"] for item in scores]
        score_by_candidate = {item["candidate"]["candidate_id"]: int(item["score"]) for item in scores}
        score_vector = [score_by_candidate[candidate_id] for candidate_id in ordered_candidate_ids]
        score_counts = Counter(score_vector)
        distinct_scores = len(score_counts)
        largest_tie_group = max(score_counts.values())
        all_five_tied = distinct_scores == 1
        final_order_partly_determined_by_tiebreak = any(count > 1 for count in score_counts.values())
        scenario_type = scenario["scenario_type"]
        focal_id = scenario.get("focal_vulnerable_candidate_id")
        vulnerable_rank: int | str = "not_applicable"
        vulnerable_score: int | str = "not_applicable"
        vulnerable_tied_with_all_distractors: bool | str = "not_applicable"
        vulnerable_has_unique_pre_tiebreak_score: bool | str = "not_applicable"
        vulnerable_score_class_rank: int | str = "not_applicable"
        vulnerable_distractors_sharing_score: int | str = "not_applicable"
        vulnerable_alignment_bucket: str = "not_applicable"
        vulnerable_in_best_score_class: bool | str = "not_applicable"
        vulnerable_in_worst_score_class: bool | str = "not_applicable"
        if scenario_type == "positive":
            vulnerable_rank = ordered_candidate_ids.index(focal_id) + 1
            vulnerable_score = score_by_candidate[focal_id]
            vulnerable_tied_with_all_distractors = all(score == vulnerable_score for score in score_vector)
            vulnerable_has_unique_pre_tiebreak_score = score_counts[vulnerable_score] == 1
            distinct_score_order = sorted(score_counts, reverse=True)
            vulnerable_score_class_rank = distinct_score_order.index(vulnerable_score) + 1
            vulnerable_distractors_sharing_score = score_counts[vulnerable_score] - 1
            vulnerable_in_best_score_class = vulnerable_score == distinct_score_order[0]
            vulnerable_in_worst_score_class = vulnerable_score == distinct_score_order[-1]
            vulnerable_alignment_bucket = vulnerable_alignment(
                score_counts=score_counts,
                vulnerable_score=vulnerable_score,
                distinct_score_order=distinct_score_order,
            )
        result.append(
            {
                "scenario_id": summary["scenario_id"],
                "scenario_type": scenario_type,
                "candidate_count": len(ordered_candidate_ids),
                "score_by_candidate": score_by_candidate,
                "score_vector_in_final_order": score_vector,
                "ordered_candidate_ids": ordered_candidate_ids,
                "distinct_pre_tiebreak_scores": distinct_scores,
                "largest_tie_group_size": largest_tie_group,
                "all_five_candidates_tied_pre_tiebreak": all_five_tied,
                "final_order_wholly_determined_by_stable_tiebreak": all_five_tied,
                "final_order_partly_determined_by_stable_tiebreak": final_order_partly_determined_by_tiebreak,
                "vulnerable_candidate_rank": vulnerable_rank,
                "vulnerable_pre_tiebreak_score": vulnerable_score,
                "vulnerable_tied_with_all_distractors": vulnerable_tied_with_all_distractors,
                "vulnerable_has_unique_pre_tiebreak_score": vulnerable_has_unique_pre_tiebreak_score,
                "vulnerable_score_class_rank": vulnerable_score_class_rank,
                "vulnerable_distractors_sharing_score": vulnerable_distractors_sharing_score,
                "vulnerable_alignment_bucket": vulnerable_alignment_bucket,
                "vulnerable_in_best_score_class": vulnerable_in_best_score_class,
                "vulnerable_in_worst_score_class": vulnerable_in_worst_score_class,
                "score_equivalence_pattern": equivalence_pattern(score_counts),
                "score_vector_pattern": ">".join(str(score) for score in score_vector),
            }
        )
    return result


def summarize_discrimination(rows: list[dict[str, Any]]) -> dict[str, Any]:
    overall = summarize_discrimination_subset(rows)
    positive = summarize_discrimination_subset([row for row in rows if row["scenario_type"] == "positive"])
    negative = summarize_discrimination_subset([row for row in rows if row["scenario_type"] == "negative_only"])
    positive_rows = [row for row in rows if row["scenario_type"] == "positive"]
    no_vuln_discrimination = sum(1 for row in positive_rows if row["vulnerable_tied_with_all_distractors"] is True)
    verdict = (
        "The original v1.4 deterministic ranker provides little or no pre-tiebreak discrimination on this OWASP scenario class and relies substantially on its frozen stable tiebreak."
        if overall["exactly_1_distinct_score"]["count"] > len(rows) / 2
        else "The original v1.4 deterministic ranker discriminates among many OWASP candidates before its final stable tiebreak."
    )
    return {
        "schema_version": "owasp-xss-v14-deterministic-discrimination-summary-v1",
        "overall": overall,
        "positive_scenarios": positive,
        "negative_only_scenarios": negative,
        "positive_vulnerable_candidate_no_pre_tiebreak_discrimination_from_distractors": {
            "count": no_vuln_discrimination,
            "percentage": percentage(no_vuln_discrimination, len(positive_rows)),
        },
        "score_equivalence_pattern_distribution": dict(Counter(row["score_equivalence_pattern"] for row in rows).most_common()),
        "score_vector_distribution": dict(Counter(row["score_vector_pattern"] for row in rows).most_common()),
        "verdict": verdict,
    }


def vulnerable_alignment(
    *,
    score_counts: Counter[int],
    vulnerable_score: int,
    distinct_score_order: list[int],
) -> str:
    if len(distinct_score_order) == 1:
        return "all_candidates_tied_for_highest_and_lowest"
    tied = score_counts[vulnerable_score] > 1
    if vulnerable_score == distinct_score_order[0]:
        return "tied_for_highest" if tied else "strictly_highest"
    if vulnerable_score == distinct_score_order[-1]:
        return "tied_for_lowest" if tied else "strictly_lowest"
    return "tied_in_middle_score_class" if tied else "neither_highest_nor_lowest_middle"


def summarize_vulnerable_alignment(rows: list[dict[str, Any]]) -> dict[str, Any]:
    positive_rows = [row for row in rows if row["scenario_type"] == "positive"]
    total = len(positive_rows)
    requested_flags: Counter[str] = Counter()
    exclusive = Counter(row["vulnerable_alignment_bucket"] for row in positive_rows)
    shared = Counter(str(row["vulnerable_distractors_sharing_score"]) for row in positive_rows)
    class_rank = Counter(str(row["vulnerable_score_class_rank"]) for row in positive_rows)
    best_count = 0
    worst_count = 0
    for row in positive_rows:
        score_counts = Counter(row["score_by_candidate"].values())
        vulnerable_score = row["vulnerable_pre_tiebreak_score"]
        distinct_score_order = sorted(score_counts, reverse=True)
        is_best = vulnerable_score == distinct_score_order[0]
        is_worst = vulnerable_score == distinct_score_order[-1]
        tied = score_counts[vulnerable_score] > 1
        if is_best:
            best_count += 1
            requested_flags["tied_for_highest" if tied else "strictly_highest"] += 1
        if is_worst:
            worst_count += 1
            requested_flags["tied_for_lowest" if tied else "strictly_lowest"] += 1
        if not is_best and not is_worst:
            requested_flags["tied_in_middle_score_class" if tied else "neither_highest_nor_lowest_middle"] += 1
    scenario_rows = [
        {
            "scenario_id": row["scenario_id"],
            "vulnerable_candidate_rank": row["vulnerable_candidate_rank"],
            "vulnerable_pre_tiebreak_score": row["vulnerable_pre_tiebreak_score"],
            "vulnerable_score_class_rank": row["vulnerable_score_class_rank"],
            "distinct_pre_tiebreak_scores": row["distinct_pre_tiebreak_scores"],
            "vulnerable_alignment_bucket": row["vulnerable_alignment_bucket"],
            "vulnerable_distractors_sharing_score": row["vulnerable_distractors_sharing_score"],
            "vulnerable_in_best_score_class": row["vulnerable_in_best_score_class"],
            "vulnerable_in_worst_score_class": row["vulnerable_in_worst_score_class"],
            "score_vector_in_final_order": row["score_vector_in_final_order"],
            "score_equivalence_pattern": row["score_equivalence_pattern"],
        }
        for row in positive_rows
    ]
    return {
        "schema_version": "owasp-xss-v14-vulnerable-score-alignment-summary-v1",
        "positive_scenarios": total,
        "requested_alignment_flag_counts": {
            key: count_percent(requested_flags[key], total)
            for key in [
                "strictly_highest",
                "tied_for_highest",
                "neither_highest_nor_lowest_middle",
                "tied_in_middle_score_class",
                "strictly_lowest",
                "tied_for_lowest",
            ]
        },
        "requested_alignment_flags_note": (
            "These requested flags are not mutually exclusive for all-five-tied scenarios: "
            "the vulnerable candidate is both tied for highest and tied for lowest."
        ),
        "exclusive_alignment_bucket_counts": {
            key: count_percent(exclusive[key], total)
            for key in [
                "strictly_highest",
                "tied_for_highest",
                "neither_highest_nor_lowest_middle",
                "tied_in_middle_score_class",
                "strictly_lowest",
                "tied_for_lowest",
                "all_candidates_tied_for_highest_and_lowest",
            ]
        },
        "distractors_sharing_vulnerable_score_distribution": {
            str(count): count_percent(shared[str(count)], total) for count in range(5)
        },
        "vulnerable_score_class_rank_distribution": {
            key: count_percent(class_rank[key], total) for key in sorted(class_rank, key=int)
        },
        "pre_tiebreak_scoring_places_vulnerable_in_best_score_class": count_percent(best_count, total),
        "pre_tiebreak_scoring_places_vulnerable_in_worst_score_class": count_percent(worst_count, total),
        "interpretation": (
            "The original deterministic scoring frequently creates structural score differences, "
            "but it never assigns the vulnerable candidate a strictly highest score over all four distractors. "
            "Many best-score-class placements are shared ties, and worst-score-class placement is also substantial. "
            "This indicates weak alignment between the original structural score and OWASP XSS vulnerability status."
        ),
        "scenario_rows": scenario_rows,
    }


def summarize_discrimination_subset(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    distinct = Counter(int(row["distinct_pre_tiebreak_scores"]) for row in rows)
    largest = Counter(int(row["largest_tie_group_size"]) for row in rows)
    all_five = sum(1 for row in rows if row["all_five_candidates_tied_pre_tiebreak"])
    partly = sum(1 for row in rows if row["final_order_partly_determined_by_stable_tiebreak"])
    wholly = sum(1 for row in rows if row["final_order_wholly_determined_by_stable_tiebreak"])
    return {
        "scenario_count": total,
        "exactly_1_distinct_score": count_percent(distinct[1], total),
        "exactly_2_distinct_scores": count_percent(distinct[2], total),
        "exactly_3_distinct_scores": count_percent(distinct[3], total),
        "exactly_4_distinct_scores": count_percent(distinct[4], total),
        "exactly_5_distinct_scores": count_percent(distinct[5], total),
        "all_five_tied_scenarios": count_percent(all_five, total),
        "final_order_partly_determined_by_stable_tiebreak": count_percent(partly, total),
        "final_order_wholly_determined_by_stable_tiebreak": count_percent(wholly, total),
        "largest_tie_group_distribution": {str(size): count_percent(count, total) for size, count in sorted(largest.items())},
    }


def build_random_reference(scoring: dict[str, Any], aggregates: dict[str, Any]) -> dict[str, Any]:
    positive = [scenario for scenario in scoring["scenarios"] if scenario["scenario_type"] == "positive"]
    pack_sizes = Counter(len(scenario["candidate_ids"]) for scenario in positive)
    vulnerable_per_positive = [
        sum(1 for candidate_id in scenario["candidate_ids"] if candidate_expected(scoring, candidate_id) == "vulnerable")
        for scenario in positive
    ]
    observed = aggregates["arms"][ARM]
    rank_distribution = {str(rank): int(observed["rank_distribution"][str(rank)]) for rank in range(1, 6)}
    deterministic_top1 = observed["top1"]
    deterministic_top2 = (rank_distribution["1"] + rank_distribution["2"]) / len(positive)
    deterministic_top4 = observed["topk"]
    deterministic_mrr = observed["mrr"]
    random_values = {
        "top1": 1 / 5,
        "top2": 2 / 5,
        "top4": 4 / 5,
        "mrr": sum(1 / rank for rank in range(1, 6)) / 5,
    }
    observed_values = {
        "top1": deterministic_top1,
        "top2": deterministic_top2,
        "top4": deterministic_top4,
        "mrr": deterministic_mrr,
    }
    return {
        "schema_version": "owasp-xss-v14-random-reference-vs-deterministic-v1",
        "random_reference_basis": {
            "positive_scenarios": len(positive),
            "candidate_pack_size": 5,
            "exactly_one_vulnerable_candidate_per_positive_scenario": all(count == 1 for count in vulnerable_per_positive),
            "positive_pack_size_distribution": dict(pack_sizes),
            "expected_mrr_formula": "mean(1/rank) for ranks 1..5 under uniform random ranking",
        },
        "metrics": [
            metric_row("Top-1", random_values["top1"], observed_values["top1"]),
            metric_row("Top-2", random_values["top2"], observed_values["top2"]),
            metric_row("Top-4", random_values["top4"], observed_values["top4"]),
            metric_row("MRR", random_values["mrr"], observed_values["mrr"]),
        ],
        "observed_rank_distribution": rank_distribution,
        "inference_policy": "No new inferential hypothesis test was performed because this random-reference comparison was not part of the original frozen v1.4 statistical plan.",
    }


def build_reuse_summary(scoring: dict[str, Any], decoys: dict[str, Any]) -> dict[str, Any]:
    expected_by_candidate = {item["candidate_id"]: item["expected_result"] for item in scoring["candidate_ground_truth"]}
    vulnerable = [candidate_id for candidate_id, expected in expected_by_candidate.items() if expected == "vulnerable"]
    negatives = [candidate_id for candidate_id, expected in expected_by_candidate.items() if expected == "non_vulnerable"]
    positive_scenarios = [scenario for scenario in scoring["scenarios"] if scenario["scenario_type"] == "positive"]
    negative_scenarios = [scenario for scenario in scoring["scenarios"] if scenario["scenario_type"] == "negative_only"]
    positive_decoy_placements: Counter[str] = Counter()
    negative_only_placements: Counter[str] = Counter()
    for scenario in positive_scenarios:
        focal = scenario["focal_vulnerable_candidate_id"]
        for candidate_id in scenario["candidate_ids"]:
            if candidate_id != focal:
                positive_decoy_placements[candidate_id] += 1
    for scenario in negative_scenarios:
        for candidate_id in scenario["candidate_ids"]:
            negative_only_placements[candidate_id] += 1
    total_placements = Counter(positive_decoy_placements)
    total_placements.update(negative_only_placements)
    rows = []
    for candidate_id in sorted(negatives):
        rows.append(
            {
                "candidate_id": candidate_id,
                "positive_decoy_placements": positive_decoy_placements[candidate_id],
                "negative_only_placements": negative_only_placements[candidate_id],
                "total_non_vulnerable_pack_placements": total_placements[candidate_id],
            }
        )
    total_counts = [row["total_non_vulnerable_pack_placements"] for row in rows]
    positive_counts = [row["positive_decoy_placements"] for row in rows]
    unused = [row["candidate_id"] for row in rows if row["total_non_vulnerable_pack_placements"] == 0]
    return {
        "schema_version": "owasp-xss-v14-distractor-reuse-summary-v1",
        "construction_source": {
            "protocol": "docs/evaluation-protocol-v1.4.md Candidate-Pack Construction",
            "implementation": "src/adstf/owasp_xss_v14_protocol_prep.py build_scenarios",
            "assignment_seed": decoys["assignment_seed"],
            "candidate_order_seed": decoys["candidate_order_seed"],
            "positive_decoy_policy": decoys["positive_decoy_policy"],
            "negative_only_policy": decoys["negative_only_policy"],
        },
        "denominators": {
            "eligible_unique_candidates": len(expected_by_candidate),
            "vulnerable_unique_candidates": len(vulnerable),
            "non_vulnerable_unique_candidates": len(negatives),
            "positive_scenarios": len(positive_scenarios),
            "negative_only_scenarios": len(negative_scenarios),
            "pack_size": 5,
            "positive_scenario_distractor_placements": sum(positive_decoy_placements.values()),
            "negative_only_placements": sum(negative_only_placements.values()),
            "total_non_vulnerable_candidate_placements_across_all_packs": sum(total_placements.values()),
            "unique_non_vulnerable_candidates_used": sum(1 for count in total_counts if count > 0),
            "unused_non_vulnerable_candidates": len(unused),
        },
        "positive_reuse_counts": summarize_counts(positive_counts),
        "total_reuse_counts": summarize_counts(total_counts),
        "positive_reuse_count_distribution": dict(Counter(positive_counts)),
        "total_reuse_count_distribution": dict(Counter(total_counts)),
        "unused_non_vulnerable_candidate_ids": unused,
        "most_frequently_reused_distractors_total": sorted(rows, key=lambda row: (-row["total_non_vulnerable_pack_placements"], row["candidate_id"]))[:15],
        "reuse_balance_interpretation": "positive decoy reuse is deterministic and balanced by round-robin; total reuse differs by one negative-only placement for 150 of 152 non-vulnerable candidates",
        "candidate_set_construction_tiebreak_influence": (
            "Candidate pack input order is SHA-256 randomized and is not used by the deterministic ranker once it re-sorts candidates. "
            "However, when deterministic scores tie, final ordering is mechanically determined by normalized action URL, parameter name, source and candidate ID; "
            "the OWASP external candidate paths and neutralized parameter names therefore can determine ranks whenever pre-tiebreak scores are identical."
        ),
        "reuse_by_candidate": rows,
    }


def build_raw_source_provenance(rows: list[dict[str, Any]]) -> dict[str, Any]:
    raw_checksum_path = RAW_RUN / "checksums.sha256"
    canonical_scored_rows = load_json(CANONICAL / "normalized" / "scored-rows.json")
    canonical_det_refs = {
        row["raw_artifact_path"]
        for row in canonical_scored_rows
        if row.get("arm_id") == ARM
    }
    checksum_map = load_checksum_map(raw_checksum_path)
    row_paths = [REPO_ROOT / row["_artifact_path"] for row in rows]
    raw_relatives = [path.resolve().relative_to(RAW_RUN.resolve()).as_posix() for path in row_paths]
    missing_checksum_entries = [relative for relative in raw_relatives if relative not in checksum_map]
    checksum_mismatches = [
        relative
        for relative in raw_relatives
        if relative in checksum_map and sha256_file(RAW_RUN / relative) != checksum_map[relative]
    ]
    sequences = [int(row["summary"]["sequence"]) for row in rows]
    sequence_counts = Counter(sequences)
    duplicate_sequences = sorted(sequence for sequence, count in sequence_counts.items() if count > 1)
    expected_sequences = set(range(1, 267))
    missing_sequences = sorted(expected_sequences.difference(sequences))
    row_ids = [
        (
            row["summary"]["sequence"],
            row["summary"]["arm_id"],
            row["summary"]["scenario_id"],
            row["summary"]["trial_number"],
        )
        for row in rows
    ]
    row_id_counts = Counter(row_ids)
    duplicate_row_ids = [
        {"sequence": item[0], "arm_id": item[1], "scenario_id": item[2], "trial_number": item[3], "count": count}
        for item, count in sorted(row_id_counts.items())
        if count > 1
    ]
    canonical_missing_refs = sorted(ref for ref in canonical_det_refs if not (REPO_ROOT / ref).exists())
    raw_paths_as_repo_refs = {display_path(path) for path in row_paths}
    raw_refs_missing_from_canonical = sorted(raw_paths_as_repo_refs.difference(canonical_det_refs))
    validation_checksum_errors = validate_checksums(raw_checksum_path, RAW_RUN)
    source_integrity_verified = (
        len(rows) == 266
        and not missing_sequences
        and not duplicate_sequences
        and not duplicate_row_ids
        and not missing_checksum_entries
        and not checksum_mismatches
        and not canonical_missing_refs
        and not raw_refs_missing_from_canonical
        and not validation_checksum_errors
    )
    return {
        "schema_version": "owasp-xss-v14-deterministic-raw-source-provenance-v1",
        "raw_run_dir": display_path(RAW_RUN),
        "raw_checksum_source": display_path(raw_checksum_path),
        "canonical_integrity_source": display_path(CANONICAL / "execution-integrity-report.json"),
        "canonical_scored_rows_source": display_path(CANONICAL / "normalized" / "scored-rows.json"),
        "raw_validation_report_source": display_path(RAW_RUN / "validation-report.json"),
        "deterministic_raw_rows_checked": len(rows),
        "deterministic_raw_rows_covered_by_raw_checksum": len(rows) - len(missing_checksum_entries),
        "raw_checksum_total_entries": len(checksum_map),
        "raw_checksum_deterministic_ranking_entries": sum(1 for relative in checksum_map if relative.startswith("raw/ranking-rows/") and "__deterministic_structural__" in relative),
        "missing_checksum_entries": missing_checksum_entries,
        "checksum_mismatches": checksum_mismatches,
        "raw_run_checksum_validation_errors": validation_checksum_errors[:25],
        "raw_run_checksum_validation_error_count": len(validation_checksum_errors),
        "missing_sequences": missing_sequences,
        "duplicate_sequences": duplicate_sequences,
        "duplicate_row_ids": duplicate_row_ids,
        "canonical_deterministic_references": len(canonical_det_refs),
        "canonical_missing_references": canonical_missing_refs,
        "raw_references_missing_from_canonical_scored_rows": raw_refs_missing_from_canonical,
        "source_integrity_verified": source_integrity_verified,
        "verdict": (
            "verified_source_integrity"
            if source_integrity_verified
            else "source_integrity_limitation_or_mismatch"
        ),
    }


def validate_package_inputs(
    scoring: dict[str, Any],
    scenario_manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    random_reference: dict[str, Any],
    reuse: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, Any]:
    errors = []
    if scenario_manifest.get("scenario_count") != 266:
        errors.append("scenario_count_mismatch")
    if len(rows) != 266:
        errors.append("deterministic_row_count_mismatch")
    den = reuse["denominators"]
    expected = {
        "eligible_unique_candidates": 388,
        "vulnerable_unique_candidates": 236,
        "non_vulnerable_unique_candidates": 152,
        "positive_scenarios": 236,
        "negative_only_scenarios": 30,
        "pack_size": 5,
        "positive_scenario_distractor_placements": 944,
        "negative_only_placements": 150,
        "total_non_vulnerable_candidate_placements_across_all_packs": 1094,
    }
    for key, value in expected.items():
        if den.get(key) != value:
            errors.append(f"{key}_expected_{value}_actual_{den.get(key)}")
    if random_reference["random_reference_basis"]["exactly_one_vulnerable_candidate_per_positive_scenario"] is not True:
        errors.append("positive_scenario_vulnerable_count_mismatch")
    checksum_errors = validate_checksums(PROTOCOL_PACKAGE / "checksums.sha256", PROTOCOL_PACKAGE)
    checksum_errors.extend(validate_checksums(CANONICAL / "checksums.sha256", CANONICAL))
    checksum_errors.extend(validate_checksums(RAW_RUN / "checksums.sha256", RAW_RUN))
    if provenance["source_integrity_verified"] is not True:
        errors.append("deterministic_raw_source_integrity_not_verified")
    return {
        "schema_version": "owasp-xss-v14-random-baseline-audit-validation-v1",
        "valid": not errors and not checksum_errors,
        "errors": errors,
        "source_checksum_errors": checksum_errors[:25],
        "source_checksum_error_count": len(checksum_errors),
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
    random_reference: dict[str, Any],
    discrimination: dict[str, Any],
    alignment: dict[str, Any],
    reuse: dict[str, Any],
    provenance: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    lines = [
        "# Professor Comment 1 Closure Analysis: Original OWASP XSS v1.4",
        "",
        "This is a derived post-run audit of the original frozen OWASP XSS v1.4 evaluation. It does not modify v1.4 or v1.4.1 frozen/canonical artifacts and performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier or scored calls.",
        "",
        "## Random Reference",
        "",
        render_random_reference_table(random_reference).strip(),
        "",
        "The analytically expected random reference follows from the verified positive-scenario structure: each positive scenario has five candidates and exactly one vulnerable candidate. Under uniform random ranking, Top-1 is 1/5 = 0.2000, Top-2 is 2/5 = 0.4000, Top-4 is 4/5 = 0.8000 and expected MRR is mean(1, 1/2, 1/3, 1/4, 1/5) = 0.4567.",
        "",
        "## Pre-Tiebreak Discrimination",
        "",
        render_discrimination_table(discrimination).strip(),
        "",
        f"Positive scenarios where the vulnerable candidate received no pre-tiebreak discrimination from all four distractors: {discrimination['positive_vulnerable_candidate_no_pre_tiebreak_discrimination_from_distractors']['count']} ({discrimination['positive_vulnerable_candidate_no_pre_tiebreak_discrimination_from_distractors']['percentage']:.2f}%).",
        "",
        f"Evidence-based verdict: {discrimination['verdict']}",
        "",
        "## Vulnerable-Candidate Pre-Tiebreak Alignment",
        "",
        render_vulnerable_alignment_table(alignment).strip(),
        "",
        f"Pre-tiebreak scoring alone places the vulnerable candidate in the best score class in {alignment['pre_tiebreak_scoring_places_vulnerable_in_best_score_class']['count']} of {alignment['positive_scenarios']} positive scenarios ({alignment['pre_tiebreak_scoring_places_vulnerable_in_best_score_class']['percentage']:.2f}%) and in the worst score class in {alignment['pre_tiebreak_scoring_places_vulnerable_in_worst_score_class']['count']} scenarios ({alignment['pre_tiebreak_scoring_places_vulnerable_in_worst_score_class']['percentage']:.2f}%). The requested tied-for-highest and tied-for-lowest categories are non-exclusive for all-five-tied scenarios.",
        "",
        alignment["interpretation"],
        "",
        "## Candidate-Pack Construction and Reuse",
        "",
        f"- Eligible unique candidates: {reuse['denominators']['eligible_unique_candidates']}",
        f"- Vulnerable unique candidates: {reuse['denominators']['vulnerable_unique_candidates']}",
        f"- Non-vulnerable unique candidates: {reuse['denominators']['non_vulnerable_unique_candidates']}",
        f"- Positive scenarios: {reuse['denominators']['positive_scenarios']}",
        f"- Negative-only scenarios: {reuse['denominators']['negative_only_scenarios']}",
        f"- Positive-scenario distractor placements: {reuse['denominators']['positive_scenario_distractor_placements']}",
        f"- Negative-only placements: {reuse['denominators']['negative_only_placements']}",
        f"- Total non-vulnerable placements across all packs: {reuse['denominators']['total_non_vulnerable_candidate_placements_across_all_packs']}",
        f"- Unique non-vulnerable candidates used: {reuse['denominators']['unique_non_vulnerable_candidates_used']}",
        f"- Unused non-vulnerable candidates: {reuse['denominators']['unused_non_vulnerable_candidates']}",
        "",
        f"Positive decoy reuse counts: min {reuse['positive_reuse_counts']['min']}, max {reuse['positive_reuse_counts']['max']}, mean {reuse['positive_reuse_counts']['mean']:.4f}, median {reuse['positive_reuse_counts']['median']}. Total non-vulnerable placement counts: min {reuse['total_reuse_counts']['min']}, max {reuse['total_reuse_counts']['max']}, mean {reuse['total_reuse_counts']['mean']:.4f}, median {reuse['total_reuse_counts']['median']}.",
        "",
        "The frozen construction uses a deterministic balanced round-robin over a SHA-256-sorted negative pool for positive-scenario decoys. Negative-only scenarios use disjoint packs of five from the same sorted negative pool, with two leftover negatives recorded and not used in negative-only packs. Candidate order within each pack is SHA-256-based, but the original deterministic ranker re-sorts candidates; when scores tie, its own stable tiebreak over action URL, parameter name, source and candidate ID determines relative ordering.",
        "",
        "## Validation",
        "",
        f"- Validation valid: {validation['valid']}",
        f"- Source checksum errors: {validation['source_checksum_error_count']}",
        f"- Deterministic raw rows checked: {provenance['deterministic_raw_rows_checked']}",
        f"- Deterministic raw rows covered by raw checksum: {provenance['deterministic_raw_rows_covered_by_raw_checksum']}",
        f"- Raw source-integrity verdict: {provenance['verdict']}",
        "- New experimental/scored calls: 0",
    ]
    return "\n".join(lines) + "\n"


def render_random_reference_table(random_reference: dict[str, Any]) -> str:
    lines = [
        "| Metric | Random reference | Original deterministic v1.4 | Difference observed - random |",
        "| --- | ---: | ---: | ---: |",
    ]
    for row in random_reference["metrics"]:
        lines.append(f"| {row['metric']} | {row['random_reference']:.4f} | {row['observed_deterministic']:.4f} | {row['difference_observed_minus_random']:+.4f} |")
    return "\n".join(lines) + "\n"


def render_discrimination_table(discrimination: dict[str, Any]) -> str:
    lines = [
        "| Scenario subset | 1 distinct | 2 distinct | 3 distinct | 4 distinct | 5 distinct | All five tied | Partly tie-broken |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for label, key in [("All scenarios", "overall"), ("Positive", "positive_scenarios"), ("Negative-only", "negative_only_scenarios")]:
        row = discrimination[key]
        lines.append(
            f"| {label} | {count_percent_text(row['exactly_1_distinct_score'])} | {count_percent_text(row['exactly_2_distinct_scores'])} | "
            f"{count_percent_text(row['exactly_3_distinct_scores'])} | {count_percent_text(row['exactly_4_distinct_scores'])} | "
            f"{count_percent_text(row['exactly_5_distinct_scores'])} | {count_percent_text(row['all_five_tied_scenarios'])} | "
            f"{count_percent_text(row['final_order_partly_determined_by_stable_tiebreak'])} |"
        )
    return "\n".join(lines) + "\n"


def render_vulnerable_alignment_table(alignment: dict[str, Any]) -> str:
    flags = alignment["requested_alignment_flag_counts"]
    exclusive = alignment["exclusive_alignment_bucket_counts"]
    shared = alignment["distractors_sharing_vulnerable_score_distribution"]
    ranks = alignment["vulnerable_score_class_rank_distribution"]
    lines = [
        "Requested alignment flags:",
        "",
        "| Alignment flag | Count | Percentage |",
        "| --- | ---: | ---: |",
    ]
    for key, label in [
        ("strictly_highest", "Strictly highest"),
        ("tied_for_highest", "Tied for highest"),
        ("neither_highest_nor_lowest_middle", "Neither highest nor lowest / middle"),
        ("tied_in_middle_score_class", "Tied in a middle score class"),
        ("strictly_lowest", "Strictly lowest"),
        ("tied_for_lowest", "Tied for lowest"),
    ]:
        lines.append(f"| {label} | {flags[key]['count']} | {flags[key]['percentage']:.2f}% |")
    lines.extend(
        [
            "",
            "Exclusive alignment buckets:",
            "",
            "| Exclusive bucket | Count | Percentage |",
            "| --- | ---: | ---: |",
        ]
    )
    for key, label in [
        ("strictly_highest", "Strictly highest"),
        ("tied_for_highest", "Tied for highest"),
        ("neither_highest_nor_lowest_middle", "Middle, unique score"),
        ("tied_in_middle_score_class", "Middle, tied score class"),
        ("strictly_lowest", "Strictly lowest"),
        ("tied_for_lowest", "Tied for lowest"),
        ("all_candidates_tied_for_highest_and_lowest", "All candidates tied"),
    ]:
        lines.append(f"| {label} | {exclusive[key]['count']} | {exclusive[key]['percentage']:.2f}% |")
    lines.extend(
        [
            "",
            "Distractors sharing the vulnerable candidate's score:",
            "",
            "| Distractors sharing score | Count | Percentage |",
            "| ---: | ---: | ---: |",
        ]
    )
    for count in range(5):
        item = shared[str(count)]
        lines.append(f"| {count} | {item['count']} | {item['percentage']:.2f}% |")
    lines.extend(
        [
            "",
            "Vulnerable candidate score-class rank among distinct classes:",
            "",
            "| Score-class rank | Count | Percentage |",
            "| ---: | ---: | ---: |",
        ]
    )
    for key in sorted(ranks, key=int):
        item = ranks[key]
        lines.append(f"| {key} | {item['count']} | {item['percentage']:.2f}% |")
    return "\n".join(lines) + "\n"


def render_methodology_note(provenance: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance",
            "",
            "- Scope: original frozen OWASP XSS v1.4 evaluation only.",
            "- Excluded: v1.4.1 enriched deterministic rules and all later context-enrichment results.",
            "- Sources: v1.4 protocol package, v1.4 canonical package, and retained v1.4 deterministic raw ranking artifacts.",
            "- Ground truth use: limited to post-run structural verification of positive/negative scenario composition and final vulnerable ranks.",
            "- Random reference: analytical, not an empirical rerun.",
            f"- Deterministic raw ranking provenance: {provenance['deterministic_raw_rows_checked']} retained deterministic row artifacts are checked against `{provenance['raw_checksum_source']}` and linked to canonical scored rows through `{provenance['canonical_scored_rows_source']}`.",
            f"- Deterministic raw source-integrity verdict: `{provenance['verdict']}`.",
            "- Inference: no new hypothesis test was performed because the random-reference comparison was not frozen in the original v1.4 statistical plan.",
            "- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero deterministic ranking calls, zero verifier calls.",
        ]
    ) + "\n"


def metric_row(metric: str, random_reference: float, observed: float) -> dict[str, Any]:
    return {
        "metric": metric,
        "random_reference": random_reference,
        "observed_deterministic": observed,
        "difference_observed_minus_random": observed - random_reference,
    }


def discrimination_table_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for label, key in [("overall", "overall"), ("positive", "positive_scenarios"), ("negative_only", "negative_only_scenarios")]:
        values = summary[key]
        rows.append(
            {
                "subset": label,
                "scenario_count": values["scenario_count"],
                "exactly_1_distinct_score_count": values["exactly_1_distinct_score"]["count"],
                "exactly_2_distinct_scores_count": values["exactly_2_distinct_scores"]["count"],
                "exactly_3_distinct_scores_count": values["exactly_3_distinct_scores"]["count"],
                "exactly_4_distinct_scores_count": values["exactly_4_distinct_scores"]["count"],
                "exactly_5_distinct_scores_count": values["exactly_5_distinct_scores"]["count"],
                "all_five_tied_count": values["all_five_tied_scenarios"]["count"],
                "partly_tiebreak_count": values["final_order_partly_determined_by_stable_tiebreak"]["count"],
            }
        )
    return rows


def candidate_expected(scoring: dict[str, Any], candidate_id: str) -> str:
    for item in scoring["candidate_ground_truth"]:
        if item["candidate_id"] == candidate_id:
            return item["expected_result"]
    raise KeyError(candidate_id)


def equivalence_pattern(score_counts: Counter[int]) -> str:
    return "-".join(str(count) for count in sorted(score_counts.values(), reverse=True))


def summarize_counts(values: list[int]) -> dict[str, Any]:
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
    }


def count_percent(count: int, total: int) -> dict[str, Any]:
    return {"count": count, "percentage": percentage(count, total)}


def count_percent_text(item: dict[str, Any]) -> str:
    return f"{item['count']} ({item['percentage']:.2f}%)"


def percentage(count: int, total: int) -> float:
    return (count / total * 100) if total else 0.0


def manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-random-baseline-audit-manifest-v1",
        "created_at": now_utc(),
        "artifact_status": "derived_post_run_audit",
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


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


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
