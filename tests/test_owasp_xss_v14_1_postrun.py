import unittest

from adstf.owasp_xss_v14_1_postrun import (
    NOT_APPLICABLE,
    NOT_AVAILABLE,
    aggregate_arm_metrics,
    cost_summary,
    holm_adjust_pvalues,
    primary_mrr_comparisons,
    score_ranking_row,
)


def row(
    *,
    sequence=1,
    arm_id="gpt_enriched",
    scenario_id="s1",
    trial_number=1,
    status="valid",
    contract_valid=True,
    parsed_ranking=None,
    usage=None,
    cost=None,
    latency_ms=10,
):
    parsed_ranking = parsed_ranking or ["c1", "c2", "c3", "c4", "c5"]
    return {
        "schema_version": "test-row",
        "_artifact_path": f"raw/{sequence}.json",
        "ground_truth_included": False,
        "summary": {
            "sequence": sequence,
            "row_id": f"row-{sequence}",
            "scenario_id": scenario_id,
            "arm_id": arm_id,
            "arm_family": arm_id.split("_", 1)[0],
            "representation_condition": arm_id.split("_", 1)[1],
            "trial_number": trial_number,
            "snapshot_path": f"snapshot/{scenario_id}.json",
            "candidate_input_sha256": "abc",
            "candidate_test_budget": 4,
            "top_k": 4,
            "status": status,
            "contract_valid": contract_valid,
            "provider_failed": False,
            "validation_errors": [] if contract_valid else ["bad output"],
            "latency_ms": latency_ms,
            "model_identifier": "model",
            "provider": "provider",
        },
        "ranking_result": {
            "parsed_ranking": parsed_ranking,
            "usage": usage,
            "cost": cost,
        },
    }


POSITIVE_SCENARIO = {
    "scenario_id": "s1",
    "scenario_type": "positive",
    "focal_vulnerable_candidate_id": "v",
    "candidate_ids": ["c1", "c2", "v", "c4", "c5"],
}

NEGATIVE_SCENARIO = {
    "scenario_id": "s2",
    "scenario_type": "negative_only",
    "candidate_ids": ["c1", "c2", "c3", "c4", "c5"],
}


class OwaspXssV141PostrunTests(unittest.TestCase):
    def test_scores_positive_valid_ranking_with_top2_and_top4(self):
        scored = score_ranking_row(row(parsed_ranking=["c1", "c2", "v", "c4", "c5"]), POSITIVE_SCENARIO)

        self.assertEqual(scored["vulnerable_rank"], 3)
        self.assertFalse(scored["top1"])
        self.assertFalse(scored["top2"])
        self.assertTrue(scored["top4"])
        self.assertAlmostEqual(scored["reciprocal_rank"], 1 / 3)

    def test_invalid_positive_row_is_retained_but_ranking_metrics_are_unavailable(self):
        scored = score_ranking_row(
            row(status="malformed", contract_valid=False, parsed_ranking=[]),
            POSITIVE_SCENARIO,
        )

        self.assertEqual(scored["status"], "malformed")
        self.assertFalse(scored["contract_valid"])
        self.assertEqual(scored["vulnerable_rank"], NOT_AVAILABLE)
        self.assertEqual(scored["top1"], NOT_AVAILABLE)
        self.assertEqual(scored["top2"], NOT_AVAILABLE)
        self.assertEqual(scored["top4"], NOT_AVAILABLE)
        self.assertEqual(scored["reciprocal_rank"], NOT_AVAILABLE)

    def test_negative_scenario_has_no_vulnerable_rank_or_mrr_denominator(self):
        scored = score_ranking_row(row(scenario_id="s2"), NEGATIVE_SCENARIO)

        self.assertEqual(scored["scenario_type"], "negative_only")
        self.assertEqual(scored["vulnerable_rank"], NOT_APPLICABLE)
        self.assertEqual(scored["top1"], NOT_APPLICABLE)
        self.assertEqual(scored["top2"], NOT_APPLICABLE)
        self.assertEqual(scored["top4"], NOT_APPLICABLE)
        self.assertEqual(scored["reciprocal_rank"], NOT_APPLICABLE)

    def test_aggregate_uses_scenarios_not_repeated_trials_as_independent_units(self):
        scored_rows = [
            score_ranking_row(row(sequence=1, scenario_id="s1", trial_number=1, parsed_ranking=["v", "c1", "c2", "c3", "c4"]), POSITIVE_SCENARIO),
            score_ranking_row(row(sequence=2, scenario_id="s1", trial_number=2, parsed_ranking=["c1", "v", "c2", "c3", "c4"]), POSITIVE_SCENARIO),
            score_ranking_row(row(sequence=3, scenario_id="s3", trial_number=1, parsed_ranking=["c1", "c2", "c3", "v", "c4"]), {**POSITIVE_SCENARIO, "scenario_id": "s3"}),
            score_ranking_row(row(sequence=4, scenario_id="s2", trial_number=1), NEGATIVE_SCENARIO),
        ]

        aggregate = aggregate_arm_metrics(scored_rows)

        self.assertEqual(aggregate["eligible_positive_scenarios"], 2)
        self.assertEqual(aggregate["positive_valid_trials"], 3)
        self.assertAlmostEqual(aggregate["scenario_level_mrr"], ((1.0 + 0.5) / 2 + 0.25) / 2)
        self.assertEqual(aggregate["negative_scenarios"], 1)
        self.assertEqual(aggregate["negative_top1_top2_top4_mrr"], NOT_APPLICABLE)

    def test_primary_comparisons_pair_on_scenario_and_apply_holm_adjustment(self):
        scenario_metrics = [
            {"scenario_id": "s1", "arm_id": "gpt_minimal", "scenario_level_mrr": 0.2},
            {"scenario_id": "s1", "arm_id": "gpt_enriched", "scenario_level_mrr": 0.8},
            {"scenario_id": "s1", "arm_id": "qwen_minimal", "scenario_level_mrr": 0.3},
            {"scenario_id": "s1", "arm_id": "qwen_enriched", "scenario_level_mrr": 0.7},
            {"scenario_id": "s1", "arm_id": "deterministic_enriched", "scenario_level_mrr": 0.5},
            {"scenario_id": "s2", "arm_id": "gpt_minimal", "scenario_level_mrr": 0.4},
            {"scenario_id": "s2", "arm_id": "gpt_enriched", "scenario_level_mrr": 0.6},
            {"scenario_id": "s2", "arm_id": "qwen_minimal", "scenario_level_mrr": 0.4},
            {"scenario_id": "s2", "arm_id": "qwen_enriched", "scenario_level_mrr": 0.4},
            {"scenario_id": "s2", "arm_id": "deterministic_enriched", "scenario_level_mrr": 0.6},
        ]

        comparisons = primary_mrr_comparisons(scenario_metrics, bootstrap_iterations=200, permutation_iterations=200, seed=123)

        self.assertEqual(len(comparisons), 4)
        self.assertTrue(all(item["paired_scenarios"] == 2 for item in comparisons))
        self.assertTrue(all("holm_adjusted_p_value" in item for item in comparisons))
        self.assertEqual([item["holm_family_size"] for item in comparisons], [4, 4, 4, 4])

    def test_cost_policy_keeps_missing_cost_unavailable_and_deterministic_not_applicable(self):
        self.assertEqual(cost_summary([], "deterministic_minimal"), NOT_APPLICABLE)
        self.assertEqual(cost_summary([score_ranking_row(row(), POSITIVE_SCENARIO)], "gpt_enriched")["availability"], NOT_AVAILABLE)


if __name__ == "__main__":
    unittest.main()
