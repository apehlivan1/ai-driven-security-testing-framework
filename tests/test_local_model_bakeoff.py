import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.local_model_bakeoff import (
    CALIBRATION_SCENARIOS,
    FORBIDDEN_BOUNDARY_KEYS,
    MODEL_SETTINGS,
    SHORTLISTED_MODELS,
    FakeLocalModelClient,
    apply_selection_rules,
    authority_boundary_preserved,
    evaluate_trial,
    fake_clients,
    model_is_eligible,
    run_bakeoff,
    selection_sort_key,
    validate_bakeoff_design,
    write_bakeoff_package,
)
from adstf.llm_ranking import rank_candidates_with_model
from adstf.xss_v13_benchmark import SCENARIOS as FINAL_XSS_V13_SCENARIOS


class LocalModelBakeoffTests(unittest.TestCase):
    def test_calibration_design_is_fixed_and_separate_from_final_xss_v13(self) -> None:
        result = validate_bakeoff_design()

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(len(CALIBRATION_SCENARIOS), 6)
        self.assertEqual(sum(1 for item in CALIBRATION_SCENARIOS if item.outcome_class == "vulnerable"), 4)
        self.assertEqual(sum(1 for item in CALIBRATION_SCENARIOS if item.outcome_class == "negative"), 2)
        final_ids = {scenario.scenario_id for scenario in FINAL_XSS_V13_SCENARIOS}
        for scenario in CALIBRATION_SCENARIOS:
            self.assertNotIn(scenario.scenario_id, final_ids)
            self.assertGreaterEqual(len(scenario.candidates), 4)
            self.assertLessEqual(len(scenario.candidates), 8)
            for candidate in scenario.candidates:
                self.assertNotIn("/suite-v13/", candidate.action_url)
                self.assertIn("/calibration/", candidate.action_url)

    def test_valid_ranking_trial_preserves_candidate_contract(self) -> None:
        scenario = CALIBRATION_SCENARIOS[0]
        model = SHORTLISTED_MODELS[0]
        result = rank_candidates_with_model(
            candidates=list(scenario.candidates),
            scenario_id=scenario.scenario_id,
            trial_number=1,
            model_client=FakeLocalModelClient("fake-valid", "as_listed"),
            settings={**MODEL_SETTINGS, "scenario_id": scenario.scenario_id, "trial_number": 1},
        )

        row = evaluate_trial(model, scenario, result, fake_data=True)

        self.assertTrue(row["valid"])
        self.assertTrue(row["authority_boundary_preserved"])
        self.assertEqual(row["top_rank_candidate_id"], scenario.candidates[0].candidate_id)
        self.assertEqual(row["prompt_version"], "llm-candidate-ranking-v1")
        self.assertTrue(set(row["candidate_input_keys"]).isdisjoint(FORBIDDEN_BOUNDARY_KEYS))

    def test_invalid_output_categories_are_explicit(self) -> None:
        scenario = CALIBRATION_SCENARIOS[0]
        model = SHORTLISTED_MODELS[0]
        cases = {
            "malformed": "malformed",
            "duplicate_first": "duplicate_id",
            "unknown_first": "unknown_id",
            "omit_last": "omitted_id",
            "timeout": "timeout",
            "provider_failure": "provider_failed",
        }
        for strategy, expected_flag in cases.items():
            with self.subTest(strategy=strategy):
                result = rank_candidates_with_model(
                    candidates=list(scenario.candidates),
                    scenario_id=scenario.scenario_id,
                    trial_number=1,
                    model_client=FakeLocalModelClient("fake-invalid", strategy),
                    settings={**MODEL_SETTINGS, "scenario_id": scenario.scenario_id, "trial_number": 1},
                )
                row = evaluate_trial(model, scenario, result, fake_data=True)

                self.assertFalse(row["valid"])
                self.assertTrue(row[expected_flag])
                self.assertTrue(row["validation_errors"])

    def test_negative_scenarios_have_not_applicable_vulnerability_rank_metrics(self) -> None:
        scenario = next(item for item in CALIBRATION_SCENARIOS if item.outcome_class == "negative")
        result = rank_candidates_with_model(
            candidates=list(scenario.candidates),
            scenario_id=scenario.scenario_id,
            trial_number=1,
            model_client=FakeLocalModelClient("fake-valid", "as_listed"),
            settings={**MODEL_SETTINGS, "scenario_id": scenario.scenario_id, "trial_number": 1},
        )

        row = evaluate_trial(SHORTLISTED_MODELS[0], scenario, result, fake_data=True)

        self.assertEqual(row["top_rank_is_vulnerable"], "not_applicable")
        self.assertEqual(row["vulnerable_candidate_rank"], "not_applicable")
        self.assertEqual(row["top_k_recall"], "not_applicable")
        self.assertEqual(row["negative_scenario_behavior"], "ranking_only_no_verifier_false_positive_not_applicable")

    def test_fake_bakeoff_derives_metrics_and_makes_no_selection(self) -> None:
        package = run_bakeoff(fake_clients(), fake_data=True)

        self.assertEqual(len(package["trial_results"]), 72)
        self.assertEqual(len(package["model_summaries"]), 4)
        self.assertTrue(package["validation_report"]["valid"], package["validation_report"]["errors"])
        self.assertFalse(package["selection_decision"]["final_selection_made"])
        self.assertEqual(package["selection_decision"]["primary_model_candidate_id"], "not_applicable")

    def test_eligibility_gates_are_enforced(self) -> None:
        eligible = _summary("a", valid=0.90, fail=0.10, scenarios=6, memory=True)
        invalid_rate = _summary("b", valid=0.89, fail=0.0, scenarios=6, memory=True)
        failure_rate = _summary("c", valid=1.0, fail=0.11, scenarios=6, memory=True)
        memory = _summary("d", valid=1.0, fail=0.0, scenarios=6, memory=False)
        incomplete = _summary("e", valid=1.0, fail=0.0, scenarios=5, memory=True)

        self.assertTrue(model_is_eligible(eligible))
        self.assertFalse(model_is_eligible(invalid_rate))
        self.assertFalse(model_is_eligible(failure_rate))
        self.assertFalse(model_is_eligible(memory))
        self.assertFalse(model_is_eligible(incomplete))

    def test_selection_tie_breaking_is_deterministic(self) -> None:
        alpha = _summary("alpha", valid=1.0, fail=0.0, scenarios=6, memory=True)
        bravo = _summary("bravo", valid=1.0, fail=0.0, scenarios=6, memory=True)

        ranked = sorted([bravo, alpha], key=selection_sort_key)

        self.assertEqual([item["model_candidate_id"] for item in ranked], ["alpha", "bravo"])

    def test_authority_boundary_rejects_forbidden_candidate_fields(self) -> None:
        self.assertTrue(authority_boundary_preserved([{"candidate_id": "a", "action_path": "/a"}]))
        self.assertFalse(authority_boundary_preserved([{"candidate_id": "a", "raw_html": "<form>"}]))
        self.assertFalse(authority_boundary_preserved([{"candidate_id": "a", "ground_truth": True}]))

    def test_reporting_package_structure_is_written_from_fake_data(self) -> None:
        package = run_bakeoff(fake_clients(), fake_data=True)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "package"
            write_bakeoff_package(package, output)

            self.assertTrue((output / "manifest.json").exists())
            self.assertTrue((output / "hardware-report.json").exists())
            self.assertTrue((output / "trial-results.csv").exists())
            self.assertTrue((output / "model-summary.csv").exists())
            self.assertTrue((output / "selection-decision.json").exists())
            self.assertTrue((output / "figures" / "valid-output-rate-placeholder.png").exists())
            self.assertTrue((output / "figures" / "valid-output-rate-placeholder.pdf").exists())
            self.assertTrue((output / "checksums.sha256").exists())


def _summary(
    model_id: str,
    *,
    valid: float,
    fail: float,
    scenarios: int,
    memory: bool,
) -> dict:
    return {
        "model_candidate_id": model_id,
        "eligible": valid >= 0.90 and fail <= 0.10 and scenarios == 6 and memory,
        "valid_output_rate": valid,
        "timeout_provider_failure_rate": fail,
        "memory_feasible": memory,
        "completed_required_calibration_scenarios": scenarios,
        "required_calibration_scenarios": 6,
        "mean_reciprocal_rank": 0.5,
        "top_1_accuracy": 0.5,
        "top_k_recall": 0.5,
        "ranking_stability": 1.0,
        "malformed_output_rate": 0.0,
        "median_latency_ms": 100,
        "estimated_peak_memory_gb": 4.0,
        "metadata_completeness_score": 1.0,
    }


if __name__ == "__main__":
    unittest.main()
