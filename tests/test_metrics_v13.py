import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.metrics import NOT_APPLICABLE, NOT_AVAILABLE, derive_measurements


class MetricsV13Tests(unittest.TestCase):
    def test_measurement_fields_are_derived_from_artifacts(self) -> None:
        measurements = derive_measurements(
            action_requests=[
                _action("a1", "mutate_parameter", "candidate-1"),
                _action("a2", "observe_browser", "candidate-1"),
                _action("a3", "replay_request", "candidate-2"),
                _action("a4", "replay_request", "candidate-3"),
            ],
            action_results=[
                _result("a1", "executed", "2026-07-29T10:00:01+00:00", "2026-07-29T10:00:02+00:00", {"http_request_count": 2, "candidate_id": "candidate-1"}),
                _result("a2", "executed", "2026-07-29T10:00:03+00:00", "2026-07-29T10:00:04+00:00", {"browser_navigation_count": 1, "candidate_id": "candidate-1"}),
                _result("a3", "blocked", "2026-07-29T10:00:05+00:00", "2026-07-29T10:00:06+00:00", {"candidate_id": "candidate-2"}),
                _result("a4", "failed", "2026-07-29T10:00:07+00:00", "2026-07-29T10:00:08+00:00", {"candidate_id": "candidate-3"}),
            ],
            findings=[
                _finding("verified", "2026-07-29T10:00:05+00:00"),
            ],
            verifier_results=[
                {"outcome": "verified"},
                {"outcome": "rejected"},
            ],
            candidate_based=True,
        )

        self.assertEqual(measurements["action_counts"]["requested"], 4)
        self.assertEqual(measurements["action_counts"]["approved"], 3)
        self.assertEqual(measurements["action_counts"]["blocked"], 1)
        self.assertEqual(measurements["action_counts"]["executed"], 2)
        self.assertEqual(measurements["action_counts"]["failed"], 1)
        self.assertEqual(measurements["request_counts"]["http_requests"], 2)
        self.assertEqual(measurements["request_counts"]["browser_navigations"], 1)
        self.assertEqual(measurements["first_verified_finding"]["time_to_first_verified_finding_ms"], 4000)
        self.assertEqual(measurements["first_verified_finding"]["requests_to_first_verified_finding"], 3)
        self.assertEqual(measurements["first_verified_finding"]["candidates_tested_before_first_verification"], 1)
        self.assertEqual(measurements["verifier_decisions"]["verified"], 1)
        self.assertEqual(measurements["verifier_decisions"]["rejected"], 1)

    def test_missing_provider_cost_remains_not_available(self) -> None:
        measurements = derive_measurements(
            model_artifacts=[
                _model_trial(
                    "s1",
                    1,
                    usage={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
                    cost=None,
                    latency_ms=250,
                )
            ],
            arm_type="llm",
        )

        provider = measurements["model_provider"]
        self.assertEqual(provider["tokens"]["input"], 100)
        self.assertEqual(provider["tokens"]["output"], 20)
        self.assertEqual(provider["tokens"]["total"], 120)
        self.assertEqual(provider["cost_availability"], NOT_AVAILABLE)
        self.assertEqual(provider["cost_per_ranking_trial_usd"], NOT_AVAILABLE)

    def test_deterministic_arm_provider_cost_is_not_applicable(self) -> None:
        measurements = derive_measurements(arm_type="deterministic")

        provider = measurements["model_provider"]
        self.assertFalse(provider["provider_applicable"])
        self.assertEqual(provider["cost_availability"], NOT_APPLICABLE)
        self.assertEqual(provider["cost_per_ranking_trial_usd"], NOT_APPLICABLE)

    def test_no_verified_finding_uses_not_applicable_first_finding_values(self) -> None:
        measurements = derive_measurements(
            action_requests=[_action("a1", "replay_request", "candidate-1")],
            action_results=[
                _result("a1", "executed", "2026-07-29T10:00:01+00:00", "2026-07-29T10:00:02+00:00", {"http_request_count": 1})
            ],
            findings=[_finding("rejected", None)],
            model_artifacts=[
                _model_trial("s1", 1, cost={"estimated_cost_usd": 0.01}, latency_ms=100)
            ],
            arm_type="llm",
            candidate_based=True,
        )

        first = measurements["first_verified_finding"]
        self.assertEqual(first["time_to_first_verified_finding_ms"], NOT_APPLICABLE)
        self.assertEqual(first["requests_to_first_verified_finding"], NOT_APPLICABLE)
        self.assertEqual(first["candidates_tested_before_first_verification"], NOT_APPLICABLE)
        self.assertEqual(measurements["model_provider"]["cost_per_verified_finding_usd"], NOT_APPLICABLE)

    def test_verification_completed_at_supports_time_to_first_verified_finding(self) -> None:
        measurements = derive_measurements(
            action_requests=[_action("a1", "observe_browser", "candidate-1")],
            action_results=[
                _result("a1", "executed", "2026-08-08T10:00:00+00:00", "2026-08-08T10:00:01+00:00", {"browser_navigation_count": 1, "candidate_id": "candidate-1"})
            ],
            findings=[
                {
                    "state": "verified",
                    "report_fields": {"verification_completed_at": "2026-08-08T10:00:03+00:00"},
                }
            ],
            candidate_based=True,
        )

        first = measurements["first_verified_finding"]
        self.assertEqual(first["timestamp"], "2026-08-08T10:00:03+00:00")
        self.assertEqual(first["time_to_first_verified_finding_ms"], 3000)
        self.assertEqual(first["requests_to_first_verified_finding"], 1)
        self.assertEqual(first["candidates_tested_before_first_verification"], 1)

    def test_repeated_llm_trials_are_not_independent_cases(self) -> None:
        measurements = derive_measurements(
            model_artifacts=[
                _model_trial("scenario-a", 1),
                _model_trial("scenario-a", 2),
                _model_trial("scenario-b", 1),
            ],
            arm_type="llm",
        )

        self.assertEqual(measurements["case_accounting"]["model_trial_count"], 3)
        self.assertEqual(measurements["case_accounting"]["independent_model_scenario_count"], 2)

    def test_model_failure_categories_are_explicit(self) -> None:
        measurements = derive_measurements(
            model_artifacts=[
                _model_trial("s1", 1, validation_errors=["malformed JSON response: x"]),
                _model_trial("s1", 2, provider_failed=True, validation_errors=["model command timed out after 30 seconds"]),
                _model_trial("s1", 3, provider_failed=True, validation_errors=["provider returned 500"]),
            ],
            arm_type="llm",
        )

        provider = measurements["model_provider"]
        self.assertEqual(provider["malformed_output_count"], 1)
        self.assertEqual(provider["timeout_count"], 1)
        self.assertEqual(provider["provider_failure_count"], 1)
        self.assertAlmostEqual(provider["malformed_output_rate"], 1 / 3)

    def test_classification_counts_remain_unchanged(self) -> None:
        rows = [
            {"case_id": "one", "classification": "TP"},
            {"case_id": "two", "classification": "FP"},
            {"case_id": "three", "classification": "FN"},
            {"case_id": "four", "classification": "TN"},
            {"case_id": "five", "classification": "TN"},
        ]

        measurements = derive_measurements(case_rows=rows)

        self.assertEqual(
            measurements["classification_counts"],
            {"TP": 1, "FP": 1, "FN": 1, "TN": 2},
        )


def _action(action_id: str, action_type: str, candidate_id: str | None = None) -> dict:
    return {
        "action_id": action_id,
        "action_type": action_type,
        "scope_context": {"candidate_id": candidate_id} if candidate_id else {},
        "parameters": {},
    }


def _result(action_id: str, status: str, started_at: str, completed_at: str, observations: dict) -> dict:
    return {
        "action_id": action_id,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "normalized_observations": observations,
    }


def _finding(state: str, verified_at: str | None) -> dict:
    return {
        "state": state,
        "report_fields": {"verified_at": verified_at} if verified_at else {},
    }


def _model_trial(
    scenario_id: str,
    trial_number: int,
    *,
    usage: dict | None = None,
    cost: dict | None = None,
    latency_ms: int | None = None,
    validation_errors: list[str] | None = None,
    provider_failed: bool = False,
) -> dict:
    return {
        "scenario_id": scenario_id,
        "trial_number": trial_number,
        "timestamp": "2026-07-29T10:00:00+00:00",
        "usage": usage,
        "cost": cost,
        "latency_ms": latency_ms,
        "validation_errors": validation_errors or [],
        "provider_failed": provider_failed,
    }


if __name__ == "__main__":
    unittest.main()
