import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.discovery import ReflectedInputCandidate
from adstf.llm_ranking import (
    FakeModelClient,
    _completion_from_command_stdout,
    parse_model_ranking,
    rank_candidates_with_model,
)


class LLMRankingTests(unittest.TestCase):
    def test_fake_model_returns_ordered_existing_candidate_ids(self) -> None:
        candidates = [
            candidate("b", "/b", "item"),
            candidate("a", "/a", "term"),
        ]

        result = rank_candidates_with_model(
            candidates=candidates,
            scenario_id="case-a",
            trial_number=1,
            model_client=FakeModelClient(),
        )

        self.assertEqual(result.model_identifier, "fake-llm-as-listed")
        self.assertEqual(result.prompt_version, "llm-candidate-ranking-v1")
        self.assertEqual(result.ordered_candidate_ids, ["a", "b"])
        self.assertFalse(result.validation_errors)
        self.assertIn("Candidates:", result.prompt)

    def test_duplicate_unknown_and_omitted_ids_are_explicit_errors(self) -> None:
        raw = {
            "ranking": [
                {"candidate_id": "known-1", "rationale": "first"},
                {"candidate_id": "known-1", "rationale": "duplicate"},
                {"candidate_id": "unknown", "rationale": "bad"},
            ]
        }

        ordered, rationales, errors = parse_model_ranking(
            __import__("json").dumps(raw),
            ["known-1", "known-2"],
        )

        self.assertEqual(ordered, ["known-1", "known-2"])
        self.assertEqual(rationales["known-1"], "first")
        self.assertTrue(any("duplicate" in error for error in errors))
        self.assertTrue(any("unknown" in error for error in errors))
        self.assertTrue(any("omitted" in error for error in errors))

    def test_malformed_output_is_not_silently_corrected(self) -> None:
        ordered, rationales, errors = parse_model_ranking("not-json", ["a", "b"])

        self.assertEqual(ordered, ["a", "b"])
        self.assertEqual(rationales, {})
        self.assertTrue(any("malformed JSON" in error for error in errors))

    def test_provider_failure_is_recorded(self) -> None:
        result = rank_candidates_with_model(
            candidates=[candidate("a", "/a", "term")],
            scenario_id="case-a",
            trial_number=2,
            model_client=FakeModelClient(strategy="provider_failure"),
        )

        self.assertTrue(result.provider_failed)
        self.assertTrue(result.validation_errors)
        self.assertEqual(result.ordered_candidate_ids, ["a"])

    def test_timeout_is_recorded(self) -> None:
        result = rank_candidates_with_model(
            candidates=[candidate("a", "/a", "term")],
            scenario_id="case-a",
            trial_number=3,
            model_client=FakeModelClient(strategy="timeout"),
        )

        self.assertTrue(result.provider_failed)
        self.assertTrue(any("timeout" in error for error in result.validation_errors))
        self.assertEqual(result.ordered_candidate_ids, ["a"])

    def test_command_envelope_preserves_provider_metadata(self) -> None:
        completion = _completion_from_command_stdout(
            __import__("json").dumps(
                {
                    "provider": "example",
                    "model_identifier": "example-model",
                    "raw_response": '{"ranking":[]}',
                    "usage": {"input_tokens": 10, "output_tokens": 3},
                    "cost": {"estimated_usd": 0.01},
                    "latency_ms": 123,
                    "metadata": {"response_id": "resp_1"},
                }
            ),
            fallback_model_identifier="fallback",
            fallback_latency_ms=999,
        )

        self.assertEqual(completion.provider, "example")
        self.assertEqual(completion.model_identifier, "example-model")
        self.assertEqual(completion.raw_response, '{"ranking":[]}')
        self.assertEqual(completion.usage["input_tokens"], 10)
        self.assertEqual(completion.cost["estimated_usd"], 0.01)
        self.assertEqual(completion.latency_ms, 123)
        self.assertEqual(completion.metadata["response_id"], "resp_1")


def candidate(candidate_id: str, path: str, parameter_name: str) -> ReflectedInputCandidate:
    return ReflectedInputCandidate(
        candidate_id=candidate_id,
        page_url="http://127.0.0.1:4291/start",
        action_url=f"http://127.0.0.1:4291{path}",
        method="GET",
        parameter_name=parameter_name,
        source="get_form",
    )


if __name__ == "__main__":
    unittest.main()
