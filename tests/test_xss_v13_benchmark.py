import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.discovery import discover_reflected_input_candidates
from adstf.xss_v13_benchmark import (
    DEFAULT_BASE_URL,
    DEFAULT_GROUND_TRUTH_PATH,
    DEFAULT_MANIFEST_PATH,
    DEFAULT_TARGET_CONFIG_PATH,
    SCENARIOS,
    neutral_name_errors,
    render_v13_xss_response,
    validate_xss_v13_structure,
)


class XssV13BenchmarkTests(unittest.TestCase):
    def test_manifest_contains_exactly_24_scenarios_with_16_vulnerable_and_8_negative(self) -> None:
        manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))

        self.assertEqual(manifest["scenario_count"], 24)
        self.assertEqual(manifest["vulnerable_scenario_count"], 16)
        self.assertEqual(manifest["negative_scenario_count"], 8)
        self.assertEqual(len(manifest["scenarios"]), 24)
        self.assertEqual(
            [scenario["id"] for scenario in manifest["scenarios"]],
            [scenario.scenario_id for scenario in SCENARIOS],
        )

    def test_all_scenarios_discover_between_4_and_8_candidates(self) -> None:
        manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
        counts = []
        for scenario in manifest["scenarios"]:
            candidates = []
            for seed_path in scenario["seed_paths"]:
                parsed = urlparse(urljoin(f"{DEFAULT_BASE_URL.rstrip('/')}/", seed_path))
                status, body, _ = render_v13_xss_response(parsed.path, parsed.query)
                self.assertEqual(status, 200)
                candidates.extend(discover_reflected_input_candidates(parsed.geturl(), body))
            counts.append(len(candidates))
            self.assertGreaterEqual(len(candidates), 4, scenario["id"])
            self.assertLessEqual(len(candidates), 8, scenario["id"])
            self.assertEqual(len(candidates), scenario["candidate_count"])

        self.assertEqual(min(counts), 4)
        self.assertEqual(max(counts), 8)

    def test_neutral_names_do_not_encode_expected_outcomes(self) -> None:
        manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))

        self.assertEqual(neutral_name_errors(), [])
        for scenario in manifest["scenarios"]:
            for seed_path in scenario["seed_paths"]:
                parsed = urlparse(seed_path)
                self.assertNotIn("xss", parsed.path.lower())
                self.assertNotIn("vuln", parsed.path.lower())
                self.assertNotIn("safe", parsed.path.lower())
                self.assertNotIn("control", parsed.path.lower())
                self.assertNotIn("negative", parsed.path.lower())

    def test_structural_validation_does_not_semantically_load_ground_truth(self) -> None:
        with patch("adstf.xss_v13_benchmark.load_xss_v13_ground_truth", side_effect=AssertionError("ground truth loaded")):
            result = validate_xss_v13_structure()

        self.assertTrue(result["valid"], result["errors"])
        self.assertFalse(result["ground_truth_semantics_loaded"])
        self.assertIsNotNone(result["ground_truth_sha256"])

    def test_ground_truth_is_separate_from_manifest_and_target_config(self) -> None:
        manifest = json.loads(DEFAULT_MANIFEST_PATH.read_text(encoding="utf-8"))
        target = json.loads(DEFAULT_TARGET_CONFIG_PATH.read_text(encoding="utf-8"))
        truth = json.loads(DEFAULT_GROUND_TRUTH_PATH.read_text(encoding="utf-8"))

        self.assertFalse(manifest["ground_truth_available_to_framework"])
        self.assertEqual(manifest["ground_truth_path"], "examples/benchmarks/xss-v13-ground-truth.json")
        self.assertEqual(target["metadata"]["ground_truth_path"], "examples/benchmarks/xss-v13-ground-truth.json")
        self.assertIn("cases", truth["scenarios"][0])
        self.assertNotIn("cases", manifest["scenarios"][0])

    def test_health_and_reset_endpoints_render_without_stateful_side_effects(self) -> None:
        status, body, headers = render_v13_xss_response("/suite-v13/health")
        self.assertEqual(status, 200)
        self.assertIn("ok", body)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")

        status, body, _ = render_v13_xss_response("/suite-v13/reset")
        self.assertEqual(status, 200)
        self.assertIn("state reset", body)

        status, body, _ = render_v13_xss_response("/suite-v13/x13-001/health")
        self.assertEqual(status, 200)
        self.assertIn("x13-001 ok", body)

    def test_structural_validation_summary_contract(self) -> None:
        result = validate_xss_v13_structure()

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["scenario_count"], 24)
        self.assertEqual(result["outcome_counts"], {"vulnerable": 16, "negative": 8})
        self.assertEqual(result["candidate_count_min"], 4)
        self.assertEqual(result["candidate_count_max"], 8)
        self.assertEqual(
            result["candidate_count_distribution"],
            {"4": 4, "5": 5, "6": 8, "7": 4, "8": 3},
        )


if __name__ == "__main__":
    unittest.main()
