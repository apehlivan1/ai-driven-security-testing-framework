import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dev_benchmark_xss import DEFAULT_CONFIG_PATH, DEFAULT_OUTPUT_ROOT, evaluate_run_against_ground_truth


class DevelopmentBenchmarkXssTests(unittest.TestCase):
    def test_default_paths_are_repository_relative(self) -> None:
        self.assertTrue(DEFAULT_CONFIG_PATH.exists())
        self.assertEqual(DEFAULT_CONFIG_PATH.name, "reflected-dev-local.json")
        self.assertEqual(DEFAULT_OUTPUT_ROOT.name, ".adstf-runs")

    def test_post_run_evaluation_uses_separate_ground_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            evidence_dir = run_dir / "evidence"
            finding_dir = run_dir / "findings"
            evidence_dir.mkdir(parents=True)
            finding_dir.mkdir()
            ground_truth_path = Path(tmp) / "ground-truth.json"
            ground_truth_path.write_text(
                json.dumps(
                    {
                        "benchmark_id": "test-benchmark",
                        "cases": [
                            {"action_path": "/alpha", "parameter_name": "term", "vulnerable": True},
                            {"action_path": "/beta", "parameter_name": "item", "vulnerable": False},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (evidence_dir / "selected.json").write_text(
                json.dumps(
                    {
                        "evidence_type": "attack_surface_candidate",
                        "attributes": {
                            "rank": 1,
                            "score": 165,
                            "selected": True,
                            "candidate_id": "candidate-1",
                            "action_url": "http://127.0.0.1:4291/alpha",
                            "parameter_name": "term",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (evidence_dir / "other.json").write_text(
                json.dumps(
                    {
                        "evidence_type": "attack_surface_candidate",
                        "attributes": {
                            "rank": 2,
                            "score": 162,
                            "selected": False,
                            "candidate_id": "candidate-2",
                            "action_url": "http://127.0.0.1:4291/beta",
                            "parameter_name": "item",
                        },
                    }
                ),
                encoding="utf-8",
            )
            (finding_dir / "finding.json").write_text(
                json.dumps({"state": "verified"}),
                encoding="utf-8",
            )

            evaluation = evaluate_run_against_ground_truth(run_dir, ground_truth_path)

            self.assertEqual(evaluation["candidate_count"], 2)
            self.assertEqual(evaluation["vulnerable_candidate_count"], 1)
            self.assertTrue(evaluation["top_rank_is_vulnerable"])
            self.assertEqual(evaluation["verified_finding_count"], 1)
            self.assertEqual(evaluation["ground_truth_used_phase"], "post_run_evaluation_only")


if __name__ == "__main__":
    unittest.main()
