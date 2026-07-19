import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dev_benchmark_sqli import DEFAULT_CONFIG_PATH, DEFAULT_OUTPUT_ROOT, evaluate_run_against_ground_truth


class DevelopmentBenchmarkSqliTests(unittest.TestCase):
    def test_default_paths_are_repository_relative(self) -> None:
        self.assertTrue(DEFAULT_CONFIG_PATH.exists())
        self.assertEqual(DEFAULT_CONFIG_PATH.name, "sqli-dev-local.json")
        self.assertEqual(DEFAULT_OUTPUT_ROOT.name, ".adstf-runs")

    def test_post_run_evaluation_distinguishes_verified_and_rejected_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            finding_dir = run_dir / "findings"
            finding_dir.mkdir(parents=True)
            ground_truth_path = Path(tmp) / "ground-truth.json"
            ground_truth_path.write_text(
                json.dumps(
                    {
                        "benchmark_id": "sqli-test",
                        "cases": [
                            {
                                "case_id": "view-boolean",
                                "path": "/sqli/view",
                                "parameter": "item",
                                "vulnerable": True,
                            },
                            {
                                "case_id": "safe-boolean",
                                "path": "/sqli/safe",
                                "parameter": "item",
                                "vulnerable": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _write_finding(finding_dir, "view-boolean", "verified")
            _write_finding(finding_dir, "safe-boolean", "rejected")

            evaluation = evaluate_run_against_ground_truth(run_dir, ground_truth_path)

            self.assertEqual(evaluation["verified_finding_count"], 1)
            self.assertEqual(evaluation["rejected_finding_count"], 1)
            self.assertEqual(evaluation["ground_truth_match_count"], 2)
            self.assertEqual(evaluation["ground_truth_mismatch_count"], 0)
            self.assertEqual(evaluation["ground_truth_used_phase"], "post_run_evaluation_only")


def _write_finding(finding_dir: Path, case_id: str, state: str) -> None:
    (finding_dir / f"{case_id}.json").write_text(
        json.dumps({"state": state, "report_fields": {"case_id": case_id}}),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
