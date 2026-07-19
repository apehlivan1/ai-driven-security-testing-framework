import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.dev_benchmark_xss import DEFAULT_CONFIG_PATH, DEFAULT_OUTPUT_ROOT, evaluate_run_against_ground_truth
from adstf.discovery import DETERMINISTIC_RANKING_RULESET_VERSION


class DevelopmentBenchmarkXssTests(unittest.TestCase):
    def test_default_paths_are_repository_relative(self) -> None:
        self.assertTrue(DEFAULT_CONFIG_PATH.exists())
        self.assertEqual(DEFAULT_CONFIG_PATH.name, "reflected-dev-local.json")
        self.assertEqual(DEFAULT_OUTPUT_ROOT.name, ".adstf-runs")

    def test_post_run_evaluation_reports_ranking_and_verification_metrics(self) -> None:
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
                        "ranking_ruleset_version": DETERMINISTIC_RANKING_RULESET_VERSION,
                        "scenarios": [
                            {
                                "scenario_id": "case-a",
                                "cases": [
                                    {"action_path": "/alpha", "parameter_name": "term", "vulnerable": True},
                                    {"action_path": "/beta", "parameter_name": "item", "vulnerable": False},
                                ],
                            },
                            {
                                "scenario_id": "case-c",
                                "cases": [
                                    {"action_path": "/north", "parameter_name": "name", "vulnerable": False},
                                ],
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            _write_candidate(evidence_dir, "case-a", 1, "/beta", "item", selected=True)
            _write_candidate(evidence_dir, "case-a", 2, "/alpha", "term")
            _write_candidate(evidence_dir, "case-c", 1, "/north", "name", selected=True)
            _write_finding(finding_dir, "case-a", 1, "inconclusive")
            _write_finding(finding_dir, "case-a", 2, "verified")
            _write_finding(finding_dir, "case-c", 1, "inconclusive")

            evaluation = evaluate_run_against_ground_truth(run_dir, ground_truth_path)

            self.assertEqual(evaluation["scenario_count"], 2)
            baseline = evaluation["deterministic_baseline"]
            self.assertEqual(baseline["ranking_source"], "deterministic")
            self.assertEqual(baseline["top_1_accuracy"], 0.0)
            self.assertEqual(baseline["top_k_recall"], 1.0)
            self.assertEqual(baseline["mean_reciprocal_rank"], 0.5)
            self.assertEqual(baseline["no_vulnerability_scenario_count"], 1)
            self.assertEqual(baseline["no_vulnerability_false_positive_count"], 0)
            case_a = baseline["scenario_results"][0]
            case_c = baseline["scenario_results"][1]
            self.assertEqual(case_a["candidates_tested_before_verification"], 2)
            self.assertEqual(case_a["verified_finding_count"], 1)
            self.assertEqual(case_c["no_vulnerability_behavior"], "no_verified_findings")
            self.assertEqual(evaluation["ground_truth_used_phase"], "post_run_evaluation_only")


def _write_candidate(
    evidence_dir: Path,
    scenario_id: str,
    rank: int,
    action_path: str,
    parameter_name: str,
    *,
    selected: bool = False,
) -> None:
    (evidence_dir / f"{scenario_id}-{rank}.json").write_text(
        json.dumps(
            {
                "evidence_type": "attack_surface_candidate",
                "attributes": {
                    "scenario_id": scenario_id,
                    "test_budget": 2,
                    "rank": rank,
                    "score": 100 - rank,
                    "selected": selected,
                    "candidate_id": f"{scenario_id}-{rank}",
                    "action_url": f"http://127.0.0.1:4291{action_path}",
                    "parameter_name": parameter_name,
                },
            }
        ),
        encoding="utf-8",
    )


def _write_finding(finding_dir: Path, scenario_id: str, rank: int, state: str) -> None:
    (finding_dir / f"{scenario_id}-{rank}.json").write_text(
        json.dumps(
            {
                "state": state,
                "report_fields": {
                    "scenario_id": scenario_id,
                    "candidate_rank": rank,
                },
            }
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    unittest.main()
