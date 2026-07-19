import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.mvp_benchmark import normalize_mvp_results, render_mvp_report


class MvpBenchmarkTests(unittest.TestCase):
    def test_normalizes_xss_deterministic_scenarios(self) -> None:
        summary = normalize_mvp_results(
            [
                {
                    "name": "reflected-xss",
                    "module_id": "xss.reflected",
                    "category": "reflected_xss",
                    "target_name": "XSS Target",
                    "target_base_url": "http://127.0.0.1:4291",
                    "benchmark_id": "reflected-input-development",
                    "config_path": "examples/targets/reflected-dev-local.json",
                    "enabled_modules": ["xss.reflected"],
                    "max_actions": 20,
                    "settings": {},
                    "status": "completed",
                    "started_at": "2026-07-19T00:00:00+00:00",
                    "completed_at": "2026-07-19T00:00:01+00:00",
                    "duration_ms": 1000,
                    "run_dir": "run-xss",
                    "evaluation_artifact": "run-xss/artifacts/benchmark-evaluation.json",
                    "evaluation": {
                        "deterministic_baseline": {
                            "scenario_results": [
                                {
                                    "scenario_id": "case-a",
                                    "vulnerable_candidate_count": 1,
                                    "verified_finding_count": 1,
                                },
                                {
                                    "scenario_id": "case-c",
                                    "vulnerable_candidate_count": 0,
                                    "verified_finding_count": 0,
                                },
                            ]
                        }
                    },
                }
            ],
            started_at="2026-07-19T00:00:00+00:00",
            completed_at="2026-07-19T00:00:01+00:00",
            settings={},
        )

        self.assertEqual(summary["counts"]["TP"], 1)
        self.assertEqual(summary["counts"]["TN"], 1)
        self.assertEqual(summary["counts"]["FP"], 0)
        self.assertEqual(summary["counts"]["FN"], 0)

    def test_normalizes_verified_rejected_and_inconclusive_case_results(self) -> None:
        summary = normalize_mvp_results(
            [
                _slice_result(
                    "read-only-idor",
                    "access.idor_read_only",
                    [
                        {
                            "case_id": "open-cross-user",
                            "expected_vulnerable": True,
                            "finding_state": "verified",
                        },
                        {
                            "case_id": "guarded-cross-user",
                            "expected_vulnerable": False,
                            "finding_state": "rejected",
                        },
                        {
                            "case_id": "missing-vulnerable",
                            "expected_vulnerable": True,
                            "finding_state": "inconclusive",
                        },
                    ],
                )
            ],
            started_at="2026-07-19T00:00:00+00:00",
            completed_at="2026-07-19T00:00:01+00:00",
            settings={},
        )

        self.assertEqual(summary["counts"]["verified"], 1)
        self.assertEqual(summary["counts"]["rejected"], 1)
        self.assertEqual(summary["counts"]["inconclusive"], 1)
        self.assertEqual(summary["counts"]["TP"], 1)
        self.assertEqual(summary["counts"]["TN"], 1)
        self.assertEqual(summary["counts"]["FN"], 1)

    def test_renders_traditional_scanner_baselines_separately(self) -> None:
        summary = normalize_mvp_results(
            [],
            started_at="2026-07-19T00:00:00+00:00",
            completed_at="2026-07-19T00:00:01+00:00",
            settings={"traditional_scanner_enabled": True},
            baselines=[
                {
                    "baseline_id": "zap_passive",
                    "mapping_version": "zap-passive-mapping-v1",
                    "evaluated_case_count": 6,
                    "unsupported_case_count": 2,
                    "raw_alert_count": 3,
                    "matched_alert_count": 2,
                    "unmatched_alert_count": 1,
                    "counts": {"TP": 2, "FP": 0, "FN": 2, "TN": 2},
                }
            ],
        )

        report = render_mvp_report(summary)

        self.assertEqual(summary["baselines"][0]["baseline_id"], "zap_passive")
        self.assertIn("Traditional Scanner Baselines", report)
        self.assertIn("zap_passive", report)


def _slice_result(name: str, module_id: str, cases: list[dict]) -> dict:
    return {
        "name": name,
        "module_id": module_id,
        "category": "test_category",
        "target_name": "Target",
        "target_base_url": "http://127.0.0.1",
        "benchmark_id": "benchmark",
        "config_path": "target.json",
        "enabled_modules": [module_id],
        "max_actions": 20,
        "settings": {},
        "status": "completed",
        "started_at": "2026-07-19T00:00:00+00:00",
        "completed_at": "2026-07-19T00:00:01+00:00",
        "duration_ms": 1000,
        "run_dir": "run",
        "evaluation_artifact": "run/artifacts/evaluation.json",
        "evaluation": {"case_results": cases},
    }


if __name__ == "__main__":
    unittest.main()
