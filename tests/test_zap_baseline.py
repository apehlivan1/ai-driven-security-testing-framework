import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.zap_baseline import (
    ZAP_PASSIVE_MAPPING_VERSION,
    _combine_zap_reports,
    _scope_validation,
    extract_zap_alerts,
    load_zap_report,
    normalize_zap_passive_report,
)


FIXTURE_PATH = (
    Path(__file__).resolve().parent / "fixtures" / "zap" / "passive-xss-sqli-report.json"
)


class ZapPassiveBaselineTests(unittest.TestCase):
    def test_extracts_alert_instances_from_zap_json_report(self) -> None:
        report = load_zap_report(FIXTURE_PATH)

        alerts = extract_zap_alerts(report)

        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["name"], "Cross Site Scripting (Reflected)")
        self.assertEqual(alerts[0]["parameter"], "term")

    def test_normalizes_zap_alerts_to_case_level_baseline_results(self) -> None:
        report = load_zap_report(FIXTURE_PATH)

        summary = normalize_zap_passive_report(report, report_path=str(FIXTURE_PATH))

        self.assertEqual(summary["baseline_id"], "zap_passive")
        self.assertEqual(summary["mapping_version"], ZAP_PASSIVE_MAPPING_VERSION)
        self.assertEqual(summary["report_metadata"]["zap_report_version"], "2.16.1")
        self.assertEqual(summary["evaluated_case_count"], 6)
        self.assertEqual(summary["unsupported_case_count"], 2)
        self.assertEqual(summary["raw_alert_count"], 3)
        self.assertEqual(summary["matched_alert_count"], 2)
        self.assertEqual(summary["unmatched_alert_count"], 1)
        self.assertEqual(summary["counts"]["TP"], 2)
        self.assertEqual(summary["counts"]["FP"], 0)
        self.assertEqual(summary["counts"]["FN"], 2)
        self.assertEqual(summary["counts"]["TN"], 2)

        cases = {case["suite_case_id"]: case for case in summary["cases"]}
        self.assertEqual(cases["reflected-xss::case-a"]["classification"], "TP")
        self.assertEqual(cases["reflected-xss::case-b"]["classification"], "FN")
        self.assertEqual(cases["reflected-xss::case-c"]["classification"], "TN")
        self.assertEqual(cases["boolean-sqli::view-boolean"]["classification"], "TP")
        self.assertEqual(cases["boolean-sqli::safe-boolean"]["classification"], "TN")
        self.assertEqual(summary["unsupported_cases"][0]["evaluation_status"], "unsupported")

    def test_secure_case_alert_is_false_positive(self) -> None:
        report = {
            "alerts": [
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "instances": [
                        {
                            "uri": "http://127.0.0.1:4293/sqli/safe?item=1",
                            "param": "item",
                            "method": "GET",
                        }
                    ],
                }
            ]
        }

        summary = normalize_zap_passive_report(report)

        self.assertEqual(summary["counts"]["FP"], 1)
        cases = {case["suite_case_id"]: case for case in summary["cases"]}
        self.assertEqual(cases["boolean-sqli::safe-boolean"]["classification"], "FP")

    def test_combined_reports_preserve_scope_validation(self) -> None:
        first = {
            "@version": "2.16.1",
            "site": [
                {
                    "@name": "http://host.docker.internal:4291",
                    "alerts": [],
                }
            ],
        }
        second = {
            "@version": "2.16.1",
            "site": [
                {
                    "@name": "http://host.docker.internal:4293",
                    "alerts": [],
                }
            ],
        }

        combined = _combine_zap_reports([first, second])
        validation = _scope_validation(
            combined,
            [
                "http://host.docker.internal:4291/",
                "http://host.docker.internal:4293/sqli/health",
            ],
        )

        self.assertEqual(combined["source_report_count"], 2)
        self.assertTrue(validation["in_scope_only"])
        self.assertEqual(validation["out_of_scope_netlocs"], [])


if __name__ == "__main__":
    unittest.main()
