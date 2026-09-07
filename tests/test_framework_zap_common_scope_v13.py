from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.framework_zap_common_scope_v13 import (  # noqa: E402
    EXPECTED_BY_CATEGORY,
    EXPECTED_BY_CATEGORY_AND_LABEL,
    EXPECTED_TOTAL_CASES,
    COMMON_SQLI_ADAPTERS,
    COMMON_XSS_SOURCES,
    DEFAULT_OUTPUT_DIR,
    CommonScopeError,
    prepare_protocol,
    require_prepared_protocol,
    select_cases,
    validate_protocol,
    zap_rule_for_case,
    zap_target_for_case,
)
from adstf.zap_baseline import _alert_matches_rule  # noqa: E402


class FrameworkZapCommonScopeV13Tests(unittest.TestCase):
    def test_selects_fifty_cases_with_frozen_strata(self) -> None:
        selected = select_cases()

        self.assertEqual(len(selected), EXPECTED_TOTAL_CASES)
        self.assertEqual(
            counts(row["category"] for row in selected),
            EXPECTED_BY_CATEGORY,
        )
        self.assertEqual(
            counts((row["category"], row["expected_result"]) for row in selected),
            EXPECTED_BY_CATEGORY_AND_LABEL,
        )
        self.assertEqual(len({row["case_key"] for row in selected}), EXPECTED_TOTAL_CASES)
        self.assertEqual([row["selection_sequence"] for row in selected], list(range(1, 51)))

    def test_common_scope_selection_excludes_header_cookie_and_form_only_cases(self) -> None:
        selected = select_cases()

        self.assertTrue(
            all(row["source"] in COMMON_XSS_SOURCES for row in selected if row["category"] == "reflected_xss")
        )
        self.assertTrue(
            all(row["transport"] in COMMON_SQLI_ADAPTERS for row in selected if row["category"] == "boolean_sqli")
        )

    def test_prepare_protocol_keeps_runtime_selection_ground_truth_free(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            validation = prepare_protocol(root)

            self.assertTrue(validation["valid"], validation["errors"])
            selected_text = (root / "selected-cases.json").read_text(encoding="utf-8")
            execution_text = (root / "execution" / "framework-execution-specifications.json").read_text(encoding="utf-8")
            self.assertNotIn("expected_result", selected_text)
            self.assertNotIn("vulnerable", selected_text)
            self.assertNotIn("non_vulnerable", selected_text)
            self.assertNotIn("expected_result", execution_text)
            scoring = json.loads((root / "ground-truth" / "scoring-data.json").read_text(encoding="utf-8"))
            self.assertEqual(len(scoring["candidate_ground_truth"]), EXPECTED_TOTAL_CASES)

    def test_refuses_to_prepare_over_existing_nonempty_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "existing.txt").write_text("existing", encoding="utf-8")

            with self.assertRaises(CommonScopeError):
                prepare_protocol(root)

    def test_prepared_protocol_validation_is_required_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            with self.assertRaises(CommonScopeError):
                require_prepared_protocol(root)

    def test_protocol_does_not_target_existing_v12_artifact_directories(self) -> None:
        self.assertNotIn("heldout-evaluation-v1.2", str(DEFAULT_OUTPUT_DIR))
        self.assertNotIn("heldout", str(DEFAULT_OUTPUT_DIR))

    def test_dynamic_zap_rule_matches_only_selected_case_family_path_and_parameter(self) -> None:
        selected = select_cases()
        case = next(row for row in selected if row["category"] == "boolean_sqli")
        truth = {"expected_result": case["expected_result"]}
        rule = zap_rule_for_case(case, truth)
        alert = {
            "name": "SQL Injection",
            "url": f"https://host.docker.internal:8443{rule.path}?{rule.parameter}=seed",
            "parameter": rule.parameter,
        }

        self.assertTrue(_alert_matches_rule(alert, rule))

        wrong_family = dict(alert)
        wrong_family["name"] = "Cross Site Scripting (Reflected)"
        self.assertFalse(_alert_matches_rule(wrong_family, rule))

    def test_zap_targets_resolve_from_ground_truth_free_selected_case_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            prepare_protocol(root)
            selected = json.loads((root / "selected-cases.json").read_text(encoding="utf-8"))["cases"]

            target = zap_target_for_case(selected[0])

            self.assertIn("target_url", target)
            self.assertIn(selected[0]["parameter"], target["target_url"])


def counts(values):
    output = {}
    for value in values:
        output[value] = output.get(value, 0) + 1
    return output


if __name__ == "__main__":
    unittest.main()
