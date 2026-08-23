from __future__ import annotations

import json
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from adstf.owasp_sqli_v15 import (
    DEFAULT_AUDIT_DIR,
    DEFAULT_BENCHMARK_ROOT,
    FALSE_PROBE_VALUE,
    READINESS_CLASSES,
    READINESS_PER_CLASS_PER_LABEL,
    TRUE_PROBE_VALUE,
    assign_evaluation_roles,
    build_request,
    construct_candidate,
    load_case_audit,
    parse_crawler_inputs,
    readiness_adapter_class,
    run_readiness,
    select_readiness_rows,
)


class OwaspSqliV15ReadinessTests(unittest.TestCase):
    def test_selects_stratified_readiness_subset_deterministically(self) -> None:
        rows = load_case_audit(DEFAULT_AUDIT_DIR / "case-audit.csv")
        first, first_notes = select_readiness_rows(rows)
        second, second_notes = select_readiness_rows(rows)

        expected_count = READINESS_PER_CLASS_PER_LABEL * len(READINESS_CLASSES) * 2
        self.assertEqual(first, second)
        self.assertEqual(first_notes, second_notes)
        self.assertEqual(len(first), expected_count)
        self.assertEqual(Counter(row["expected_result"] for row in first), {"vulnerable": 10, "non_vulnerable": 10})
        self.assertEqual(Counter(readiness_adapter_class(row) for row in first), {key: 4 for key in READINESS_CLASSES})

    def test_assigns_readiness_roles_without_consuming_all_adapter_supported_cases(self) -> None:
        rows = load_case_audit(DEFAULT_AUDIT_DIR / "case-audit.csv")
        selected, _notes = select_readiness_rows(rows)
        assigned = assign_evaluation_roles(rows, {row["benchmark_case_id"] for row in selected})

        self.assertEqual(sum(row["evaluation_role"] == "READINESS_ONLY" for row in assigned), 20)
        self.assertEqual(sum(row["evaluation_role"] == "FINAL_CONFIRMATORY_ELIGIBLE" for row in assigned), 200)
        self.assertEqual(sum(row["evaluation_role"] == "EXCLUDED" for row in assigned), 284)

    def test_constructed_candidates_keep_provenance_execution_and_ranker_data_separate(self) -> None:
        rows = load_case_audit(DEFAULT_AUDIT_DIR / "case-audit.csv")
        selected, _notes = select_readiness_rows(rows)
        assigned = assign_evaluation_roles(rows, {row["benchmark_case_id"] for row in selected})
        crawler_inputs = parse_crawler_inputs(DEFAULT_BENCHMARK_ROOT)

        for row in [item for item in assigned if item["evaluation_role"] == "READINESS_ONLY"]:
            candidate = construct_candidate(row, crawler_inputs[row["benchmark_case_id"]])
            model_facing = json.dumps(candidate.ranker_candidate.__dict__, sort_keys=True)
            self.assertIn(candidate.provenance.benchmark_case_id, json.dumps(candidate.provenance.__dict__))
            self.assertNotIn(candidate.provenance.benchmark_case_id, model_facing)
            self.assertNotIn(candidate.provenance.expected_result, model_facing)
            self.assertNotIn(candidate.provenance.source_file, model_facing)

    def test_build_request_supports_all_readiness_adapter_classes(self) -> None:
        rows = load_case_audit(DEFAULT_AUDIT_DIR / "case-audit.csv")
        selected, _notes = select_readiness_rows(rows)
        assigned = assign_evaluation_roles(rows, {row["benchmark_case_id"] for row in selected})
        crawler_inputs = parse_crawler_inputs(DEFAULT_BENCHMARK_ROOT)
        by_class = {}
        for row in [item for item in assigned if item["evaluation_role"] == "READINESS_ONLY"]:
            by_class.setdefault(readiness_adapter_class(row), construct_candidate(row, crawler_inputs[row["benchmark_case_id"]]))

        form_url, form_method, form_headers, form_body = build_request("https://127.0.0.1:8443/benchmark", by_class["form"].execution, TRUE_PROBE_VALUE)
        self.assertEqual(form_method, "POST")
        self.assertIn("Content-Type", form_headers)
        self.assertTrue(any(TRUE_PROBE_VALUE in values for values in parse_qs(form_body or "").values()))
        self.assertNotIn(TRUE_PROBE_VALUE, form_url)

        multi_url, multi_method, _multi_headers, multi_body = build_request("https://127.0.0.1:8443/benchmark", by_class["multi_query"].execution, FALSE_PROBE_VALUE)
        self.assertEqual(multi_method, "GET")
        self.assertIsNone(multi_body)
        self.assertTrue(any(FALSE_PROBE_VALUE in values for values in parse_qs(urlparse(multi_url).query).values()))

        header_url, header_method, header_headers, header_body = build_request("https://127.0.0.1:8443/benchmark", by_class["header"].execution, "probe")
        self.assertEqual(header_method, "GET")
        self.assertIsNone(header_body)
        self.assertTrue(header_headers)
        self.assertNotIn("probe", header_url)

        cookie_url, cookie_method, cookie_headers, cookie_body = build_request("https://127.0.0.1:8443/benchmark", by_class["cookie"].execution, "probe")
        self.assertEqual(cookie_method, "GET")
        self.assertIsNone(cookie_body)
        self.assertIn("Cookie", cookie_headers)
        self.assertNotIn("probe", cookie_url)

    def test_unreachable_readiness_run_still_preserves_package_and_no_scored_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            readiness = run_readiness(output_dir=Path(tmp), base_url="http://127.0.0.1:1/benchmark")
            root = Path(tmp)
            validation = json.loads((root / "validation-report.json").read_text(encoding="utf-8"))
            corpus = json.loads((root / "reconciled-corpus-summary.json").read_text(encoding="utf-8"))

            self.assertEqual(readiness["status"], "FAIL")
            self.assertTrue(validation["valid"])
            self.assertEqual(readiness["selected_case_count"], 20)
            self.assertEqual(corpus["readiness_only_count"], 20)
            self.assertEqual(corpus["final_confirmatory_eligible_count"], 200)
            self.assertFalse(readiness["final_confirmatory_cases_executed"])
            self.assertFalse(readiness["gpt_calls_executed"])
            self.assertFalse(readiness["qwen_calls_executed"])


if __name__ == "__main__":
    unittest.main()
