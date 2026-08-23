from __future__ import annotations

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.audit_owasp_benchmark_sqli import (
    COMPATIBILITY_CLASSES,
    DEFAULT_BENCHMARK_ROOT,
    FORBIDDEN_MODELFACING_FRAGMENTS,
    build_case_audit,
    summarize,
    validate_audit,
    write_outputs,
)


class OwaspSqliV15CompatibilityAuditTests(unittest.TestCase):
    def test_audits_all_sqli_cases_with_expected_static_counts(self) -> None:
        rows, context = build_case_audit(DEFAULT_BENCHMARK_ROOT)
        summary = summarize(rows, context["provenance"])
        validation = validate_audit(rows, context["all_expected_results"], DEFAULT_BENCHMARK_ROOT)

        self.assertTrue(validation["valid"])
        self.assertEqual(summary["total_sqli"], 504)
        self.assertEqual(summary["vulnerable_sqli"], 272)
        self.assertEqual(summary["non_vulnerable_sqli"], 232)
        self.assertEqual(summary["compatibility_distribution"]["DIRECT"]["total"], 0)
        self.assertEqual(summary["compatibility_distribution"]["ADAPTER_SUPPORTED"]["total"], 220)
        self.assertEqual(summary["compatibility_distribution"]["DERIVED_ADAPTED"]["total"], 0)
        self.assertEqual(summary["compatibility_distribution"]["EXCLUDED"]["total"], 127)
        self.assertEqual(summary["compatibility_distribution"]["MANUAL_REVIEW"]["total"], 157)
        self.assertEqual(summary["eligible_original_external_evaluation"], 220)
        self.assertEqual(summary["eligible_candidate_ranking"], 220)

    def test_counts_reconcile_with_pinned_expected_results_and_crawler_metadata(self) -> None:
        rows, context = build_case_audit(DEFAULT_BENCHMARK_ROOT)
        ids = [row["benchmark_case_id"] for row in rows]
        expected_sqli_ids = [row.case_id for row in context["all_expected_results"] if row.category == "sqli"]

        self.assertEqual(sorted(ids), sorted(expected_sqli_ids))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(sum(row["expected_result"] == "vulnerable" for row in rows), 272)
        self.assertEqual(sum(row["expected_result"] == "non_vulnerable" for row in rows), 232)
        self.assertEqual({row["compatibility_class"] for row in rows}, COMPATIBILITY_CLASSES - {"DIRECT", "DERIVED_ADAPTED"})

    def test_non_destructive_rules_exclude_write_and_stored_procedure_cases(self) -> None:
        rows, _context = build_case_audit(DEFAULT_BENCHMARK_ROOT)
        for row in rows:
            if row["read_write_category"] in {"write_or_state_changing", "stored_procedure_ambiguous"}:
                self.assertNotIn(row["compatibility_class"], {"DIRECT", "ADAPTER_SUPPORTED"})
                self.assertEqual(row["eligible_original_external_evaluation"], "false")
                self.assertEqual(row["eligible_candidate_ranking"], "false")

    def test_model_facing_preview_does_not_expose_ground_truth_or_benchmark_identity(self) -> None:
        rows, _context = build_case_audit(DEFAULT_BENCHMARK_ROOT)
        for row in rows:
            preview = row["model_facing_preview"]
            if not preview:
                continue
            parsed = json.loads(preview)
            self.assertEqual(sorted(parsed.keys()), sorted(row["retained_model_facing_fields"].split(";")))
            forbidden = [
                row["benchmark_case_id"],
                row["source_file"],
                row["expected_result"],
                row["vulnerability_label"],
                row["sql_operation_category"],
                *FORBIDDEN_MODELFACING_FRAGMENTS,
            ]
            for fragment in forbidden:
                self.assertNotIn(fragment, preview)

    def test_write_outputs_produces_valid_non_scored_audit_package(self) -> None:
        rows, context = build_case_audit(DEFAULT_BENCHMARK_ROOT)
        summary = summarize(rows, context["provenance"])
        with tempfile.TemporaryDirectory() as tmp:
            validation = write_outputs(rows, context["all_expected_results"], summary, Path(tmp), DEFAULT_BENCHMARK_ROOT)
            root = Path(tmp)
            checksum_validation = json.loads((root / "checksum-validation-report.json").read_text(encoding="utf-8"))
            with (root / "case-audit.csv").open(newline="", encoding="utf-8") as handle:
                audit_rows = list(csv.DictReader(handle))

            self.assertTrue(validation["valid"])
            self.assertTrue(checksum_validation["valid"])
            self.assertEqual(len(audit_rows), 504)
            self.assertEqual(validation["runtime_execution_counts"]["sqli_runtime_executions"], 0)
            self.assertEqual(validation["runtime_execution_counts"]["gpt_calls"], 0)
            self.assertEqual(validation["runtime_execution_counts"]["qwen_calls"], 0)


if __name__ == "__main__":
    unittest.main()
