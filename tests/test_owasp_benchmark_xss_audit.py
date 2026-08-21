from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.audit_owasp_benchmark_xss import (
    ExpectedResult,
    classify_case,
    extract_source_info,
    parse_expected_results,
    ranking_scale,
    sanitized_action_path,
    validate_audit,
)


class OwaspBenchmarkXssAuditTests(unittest.TestCase):
    def test_expected_results_parsing_and_xss_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expectedresults-1.2.csv"
            path.write_text(
                "# test name, category, real vulnerability, cwe, Benchmark version: 1.2\n"
                "BenchmarkTest00001,pathtraver,true,22\n"
                "BenchmarkTest00013,xss,true,79\n"
                "BenchmarkTest00147,xss,false,79\n",
                encoding="utf-8",
            )
            rows = parse_expected_results(path)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row.case_id for row in rows if row.category == "xss"], ["BenchmarkTest00013", "BenchmarkTest00147"])

    def test_java_source_extraction_for_header_and_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
            source_dir.mkdir(parents=True)
            (source_dir / "BenchmarkTest00013.java").write_text(
                '@WebServlet(value = "/xss-00/BenchmarkTest00013")\n'
                "public class BenchmarkTest00013 extends HttpServlet {\n"
                "public void doGet(HttpServletRequest request, HttpServletResponse response) { doPost(request, response); }\n"
                "public void doPost(HttpServletRequest request, HttpServletResponse response) {\n"
                'response.setContentType("text/html;charset=UTF-8");\n'
                'String param = request.getHeader("Referer");\n'
                'param = java.net.URLDecoder.decode(param, "UTF-8");\n'
                'response.getWriter().print(param);\n'
                "}\n}\n",
                encoding="utf-8",
            )
            info = extract_source_info(root, "BenchmarkTest00013")
        self.assertEqual(info.endpoint, "/xss-00/BenchmarkTest00013")
        self.assertEqual(info.input_source, "header")
        self.assertEqual(info.parameter, "Referer")
        self.assertEqual(info.request_method, "GET_delegates_to_POST")

    def test_parameter_case_is_direct_with_current_framework(self) -> None:
        source = _source_info(input_source="parameter", request_method="GET_delegates_to_POST")
        row = classify_case(ExpectedResult("BenchmarkTest00360", "xss", "true", "79"), source, 1, "1.2", "abc")
        self.assertEqual(row["compatibility_class"], "DIRECT")
        self.assertEqual(row["current_framework_compatible"], "true")

    def test_query_string_case_is_direct_with_current_framework(self) -> None:
        source = _source_info(input_source="query_string", request_method="GET_delegates_to_POST")
        row = classify_case(ExpectedResult("BenchmarkTest00047", "xss", "true", "79"), source, 1, "1.2", "abc")
        self.assertEqual(row["compatibility_class"], "DIRECT")
        self.assertEqual(row["candidate_representation_support"], "current")

    def test_header_case_is_adapter_supported(self) -> None:
        source = _source_info(input_source="header", parameter="Referer", request_method="GET_delegates_to_POST")
        row = classify_case(ExpectedResult("BenchmarkTest00013", "xss", "true", "79"), source, 1, "1.2", "abc")
        self.assertEqual(row["compatibility_class"], "ADAPTER_SUPPORTED")
        self.assertEqual(row["required_adapter"], "header_input")
        self.assertIn("input_source_header", row["candidate_representation_gap"])

    def test_unknown_source_is_excluded_not_guessed(self) -> None:
        source = _source_info(input_source="unknown", parameter="unknown", request_method="unknown", endpoint="unknown")
        row = classify_case(ExpectedResult("BenchmarkTest99999", "xss", "false", "79"), source, 1, "1.2", "abc")
        self.assertEqual(row["compatibility_class"], "EXCLUDED")
        self.assertTrue(row["exclusion_reason"])

    def test_static_helper_value_is_excluded_as_no_external_input(self) -> None:
        source = _source_info(input_source="no_external_input", parameter="BenchmarkTest00879", request_method="GET_delegates_to_POST")
        row = classify_case(ExpectedResult("BenchmarkTest00879", "xss", "false", "79"), source, 1, "1.2", "abc")
        self.assertEqual(row["compatibility_class"], "EXCLUDED")
        self.assertEqual(row["exclusion_reason"], "no_externally_controllable_input_source")

    def test_deterministic_sanitized_ids_do_not_reveal_case_id(self) -> None:
        self.assertEqual(sanitized_action_path("/xss-00/BenchmarkTest00013", 13), "/external-v14/case-000013")

    def test_ranking_scale_balances_decoy_reuse(self) -> None:
        scale = ranking_scale(vulnerable_count=100, negative_count=25, pack_size=6, budget=4)
        self.assertEqual(scale["positive_ranking_scenarios"], 100)
        self.assertEqual(scale["required_negative_decoy_assignments"], 500)
        self.assertEqual(scale["maximum_negative_case_reuse_for_positive_scenarios"], 20)

    def test_validation_rejects_missing_non_direct_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
            source.mkdir(parents=True)
            (source / "BenchmarkTest00013.java").write_text("class X {}", encoding="utf-8")
            rows = [
                {
                    "benchmark_case_id": "BenchmarkTest00013",
                    "vulnerability_label": "xss",
                    "expected_result": "vulnerable",
                    "compatibility_class": "ADAPTER_SUPPORTED",
                    "incompatibility_reason": "",
                    "required_adapter": "header_input",
                    "exclusion_reason": "",
                    "source_file": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00013.java",
                    "sanitized_candidate_id": "ox14-c000001",
                    "sanitized_action_path": "/external-v14/case-000001",
                    "sanitized_parameter_name": "input_000001",
                    "retained_model_facing_fields": "opaque_candidate_id",
                }
            ]
            validation = validate_audit(rows, [ExpectedResult("BenchmarkTest00013", "xss", "true", "79")], root)
        self.assertFalse(validation["valid"])
        self.assertTrue(any("without incompatibility_reason" in error for error in validation["errors"]))


def _source_info(
    *,
    input_source: str,
    parameter: str = "BenchmarkTest00360",
    request_method: str,
    endpoint: str = "/xss-00/BenchmarkTest00360",
):
    from scripts.audit_owasp_benchmark_xss import SourceInfo

    return SourceInfo(
        source_file="src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00360.java",
        endpoint=endpoint,
        has_do_get=True,
        has_do_post=True,
        do_get_calls_do_post=request_method == "GET_delegates_to_POST",
        do_get_dispatches_form=False,
        request_method=request_method,
        input_source=input_source,
        parameter=parameter,
        content_type="text/html;charset=UTF-8",
        encoding_or_transform="none_identified",
        output_behavior="writer_print",
        authentication_required="not_identified",
        stateful_prerequisite="not_identified",
        extraction_notes=[],
    )


if __name__ == "__main__":
    unittest.main()
