from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.contracts import ActionStatus, TargetConfig
from adstf.owasp_xss_v14 import (
    READINESS_INPUT_SOURCES,
    assign_evaluation_roles,
    build_value_request,
    construct_external_candidate,
    health_check,
    payload_for_marker,
    select_readiness_rows,
    target_config_for_url,
    validate_model_facing_candidate,
    validate_readiness_package,
)
from scripts.audit_owasp_benchmark_xss import ExpectedResult, SourceInfo, classify_case


class OwaspXssV14Tests(unittest.TestCase):
    def test_constructs_separate_provenance_execution_and_ranker_candidate(self) -> None:
        row = audit_row(
            case_id="BenchmarkTest00013",
            index=13,
            expected="true",
            input_source="header",
            parameter="Referer",
        )
        row["evaluation_role"] = "READINESS_ONLY"

        candidate = construct_external_candidate(row)

        self.assertEqual(candidate.provenance.benchmark_case_id, "BenchmarkTest00013")
        self.assertEqual(candidate.provenance.expected_result, "vulnerable")
        self.assertEqual(candidate.execution.input_name, "Referer")
        self.assertEqual(candidate.execution.transport, "header")
        serialized_ranker = json.dumps(candidate.ranker_candidate.__dict__, sort_keys=True)
        self.assertNotIn("BenchmarkTest", serialized_ranker)
        self.assertNotIn("vulnerable", serialized_ranker)
        self.assertNotIn("Referer", serialized_ranker)

    def test_direct_parameter_transport_places_payload_in_query_parameter(self) -> None:
        candidate = construct_external_candidate(
            audit_row(case_id="BenchmarkTest00360", index=1, expected="true", input_source="parameter")
        )

        url, headers = build_value_request("https://127.0.0.1:8443/benchmark", candidate.execution, "VALUE")

        self.assertEqual(headers, {})
        self.assertEqual(urlparse(url).path, "/benchmark/xss-00/BenchmarkTest00360")
        self.assertEqual(dict(parse_qsl(urlparse(url).query)), {"BenchmarkTest00360": "VALUE"})

    def test_parameter_map_transport_uses_original_parameter_name(self) -> None:
        candidate = construct_external_candidate(
            audit_row(case_id="BenchmarkTest00400", index=2, expected="false", input_source="parameter_map")
        )

        url, headers = build_value_request("https://127.0.0.1:8443/benchmark", candidate.execution, "VALUE")

        self.assertEqual(headers, {})
        self.assertEqual(dict(parse_qsl(urlparse(url).query)), {"BenchmarkTest00400": "VALUE"})

    def test_query_string_transport_uses_original_parameter_name(self) -> None:
        candidate = construct_external_candidate(
            audit_row(case_id="BenchmarkTest00047", index=3, expected="true", input_source="query_string")
        )

        url, headers = build_value_request("https://127.0.0.1:8443/benchmark", candidate.execution, "VALUE")

        self.assertEqual(headers, {})
        self.assertEqual(dict(parse_qsl(urlparse(url).query)), {"BenchmarkTest00047": "VALUE"})

    def test_header_transport_places_payload_in_header_not_url(self) -> None:
        candidate = construct_external_candidate(
            audit_row(
                case_id="BenchmarkTest00013",
                index=4,
                expected="true",
                input_source="header",
                parameter="Referer",
            )
        )

        url, headers = build_value_request("https://127.0.0.1:8443/benchmark", candidate.execution, "VALUE")

        self.assertEqual(urlparse(url).query, "")
        self.assertEqual(headers, {"Referer": "https://adstf.local/VALUE"})

    def test_parameter_name_enumeration_uses_marker_as_name_and_case_id_as_value(self) -> None:
        candidate = construct_external_candidate(
            audit_row(
                case_id="BenchmarkTest00036",
                index=5,
                expected="true",
                input_source="parameter_name_enumeration",
                parameter="dynamic_parameter_name",
            )
        )

        url, headers = build_value_request("https://127.0.0.1:8443/benchmark", candidate.execution, "MARKER")

        self.assertEqual(headers, {})
        self.assertEqual(dict(parse_qsl(urlparse(url).query)), {"MARKER": "BenchmarkTest00036"})

    def test_payload_and_control_are_deterministic_and_benign_control_contains_no_script(self) -> None:
        payload = payload_for_marker("marker")

        self.assertEqual(payload, "<script>window.__adstfXssMarker='marker'</script> ")
        self.assertNotIn("<script>", "control_marker")

    def test_selection_is_stratified_and_deterministic(self) -> None:
        rows = []
        index = 1
        for source in READINESS_INPUT_SOURCES:
            for expected in ("true", "false"):
                for suffix in range(3):
                    rows.append(
                        audit_row(
                            case_id=f"BenchmarkTest{index:05d}",
                            index=index,
                            expected=expected,
                            input_source=source,
                            parameter="Referer" if source == "header" else f"BenchmarkTest{index:05d}",
                        )
                    )
                    index += 1

        first, first_notes = select_readiness_rows(rows)
        second, second_notes = select_readiness_rows(rows)

        self.assertEqual([row["benchmark_case_id"] for row in first], [row["benchmark_case_id"] for row in second])
        self.assertEqual(first_notes, second_notes)
        self.assertEqual(len(first), 20)

    def test_assign_evaluation_roles_keeps_compatibility_separate(self) -> None:
        rows = [
            audit_row(case_id="BenchmarkTest00001", index=1, expected="true", input_source="parameter"),
            audit_row(case_id="BenchmarkTest00002", index=2, expected="false", input_source="header", parameter="Referer"),
            excluded_row(case_id="BenchmarkTest00003"),
        ]

        assigned = assign_evaluation_roles(rows, {"BenchmarkTest00002"})

        roles = {row["benchmark_case_id"]: row["evaluation_role"] for row in assigned}
        self.assertEqual(roles["BenchmarkTest00001"], "FINAL_CONFIRMATORY_ELIGIBLE")
        self.assertEqual(roles["BenchmarkTest00002"], "READINESS_ONLY")
        self.assertEqual(roles["BenchmarkTest00003"], "EXCLUDED")
        self.assertEqual(assigned[1]["compatibility_class"], "ADAPTER_SUPPORTED")

    def test_target_config_is_local_and_reflected_xss_only(self) -> None:
        target = target_config_for_url("https://127.0.0.1:8443/benchmark")

        self.assertEqual(target.allowed_hosts, ["127.0.0.1"])
        self.assertEqual(target.allowed_ports, [8443])
        self.assertEqual(target.allowed_schemes, ["https"])
        self.assertEqual(target.enabled_modules, ["xss.reflected"])

    def test_health_check_falls_back_to_playwright_probe_on_tls_probe_failure(self) -> None:
        with patch("adstf.owasp_xss_v14.urlopen", side_effect=OSError("tls failed")):
            with patch(
                "adstf.owasp_xss_v14.playwright_health_check",
                return_value={
                    "reachable": True,
                    "status": 200,
                    "url": "https://127.0.0.1:8443/benchmark/",
                    "started_at": "fallback-start",
                    "completed_at": "fallback-end",
                    "error": None,
                    "method": "playwright_ignore_https_errors",
                },
            ):
                result = health_check("https://127.0.0.1:8443/benchmark")

        self.assertTrue(result["reachable"])
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["method"], "playwright_ignore_https_errors")
        self.assertIn("tls failed", result["primary_error"])

    def test_model_facing_candidate_rejects_benchmark_identity_leakage(self) -> None:
        candidate = construct_external_candidate(
            audit_row(case_id="BenchmarkTest00013", index=13, expected="true", input_source="parameter")
        ).ranker_candidate
        leaked = candidate.__class__(
            candidate_id=candidate.candidate_id,
            action_path="/BenchmarkTest00013",
            method=candidate.method,
            parameter_name=candidate.parameter_name,
            source=candidate.source,
            input_type=candidate.input_type,
            editable_input_count=candidate.editable_input_count,
            required_input_count=candidate.required_input_count,
            parameter_count=candidate.parameter_count,
        )

        with self.assertRaises(ValueError):
            validate_model_facing_candidate(leaked)

    def test_readiness_validation_detects_ground_truth_leakage_in_preview(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sanitized-candidate-preview.json").write_text(
                '[{"candidate_id":"ox14-c000001","action_path":"/BenchmarkTest00001"}]',
                encoding="utf-8",
            )
            readiness = {
                "selected_case_count": 20,
                "selected_case_ids": ["BenchmarkTest00001"],
                "final_confirmatory_cases_executed": False,
                "gpt_calls_executed": False,
                "qwen_calls_executed": False,
                "status": "PASS",
            }
            assigned_rows = [
                {
                    "benchmark_case_id": "BenchmarkTest00001",
                    "evaluation_role": "READINESS_ONLY",
                }
            ]

            validation = validate_readiness_package(root, readiness, assigned_rows)

        self.assertFalse(validation["valid"])
        self.assertTrue(any("leaks forbidden fragment" in error for error in validation["errors"]))


def audit_row(
    *,
    case_id: str,
    index: int,
    expected: str,
    input_source: str,
    parameter: str | None = None,
) -> dict[str, str]:
    source = SourceInfo(
        source_file=f"src/main/java/org/owasp/benchmark/testcode/{case_id}.java",
        endpoint=f"/xss-00/{case_id}",
        has_do_get=True,
        has_do_post=True,
        do_get_calls_do_post=True,
        do_get_dispatches_form=False,
        request_method="GET_delegates_to_POST",
        input_source=input_source,
        parameter=parameter or case_id,
        content_type="text/html;charset=UTF-8",
        encoding_or_transform="none_identified",
        output_behavior="writer_print",
        authentication_required="not_identified",
        stateful_prerequisite="not_identified",
        extraction_notes=[],
    )
    return classify_case(ExpectedResult(case_id, "xss", expected, "79"), source, index, "1.2", "revision")


def excluded_row(*, case_id: str) -> dict[str, str]:
    row = audit_row(case_id=case_id, index=99, expected="false", input_source="no_external_input")
    row["compatibility_class"] = "EXCLUDED"
    row["exclusion_reason"] = "no_externally_controllable_input_source"
    row["eligible_for_external_ranking"] = "false"
    row["eligible_for_direct_external_execution"] = "false"
    row["sanitized_candidate_id"] = ""
    return row


if __name__ == "__main__":
    unittest.main()
