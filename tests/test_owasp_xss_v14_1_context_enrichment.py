from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.owasp_xss_v14_1_context_enrichment import (  # noqa: E402
    CONTEXT_ENRICHMENT_MARKER,
    EnrichmentLeakageError,
    abstract_minimal_snapshot,
    build_context_enrichment_readiness_package,
    collect_benign_context_observations,
    categorize_content_type,
    categorize_reflection_count,
    classify_marker_preservation,
    classify_reflection_context,
    enrich_snapshot,
    enriched_rankings,
    marker_policy,
    observation_from_http_response,
    prepare_collection_plan_without_ground_truth,
    validate_marker,
    validate_ranker_facing_snapshot,
    validate_v14_structural_equality,
)


class OwaspXssV141ContextEnrichmentTests(unittest.TestCase):
    def test_marker_policy_uses_inert_fixed_marker(self) -> None:
        policy = marker_policy()

        self.assertEqual(policy["marker"], CONTEXT_ENRICHMENT_MARKER)
        self.assertTrue(validate_marker(policy["marker"]))
        for forbidden in ["<", ">", "'", '"', "\n", "\r", "\t"]:
            self.assertNotIn(forbidden, policy["marker"])
        self.assertFalse(policy["executable_syntax"])

    def test_reflection_presence_and_count_categories_are_deterministic(self) -> None:
        marker = CONTEXT_ENRICHMENT_MARKER

        self.assertEqual(categorize_reflection_count(0), "0")
        self.assertEqual(categorize_reflection_count(1), "1")
        self.assertEqual(categorize_reflection_count(2), "2")
        self.assertEqual(categorize_reflection_count(3), "3_or_more")
        self.assertEqual(observation_from_http_response("", "text/html")["reflection_count_category"], "0")
        self.assertEqual(
            observation_from_http_response(f"{marker} {marker} {marker} {marker}", "text/html")[
                "reflection_count_category"
            ],
            "3_or_more",
        )

    def test_reflection_context_categories(self) -> None:
        marker = CONTEXT_ENRICHMENT_MARKER

        self.assertEqual(classify_reflection_context(f"<p>{marker}</p>", marker), "html_text")
        self.assertEqual(classify_reflection_context(f"<input value=\"{marker}\">", marker), "html_attribute")
        self.assertEqual(classify_reflection_context(f"<script>var value='{marker}';</script>", marker), "script_like")
        self.assertEqual(classify_reflection_context(f"<a href=\"https://example.test/{marker}\">x</a>", marker), "url_like")
        self.assertEqual(classify_reflection_context("no marker here", marker), "none")

    def test_multi_context_reflection_uses_declared_precedence_independent_of_count(self) -> None:
        marker = CONTEXT_ENRICHMENT_MARKER
        body = f"<p>{marker}</p><script>var marker='{marker}';</script>"

        observation = observation_from_http_response(body, "text/html")

        self.assertEqual(observation["reflection_context_category"], "script_like")
        self.assertEqual(observation["reflection_count_category"], "2")

    def test_url_like_precedes_attribute_when_multiple_occurrences_are_present(self) -> None:
        marker = CONTEXT_ENRICHMENT_MARKER
        body = f"<input value=\"{marker}\"><a href=\"https://example.test/{marker}\">x</a>"

        observation = observation_from_http_response(body, "text/html")

        self.assertEqual(observation["reflection_context_category"], "url_like")
        self.assertEqual(observation["reflection_count_category"], "2")

    def test_marker_preservation_categories(self) -> None:
        marker = "ADSTF_CTX_V141/SAFE"

        self.assertEqual(classify_marker_preservation(f"prefix {marker} suffix", marker), "unchanged")
        self.assertEqual(classify_marker_preservation("ADSTF_CTX_V141%2FSAFE", marker), "encoded")
        self.assertEqual(classify_marker_preservation("ADSTF_CTX_V141 SAFE", marker), "transformed")
        self.assertEqual(classify_marker_preservation("nothing related", marker), "stripped")
        self.assertEqual(classify_marker_preservation("nothing related", marker, reflected=False), "not_reflected")

    def test_observation_from_response_reports_transformed_marker_tokens(self) -> None:
        marker = CONTEXT_ENRICHMENT_MARKER
        body = "The marker appears as ADSTF CTX V141 SAFE after transport normalization."

        observation = observation_from_http_response(body, "text/plain", marker=marker)

        self.assertTrue(observation["reflection_detected"])
        self.assertEqual(observation["reflection_count_category"], "1")
        self.assertEqual(observation["marker_preservation_category"], "transformed")
        self.assertEqual(observation["reflection_context_category"], "other")

    def test_content_type_categorization(self) -> None:
        self.assertEqual(categorize_content_type("text/html; charset=utf-8"), "html")
        self.assertEqual(categorize_content_type("application/json"), "json")
        self.assertEqual(categorize_content_type("text/plain"), "text")
        self.assertEqual(categorize_content_type(""), "not_available")
        self.assertEqual(categorize_content_type("application/octet-stream"), "other")

    def test_abstracted_snapshot_preserves_candidate_ids_order_and_removes_path_names(self) -> None:
        snapshot = {
            "scenario_id": "ow14-test",
            "candidate_count": 2,
            "candidate_test_budget": 4,
            "top_k": 2,
            "candidate_input": [
                {
                    "candidate_id": "ox14-c000001",
                    "action_path": "/external-v14/case-000001",
                    "method": "GET",
                    "parameter_name": "input_000001",
                    "source": "request_parameter",
                    "input_type": "text",
                    "editable_input_count": 1,
                    "required_input_count": 0,
                    "parameter_count": 1,
                },
                {
                    "candidate_id": "ox14-c000002",
                    "action_path": "/external-v14/case-000002",
                    "method": "GET",
                    "parameter_name": "header_000002",
                    "source": "request_header",
                    "input_type": "header",
                    "editable_input_count": 1,
                    "required_input_count": 0,
                    "parameter_count": 1,
                },
            ],
        }

        abstracted = abstract_minimal_snapshot(snapshot)

        self.assertEqual([item["candidate_id"] for item in abstracted["candidate_input"]], ["ox14-c000001", "ox14-c000002"])
        self.assertNotIn("action_path", abstracted["candidate_input"][0])
        self.assertNotIn("parameter_name", abstracted["candidate_input"][0])
        self.assertEqual(abstracted["candidate_input"][0]["input_carrier_category"], "query_parameter")
        self.assertEqual(abstracted["candidate_input"][1]["input_carrier_category"], "header")
        validate_ranker_facing_snapshot(abstracted)

    def test_leakage_validator_rejects_ground_truth_raw_paths_and_case_identity(self) -> None:
        clean = {
            "schema_version": "ow14-1-minimal-candidate-snapshot-v1",
            "scenario_id": "ow14-s0001",
            "candidate_input": [
                {
                    "candidate_id": "ox14-c000001",
                    "http_method": "GET",
                    "input_carrier_category": "query_parameter",
                    "input_type_category": "text",
                    "editable_input_count": 1,
                    "required_input_count": 0,
                    "parameter_count": 1,
                    "multiple_parameters": False,
                    "request_shape_category": "single_query_parameter",
                }
            ],
        }
        validate_ranker_facing_snapshot(clean)

        for key, value in [
            ("ground_truth", "vulnerable"),
            ("action_path", "/external-v14/case-000001"),
            ("parameter_name", "input_000001"),
            ("source_file", "BenchmarkTest00001.java"),
            ("verifier_state", "verified"),
            ("raw_html", "<html>body</html>"),
        ]:
            dirty = json.loads(json.dumps(clean))
            dirty["candidate_input"][0][key] = value
            with self.assertRaises(EnrichmentLeakageError, msg=key):
                validate_ranker_facing_snapshot(dirty)

    def test_enriched_snapshot_adds_only_permitted_context_fields_without_reordering(self) -> None:
        original = json.loads(
            Path("results/owasp-xss-v14-protocol-freeze/model-facing/candidate-snapshots/ow14-s0001.json").read_text(
                encoding="utf-8"
            )
        )
        minimal = abstract_minimal_snapshot(original)
        observations = {
            candidate["candidate_id"]: {
                "reflection_detected": False,
                "reflection_count_category": "0",
                "reflection_context_category": "none",
                "marker_preservation_category": "not_reflected",
                "response_content_type_category": "html",
            }
            for candidate in minimal["candidate_input"]
        }

        enriched = enrich_snapshot(minimal, observations)

        self.assertEqual(
            [candidate["candidate_id"] for candidate in minimal["candidate_input"]],
            [candidate["candidate_id"] for candidate in enriched["candidate_input"]],
        )
        for before, after in zip(minimal["candidate_input"], enriched["candidate_input"], strict=True):
            self.assertLess(set(before), set(after))
            self.assertEqual({key: after[key] for key in before}, before)
        validate_ranker_facing_snapshot(enriched)

    def test_enriched_ranking_is_lexicographic_and_uses_label_independent_context_features(self) -> None:
        candidates = [
            {
                "candidate_id": "b",
                "http_method": "GET",
                "input_carrier_category": "query_parameter",
                "input_type_category": "text",
                "editable_input_count": 1,
                "required_input_count": 0,
                "parameter_count": 1,
                "multiple_parameters": False,
                "request_shape_category": "single_query_parameter",
                "reflection_detected": True,
                "reflection_count_category": "1",
                "reflection_context_category": "html_text",
                "marker_preservation_category": "unchanged",
                "response_content_type_category": "html",
            },
            {
                "candidate_id": "a",
                "http_method": "GET",
                "input_carrier_category": "query_parameter",
                "input_type_category": "text",
                "editable_input_count": 1,
                "required_input_count": 0,
                "parameter_count": 1,
                "multiple_parameters": False,
                "request_shape_category": "single_query_parameter",
                "reflection_detected": True,
                "reflection_count_category": "1",
                "reflection_context_category": "script_like",
                "marker_preservation_category": "unchanged",
                "response_content_type_category": "html",
            },
        ]

        rankings = enriched_rankings(candidates)
        repeat = enriched_rankings(list(reversed(candidates)))

        self.assertEqual([item["candidate_id"] for item in rankings], ["a", "b"])
        self.assertEqual([item["candidate_id"] for item in repeat], ["a", "b"])
        self.assertGreater(rankings[0]["sort_key"], rankings[1]["sort_key"])
        self.assertEqual(rankings[0]["policy"], "lexicographic_ordinal")
        self.assertIn("context=script_like", " ".join(rankings[0]["rationale"]))

    def test_enriched_ranking_uses_existing_structural_rank_as_late_fallback(self) -> None:
        candidates = [
            {
                "candidate_id": "b",
                "http_method": "GET",
                "input_carrier_category": "query_parameter",
                "input_type_category": "text",
                "editable_input_count": 1,
                "required_input_count": 0,
                "parameter_count": 1,
                "multiple_parameters": False,
                "request_shape_category": "single_query_parameter",
                "reflection_detected": True,
                "reflection_count_category": "1",
                "reflection_context_category": "html_text",
                "marker_preservation_category": "unchanged",
                "response_content_type_category": "html",
            },
            {
                "candidate_id": "a",
                "http_method": "GET",
                "input_carrier_category": "query_parameter",
                "input_type_category": "text",
                "editable_input_count": 1,
                "required_input_count": 1,
                "parameter_count": 2,
                "multiple_parameters": True,
                "request_shape_category": "multi_query_parameter",
                "reflection_detected": True,
                "reflection_count_category": "1",
                "reflection_context_category": "html_text",
                "marker_preservation_category": "unchanged",
                "response_content_type_category": "html",
            },
        ]

        rankings = enriched_rankings(candidates)

        self.assertEqual([item["candidate_id"] for item in rankings], ["b", "a"])
        self.assertIn("structural fallback", " ".join(rankings[0]["rationale"]))

    def test_frozen_v14_scenario_membership_and_order_are_preserved(self) -> None:
        report = validate_v14_structural_equality(Path("results/owasp-xss-v14-protocol-freeze"))

        self.assertTrue(report["valid"], report)
        self.assertEqual(report["scenario_count"], 266)
        self.assertEqual(report["candidate_reference_count"], 1330)
        self.assertEqual(report["unique_candidate_count"], 388)
        self.assertEqual(report["positive_scenario_count"], 236)
        self.assertEqual(report["negative_only_scenario_count"], 30)
        self.assertEqual(report["candidate_count_distribution"], {"5": 266})

    def test_live_collection_plan_uses_no_ground_truth_scoring_file(self) -> None:
        report = prepare_collection_plan_without_ground_truth(Path("results/owasp-xss-v14-protocol-freeze"))

        self.assertTrue(report["valid"], report)
        self.assertEqual(report["unique_candidate_count"], 388)
        self.assertEqual(report["benign_marker_request_limit"], 388)
        self.assertFalse(report["ground_truth_scoring_data_loaded"])
        self.assertNotIn("ground-truth/scoring-data.json", report["files_read"])

    def test_readiness_package_is_offline_and_records_projected_denominators(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manifest = build_context_enrichment_readiness_package(output_dir=Path(tmp))
            root = Path(tmp)

            validation = json.loads((root / "validation-report.json").read_text(encoding="utf-8"))
            denominators = json.loads((root / "projected-denominators.json").read_text(encoding="utf-8"))

            self.assertTrue(validation["valid"], validation)
            self.assertEqual(manifest["external_activity"]["gpt_calls"], 0)
            self.assertEqual(manifest["external_activity"]["qwen_calls"], 0)
            self.assertEqual(manifest["external_activity"]["http_benchmark_requests"], 0)
            self.assertEqual(denominators["scenario_count"], 266)
            self.assertEqual(denominators["benign_marker_request_denominator"], 388)
            self.assertEqual(denominators["ranking_rows"]["total"], 5852)
            self.assertTrue((root / "checksums.sha256").exists())

    def test_collection_with_fake_executor_attempts_each_unique_candidate_once_without_ground_truth(self) -> None:
        class FakeExecutor:
            def __init__(self) -> None:
                self.calls: list[object] = []

            def execute(self, action):  # type: ignore[no-untyped-def]
                self.calls.append(action)
                now = "2026-01-01T00:00:00+00:00"
                from adstf.contracts import ActionResult, ActionStatus, EvidenceRecord, EvidenceType, RedactionStatus

                body = f"<p>{CONTEXT_ENRICHMENT_MARKER}</p>"
                evidence = EvidenceRecord(
                    evidence_id=f"evidence-{len(self.calls)}",
                    run_id=action.run_id,
                    source="fake_http_executor",
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    target_ref=action.target_ref,
                    created_at=now,
                    summary="fake benign response",
                    data_ref=None,
                    redaction_status=RedactionStatus.ABSENT,
                    related_action_ids=[action.action_id],
                    attributes={
                        "status_code": 200,
                        "content_type": "text/html",
                        "body_text": body,
                        "body_sha256": "fake",
                        "body_length": len(body),
                    },
                )
                return (
                    ActionResult(
                        action_id=action.action_id,
                        run_id=action.run_id,
                        status=ActionStatus.EXECUTED,
                        started_at=now,
                        completed_at=now,
                        executor="fake",
                        normalized_observations=evidence.attributes,
                        evidence_refs=[evidence.evidence_id],
                        safety_notes=[],
                    ),
                    [evidence],
                )

        fake = FakeExecutor()
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = collect_benign_context_observations(output_root=Path(tmp) / "runs", audit_dir=Path(tmp) / "audit", executor=fake)
            manifest = json.loads((run_dir / "collection-manifest.json").read_text(encoding="utf-8"))
            sanitized = json.loads((run_dir / "sanitized-observations" / "candidate-observations.json").read_text(encoding="utf-8"))
            audit = json.loads((run_dir / "post-collection-audit.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["scheduled_candidates"], 388)
        self.assertEqual(manifest["actual_candidate_http_requests"], 388)
        self.assertEqual(len(fake.calls), 388)
        self.assertEqual(len({call.scope_context["candidate_id"] for call in fake.calls}), 388)
        self.assertFalse(manifest["ground_truth_scoring_data_loaded"])
        self.assertEqual(manifest["gpt_calls"], 0)
        self.assertEqual(manifest["qwen_calls"], 0)
        self.assertEqual(manifest["verification_runs"], 0)
        self.assertEqual(len(sanitized["observations"]), 388)
        self.assertTrue(audit["draft_enriched_snapshot_validation"]["valid"], audit)

    def test_collection_failure_is_unavailable_not_not_reflected(self) -> None:
        class FailingExecutor:
            def execute(self, action):  # type: ignore[no-untyped-def]
                from adstf.contracts import ActionResult, ActionStatus

                return (
                    ActionResult(
                        action_id=action.action_id,
                        run_id=action.run_id,
                        status=ActionStatus.FAILED,
                        started_at="2026-01-01T00:00:00+00:00",
                        completed_at="2026-01-01T00:00:00+00:00",
                        executor="fake",
                        normalized_observations={},
                        evidence_refs=[],
                        safety_notes=[],
                        error="planned failure",
                    ),
                    [],
                )

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = collect_benign_context_observations(output_root=Path(tmp) / "runs", audit_dir=Path(tmp) / "audit", executor=FailingExecutor())
            sanitized = json.loads((run_dir / "sanitized-observations" / "candidate-observations.json").read_text(encoding="utf-8"))

        first = sanitized["observations"][0]
        self.assertEqual(first["collection_status"], "failure")
        self.assertEqual(first["reflection_detected"], "not_available")
        self.assertEqual(first["reflection_context_category"], "not_available")
        self.assertEqual(first["failure_state"], "planned failure")


if __name__ == "__main__":
    unittest.main()
