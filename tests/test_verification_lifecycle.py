import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from adstf.contracts import (
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    VerificationOutcome,
)
from adstf.lifecycle import apply_verifier_result, request_verification
from adstf.modules import mvp_modules
from adstf.verification import FindingVerifier


def evidence(
    evidence_id: str,
    evidence_type: EvidenceType,
    attributes: dict | None = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        run_id="run-1",
        source="test",
        evidence_type=evidence_type,
        target_ref="http://lab.local/search",
        created_at=datetime.now(UTC).isoformat(),
        summary=f"{evidence_type.value} evidence",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[],
        attributes=attributes or {},
    )


def finding(
    refs: list[str],
    state: FindingState = FindingState.SUSPECTED,
    module_id: str = "xss.reflected",
) -> FindingRecord:
    return FindingRecord(
        finding_id="finding-1",
        run_id="run-1",
        module_id=module_id,
        title="Possible reflected XSS",
        category={
            "xss.reflected": "reflected_xss",
            "access.idor_read_only": "read_only_idor",
            "sqli.boolean": "boolean_sqli",
        }[module_id],
        affected_target="http://lab.local/search?q=",
        state=state,
        hypothesis="Input may execute in browser context.",
        created_by="test",
        supporting_evidence_refs=refs,
    )


class VerificationLifecycleTests(unittest.TestCase):
    def test_verifies_when_required_evidence_and_control_case_exist(self) -> None:
        records = [
            evidence("e-1", EvidenceType.HTTP_EXCHANGE),
            evidence("e-2", EvidenceType.BROWSER_OBSERVATION, {"execution_marker_observed": True}),
            evidence(
                "e-3",
                EvidenceType.COMPARISON_RESULT,
                {"is_control_case": True, "control_case_passed": True},
            ),
        ]
        requested = request_verification(finding(["e-1", "e-2", "e-3"]))

        result = FindingVerifier(mvp_modules()).verify(requested, records)
        updated = apply_verifier_result(requested, result)

        self.assertEqual(result.outcome, VerificationOutcome.VERIFIED)
        self.assertIsNotNone(result.completed_at)
        self.assertEqual(updated.state, FindingState.VERIFIED)
        self.assertEqual(updated.verification_result_ref, result.verification_result_id)
        self.assertEqual(updated.report_fields["verification_completed_at"], result.completed_at)

    def test_inconclusive_when_control_case_is_missing(self) -> None:
        records = [
            evidence("e-1", EvidenceType.HTTP_EXCHANGE),
            evidence("e-2", EvidenceType.BROWSER_OBSERVATION),
            evidence("e-3", EvidenceType.COMPARISON_RESULT),
        ]
        requested = request_verification(finding(["e-1", "e-2", "e-3"]))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.INCONCLUSIVE)
        self.assertIn("has_passing_control_case", result.criteria_missing)

    def test_xss_requires_explicit_browser_execution_signal(self) -> None:
        records = [
            evidence("e-1", EvidenceType.HTTP_EXCHANGE),
            evidence("e-2", EvidenceType.BROWSER_OBSERVATION, {"execution_marker_observed": False}),
            evidence(
                "e-3",
                EvidenceType.COMPARISON_RESULT,
                {"is_control_case": True, "control_case_passed": True},
            ),
        ]
        requested = request_verification(finding(["e-1", "e-2", "e-3"]))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.INCONCLUSIVE)
        self.assertIn("has_browser_execution_signal", result.criteria_missing)

    def test_rejects_when_evidence_contradicts_hypothesis(self) -> None:
        records = [
            evidence("e-1", EvidenceType.HTTP_EXCHANGE),
            evidence("e-2", EvidenceType.BROWSER_OBSERVATION, {"rejects_hypothesis": True}),
            evidence(
                "e-3",
                EvidenceType.COMPARISON_RESULT,
                {"is_control_case": True, "control_case_passed": True},
            ),
        ]
        requested = request_verification(finding(["e-1", "e-2", "e-3"]))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.REJECTED)

    def test_idor_verifies_with_distinct_sessions_ownership_access_and_control(self) -> None:
        records = [
            evidence("s-a", EvidenceType.SESSION_CONTEXT, {"user_label": "user_a"}),
            evidence("s-b", EvidenceType.SESSION_CONTEXT, {"user_label": "user_b"}),
            evidence("o-1", EvidenceType.RESOURCE_OWNERSHIP, {"resource_id": "n-104", "owner_user_label": "user_a"}),
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 200}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "cross_user_access_granted": True,
                    "owner_user_label": "user_a",
                    "requesting_user_label": "user_b",
                },
            ),
            evidence(
                "c-2",
                EvidenceType.COMPARISON_RESULT,
                {"is_control_case": True, "control_case_passed": True},
            ),
        ]
        requested = request_verification(
            finding(["s-a", "s-b", "o-1", "h-1", "c-1", "c-2"], module_id="access.idor_read_only")
        )

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.VERIFIED)
        self.assertIn("has_cross_user_read_access", result.criteria_satisfied)

    def test_idor_rejects_when_secure_control_contradicts_hypothesis(self) -> None:
        records = [
            evidence("s-a", EvidenceType.SESSION_CONTEXT, {"user_label": "user_a"}),
            evidence("s-b", EvidenceType.SESSION_CONTEXT, {"user_label": "user_b"}),
            evidence("o-1", EvidenceType.RESOURCE_OWNERSHIP, {"resource_id": "n-306", "owner_user_label": "user_a"}),
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 403}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "is_control_case": True,
                    "control_case_passed": True,
                    "rejects_hypothesis": True,
                },
            ),
        ]
        requested = request_verification(
            finding(["s-a", "s-b", "o-1", "h-1", "c-1"], module_id="access.idor_read_only")
        )

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.REJECTED)

    def test_idor_is_inconclusive_without_distinct_sessions(self) -> None:
        records = [
            evidence("s-a", EvidenceType.SESSION_CONTEXT, {"user_label": "user_a"}),
            evidence("o-1", EvidenceType.RESOURCE_OWNERSHIP, {"resource_id": "n-104", "owner_user_label": "user_a"}),
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 200}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "cross_user_access_granted": True,
                    "owner_user_label": "user_a",
                    "requesting_user_label": "user_b",
                    "is_control_case": True,
                    "control_case_passed": True,
                },
            ),
        ]
        requested = request_verification(
            finding(["s-a", "o-1", "h-1", "c-1"], module_id="access.idor_read_only")
        )

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.INCONCLUSIVE)
        self.assertIn("has_distinct_benchmark_sessions", result.criteria_missing)

    def test_sqli_verifies_with_stable_baseline_and_reproducible_boolean_difference(self) -> None:
        records = [
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 200}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "is_control_case": True,
                    "control_case_passed": True,
                    "baseline_stable": True,
                    "true_false_difference_reproducible": True,
                    "server_error_observed": False,
                    "reflected_payload_only": False,
                },
            ),
        ]
        requested = request_verification(finding(["h-1", "c-1"], module_id="sqli.boolean"))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.VERIFIED)
        self.assertIn("has_stable_baseline_behavior", result.criteria_satisfied)
        self.assertIn("has_reproducible_boolean_difference", result.criteria_satisfied)

    def test_sqli_rejects_secure_control_that_contradicts_hypothesis(self) -> None:
        records = [
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 200}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "is_control_case": True,
                    "control_case_passed": True,
                    "baseline_stable": True,
                    "true_false_difference_reproducible": False,
                    "rejects_hypothesis": True,
                },
            ),
        ]
        requested = request_verification(finding(["h-1", "c-1"], module_id="sqli.boolean"))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.REJECTED)

    def test_sqli_is_inconclusive_when_difference_is_only_server_error(self) -> None:
        records = [
            evidence("h-1", EvidenceType.HTTP_EXCHANGE, {"status_code": 500}),
            evidence(
                "c-1",
                EvidenceType.COMPARISON_RESULT,
                {
                    "is_control_case": True,
                    "control_case_passed": True,
                    "baseline_stable": True,
                    "true_false_difference_reproducible": True,
                    "server_error_observed": True,
                    "reflected_payload_only": False,
                },
            ),
        ]
        requested = request_verification(finding(["h-1", "c-1"], module_id="sqli.boolean"))

        result = FindingVerifier(mvp_modules()).verify(requested, records)

        self.assertEqual(result.outcome, VerificationOutcome.INCONCLUSIVE)
        self.assertIn("has_stable_baseline_behavior", result.criteria_missing)
        self.assertIn("has_reproducible_boolean_difference", result.criteria_missing)

    def test_invalid_lifecycle_transition_raises(self) -> None:
        with self.assertRaises(ValueError):
            request_verification(finding([], FindingState.VERIFIED))


if __name__ == "__main__":
    unittest.main()
