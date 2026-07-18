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


def finding(refs: list[str], state: FindingState = FindingState.SUSPECTED) -> FindingRecord:
    return FindingRecord(
        finding_id="finding-1",
        run_id="run-1",
        module_id="xss.reflected",
        title="Possible reflected XSS",
        category="reflected_xss",
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
        self.assertEqual(updated.state, FindingState.VERIFIED)
        self.assertEqual(updated.verification_result_ref, result.verification_result_id)

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

    def test_invalid_lifecycle_transition_raises(self) -> None:
        with self.assertRaises(ValueError):
            request_verification(finding([], FindingState.VERIFIED))


if __name__ == "__main__":
    unittest.main()
