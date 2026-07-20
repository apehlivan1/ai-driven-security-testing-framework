import json
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
)
from adstf.heldout_evaluation import (
    assert_no_cross_case_rejecting_evidence,
    heldout_idor_case_plans,
    heldout_zap_supported_suite_case_ids,
    idor_supporting_evidence_for_case,
    normalize_heldout_zap_active_report,
    normalize_heldout_zap_passive_report,
    validate_heldout_evaluation_harness,
    zap_supported_manifest_scope,
)
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.verification import FindingVerifier
from adstf.zap_baseline import (
    ZAP_HELDOUT_ACTIVE_MAPPING_VERSION,
    ZAP_HELDOUT_PASSIVE_MAPPING_VERSION,
)


class HeldoutEvaluationHarnessTests(unittest.TestCase):
    def test_heldout_zap_case_set_matches_supported_manifest_scope(self) -> None:
        expected = [
            "heldout-xss::hx-001",
            "heldout-xss::hx-002",
            "heldout-xss::hx-003",
            "heldout-sqli::hs-001",
            "heldout-sqli::hs-002",
        ]

        self.assertEqual(zap_supported_manifest_scope(), expected)
        self.assertEqual(heldout_zap_supported_suite_case_ids(), expected)

        passive = normalize_heldout_zap_passive_report({"alerts": []})
        active = normalize_heldout_zap_active_report({"alerts": []})

        self.assertEqual(passive["mapping_version"], ZAP_HELDOUT_PASSIVE_MAPPING_VERSION)
        self.assertEqual(active["mapping_version"], ZAP_HELDOUT_ACTIVE_MAPPING_VERSION)
        self.assertEqual([case["suite_case_id"] for case in passive["cases"]], expected)
        self.assertEqual([case["suite_case_id"] for case in active["cases"]], expected)
        self.assertEqual(passive["evaluated_case_count"], 5)
        self.assertEqual(active["evaluated_case_count"], 5)
        self.assertEqual([case["suite_case_id"] for case in passive["unsupported_cases"]], ["heldout-idor::hi-001", "heldout-idor::hi-002"])
        self.assertEqual([case["suite_case_id"] for case in active["unsupported_cases"]], ["heldout-idor::hi-001", "heldout-idor::hi-002"])

    def test_heldout_zap_secure_case_alert_maps_to_heldout_false_positive(self) -> None:
        report = {
            "alerts": [
                {
                    "pluginid": "40012",
                    "alert": "Cross Site Scripting (Reflected)",
                    "instances": [
                        {
                            "uri": "http://host.docker.internal:4391/ledger/memo?memo=probe",
                            "param": "memo",
                            "method": "GET",
                        }
                    ],
                }
            ]
        }

        summary = normalize_heldout_zap_passive_report(report)
        cases = {case["suite_case_id"]: case for case in summary["cases"]}

        self.assertEqual(summary["matched_alert_count"], 1)
        self.assertEqual(cases["heldout-xss::hx-002"]["classification"], "FP")

    def test_idor_supporting_evidence_is_separated_by_case(self) -> None:
        plans = {plan.case_id: plan for plan in heldout_idor_case_plans()}
        hi_001 = plans["hi-001"]
        hi_002 = plans["hi-002"]
        session_evidence = {
            "user_a": _evidence(EvidenceType.SESSION_CONTEXT, {"user_label": "user_a"}),
            "user_b": _evidence(EvidenceType.SESSION_CONTEXT, {"user_label": "user_b"}),
        }
        ownership_evidence = {
            "r-218": _evidence(EvidenceType.RESOURCE_OWNERSHIP, {"resource_id": "r-218"}),
            "r-427": _evidence(EvidenceType.RESOURCE_OWNERSHIP, {"resource_id": "r-427"}),
        }
        read_evidence = {
            "hi-001:owner:r-218": _evidence(EvidenceType.HTTP_EXCHANGE, {"case_id": "hi-001", "status_code": 200}),
            "hi-001:cross:r-218": _evidence(EvidenceType.HTTP_EXCHANGE, {"case_id": "hi-001", "status_code": 200}),
            "hi-002:owner:r-427": _evidence(EvidenceType.HTTP_EXCHANGE, {"case_id": "hi-002", "status_code": 200}),
            "hi-002:cross:r-427": _evidence(EvidenceType.HTTP_EXCHANGE, {"case_id": "hi-002", "status_code": 403}),
        }
        comparison_evidence = {
            "hi-001": _evidence(
                EvidenceType.COMPARISON_RESULT,
                {
                    "case_id": "hi-001",
                    "owner_user_label": "user_a",
                    "requesting_user_label": "user_b",
                    "cross_user_access_granted": True,
                    "is_control_case": True,
                    "control_case_passed": True,
                    "rejects_hypothesis": False,
                },
            ),
            "hi-002": _evidence(
                EvidenceType.COMPARISON_RESULT,
                {
                    "case_id": "hi-002",
                    "owner_user_label": "user_a",
                    "requesting_user_label": "user_b",
                    "cross_user_access_granted": False,
                    "is_control_case": True,
                    "control_case_passed": True,
                    "rejects_hypothesis": True,
                },
            ),
        }

        hi_001_evidence = idor_supporting_evidence_for_case(
            case_plan=hi_001,
            session_evidence=session_evidence,
            ownership_evidence=ownership_evidence,
            read_evidence=read_evidence,
            comparison_evidence=comparison_evidence,
        )
        hi_002_evidence = idor_supporting_evidence_for_case(
            case_plan=hi_002,
            session_evidence=session_evidence,
            ownership_evidence=ownership_evidence,
            read_evidence=read_evidence,
            comparison_evidence=comparison_evidence,
        )

        assert_no_cross_case_rejecting_evidence(case_plan=hi_001, evidence=hi_001_evidence)
        self.assertNotIn(comparison_evidence["hi-002"].evidence_id, {item.evidence_id for item in hi_001_evidence})
        self.assertIn(comparison_evidence["hi-002"].evidence_id, {item.evidence_id for item in hi_002_evidence})

        self.assertEqual(_verified_state("hi-001", hi_001_evidence), FindingState.VERIFIED)
        self.assertEqual(_verified_state("hi-002", hi_002_evidence), FindingState.REJECTED)

        with self.assertRaises(ValueError):
            assert_no_cross_case_rejecting_evidence(
                case_plan=hi_001,
                evidence=[*hi_001_evidence, comparison_evidence["hi-002"]],
            )

    def test_harness_structural_validation_is_valid(self) -> None:
        result = validate_heldout_evaluation_harness()

        self.assertTrue(result["valid"], result["errors"])
        self.assertEqual(result["zap_supported_manifest_scope"], result["zap_supported_mapping_scope"])


def _evidence(evidence_type: EvidenceType, attributes: dict) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id="test-run",
        source="test",
        evidence_type=evidence_type,
        target_ref="http://127.0.0.1/test",
        created_at=datetime.now(UTC).isoformat(),
        summary="test evidence",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[],
        attributes=attributes,
    )


def _verified_state(case_id: str, evidence: list[EvidenceRecord]) -> FindingState:
    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id="test-run",
        module_id="access.idor_read_only",
        title=f"IDOR {case_id}",
        category="read_only_idor",
        affected_target="http://127.0.0.1/test",
        state=FindingState.SUSPECTED,
        hypothesis="cross-user read access",
        created_by="test",
        supporting_evidence_refs=[item.evidence_id for item in evidence],
        report_fields={"case_id": case_id},
    )
    requested = request_verification(finding)
    result = FindingVerifier(mvp_modules()).verify(requested, evidence)
    return apply_verifier_result(requested, result).state


if __name__ == "__main__":
    unittest.main()
