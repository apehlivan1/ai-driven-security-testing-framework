from __future__ import annotations

from adstf.contracts import (
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    VerificationOutcome,
    VerifierResult,
)
from adstf.lifecycle import new_id
from adstf.modules import VulnerabilityModule


class FindingVerifier:
    def __init__(self, modules: dict[str, VulnerabilityModule]) -> None:
        self._modules = modules

    def verify(self, finding: FindingRecord, evidence: list[EvidenceRecord]) -> VerifierResult:
        module = self._modules.get(finding.module_id)
        if module is None:
            return self._inconclusive(
                finding,
                evidence,
                ["module is not registered"],
                ["module_registered"],
            )

        relevant = [
            item
            for item in evidence
            if item.evidence_id in finding.supporting_evidence_refs
        ]
        evidence_types = {item.evidence_type for item in relevant}

        criteria_checked = [
            f"has_{required.value}" for required in module.required_evidence_types
        ]
        criteria_satisfied = [
            f"has_{required.value}"
            for required in module.required_evidence_types
            if required in evidence_types
        ]
        criteria_missing = [
            f"has_{required.value}"
            for required in module.required_evidence_types
            if required not in evidence_types
        ]

        control_cases = [
            {
                "evidence_id": item.evidence_id,
                "summary": item.summary,
                "passed": bool(item.attributes.get("control_case_passed")),
            }
            for item in relevant
            if item.evidence_type == EvidenceType.COMPARISON_RESULT
            and item.attributes.get("is_control_case")
        ]

        if module.requires_control_case:
            criteria_checked.append("has_passing_control_case")
            if any(case["passed"] for case in control_cases):
                criteria_satisfied.append("has_passing_control_case")
            else:
                criteria_missing.append("has_passing_control_case")

        if finding.module_id == "xss.reflected":
            criteria_checked.append("has_browser_execution_signal")
            if any(
                item.evidence_type == EvidenceType.BROWSER_OBSERVATION
                and item.attributes.get("execution_marker_observed") is True
                for item in relevant
            ):
                criteria_satisfied.append("has_browser_execution_signal")
            else:
                criteria_missing.append("has_browser_execution_signal")

        if any(item.attributes.get("rejects_hypothesis") for item in relevant):
            return VerifierResult(
                verification_result_id=new_id("verification"),
                finding_id=finding.finding_id,
                module_id=finding.module_id,
                outcome=VerificationOutcome.REJECTED,
                criteria_checked=criteria_checked,
                criteria_satisfied=criteria_satisfied,
                criteria_missing=criteria_missing,
                control_cases=control_cases,
                evidence_refs=[item.evidence_id for item in relevant],
                reproduction_status="not_reproduced",
                rationale="Evidence contradicts the suspected vulnerability.",
                limitations=[],
            )

        if criteria_missing:
            return self._inconclusive(finding, relevant, criteria_missing, criteria_checked)

        return VerifierResult(
            verification_result_id=new_id("verification"),
            finding_id=finding.finding_id,
            module_id=finding.module_id,
            outcome=VerificationOutcome.VERIFIED,
            criteria_checked=criteria_checked,
            criteria_satisfied=criteria_satisfied,
            criteria_missing=[],
            control_cases=control_cases,
            evidence_refs=[item.evidence_id for item in relevant],
            reproduction_status="reproduced",
            rationale="Required evidence and control cases satisfy the module criteria.",
            limitations=[],
        )

    def _inconclusive(
        self,
        finding: FindingRecord,
        evidence: list[EvidenceRecord],
        missing: list[str],
        checked: list[str],
    ) -> VerifierResult:
        return VerifierResult(
            verification_result_id=new_id("verification"),
            finding_id=finding.finding_id,
            module_id=finding.module_id,
            outcome=VerificationOutcome.INCONCLUSIVE,
            criteria_checked=checked,
            criteria_satisfied=[item for item in checked if item not in missing],
            criteria_missing=missing,
            control_cases=[],
            evidence_refs=[item.evidence_id for item in evidence],
            reproduction_status="not_determined",
            rationale="Verification criteria were not fully satisfied.",
            limitations=["missing or insufficient evidence"],
        )
