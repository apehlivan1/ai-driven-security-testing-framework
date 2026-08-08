from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from adstf.contracts import FindingRecord, FindingState, VerificationOutcome, VerifierResult


def request_verification(finding: FindingRecord) -> FindingRecord:
    if finding.state not in {FindingState.SUSPECTED, FindingState.INCONCLUSIVE}:
        raise ValueError(f"finding state '{finding.state}' cannot request verification")
    return replace(finding, state=FindingState.VERIFICATION_REQUESTED)


def apply_verifier_result(finding: FindingRecord, result: VerifierResult) -> FindingRecord:
    if finding.state != FindingState.VERIFICATION_REQUESTED:
        raise ValueError("verifier results can only be applied after verification is requested")
    if finding.finding_id != result.finding_id:
        raise ValueError("verifier result does not belong to finding")

    next_state = {
        VerificationOutcome.VERIFIED: FindingState.VERIFIED,
        VerificationOutcome.REJECTED: FindingState.REJECTED,
        VerificationOutcome.INCONCLUSIVE: FindingState.INCONCLUSIVE,
    }[result.outcome]

    report_fields = dict(finding.report_fields)
    if result.completed_at:
        report_fields.setdefault("verification_completed_at", result.completed_at)

    return replace(
        finding,
        state=next_state,
        verification_result_ref=result.verification_result_id,
        report_fields=report_fields,
    )


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"
