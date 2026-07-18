from __future__ import annotations

import argparse
from datetime import UTC, datetime
from pathlib import Path

from adstf.contracts import (
    ActionRequest,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
)
from adstf.execution import MockExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


def run_dry_run(output_root: Path) -> Path:
    run_id = f"dry-run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    target = TargetConfig(
        name="Mock Lab Target",
        base_url="http://lab.local",
        allowed_hosts=["lab.local"],
        allowed_ports=[80],
        enabled_modules=["xss.reflected", "access.idor_read_only", "sqli.boolean"],
        test_users={"user_a": "configured", "user_b": "configured"},
    )
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    executor = MockExecutor(safety)
    modules = mvp_modules()

    approved = ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dry_run",
        module_id="xss.reflected",
        action_type=ActionType.NAVIGATE,
        target_ref="http://lab.local/search",
        scope_context={"target": target.name},
        parameters={"url": "http://lab.local/search"},
        preconditions=[],
        safety_class=SafetyClass.LOW,
        rationale="Exercise in-scope action approval.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )
    blocked = ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dry_run",
        module_id="xss.reflected",
        action_type=ActionType.NAVIGATE,
        target_ref="http://outside.example/admin",
        scope_context={"target": target.name},
        parameters={"url": "http://outside.example/admin"},
        preconditions=[],
        safety_class=SafetyClass.LOW,
        rationale="Exercise out-of-scope action rejection.",
        expected_evidence=[EvidenceType.BLOCKED_ACTION],
    )

    store.save_action_request(approved)
    store.save_action_request(blocked)

    http_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dry_run",
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        target_ref=approved.target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary="Mock reflected input request/response was captured.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[approved.action_id],
    )
    browser_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dry_run",
        evidence_type=EvidenceType.BROWSER_OBSERVATION,
        target_ref=approved.target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary="Mock browser observation recorded execution marker.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[approved.action_id],
        attributes={"execution_marker_observed": True},
    )
    control_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dry_run",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=approved.target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary="Mock control case passed for non-executing marker.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[approved.action_id],
        attributes={"is_control_case": True, "control_case_passed": True},
    )
    blocked_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="safety_boundary",
        evidence_type=EvidenceType.BLOCKED_ACTION,
        target_ref=blocked.target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary="Mock out-of-scope action was blocked.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[blocked.action_id],
    )

    for evidence in (http_evidence, browser_evidence, control_evidence, blocked_evidence):
        store.save_evidence(evidence)

    store.save_action_result(executor.execute(approved, [http_evidence.evidence_id]))
    store.save_action_result(executor.execute(blocked, [blocked_evidence.evidence_id]))

    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=run_id,
        module_id="xss.reflected",
        title="Mock reflected XSS hypothesis",
        category=modules["xss.reflected"].category,
        affected_target="http://lab.local/search?q=",
        state=FindingState.SUSPECTED,
        hypothesis="A reflected input may execute in the browser context.",
        created_by="dry_run",
        supporting_evidence_refs=[
            http_evidence.evidence_id,
            browser_evidence.evidence_id,
            control_evidence.evidence_id,
        ],
        report_fields={"payload_marker": "mock-marker"},
    )
    store.save_finding(finding)

    requested = request_verification(finding)
    store.save_finding(requested)
    verifier_result = FindingVerifier(modules).verify(
        requested,
        [http_evidence, browser_evidence, control_evidence, blocked_evidence],
    )
    store.save_verifier_result(verifier_result)

    verified = apply_verifier_result(requested, verifier_result)
    store.save_finding(verified)
    store.save_report(render_placeholder_report(target, [verified]))

    return store.run_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the scaffold dry run.")
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path(".adstf-runs"),
        help="Directory where dry-run artifacts are written.",
    )
    args = parser.parse_args()
    run_dir = run_dry_run(args.output_root)
    print(f"Dry run artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
