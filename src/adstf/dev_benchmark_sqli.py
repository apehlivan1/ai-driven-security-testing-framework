from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode, urljoin

from adstf.config import load_target_config
from adstf.contracts import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    TargetConfig,
)
from adstf.execution import HttpExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.serialization import to_json_value
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "sqli-dev-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


@dataclass(frozen=True)
class BooleanSqliCase:
    case_id: str
    path: str
    parameter: str
    baseline_value: str
    true_value: str
    false_value: str
    expected_behavior: str


def run_development_benchmark_sqli(config_path: Path, output_root: Path) -> Path:
    target = load_target_config(config_path)
    run_id = f"dev-benchmark-sqli-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    executor = HttpExecutor(safety)
    modules = mvp_modules()

    smoke_action = _request_action(
        run_id,
        target,
        case_id="health",
        path="/sqli/health",
        parameter="",
        value="",
        phase="health",
        rationale="Confirm the local SQLi development benchmark is reachable.",
    )
    store.save_action_request(smoke_action)
    smoke_result, smoke_evidence = executor.execute(smoke_action)
    store.save_action_result(smoke_result)
    for evidence in smoke_evidence:
        store.save_evidence(evidence)
    if smoke_result.status != ActionStatus.EXECUTED:
        raise RuntimeError("SQLi development benchmark is not reachable. Start the local server first.")

    findings: list[FindingRecord] = []
    for case in _case_specs(target):
        observations = _exercise_case(store, target, executor, case)
        comparison = _comparison_evidence(store.run_id, case, observations)
        store.save_evidence(comparison)
        finding = _verify_finding(
            store=store,
            target=target,
            modules=modules,
            case=case,
            comparison=comparison,
            http_evidence=[item for _, evidence in observations.values() for item in evidence],
        )
        findings.append(finding)

    evaluation = evaluate_run_against_ground_truth(store.run_dir, _ground_truth_path(target))
    store.save_artifact_text(
        "sqli-benchmark-evaluation.json",
        json.dumps(to_json_value(evaluation), indent=2, sort_keys=True) + "\n",
    )
    store.save_report(render_placeholder_report(target, findings, placeholder=False))
    return store.run_dir


def _exercise_case(
    store: RunArtifactStore,
    target: TargetConfig,
    executor: HttpExecutor,
    case: BooleanSqliCase,
) -> dict[str, tuple[ActionResult, list[EvidenceRecord]]]:
    requests = {
        "baseline_1": case.baseline_value,
        "baseline_2": case.baseline_value,
        "true_1": case.true_value,
        "true_2": case.true_value,
        "false_1": case.false_value,
        "false_2": case.false_value,
    }
    observations: dict[str, tuple[ActionResult, list[EvidenceRecord]]] = {}
    for phase, value in requests.items():
        action = _request_action(
            store.run_id,
            target,
            case_id=case.case_id,
            path=case.path,
            parameter=case.parameter,
            value=value,
            phase=phase,
            rationale=f"Replay non-destructive boolean SQLi {phase} request.",
        )
        store.save_action_request(action)
        result, evidence = executor.execute(action)
        store.save_action_result(result)
        for item in evidence:
            store.save_evidence(item)
        observations[phase] = (result, evidence)
    return observations


def _comparison_evidence(
    run_id: str,
    case: BooleanSqliCase,
    observations: dict[str, tuple[ActionResult, list[EvidenceRecord]]],
) -> EvidenceRecord:
    evidence_by_phase = {phase: evidence[0] for phase, (_, evidence) in observations.items()}
    fingerprints = {
        phase: _fingerprint(evidence)
        for phase, evidence in evidence_by_phase.items()
    }
    statuses = {
        phase: evidence.attributes.get("status_code")
        for phase, evidence in evidence_by_phase.items()
    }
    baseline_stable = fingerprints["baseline_1"] == fingerprints["baseline_2"]
    true_stable = fingerprints["true_1"] == fingerprints["true_2"]
    false_stable = fingerprints["false_1"] == fingerprints["false_2"]
    true_false_difference = fingerprints["true_1"] != fingerprints["false_1"]
    all_status_ok = all(status == 200 for status in statuses.values())
    server_error_observed = any(
        isinstance(status, int) and status >= 500
        for status in statuses.values()
    )
    reflected_payload_only = _payload_reflected(case.true_value, evidence_by_phase["true_1"]) or _payload_reflected(
        case.false_value,
        evidence_by_phase["false_1"],
    )
    true_false_difference_reproducible = (
        baseline_stable
        and true_stable
        and false_stable
        and true_false_difference
        and all_status_ok
        and not server_error_observed
        and not reflected_payload_only
    )
    secure_control = case.expected_behavior == "secure"
    control_case_passed = (
        true_false_difference_reproducible
        if not secure_control
        else baseline_stable and true_stable and false_stable and not true_false_difference and all_status_ok
    )
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dev_benchmark_sqli",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=evidence_by_phase["true_1"].target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary=f"Compared baseline, boolean-true, and boolean-false responses for {case.case_id}.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[result.action_id for result, _ in observations.values()],
        attributes={
            "case_id": case.case_id,
            "parameter": case.parameter,
            "payload_family": "bounded_boolean_condition",
            "baseline_stable": baseline_stable,
            "true_condition_stable": true_stable,
            "false_condition_stable": false_stable,
            "true_false_difference": true_false_difference,
            "true_false_difference_reproducible": true_false_difference_reproducible,
            "all_status_ok": all_status_ok,
            "server_error_observed": server_error_observed,
            "reflected_payload_only": reflected_payload_only,
            "is_control_case": True,
            "control_case_passed": control_case_passed,
            "rejects_hypothesis": secure_control and control_case_passed,
            "fingerprints": fingerprints,
            "status_codes": statuses,
            "ground_truth_used": False,
        },
    )


def _verify_finding(
    *,
    store: RunArtifactStore,
    target: TargetConfig,
    modules: dict,
    case: BooleanSqliCase,
    comparison: EvidenceRecord,
    http_evidence: list[EvidenceRecord],
) -> FindingRecord:
    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=store.run_id,
        module_id="sqli.boolean",
        title=f"Boolean SQL injection candidate observed in development benchmark {case.case_id}",
        category=modules["sqli.boolean"].category,
        affected_target=_case_url(target.base_url, case.path, case.parameter, ""),
        state=FindingState.SUSPECTED,
        hypothesis=f"The {case.parameter} parameter may alter database query logic through boolean conditions.",
        created_by="dev_benchmark_sqli",
        supporting_evidence_refs=[*[evidence.evidence_id for evidence in http_evidence], comparison.evidence_id],
        report_fields={
            "case_id": case.case_id,
            "parameter": case.parameter,
            "baseline": "[configured baseline value]",
            "true_condition": "[bounded boolean true condition]",
            "false_condition": "[bounded boolean false condition]",
        },
        severity="medium",
        confidence="verified_by_reproducible_boolean_response_difference",
    )
    store.save_finding(finding)
    requested = request_verification(finding)
    store.save_finding(requested)
    result = FindingVerifier(modules).verify(requested, [*http_evidence, comparison])
    store.save_verifier_result(result)
    updated = apply_verifier_result(requested, result)
    store.save_finding(updated)
    return updated


def evaluate_run_against_ground_truth(run_dir: Path, ground_truth_path: Path) -> dict:
    truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
    cases = {case["case_id"]: case for case in truth["cases"]}
    findings = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (run_dir / "findings").glob("*.json")
    ]
    final_findings = [
        finding
        for finding in findings
        if finding["state"] in {"verified", "rejected", "inconclusive"}
    ]
    results = []
    for finding in final_findings:
        case_id = finding["report_fields"]["case_id"]
        case = cases[case_id]
        verified = finding["state"] == "verified"
        results.append(
            {
                "case_id": case_id,
                "expected_vulnerable": case["vulnerable"],
                "finding_state": finding["state"],
                "ground_truth_match": verified == bool(case["vulnerable"]),
                "path": case["path"],
                "parameter": case["parameter"],
            }
        )
    return {
        "benchmark_id": truth["benchmark_id"],
        "ground_truth_used_phase": "post_run_evaluation_only",
        "case_count": len(truth["cases"]),
        "verified_finding_count": sum(1 for result in results if result["finding_state"] == "verified"),
        "rejected_finding_count": sum(1 for result in results if result["finding_state"] == "rejected"),
        "inconclusive_finding_count": sum(1 for result in results if result["finding_state"] == "inconclusive"),
        "ground_truth_match_count": sum(1 for result in results if result["ground_truth_match"]),
        "ground_truth_mismatch_count": sum(1 for result in results if not result["ground_truth_match"]),
        "case_results": results,
    }


def _case_specs(target: TargetConfig) -> list[BooleanSqliCase]:
    return [
        BooleanSqliCase(
            case_id=str(item["case_id"]),
            path=str(item["path"]),
            parameter=str(item["parameter"]),
            baseline_value=str(item["baseline_value"]),
            true_value=str(item["true_value"]),
            false_value=str(item["false_value"]),
            expected_behavior=str(item["expected_behavior"]),
        )
        for item in target.metadata.get("cases", [])
    ]


def _request_action(
    run_id: str,
    target: TargetConfig,
    *,
    case_id: str,
    path: str,
    parameter: str,
    value: str,
    phase: str,
    rationale: str,
) -> ActionRequest:
    url = _case_url(target.base_url, path, parameter, value)
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_sqli",
        module_id="sqli.boolean",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=url,
        scope_context={"case_id": case_id, "phase": phase, "parameter": parameter},
        parameters={
            "method": "GET",
            "url": url,
            "capture_body_text": True,
            "body_text_limit": 2048,
        },
        preconditions=["local_sqli_benchmark_running", "read_only_request"],
        safety_class=SafetyClass.LOW,
        rationale=rationale,
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def _case_url(base_url: str, path: str, parameter: str, value: str) -> str:
    url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
    if not parameter:
        return url
    return f"{url}?{urlencode({parameter: value})}"


def _fingerprint(evidence: EvidenceRecord) -> dict:
    return {
        "status_code": evidence.attributes.get("status_code"),
        "body_sha256": evidence.attributes.get("body_sha256"),
        "body_length": evidence.attributes.get("body_length"),
    }


def _payload_reflected(payload: str, evidence: EvidenceRecord) -> bool:
    body_text = evidence.attributes.get("body_text")
    return isinstance(body_text, str) and payload in body_text


def _ground_truth_path(target: TargetConfig) -> Path:
    configured = Path(str(target.metadata["ground_truth_path"]))
    return configured if configured.is_absolute() else REPO_ROOT / configured


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local boolean-SQLi development benchmark integration.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    try:
        run_dir = run_development_benchmark_sqli(args.config, args.output_root)
    except Exception as exc:
        print(f"Development benchmark boolean-SQLi integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Development benchmark boolean-SQLi artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
