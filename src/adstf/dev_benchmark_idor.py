from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen

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
from adstf.sessions import SessionRecord, SessionRegistry, session_context_evidence
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "idor-dev-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"
COOKIE_NAME = "adstf_session"


def run_development_benchmark_idor(
    config_path: Path,
    output_root: Path,
) -> Path:
    target = load_target_config(config_path)
    run_id = f"dev-benchmark-idor-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    registry = SessionRegistry()
    executor = HttpExecutor(safety, session_registry=registry)
    modules = mvp_modules()

    sessions, session_evidence = _authenticate_sessions(target, store, safety, registry)
    ownership = _ownership_evidence(target, store.run_id)
    for evidence in [*session_evidence.values(), *ownership.values()]:
        store.save_evidence(evidence)

    http_evidence = _exercise_idor_requests(target, store, executor, sessions)
    for result, evidence in http_evidence.values():
        store.save_action_result(result)
        for item in evidence:
            store.save_evidence(item)

    vulnerable_comparison = _comparison_evidence(
        run_id=store.run_id,
        case_id="open-cross-user",
        owner_user_label="user_a",
        requesting_user_label="user_b",
        resource_id="n-104",
        owner_evidence=http_evidence["user_a_own_open"][1][0],
        cross_user_evidence=http_evidence["user_b_cross_open"][1][0],
        related_action_ids=[
            http_evidence["user_a_own_open"][0].action_id,
            http_evidence["user_b_cross_open"][0].action_id,
        ],
        is_control_case=False,
    )
    secure_control_for_verified_case = _comparison_evidence(
        run_id=store.run_id,
        case_id="guarded-cross-user-control",
        owner_user_label="user_a",
        requesting_user_label="user_b",
        resource_id="n-306",
        owner_evidence=http_evidence["user_a_own_guarded"][1][0],
        cross_user_evidence=http_evidence["user_b_cross_guarded"][1][0],
        related_action_ids=[
            http_evidence["user_a_own_guarded"][0].action_id,
            http_evidence["user_b_cross_guarded"][0].action_id,
        ],
        is_control_case=True,
    )
    secure_rejection_comparison = _comparison_evidence(
        run_id=store.run_id,
        case_id="guarded-cross-user",
        owner_user_label="user_a",
        requesting_user_label="user_b",
        resource_id="n-306",
        owner_evidence=http_evidence["user_a_own_guarded"][1][0],
        cross_user_evidence=http_evidence["user_b_cross_guarded"][1][0],
        related_action_ids=[
            http_evidence["user_a_own_guarded"][0].action_id,
            http_evidence["user_b_cross_guarded"][0].action_id,
        ],
        is_control_case=True,
        rejects_hypothesis=True,
    )
    for evidence in [
        vulnerable_comparison,
        secure_control_for_verified_case,
        secure_rejection_comparison,
    ]:
        store.save_evidence(evidence)

    findings = [
        _verify_finding(
            store=store,
            modules=modules,
            title="Read-only IDOR observed in development benchmark open-cross-user",
            hypothesis="User B may read a resource owned by user A through a read-only request.",
            affected_target=_resource_url(target, "/idor/open", "n-104"),
            report_fields={
                "case_id": "open-cross-user",
                "owner_user": "user_a",
                "requesting_user": "user_b",
                "resource_id": "n-104",
            },
            evidence=[
                session_evidence["user_a"],
                session_evidence["user_b"],
                ownership["n-104"],
                ownership["n-205"],
                http_evidence["user_a_own_open"][1][0],
                http_evidence["user_b_own_open"][1][0],
                http_evidence["user_b_cross_open"][1][0],
                secure_control_for_verified_case,
                vulnerable_comparison,
            ],
        ),
        _verify_finding(
            store=store,
            modules=modules,
            title="Read-only IDOR rejected in development benchmark guarded-cross-user",
            hypothesis="User B may read a guarded resource owned by user A through a read-only request.",
            affected_target=_resource_url(target, "/idor/guarded", "n-306"),
            report_fields={
                "case_id": "guarded-cross-user",
                "owner_user": "user_a",
                "requesting_user": "user_b",
                "resource_id": "n-306",
            },
            evidence=[
                session_evidence["user_a"],
                session_evidence["user_b"],
                ownership["n-306"],
                http_evidence["user_a_own_guarded"][1][0],
                http_evidence["user_b_cross_guarded"][1][0],
                secure_rejection_comparison,
            ],
        ),
    ]

    evaluation = evaluate_run_against_ground_truth(store.run_dir, _ground_truth_path(target))
    store.save_artifact_text(
        "idor-benchmark-evaluation.json",
        json.dumps(to_json_value(evaluation), indent=2, sort_keys=True) + "\n",
    )
    store.save_report(render_placeholder_report(target, findings, placeholder=False))
    return store.run_dir


def _authenticate_sessions(
    target: TargetConfig,
    store: RunArtifactStore,
    safety: SafetyBoundary,
    registry: SessionRegistry,
) -> tuple[dict[str, SessionRecord], dict[str, EvidenceRecord]]:
    configured_users = target.metadata.get("users", {})
    sessions: dict[str, SessionRecord] = {}
    evidence: dict[str, EvidenceRecord] = {}
    for user_label, username in configured_users.items():
        password = target.test_users[str(username)]
        action = _auth_action(store.run_id, target, str(user_label), str(username))
        store.save_action_request(action)
        decision = safety.evaluate(action)
        started = datetime.now(UTC).isoformat()
        if not decision.approved:
            result = ActionResult(
                action_id=action.action_id,
                run_id=store.run_id,
                status=ActionStatus.BLOCKED,
                started_at=started,
                completed_at=datetime.now(UTC).isoformat(),
                executor="idor_authenticator",
                normalized_observations={"authenticated": False},
                evidence_refs=[],
                safety_notes=decision.reasons,
                error="blocked by safety boundary",
            )
            store.save_action_result(result)
            raise RuntimeError("authentication action was blocked by safety boundary")
        token = _login_for_cookie(target, str(username), password)
        session = registry.add_cookie_session(
            user_label=str(user_label),
            username=str(username),
            cookie_name=COOKIE_NAME,
            token=token,
        )
        session_evidence = session_context_evidence(
            run_id=store.run_id,
            record=session,
            related_action_ids=[action.action_id],
        )
        result = ActionResult(
            action_id=action.action_id,
            run_id=store.run_id,
            status=ActionStatus.EXECUTED,
            started_at=started,
            completed_at=datetime.now(UTC).isoformat(),
            executor="idor_authenticator",
            normalized_observations={
                "authenticated": True,
                "user_label": user_label,
                "username": username,
                "session_ref": session.session_ref,
                "credential_redacted": True,
                "token_redacted": True,
            },
            evidence_refs=[session_evidence.evidence_id],
            safety_notes=[],
        )
        store.save_action_result(result)
        sessions[str(user_label)] = session
        evidence[str(user_label)] = session_evidence
    return sessions, evidence


def _login_for_cookie(target: TargetConfig, username: str, password: str) -> str:
    data = urlencode({"username": username, "password": password}).encode("utf-8")
    request = Request(
        urljoin(f"{target.base_url.rstrip('/')}/", "/idor/login"),
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urlopen(request, timeout=5.0) as response:
        cookie = response.headers.get("Set-Cookie", "")
    name, _, rest = cookie.partition("=")
    token, _, _ = rest.partition(";")
    if name != COOKIE_NAME or not token:
        raise RuntimeError("benchmark login did not return an expected isolated session cookie")
    return token


def _ownership_evidence(target: TargetConfig, run_id: str) -> dict[str, EvidenceRecord]:
    records: dict[str, EvidenceRecord] = {}
    for resource in target.metadata.get("resources", []):
        resource_id = str(resource["resource_id"])
        records[resource_id] = EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=run_id,
            source="idor_dev_benchmark_config",
            evidence_type=EvidenceType.RESOURCE_OWNERSHIP,
            target_ref=_resource_url(target, str(resource["path"]), resource_id),
            created_at=datetime.now(UTC).isoformat(),
            summary=f"Benchmark setup establishes owner for resource {resource_id}.",
            data_ref=None,
            redaction_status=RedactionStatus.ABSENT,
            related_action_ids=[],
            attributes={
                "resource_id": resource_id,
                "owner_user_label": resource["owner_user_label"],
                "content_marker": resource["content_marker"],
                "ground_truth_used": False,
            },
        )
    return records


def _exercise_idor_requests(
    target: TargetConfig,
    store: RunArtifactStore,
    executor: HttpExecutor,
    sessions: dict[str, SessionRecord],
) -> dict[str, tuple[ActionResult, list[EvidenceRecord]]]:
    actions = {
        "user_a_own_open": _read_action(store.run_id, target, sessions["user_a"], "/idor/open", "n-104", "user_a own read"),
        "user_b_own_open": _read_action(store.run_id, target, sessions["user_b"], "/idor/open", "n-205", "user_b own read"),
        "user_b_cross_open": _read_action(store.run_id, target, sessions["user_b"], "/idor/open", "n-104", "user_b cross-user read"),
        "user_a_own_guarded": _read_action(store.run_id, target, sessions["user_a"], "/idor/guarded", "n-306", "user_a guarded own read"),
        "user_b_cross_guarded": _read_action(store.run_id, target, sessions["user_b"], "/idor/guarded", "n-306", "user_b guarded cross-user read"),
    }
    results: dict[str, tuple[ActionResult, list[EvidenceRecord]]] = {}
    for name, action in actions.items():
        store.save_action_request(action)
        results[name] = executor.execute(action)
    return results


def _comparison_evidence(
    *,
    run_id: str,
    case_id: str,
    owner_user_label: str,
    requesting_user_label: str,
    resource_id: str,
    owner_evidence: EvidenceRecord,
    cross_user_evidence: EvidenceRecord,
    related_action_ids: list[str],
    is_control_case: bool,
    rejects_hypothesis: bool = False,
) -> EvidenceRecord:
    owner_body = _body_json(owner_evidence)
    cross_body = _body_json(cross_user_evidence)
    cross_user_access_granted = (
        cross_user_evidence.attributes.get("status_code") == 200
        and cross_body.get("owner_user_label") == owner_user_label
        and cross_body.get("resource_id") == resource_id
        and cross_body.get("content_marker") == owner_body.get("content_marker")
    )
    control_case_passed = (
        is_control_case
        and owner_evidence.attributes.get("status_code") == 200
        and not cross_user_access_granted
        and cross_user_evidence.attributes.get("status_code") in {401, 403, 404}
    )
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dev_benchmark_idor",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=cross_user_evidence.target_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary=f"Compared owner and cross-user read behavior for {case_id}.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=related_action_ids,
        attributes={
            "case_id": case_id,
            "resource_id": resource_id,
            "owner_user_label": owner_user_label,
            "requesting_user_label": requesting_user_label,
            "owner_status_code": owner_evidence.attributes.get("status_code"),
            "cross_user_status_code": cross_user_evidence.attributes.get("status_code"),
            "owner_content_marker": owner_body.get("content_marker"),
            "cross_user_content_marker": cross_body.get("content_marker"),
            "cross_user_access_granted": cross_user_access_granted,
            "is_control_case": is_control_case,
            "control_case_passed": control_case_passed,
            "rejects_hypothesis": rejects_hypothesis,
        },
    )


def _verify_finding(
    *,
    store: RunArtifactStore,
    modules: dict,
    title: str,
    hypothesis: str,
    affected_target: str,
    report_fields: dict,
    evidence: list[EvidenceRecord],
) -> FindingRecord:
    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=store.run_id,
        module_id="access.idor_read_only",
        title=title,
        category=modules["access.idor_read_only"].category,
        affected_target=affected_target,
        state=FindingState.SUSPECTED,
        hypothesis=hypothesis,
        created_by="dev_benchmark_idor",
        supporting_evidence_refs=[item.evidence_id for item in evidence],
        report_fields=report_fields,
        severity="medium",
        confidence="verified_by_cross_user_http_comparison",
    )
    store.save_finding(finding)
    requested = request_verification(finding)
    store.save_finding(requested)
    result = FindingVerifier(modules).verify(requested, evidence)
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
                "resource_id": case["resource_id"],
                "owner_user_label": case["owner_user_label"],
                "requesting_user_label": case["requesting_user_label"],
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


def _auth_action(run_id: str, target: TargetConfig, user_label: str, username: str) -> ActionRequest:
    url = urljoin(f"{target.base_url.rstrip('/')}/", "/idor/login")
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_idor",
        module_id="access.idor_read_only",
        action_type=ActionType.AUTHENTICATE_TEST_USER,
        target_ref=url,
        scope_context={"user_label": user_label},
        parameters={"url": url, "username": username, "credential_source": "target_config"},
        preconditions=["local_idor_benchmark_running"],
        safety_class=SafetyClass.LOW,
        rationale="Authenticate configured benchmark user into an isolated session.",
        expected_evidence=[EvidenceType.SESSION_CONTEXT],
    )


def _read_action(
    run_id: str,
    target: TargetConfig,
    session: SessionRecord,
    path: str,
    resource_id: str,
    label: str,
) -> ActionRequest:
    url = _resource_url(target, path, resource_id)
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dev_benchmark_idor",
        module_id="access.idor_read_only",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=url,
        scope_context={"user_label": session.user_label, "resource_id": resource_id},
        parameters={
            "method": "GET",
            "url": url,
            "session_ref": session.session_ref,
            "capture_body_text": True,
            "body_text_limit": 2048,
        },
        preconditions=["authenticated_isolated_session", "read_only_request"],
        safety_class=SafetyClass.LOW,
        rationale=f"Replay read-only benchmark request for {label}.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )


def _resource_url(target: TargetConfig, path: str, resource_id: str) -> str:
    return urljoin(f"{target.base_url.rstrip('/')}/", f"{path.lstrip('/')}?rid={resource_id}")


def _body_json(evidence: EvidenceRecord) -> dict:
    text = evidence.attributes.get("body_text")
    if not isinstance(text, str):
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _ground_truth_path(target: TargetConfig) -> Path:
    configured = Path(str(target.metadata["ground_truth_path"]))
    return configured if configured.is_absolute() else REPO_ROOT / configured


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local read-only IDOR development benchmark integration.")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    args = parser.parse_args()
    try:
        run_dir = run_development_benchmark_idor(args.config, args.output_root)
    except Exception as exc:
        print(f"Development benchmark read-only IDOR integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"Development benchmark read-only IDOR artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
