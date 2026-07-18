from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from adstf.config import load_target_config
from adstf.contracts import (
    ActionRequest,
    ActionType,
    EvidenceRecord,
    EvidenceType,
    FindingRecord,
    FindingState,
    RedactionStatus,
    SafetyClass,
    VerificationOutcome,
)
from adstf.execution import HttpExecutor
from adstf.lifecycle import apply_verifier_result, new_id, request_verification
from adstf.modules import mvp_modules
from adstf.reporting import render_placeholder_report
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore
from adstf.verification import FindingVerifier


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "dvwa-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


def run_dvwa_reflected_xss(config_path: Path, output_root: Path, headless: bool = True) -> Path:
    target = load_target_config(config_path)
    username, password = _configured_user(target.test_users)
    run_id = f"dvwa-xss-reflected-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    store = RunArtifactStore(output_root, run_id)
    store.initialize(target)

    safety = SafetyBoundary(target)
    modules = mvp_modules()

    smoke_action = ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dvwa_xss_reflected",
        module_id="xss.reflected",
        action_type=ActionType.REPLAY_REQUEST,
        target_ref=f"{target.base_url}/login.php",
        scope_context={"target": target.name},
        parameters={"method": "GET", "url": f"{target.base_url}/login.php"},
        preconditions=["dvwa_running_locally"],
        safety_class=SafetyClass.LOW,
        rationale="Confirm the target is reachable before browser verification.",
        expected_evidence=[EvidenceType.HTTP_EXCHANGE],
    )
    store.save_action_request(smoke_action)
    smoke_result, smoke_evidence = HttpExecutor(safety).execute(smoke_action)
    for evidence in smoke_evidence:
        store.save_evidence(evidence)
    store.save_action_result(smoke_result)
    if smoke_result.status.value != "executed":
        store.save_report(render_placeholder_report(target, []))
        raise RuntimeError(
            "DVWA is not reachable. Confirm the local target is running before XSS integration."
        )

    marker = f"adstf_xss_{run_id.replace('-', '_')}"
    control_marker = f"adstf_control_{run_id.replace('-', '_')}"
    payload = f"<script>window.__adstfXssMarker='{marker}'</script>"
    xss_url = f"{target.base_url}/vulnerabilities/xss_r/?name={quote(payload, safe='')}"
    control_url = f"{target.base_url}/vulnerabilities/xss_r/?name={quote(control_marker, safe='')}"

    xss_action = _browser_action(
        run_id,
        xss_url,
        "Submit safe reflected-XSS marker payload and observe browser execution.",
    )
    control_action = _browser_action(
        run_id,
        control_url,
        "Submit benign reflected-XSS control marker and confirm no execution.",
    )
    store.save_action_request(xss_action)
    store.save_action_request(control_action)

    for action in (xss_action, control_action):
        decision = safety.evaluate(action)
        if not decision.approved:
            store.save_report(render_placeholder_report(target, []))
            raise RuntimeError("Browser action blocked by safety boundary: " + "; ".join(decision.reasons))

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        context = browser.new_context(base_url=target.base_url)
        try:
            page = context.new_page()
            _login_to_dvwa(page, target.base_url, username, password)
            context.add_cookies(
                [
                    {
                        "name": "security",
                        "value": "low",
                        "url": target.base_url,
                    }
                ]
            )

            xss_observation = _observe_url(page, xss_url, marker, "__adstfXssMarker")
            xss_screenshot = store.save_artifact_bytes(
                "xss-execution.png",
                page.screenshot(full_page=True),
            )
            xss_html = store.save_artifact_text("xss-execution.html", page.content())

            control_observation = _observe_url(page, control_url, marker, "__adstfXssMarker")
            control_screenshot = store.save_artifact_bytes(
                "xss-control.png",
                page.screenshot(full_page=True),
            )
            control_html = store.save_artifact_text("xss-control.html", page.content())
        finally:
            context.close()
            browser.close()

    now = datetime.now(UTC).isoformat()
    xss_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dvwa_xss_reflected",
        evidence_type=EvidenceType.BROWSER_OBSERVATION,
        target_ref=xss_url,
        created_at=now,
        summary="Browser observed reflected-XSS execution marker after payload navigation.",
        data_ref=str(xss_screenshot.relative_to(store.run_dir)),
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[xss_action.action_id],
        attributes={
            "execution_marker_observed": xss_observation["execution_marker_observed"],
            "marker": marker,
            "url": xss_url,
            "html_artifact": str(xss_html.relative_to(store.run_dir)),
            "screenshot_artifact": str(xss_screenshot.relative_to(store.run_dir)),
        },
    )
    control_evidence = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dvwa_xss_reflected",
        evidence_type=EvidenceType.COMPARISON_RESULT,
        target_ref=control_url,
        created_at=datetime.now(UTC).isoformat(),
        summary="Benign control marker did not set the browser execution marker.",
        data_ref=str(control_screenshot.relative_to(store.run_dir)),
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[control_action.action_id],
        attributes={
            "is_control_case": True,
            "control_case_passed": control_observation["execution_marker_observed"] is False,
            "execution_marker_observed": control_observation["execution_marker_observed"],
            "control_marker": control_marker,
            "html_artifact": str(control_html.relative_to(store.run_dir)),
            "screenshot_artifact": str(control_screenshot.relative_to(store.run_dir)),
        },
    )
    verification_note = EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="dvwa_xss_reflected",
        evidence_type=EvidenceType.VERIFICATION_NOTE,
        target_ref=xss_url,
        created_at=datetime.now(UTC).isoformat(),
        summary="Reflected-XSS verification used safe JavaScript marker assignment only.",
        data_ref=None,
        redaction_status=RedactionStatus.ABSENT,
        related_action_ids=[xss_action.action_id, control_action.action_id],
        attributes={"payload_family": "safe_marker_assignment", "no_cookie_access": True},
    )

    for evidence in (*smoke_evidence, xss_evidence, control_evidence, verification_note):
        if evidence not in smoke_evidence:
            store.save_evidence(evidence)

    store.save_action_result(
        _browser_result(xss_action, xss_evidence.evidence_id, xss_observation, "executed")
    )
    store.save_action_result(
        _browser_result(control_action, control_evidence.evidence_id, control_observation, "executed")
    )

    finding = FindingRecord(
        finding_id=new_id("finding"),
        run_id=run_id,
        module_id="xss.reflected",
        title="Reflected XSS executes in DVWA browser context",
        category=modules["xss.reflected"].category,
        affected_target=f"{target.base_url}/vulnerabilities/xss_r/?name=",
        state=FindingState.SUSPECTED,
        hypothesis="The DVWA reflected-XSS endpoint executes script supplied through the name parameter.",
        created_by="dvwa_xss_reflected",
        supporting_evidence_refs=[
            smoke_evidence[0].evidence_id,
            xss_evidence.evidence_id,
            control_evidence.evidence_id,
            verification_note.evidence_id,
        ],
        report_fields={
            "parameter": "name",
            "payload_marker": marker,
            "control_marker": control_marker,
            "execution_artifact": xss_evidence.data_ref,
            "control_artifact": control_evidence.data_ref,
        },
        severity="medium",
        confidence="verified_by_browser_marker",
    )
    store.save_finding(finding)

    requested = request_verification(finding)
    store.save_finding(requested)
    verifier_result = FindingVerifier(modules).verify(
        requested,
        [*smoke_evidence, xss_evidence, control_evidence, verification_note],
    )
    store.save_verifier_result(verifier_result)
    verified = apply_verifier_result(requested, verifier_result)
    store.save_finding(verified)
    store.save_report(render_placeholder_report(target, [verified], placeholder=False))
    if verifier_result.outcome != VerificationOutcome.VERIFIED:
        raise RuntimeError(
            "Reflected-XSS verification did not produce a verified finding. "
            f"Outcome was {verifier_result.outcome.value}."
        )
    return store.run_dir


def _configured_user(test_users: dict[str, str]) -> tuple[str, str]:
    if not test_users:
        raise ValueError("DVWA reflected-XSS integration requires a configured test user")
    username, password = next(iter(test_users.items()))
    return username, password


def _browser_action(run_id: str, url: str, rationale: str) -> ActionRequest:
    return ActionRequest(
        action_id=new_id("action"),
        run_id=run_id,
        requested_by="dvwa_xss_reflected",
        module_id="xss.reflected",
        action_type=ActionType.OBSERVE_BROWSER,
        target_ref=url,
        scope_context={},
        parameters={"url": url},
        preconditions=["authenticated_dvwa_session", "dvwa_security_low"],
        safety_class=SafetyClass.LOW,
        rationale=rationale,
        expected_evidence=[EvidenceType.BROWSER_OBSERVATION],
    )


def _login_to_dvwa(page, base_url: str, username: str, password: str) -> None:
    page.goto(f"{base_url}/login.php", wait_until="domcontentloaded")
    try:
        page.fill("input[name='username']", username)
        page.fill("input[name='password']", password)
        page.click("input[name='Login']")
        page.wait_for_load_state("domcontentloaded")
    except PlaywrightTimeoutError as exc:
        raise RuntimeError("DVWA login form was not available") from exc

    if "setup.php" in page.url:
        raise RuntimeError(
            "DVWA redirected to setup.php after login. Initialize the DVWA database first."
        )
    if "login.php" in page.url:
        raise RuntimeError("DVWA login did not establish an authenticated session")


def _observe_url(page, url: str, expected_marker: str, variable_name: str) -> dict:
    page.add_init_script(f"delete window.{variable_name};")
    page.goto(url, wait_until="domcontentloaded")
    if "login.php" in page.url or "setup.php" in page.url:
        raise RuntimeError(f"DVWA did not allow access to the XSS endpoint; current URL is {page.url}")
    observed = page.evaluate(f"window.{variable_name} === {expected_marker!r}")
    return {"url": url, "execution_marker_observed": bool(observed)}


def _browser_result(
    action: ActionRequest,
    evidence_id: str,
    observation: dict,
    status: str,
):
    from adstf.contracts import ActionResult, ActionStatus

    now = datetime.now(UTC).isoformat()
    return ActionResult(
        action_id=action.action_id,
        run_id=action.run_id,
        status=ActionStatus(status),
        started_at=now,
        completed_at=now,
        executor="playwright",
        normalized_observations=observation,
        evidence_refs=[evidence_id],
        safety_notes=[],
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the live local DVWA reflected-XSS browser integration."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--headed", action="store_true", help="Run Chromium with a visible window.")
    args = parser.parse_args()
    try:
        run_dir = run_dvwa_reflected_xss(args.config, args.output_root, headless=not args.headed)
    except Exception as exc:
        print(f"DVWA reflected-XSS integration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"DVWA reflected-XSS artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
