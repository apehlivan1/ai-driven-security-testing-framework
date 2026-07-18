from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from adstf.contracts import (
    ActionRequest,
    ActionResult,
    ActionStatus,
    EvidenceRecord,
    EvidenceType,
    RedactionStatus,
)
from adstf.lifecycle import new_id
from adstf.safety import SafetyBoundary
from adstf.storage import RunArtifactStore


class BrowserExecutor:
    """Minimal Playwright-backed executor for browser observation actions."""

    def __init__(self, safety: SafetyBoundary, store: RunArtifactStore) -> None:
        self._safety = safety
        self._store = store

    def observe(self, action: ActionRequest, page: Any) -> tuple[ActionResult, EvidenceRecord]:
        started = datetime.now(UTC).isoformat()
        decision = self._safety.evaluate(action)
        if not decision.approved:
            evidence = self._blocked_evidence(action, decision.reasons)
            return self._result(action, ActionStatus.BLOCKED, started, evidence, decision.reasons), evidence

        blocked_requests: list[dict[str, Any]] = []

        def guard_route(route: Any) -> None:
            request_url = route.request.url
            request_decision = self._safety.evaluate_url(
                request_url,
                action.module_id,
                action.safety_class,
            )
            if request_decision.approved:
                route.continue_()
                return
            blocked_requests.append({"url": request_url, "reasons": request_decision.reasons})
            route.abort()

        route_installed = False
        try:
            if hasattr(page, "route"):
                page.route("**/*", guard_route)
                route_installed = True

            url = str(action.parameters.get("url") or action.target_ref)
            marker_variable = action.parameters.get("marker_variable")
            if marker_variable and hasattr(page, "add_init_script"):
                page.add_init_script(f"delete window.{marker_variable};")
            page.goto(url, wait_until="domcontentloaded")

            final_url = str(getattr(page, "url", url))
            final_decision = self._safety.evaluate_url(
                final_url,
                action.module_id,
                action.safety_class,
            )
            if not final_decision.approved:
                blocked_requests.append({"url": final_url, "reasons": final_decision.reasons})
                evidence = self._blocked_evidence(action, final_decision.reasons, final_url)
                return self._result(action, ActionStatus.FAILED, started, evidence, final_decision.reasons), evidence

            expected_marker = action.parameters.get("expected_marker")
            execution_marker_observed = False
            if marker_variable and expected_marker:
                execution_marker_observed = bool(
                    page.evaluate(f"window.{marker_variable} === {expected_marker!r}")
                )

            artifact_prefix = str(action.parameters.get("artifact_prefix", action.action_id))
            screenshot = self._store.save_artifact_bytes(
                f"{artifact_prefix}.png",
                page.screenshot(full_page=True),
            )
            html = self._store.save_artifact_text(f"{artifact_prefix}.html", page.content())
            title = page.title() if hasattr(page, "title") else None

            evidence = EvidenceRecord(
                evidence_id=new_id("evidence"),
                run_id=action.run_id,
                source="browser_executor",
                evidence_type=EvidenceType.BROWSER_OBSERVATION,
                target_ref=action.target_ref,
                created_at=datetime.now(UTC).isoformat(),
                summary=str(action.parameters.get("summary", "Browser observation captured.")),
                data_ref=str(screenshot.relative_to(self._store.run_dir)),
                redaction_status=RedactionStatus.ABSENT,
                related_action_ids=[action.action_id],
                attributes={
                    "requested_url": url,
                    "final_url": final_url,
                    "page_title": title,
                    "execution_marker_observed": execution_marker_observed,
                    "marker": expected_marker,
                    "marker_variable": marker_variable,
                    "html_artifact": str(html.relative_to(self._store.run_dir)),
                    "screenshot_artifact": str(screenshot.relative_to(self._store.run_dir)),
                    "blocked_requests": blocked_requests,
                },
            )
            return self._result(action, ActionStatus.EXECUTED, started, evidence, []), evidence
        except Exception as exc:
            reasons = [str(exc)]
            if blocked_requests:
                reasons.extend(reason for item in blocked_requests for reason in item["reasons"])
            evidence = self._blocked_evidence(action, reasons)
            return self._result(action, ActionStatus.FAILED, started, evidence, reasons), evidence
        finally:
            if route_installed and hasattr(page, "unroute"):
                page.unroute("**/*", guard_route)

    def _result(
        self,
        action: ActionRequest,
        status: ActionStatus,
        started_at: str,
        evidence: EvidenceRecord,
        safety_notes: list[str],
    ) -> ActionResult:
        return ActionResult(
            action_id=action.action_id,
            run_id=action.run_id,
            status=status,
            started_at=started_at,
            completed_at=datetime.now(UTC).isoformat(),
            executor="browser",
            normalized_observations=evidence.attributes,
            evidence_refs=[evidence.evidence_id],
            safety_notes=safety_notes,
            error="; ".join(safety_notes) if status != ActionStatus.EXECUTED else None,
        )

    def _blocked_evidence(
        self,
        action: ActionRequest,
        reasons: list[str],
        final_url: str | None = None,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=action.run_id,
            source="browser_executor",
            evidence_type=EvidenceType.BLOCKED_ACTION,
            target_ref=action.target_ref,
            created_at=datetime.now(UTC).isoformat(),
            summary="Browser action was blocked or failed before a trusted observation.",
            data_ref=None,
            redaction_status=RedactionStatus.ABSENT,
            related_action_ids=[action.action_id],
            attributes={"final_url": final_url, "reasons": reasons},
        )
