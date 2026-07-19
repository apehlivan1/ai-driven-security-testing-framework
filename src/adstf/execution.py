from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from http.client import HTTPResponse
from typing import TYPE_CHECKING
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import HTTPRedirectHandler, Request, build_opener

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

if TYPE_CHECKING:
    from adstf.sessions import SessionRegistry


class MockExecutor:
    """Executor for dry runs; it never performs network or browser operations."""

    def __init__(self, safety: SafetyBoundary) -> None:
        self._safety = safety

    def execute(self, action: ActionRequest, evidence_refs: list[str] | None = None) -> ActionResult:
        decision = self._safety.evaluate(action)
        now = datetime.now(UTC).isoformat()

        if not decision.approved:
            return ActionResult(
                action_id=action.action_id,
                run_id=action.run_id,
                status=ActionStatus.BLOCKED,
                started_at=now,
                completed_at=now,
                executor="mock",
                normalized_observations={"executed": False},
                evidence_refs=evidence_refs or [],
                safety_notes=decision.reasons,
                error="blocked by safety boundary",
            )

        return ActionResult(
            action_id=action.action_id,
            run_id=action.run_id,
            status=ActionStatus.EXECUTED,
            started_at=now,
            completed_at=now,
            executor="mock",
            normalized_observations={
                "executed": True,
                "action_type": action.action_type.value,
                "target_ref": action.target_ref,
            },
            evidence_refs=evidence_refs or [],
            safety_notes=[],
        )


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class HttpExecutor:
    """Minimal deterministic HTTP executor with manual redirect allowlist checks."""

    def __init__(
        self,
        safety: SafetyBoundary,
        timeout_seconds: float = 5.0,
        session_registry: "SessionRegistry | None" = None,
    ) -> None:
        self._safety = safety
        self._timeout_seconds = timeout_seconds
        self._opener = build_opener(NoRedirectHandler)
        self._session_registry = session_registry

    def execute(self, action: ActionRequest) -> tuple[ActionResult, list[EvidenceRecord]]:
        started = datetime.now(UTC).isoformat()
        decision = self._safety.evaluate(action)

        if not decision.approved:
            evidence = self._blocked_evidence(action, decision.reasons)
            completed = datetime.now(UTC).isoformat()
            return (
                ActionResult(
                    action_id=action.action_id,
                    run_id=action.run_id,
                    status=ActionStatus.BLOCKED,
                    started_at=started,
                    completed_at=completed,
                    executor="http",
                    normalized_observations={"executed": False},
                    evidence_refs=[evidence.evidence_id],
                    safety_notes=decision.reasons,
                    error="blocked by safety boundary",
                ),
                [evidence],
            )

        try:
            response_info = self._request_with_checked_redirects(action)
        except Exception as exc:  # keep the executor boundary deterministic for callers
            evidence = self._failure_evidence(action, str(exc))
            completed = datetime.now(UTC).isoformat()
            return (
                ActionResult(
                    action_id=action.action_id,
                    run_id=action.run_id,
                    status=ActionStatus.FAILED,
                    started_at=started,
                    completed_at=completed,
                    executor="http",
                    normalized_observations={"executed": False},
                    evidence_refs=[evidence.evidence_id],
                    safety_notes=[],
                    error=str(exc),
                ),
                [evidence],
            )

        evidence = EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=action.run_id,
            source="http_executor",
            evidence_type=EvidenceType.HTTP_EXCHANGE,
            target_ref=action.target_ref,
            created_at=datetime.now(UTC).isoformat(),
            summary=f"HTTP {response_info['method']} {response_info['final_url']} returned {response_info['status_code']}.",
            data_ref=None,
            redaction_status=RedactionStatus.ABSENT,
            related_action_ids=[action.action_id],
            attributes=response_info,
        )
        completed = datetime.now(UTC).isoformat()
        return (
            ActionResult(
                action_id=action.action_id,
                run_id=action.run_id,
                status=ActionStatus.EXECUTED,
                started_at=started,
                completed_at=completed,
                executor="http",
                normalized_observations=response_info,
                evidence_refs=[evidence.evidence_id],
                safety_notes=[],
            ),
            [evidence],
        )

    def _request_with_checked_redirects(self, action: ActionRequest) -> dict:
        method = str(action.parameters.get("method", "GET")).upper()
        url = str(action.parameters.get("url") or action.target_ref)
        headers = {
            str(key): str(value)
            for key, value in dict(action.parameters.get("headers", {})).items()
        }
        session_ref = action.parameters.get("session_ref")
        if session_ref:
            if self._session_registry is None:
                raise RuntimeError("action references a session but no session registry is configured")
            headers.update(self._session_registry.headers_for(str(session_ref)))
        max_redirects = int(action.parameters.get("max_redirects", 3))
        capture_body_text = bool(action.parameters.get("capture_body_text", False))
        body_text_limit = int(action.parameters.get("body_text_limit", 4096))
        redirect_chain: list[dict] = []

        for _ in range(max_redirects + 1):
            request = Request(url=url, method=method, headers=headers)
            try:
                with self._opener.open(request, timeout=self._timeout_seconds) as response:
                    return self._normalize_response(
                        method,
                        url,
                        response,
                        redirect_chain,
                        capture_body_text=capture_body_text,
                        body_text_limit=body_text_limit,
                    )
            except HTTPError as error:
                if error.code in {301, 302, 303, 307, 308}:
                    try:
                        location = error.headers.get("Location")
                        if not location:
                            raise RuntimeError(
                                f"redirect response {error.code} did not include Location"
                            )
                        next_url = urljoin(url, location)
                        redirect_decision = self._safety.evaluate_url(
                            next_url,
                            action.module_id,
                            action.safety_class,
                        )
                        redirect_chain.append(
                            {
                                "from_url": url,
                                "status_code": error.code,
                                "location": next_url,
                                "approved": redirect_decision.approved,
                                "reasons": redirect_decision.reasons,
                            }
                        )
                        if not redirect_decision.approved:
                            raise RuntimeError(
                                "redirect blocked by safety boundary: "
                                + "; ".join(redirect_decision.reasons)
                            )
                        url = next_url
                        if error.code == 303:
                            method = "GET"
                    finally:
                        error.close()
                    continue
                response_info = self._normalize_response(
                    method,
                    url,
                    error,
                    redirect_chain,
                    capture_body_text=capture_body_text,
                    body_text_limit=body_text_limit,
                )
                error.close()
                return response_info
            except URLError as error:
                raise RuntimeError(f"HTTP request failed: {error.reason}") from error

        raise RuntimeError(f"too many redirects; limit is {max_redirects}")

    def _normalize_response(
        self,
        method: str,
        final_url: str,
        response: HTTPResponse | HTTPError,
        redirect_chain: list[dict],
        *,
        capture_body_text: bool = False,
        body_text_limit: int = 4096,
    ) -> dict:
        body = response.read()
        headers = dict(response.headers.items())
        content_type = response.headers.get("Content-Type")
        info = {
            "method": method,
            "final_url": final_url,
            "status_code": response.status if hasattr(response, "status") else response.code,
            "reason": getattr(response, "reason", None),
            "content_type": content_type,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers": {
                key: value
                for key, value in headers.items()
                if key.lower() in {"content-type", "location", "server"}
            },
            "redirect_chain": redirect_chain,
        }
        if capture_body_text:
            info["body_text"] = body[:body_text_limit].decode("utf-8", errors="replace")
            info["body_text_truncated"] = len(body) > body_text_limit
        return info

    def _blocked_evidence(self, action: ActionRequest, reasons: list[str]) -> EvidenceRecord:
        return EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=action.run_id,
            source="safety_boundary",
            evidence_type=EvidenceType.BLOCKED_ACTION,
            target_ref=action.target_ref,
            created_at=datetime.now(UTC).isoformat(),
            summary="HTTP action was blocked before execution.",
            data_ref=None,
            redaction_status=RedactionStatus.ABSENT,
            related_action_ids=[action.action_id],
            attributes={"reasons": reasons},
        )

    def _failure_evidence(self, action: ActionRequest, error: str) -> EvidenceRecord:
        evidence_type = (
            EvidenceType.BLOCKED_ACTION
            if "redirect blocked by safety boundary" in error
            else EvidenceType.HTTP_EXCHANGE
        )
        return EvidenceRecord(
            evidence_id=new_id("evidence"),
            run_id=action.run_id,
            source="http_executor",
            evidence_type=evidence_type,
            target_ref=action.target_ref,
            created_at=datetime.now(UTC).isoformat(),
            summary="HTTP action did not complete successfully.",
            data_ref=None,
            redaction_status=RedactionStatus.ABSENT,
            related_action_ids=[action.action_id],
            attributes={"error": error},
        )
