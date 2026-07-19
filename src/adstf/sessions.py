from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from adstf.contracts import EvidenceRecord, EvidenceType, RedactionStatus
from adstf.lifecycle import new_id


@dataclass(frozen=True)
class SessionRecord:
    session_ref: str
    user_label: str
    username: str
    headers: dict[str, str]
    token_sha256: str


class SessionRegistry:
    """In-memory session store; persisted artifacts only reference session_ref."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def add_cookie_session(
        self,
        *,
        user_label: str,
        username: str,
        cookie_name: str,
        token: str,
    ) -> SessionRecord:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        session_ref = f"session-{user_label}-{token_hash[:12]}"
        record = SessionRecord(
            session_ref=session_ref,
            user_label=user_label,
            username=username,
            headers={"Cookie": f"{cookie_name}={token}"},
            token_sha256=token_hash,
        )
        self._sessions[session_ref] = record
        return record

    def headers_for(self, session_ref: str) -> dict[str, str]:
        if session_ref not in self._sessions:
            raise KeyError(f"unknown session_ref: {session_ref}")
        return dict(self._sessions[session_ref].headers)


def session_context_evidence(
    *,
    run_id: str,
    record: SessionRecord,
    related_action_ids: list[str],
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=new_id("evidence"),
        run_id=run_id,
        source="session_registry",
        evidence_type=EvidenceType.SESSION_CONTEXT,
        target_ref=record.session_ref,
        created_at=datetime.now(UTC).isoformat(),
        summary=f"Authenticated isolated benchmark session for {record.user_label}.",
        data_ref=None,
        redaction_status=RedactionStatus.ISOLATED,
        related_action_ids=related_action_ids,
        attributes={
            "user_label": record.user_label,
            "username": record.username,
            "session_ref": record.session_ref,
            "token_sha256": record.token_sha256,
            "token_redacted": True,
            "credential_redacted": True,
            "header_names": sorted(record.headers.keys()),
        },
    )
