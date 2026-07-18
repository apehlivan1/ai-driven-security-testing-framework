from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ActionType(StrEnum):
    NAVIGATE = "navigate"
    SUBMIT_FORM = "submit_form"
    REPLAY_REQUEST = "replay_request"
    MUTATE_PARAMETER = "mutate_parameter"
    AUTHENTICATE_TEST_USER = "authenticate_test_user"
    OBSERVE_BROWSER = "observe_browser"
    COMPARE_OBSERVATIONS = "compare_observations"


class ActionStatus(StrEnum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    FAILED = "failed"
    SKIPPED = "skipped"


class EvidenceType(StrEnum):
    HTTP_EXCHANGE = "http_exchange"
    BROWSER_OBSERVATION = "browser_observation"
    COMPARISON_RESULT = "comparison_result"
    SESSION_CONTEXT = "session_context"
    RESOURCE_OWNERSHIP = "resource_ownership"
    VERIFICATION_NOTE = "verification_note"
    BLOCKED_ACTION = "blocked_action"


class FindingState(StrEnum):
    SUSPECTED = "suspected"
    VERIFICATION_REQUESTED = "verification_requested"
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class VerificationOutcome(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class RedactionStatus(StrEnum):
    ABSENT = "absent"
    REDACTED = "redacted"
    ISOLATED = "isolated"
    RETAINED = "retained"


class SafetyClass(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class TargetConfig:
    name: str
    base_url: str
    allowed_hosts: list[str]
    enabled_modules: list[str]
    allowed_schemes: list[str] = field(default_factory=lambda: ["http", "https"])
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443])
    max_actions: int = 50
    test_users: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionRequest:
    action_id: str
    run_id: str
    requested_by: str
    module_id: str | None
    action_type: ActionType
    target_ref: str
    scope_context: dict[str, Any]
    parameters: dict[str, Any]
    preconditions: list[str]
    safety_class: SafetyClass
    rationale: str
    expected_evidence: list[EvidenceType]


@dataclass(frozen=True)
class ActionResult:
    action_id: str
    run_id: str
    status: ActionStatus
    started_at: str
    completed_at: str
    executor: str
    normalized_observations: dict[str, Any]
    evidence_refs: list[str]
    safety_notes: list[str]
    error: str | None = None


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    run_id: str
    source: str
    evidence_type: EvidenceType
    target_ref: str
    created_at: str
    summary: str
    data_ref: str | None
    redaction_status: RedactionStatus
    related_action_ids: list[str]
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    run_id: str
    module_id: str
    title: str
    category: str
    affected_target: str
    state: FindingState
    hypothesis: str
    created_by: str
    supporting_evidence_refs: list[str]
    verification_result_ref: str | None = None
    report_fields: dict[str, Any] = field(default_factory=dict)
    severity: str | None = None
    confidence: str | None = None
    deduplication_key: str | None = None


@dataclass(frozen=True)
class VerifierResult:
    verification_result_id: str
    finding_id: str
    module_id: str
    outcome: VerificationOutcome
    criteria_checked: list[str]
    criteria_satisfied: list[str]
    criteria_missing: list[str]
    control_cases: list[dict[str, Any]]
    evidence_refs: list[str]
    reproduction_status: str
    rationale: str
    limitations: list[str]
