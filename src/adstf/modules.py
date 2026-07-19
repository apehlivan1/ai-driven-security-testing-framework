from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from adstf.contracts import ActionType, EvidenceRecord, EvidenceType


EvidenceCriterion = Callable[[list[EvidenceRecord]], bool]


@dataclass(frozen=True)
class VerificationCriterion:
    name: str
    evaluate: EvidenceCriterion


@dataclass(frozen=True)
class VulnerabilityModule:
    module_id: str
    display_name: str
    category: str
    supported_hypotheses: list[str]
    required_target_features: list[str]
    allowed_action_types: list[ActionType]
    required_evidence_types: list[EvidenceType]
    requires_control_case: bool
    report_fields: list[str]
    additional_verification_criteria: list[VerificationCriterion] = field(default_factory=list)


def has_browser_execution_signal(evidence: list[EvidenceRecord]) -> bool:
    return any(
        item.evidence_type == EvidenceType.BROWSER_OBSERVATION
        and item.attributes.get("execution_marker_observed") is True
        for item in evidence
    )


def has_distinct_benchmark_sessions(evidence: list[EvidenceRecord]) -> bool:
    labels = {
        item.attributes.get("user_label")
        for item in evidence
        if item.evidence_type == EvidenceType.SESSION_CONTEXT
    }
    return len(labels) >= 2


def has_cross_user_read_access(evidence: list[EvidenceRecord]) -> bool:
    return any(
        item.evidence_type == EvidenceType.COMPARISON_RESULT
        and item.attributes.get("cross_user_access_granted") is True
        and item.attributes.get("owner_user_label") != item.attributes.get("requesting_user_label")
        for item in evidence
    )


def has_stable_baseline_behavior(evidence: list[EvidenceRecord]) -> bool:
    return any(
        item.evidence_type == EvidenceType.COMPARISON_RESULT
        and item.attributes.get("baseline_stable") is True
        and item.attributes.get("server_error_observed") is not True
        for item in evidence
    )


def has_reproducible_boolean_difference(evidence: list[EvidenceRecord]) -> bool:
    return any(
        item.evidence_type == EvidenceType.COMPARISON_RESULT
        and item.attributes.get("true_false_difference_reproducible") is True
        and item.attributes.get("server_error_observed") is not True
        and item.attributes.get("reflected_payload_only") is not True
        for item in evidence
    )


def mvp_modules() -> dict[str, VulnerabilityModule]:
    modules = [
        VulnerabilityModule(
            module_id="xss.reflected",
            display_name="Reflected XSS",
            category="reflected_xss",
            supported_hypotheses=["reflected_input_executes_in_browser"],
            required_target_features=["reflected_input"],
            allowed_action_types=[
                ActionType.NAVIGATE,
                ActionType.SUBMIT_FORM,
                ActionType.MUTATE_PARAMETER,
                ActionType.OBSERVE_BROWSER,
                ActionType.COMPARE_OBSERVATIONS,
            ],
            required_evidence_types=[
                EvidenceType.HTTP_EXCHANGE,
                EvidenceType.BROWSER_OBSERVATION,
                EvidenceType.COMPARISON_RESULT,
            ],
            requires_control_case=True,
            report_fields=["payload_marker", "execution_signal", "control_case"],
            additional_verification_criteria=[
                VerificationCriterion(
                    name="has_browser_execution_signal",
                    evaluate=has_browser_execution_signal,
                )
            ],
        ),
        VulnerabilityModule(
            module_id="access.idor_read_only",
            display_name="Read-Only IDOR",
            category="read_only_idor",
            supported_hypotheses=["cross_user_read_access"],
            required_target_features=["two_test_users", "user_owned_resource"],
            allowed_action_types=[
                ActionType.AUTHENTICATE_TEST_USER,
                ActionType.REPLAY_REQUEST,
                ActionType.COMPARE_OBSERVATIONS,
            ],
            required_evidence_types=[
                EvidenceType.SESSION_CONTEXT,
                EvidenceType.RESOURCE_OWNERSHIP,
                EvidenceType.HTTP_EXCHANGE,
                EvidenceType.COMPARISON_RESULT,
            ],
            requires_control_case=True,
            report_fields=["owner_user", "requesting_user", "resource_id", "control_case"],
            additional_verification_criteria=[
                VerificationCriterion(
                    name="has_distinct_benchmark_sessions",
                    evaluate=has_distinct_benchmark_sessions,
                ),
                VerificationCriterion(
                    name="has_cross_user_read_access",
                    evaluate=has_cross_user_read_access,
                ),
            ],
        ),
        VulnerabilityModule(
            module_id="sqli.boolean",
            display_name="Boolean-Based SQL Injection",
            category="boolean_sqli",
            supported_hypotheses=["boolean_condition_changes_response"],
            required_target_features=["replayable_parameter", "stable_baseline"],
            allowed_action_types=[
                ActionType.REPLAY_REQUEST,
                ActionType.MUTATE_PARAMETER,
                ActionType.COMPARE_OBSERVATIONS,
            ],
            required_evidence_types=[
                EvidenceType.HTTP_EXCHANGE,
                EvidenceType.COMPARISON_RESULT,
            ],
            requires_control_case=True,
            report_fields=["parameter", "baseline", "true_condition", "false_condition"],
            additional_verification_criteria=[
                VerificationCriterion(
                    name="has_stable_baseline_behavior",
                    evaluate=has_stable_baseline_behavior,
                ),
                VerificationCriterion(
                    name="has_reproducible_boolean_difference",
                    evaluate=has_reproducible_boolean_difference,
                ),
            ],
        ),
    ]
    return {module.module_id: module for module in modules}
