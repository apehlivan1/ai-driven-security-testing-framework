from __future__ import annotations

from dataclasses import dataclass

from adstf.contracts import ActionType, EvidenceType


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
        ),
    ]
    return {module.module_id: module for module in modules}
