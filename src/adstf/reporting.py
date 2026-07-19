from __future__ import annotations

from collections import Counter

from adstf.contracts import FindingRecord, FindingState, TargetConfig


def render_placeholder_report(
    target: TargetConfig,
    findings: list[FindingRecord],
    *,
    placeholder: bool = True,
) -> str:
    lines = [
        f"# Security Testing Report: {target.name}",
        "",
    ]
    if placeholder:
        lines.extend(
            [
                "This placeholder report is generated from scaffold records only.",
                "It does not contain real vulnerability testing results.",
                "",
            ]
        )
    lines.extend(["## Findings", ""])

    if not findings:
        lines.append("No findings were recorded.")
    else:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- State: `{finding.state.value}`",
                    f"- Category: `{finding.category}`",
                    f"- Affected target: `{finding.affected_target}`",
                    f"- Hypothesis: {finding.hypothesis}",
                    "",
                ]
            )

    return "\n".join(lines) + "\n"


def render_benchmark_report(
    target: TargetConfig,
    findings: list[FindingRecord],
    evaluation: dict,
) -> str:
    lifecycle = evaluation.get("lifecycle_summary", {})
    aggregate = evaluation.get("aggregate_summary", {})
    lines = [
        f"# Security Testing Report: {target.name}",
        "",
        "## Lifecycle Summary",
        "",
        f"- Discovered candidates: `{lifecycle.get('discovered_candidate_count', 0)}`",
        f"- Tested vulnerability hypotheses: `{lifecycle.get('tested_hypothesis_count', 0)}`",
        f"- Verifier-confirmed findings: `{lifecycle.get('verifier_confirmed_finding_count', 0)}`",
        f"- Post-run ground-truth matches: `{lifecycle.get('post_run_ground_truth_match_count', 0)}`",
        f"- Ground truth phase: `{evaluation.get('ground_truth_used_phase')}`",
        "",
        "## Ranking Characterization",
        "",
    ]
    for source, summary in aggregate.items():
        lines.extend(
            [
                f"### {source}",
                "",
                f"- Trials: `{summary.get('trial_count', 0)}`",
                f"- Valid trials: `{summary.get('valid_trial_count', 0)}`",
                f"- Invalid trials: `{summary.get('invalid_trial_count', 0)}`",
                f"- Failed trials: `{summary.get('failed_trial_count', 0)}`",
                f"- Fallback trials: `{summary.get('fallback_trial_count', 0)}`",
                f"- Valid top-1 accuracy: `{summary.get('valid_top_1_accuracy', 'not_applicable')}`",
                f"- Valid top-k recall: `{summary.get('valid_top_k_recall', 'not_applicable')}`",
                f"- Valid MRR: `{summary.get('valid_mean_reciprocal_rank', 'not_applicable')}`",
                f"- Verified finding count total: `{summary.get('verified_finding_count_total', 0)}`",
                f"- No-vulnerability false positives: `{summary.get('no_vulnerability_false_positive_count', 0)}`",
                "",
            ]
        )

    confirmed = [finding for finding in findings if finding.state == FindingState.VERIFIED]
    hypotheses = [finding for finding in findings if finding.state != FindingState.VERIFIED]
    lines.extend(
        [
            "## Verifier-Confirmed Findings",
            "",
        ]
    )
    if confirmed:
        for finding in confirmed:
            lines.extend(_finding_lines(finding))
    else:
        lines.append("No verifier-confirmed findings were recorded.")
        lines.append("")

    lines.extend(["## Tested Vulnerability Hypotheses", ""])
    if hypotheses:
        state_counts = Counter(finding.state.value for finding in hypotheses)
        for state, count in sorted(state_counts.items()):
            lines.append(f"- `{state}`: `{count}`")
        lines.append("")
    else:
        lines.append("No unconfirmed tested hypotheses were recorded.")
        lines.append("")

    return "\n".join(lines) + "\n"


def _finding_lines(finding: FindingRecord) -> list[str]:
    return [
        f"### {finding.title}",
        "",
        f"- State: `{finding.state.value}`",
        f"- Category: `{finding.category}`",
        f"- Affected target: `{finding.affected_target}`",
        f"- Hypothesis: {finding.hypothesis}",
        "",
    ]
