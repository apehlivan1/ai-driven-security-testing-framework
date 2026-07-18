from __future__ import annotations

from adstf.contracts import FindingRecord, TargetConfig


def render_placeholder_report(target: TargetConfig, findings: list[FindingRecord]) -> str:
    lines = [
        f"# Security Testing Dry Run Report: {target.name}",
        "",
        "This placeholder report is generated from scaffold records only.",
        "It does not contain real vulnerability testing results.",
        "",
        "## Findings",
        "",
    ]

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
