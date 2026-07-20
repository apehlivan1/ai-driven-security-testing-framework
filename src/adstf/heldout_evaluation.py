from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin

from adstf.config import load_target_config
from adstf.contracts import EvidenceRecord
from adstf.serialization import to_json_value
from adstf.zap_baseline import (
    HELDOUT_MAPPING_RULES,
    HELDOUT_UNSUPPORTED_IDOR_CASES,
    ZAP_HELDOUT_ACTIVE_MAPPING_VERSION,
    ZAP_HELDOUT_PASSIVE_MAPPING_VERSION,
    normalize_zap_active_report,
    normalize_zap_passive_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = REPO_ROOT / "examples" / "benchmarks" / "heldout-manifest-v1.json"
XSS_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "heldout-xss-local.json"
IDOR_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "heldout-idor-local.json"
SQLI_CONFIG_PATH = REPO_ROOT / "examples" / "targets" / "heldout-sqli-local.json"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / ".adstf-runs"


@dataclass(frozen=True)
class HeldoutIdorCasePlan:
    case_id: str
    owner_user_label: str
    requesting_user_label: str
    resource_id: str
    path: str
    own_read_key: str
    cross_read_key: str
    control_case_id: str | None = None


def heldout_idor_case_plans(config_path: Path = IDOR_CONFIG_PATH) -> list[HeldoutIdorCasePlan]:
    target = load_target_config(config_path)
    plans: list[HeldoutIdorCasePlan] = []
    for case in target.metadata.get("cases", []):
        case_id = str(case["case_id"])
        resource_id = str(case["resource_id"])
        plans.append(
            HeldoutIdorCasePlan(
                case_id=case_id,
                owner_user_label=str(case["owner_user_label"]),
                requesting_user_label=str(case["requesting_user_label"]),
                resource_id=resource_id,
                path=str(case["path"]),
                own_read_key=f"{case_id}:owner:{resource_id}",
                cross_read_key=f"{case_id}:cross:{resource_id}",
                control_case_id=None if case_id == "hi-002" else "hi-002",
            )
        )
    return plans


def idor_resource_url(base_url: str, path: str, resource_id: str) -> str:
    return urljoin(f"{base_url.rstrip('/')}/", f"{path.lstrip('/')}?doc={resource_id}")


def idor_supporting_evidence_for_case(
    *,
    case_plan: HeldoutIdorCasePlan,
    session_evidence: dict[str, EvidenceRecord],
    ownership_evidence: dict[str, EvidenceRecord],
    read_evidence: dict[str, EvidenceRecord],
    comparison_evidence: dict[str, EvidenceRecord],
) -> list[EvidenceRecord]:
    """Return only evidence that belongs to one held-out IDOR hypothesis."""
    return [
        session_evidence[case_plan.owner_user_label],
        session_evidence[case_plan.requesting_user_label],
        ownership_evidence[case_plan.resource_id],
        read_evidence[case_plan.own_read_key],
        read_evidence[case_plan.cross_read_key],
        comparison_evidence[case_plan.case_id],
    ]


def assert_no_cross_case_rejecting_evidence(
    *,
    case_plan: HeldoutIdorCasePlan,
    evidence: list[EvidenceRecord],
) -> None:
    for item in evidence:
        evidence_case_id = item.attributes.get("case_id")
        rejects = item.attributes.get("rejects_hypothesis") is True
        if rejects and evidence_case_id != case_plan.case_id:
            raise ValueError(
                "cross-case rejecting evidence is not allowed: "
                f"{evidence_case_id} cannot support {case_plan.case_id}"
            )


def normalize_heldout_zap_passive_report(
    report: dict,
    *,
    report_path: str | None = None,
    settings: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict:
    return normalize_zap_passive_report(
        report,
        report_path=report_path,
        settings=settings,
        started_at=started_at,
        completed_at=completed_at,
        mapping_profile="heldout",
    )


def normalize_heldout_zap_active_report(
    report: dict,
    *,
    report_path: str | None = None,
    settings: dict | None = None,
    started_at: str | None = None,
    completed_at: str | None = None,
) -> dict:
    return normalize_zap_active_report(
        report,
        report_path=report_path,
        settings=settings,
        started_at=started_at,
        completed_at=completed_at,
        mapping_profile="heldout",
    )


def heldout_zap_supported_suite_case_ids() -> list[str]:
    return [rule.suite_case_id for rule in HELDOUT_MAPPING_RULES]


def heldout_zap_unsupported_suite_case_ids() -> list[str]:
    return [case["suite_case_id"] for case in HELDOUT_UNSUPPORTED_IDOR_CASES]


def zap_supported_manifest_scope(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    supported = []
    for unit in manifest["evaluation_units"]:
        if unit["category"] in {"reflected_xss", "boolean_sqli"}:
            prefix = "heldout-xss" if unit["category"] == "reflected_xss" else "heldout-sqli"
            supported.append(f"{prefix}::{unit['case_id']}")
    return supported


def validate_heldout_evaluation_harness(manifest_path: Path = DEFAULT_MANIFEST_PATH) -> dict:
    supported_manifest_scope = zap_supported_manifest_scope(manifest_path)
    supported_mapping_scope = heldout_zap_supported_suite_case_ids()
    unsupported_scope = heldout_zap_unsupported_suite_case_ids()
    idor_plans = heldout_idor_case_plans()
    result = {
        "validation_id": "heldout-evaluation-harness-v1",
        "valid": True,
        "manifest_path": str(manifest_path),
        "zap_passive_mapping_version": ZAP_HELDOUT_PASSIVE_MAPPING_VERSION,
        "zap_active_mapping_version": ZAP_HELDOUT_ACTIVE_MAPPING_VERSION,
        "zap_supported_manifest_scope": supported_manifest_scope,
        "zap_supported_mapping_scope": supported_mapping_scope,
        "zap_unsupported_scope": unsupported_scope,
        "idor_case_ids": [plan.case_id for plan in idor_plans],
        "errors": [],
    }
    if supported_manifest_scope != supported_mapping_scope:
        result["errors"].append("held-out ZAP mapping scope does not match manifest supported scope")
    if unsupported_scope != ["heldout-idor::hi-001", "heldout-idor::hi-002"]:
        result["errors"].append("held-out ZAP unsupported IDOR scope is incorrect")
    if [plan.case_id for plan in idor_plans] != ["hi-001", "hi-002"]:
        result["errors"].append("held-out IDOR case plans do not match manifest order")
    result["valid"] = not result["errors"]
    return result


def write_harness_validation(output_root: Path = DEFAULT_OUTPUT_ROOT) -> Path:
    from datetime import UTC, datetime

    run_id = f"heldout-harness-validation-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    run_dir = output_root / run_id
    artifact_dir = run_dir / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    result = validate_heldout_evaluation_harness()
    (artifact_dir / "heldout-evaluation-harness-validation.json").write_text(
        json.dumps(to_json_value(result), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (run_dir / "report.md").write_text(render_harness_validation_report(result), encoding="utf-8")
    if not result["valid"]:
        raise RuntimeError("held-out evaluation harness validation failed")
    return run_dir


def render_harness_validation_report(result: dict) -> str:
    return "\n".join(
        [
            "# Held-Out Evaluation Harness Validation",
            "",
            f"- Valid: `{result['valid']}`",
            f"- ZAP passive mapping: `{result['zap_passive_mapping_version']}`",
            f"- ZAP active mapping: `{result['zap_active_mapping_version']}`",
            f"- Supported ZAP scope: `{', '.join(result['zap_supported_mapping_scope'])}`",
            f"- Unsupported ZAP scope: `{', '.join(result['zap_unsupported_scope'])}`",
            f"- IDOR case plans: `{', '.join(result['idor_case_ids'])}`",
            "",
        ]
    )


def main() -> None:
    run_dir = write_harness_validation()
    print(f"Held-out evaluation harness validation artifacts written to: {run_dir}")


if __name__ == "__main__":
    main()
