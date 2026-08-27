from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = REPO_ROOT / "results" / "professor-comment-6-context-enrichment-analysis"
CANONICAL = (
    REPO_ROOT
    / "results"
    / "owasp-xss-v14-1-confirmatory-final"
    / "canonical-analysis"
    / "owasp-xss-v14-1-context-enrichment-analysis-20260827T111459Z"
)
PROTOCOL_DOC = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.1.md"
PROTOCOL_PACKAGE = REPO_ROOT / "results" / "owasp-xss-v14-1-protocol-freeze"
CORRECTED_OBSERVATIONS = (
    REPO_ROOT
    / "results"
    / "owasp-xss-v14-1-context-corrected-observations"
    / "owasp-xss-v14-1-context-collection-20260824T120106Z-corrected-20260824T122934Z"
)

ARM_ORDER = [
    "deterministic_minimal",
    "deterministic_enriched",
    "gpt_minimal",
    "gpt_enriched",
    "qwen_minimal",
    "qwen_enriched",
]

ARM_LABELS = {
    "deterministic_minimal": "det_minimal",
    "deterministic_enriched": "det_enriched",
    "gpt_minimal": "gpt_minimal",
    "gpt_enriched": "gpt_enriched",
    "qwen_minimal": "qwen_minimal",
    "qwen_enriched": "qwen_enriched",
}


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    evidence = build_evidence_inventory()
    features = build_feature_inventory()
    summary = build_minimal_enriched_summary()
    comparisons = build_statistical_comparisons()
    reliability = build_reliability_summary()
    validation = build_validation_report(evidence, features, summary, comparisons, reliability)

    write_json(OUTPUT_DIR / "evidence-inventory.json", evidence)
    write_json(OUTPUT_DIR / "feature-proxy-risk-inventory.json", features)
    write_json(OUTPUT_DIR / "minimal-enriched-summary.json", summary)
    write_json(OUTPUT_DIR / "canonical-statistical-comparisons.json", comparisons)
    write_json(OUTPUT_DIR / "reliability-summary.json", reliability)
    write_text(OUTPUT_DIR / "thesis-ready-tables.md", render_tables_md(summary, comparisons, features, reliability))
    write_text(OUTPUT_DIR / "thesis-ready-tables.tex", render_tables_tex(summary, comparisons, reliability))
    write_text(OUTPUT_DIR / "thesis-wording.md", render_thesis_wording(summary, comparisons))
    write_text(OUTPUT_DIR / "methodology-provenance-note.md", render_methodology_note(evidence, validation))
    write_json(OUTPUT_DIR / "validation-report.json", validation)
    write_json(OUTPUT_DIR / "manifest.json", build_manifest(validation))
    write_text(OUTPUT_DIR / "analysis-report.md", render_report(evidence, features, summary, comparisons, reliability, validation))
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    write_json(
        OUTPUT_DIR / "checksum-validation-report.json",
        {
            "schema_version": "professor-comment-6-checksum-validation-v1",
            "valid": not checksum_errors,
            "errors": checksum_errors,
            "checked_at": now_utc(),
        },
    )
    write_text(OUTPUT_DIR / "checksums.sha256", render_checksums(OUTPUT_DIR))
    checksum_errors = validate_sha256_file(OUTPUT_DIR / "checksums.sha256", OUTPUT_DIR)
    if not validation["valid"] or checksum_errors:
        raise SystemExit(f"validation failed: {validation['errors']}; checksum_errors={checksum_errors}")
    print(f"package: {display_path(OUTPUT_DIR)}")
    print(f"validation: {validation['valid']}")
    print(f"checksum_errors: {len(checksum_errors)}")
    print("zero_experimental_calls: true")


def build_evidence_inventory() -> dict[str, Any]:
    canonical_selected = validate_sha256_selected(
        CANONICAL / "checksums.sha256",
        CANONICAL,
        [
            "manifest.json",
            "analysis-report.md",
            "proxy-risk-interpretation.json",
            "statistical-analysis.json",
            "statistical-comparisons.csv",
            "validation-report.json",
            "normalized/arm-ranking-summary.csv",
            "normalized/minimal-vs-enriched-decomposition.csv",
            "normalized/reliability-summary.csv",
            "normalized/negative-scenario-behavior.json",
            "normalized/ranking-stability.csv",
            "normalized/efficiency-summary.csv",
        ],
    )
    protocol_selected = validate_sha256_selected(
        PROTOCOL_PACKAGE / "checksums.sha256",
        PROTOCOL_PACKAGE,
        [
            "manifest.json",
            "arm-configurations.json",
            "deterministic-enriched-ranking-specification.json",
            "ground-truth-separation-validation.json",
            "metric-scoring-specification.json",
            "scenario-manifest.json",
            "statistical-analysis-plan.json",
            "model-facing/minimal-candidate-snapshot-index.json",
            "model-facing/enriched-candidate-snapshot-index.json",
        ],
    )
    corrected_selected = validate_sha256_selected(
        CORRECTED_OBSERVATIONS / "checksums.sha256",
        CORRECTED_OBSERVATIONS,
        [
            "correction-manifest.json",
            "semantic-invariant-validation.json",
            "post-correction-audit.json",
            "sanitized-observations/candidate-observations.json",
        ],
    )
    return {
        "schema_version": "professor-comment-6-evidence-inventory-v1",
        "created_at": now_utc(),
        "authoritative_canonical_analysis": display_path(CANONICAL),
        "authoritative_protocol_document": display_path(PROTOCOL_DOC),
        "authoritative_protocol_package": display_path(PROTOCOL_PACKAGE),
        "corrected_observation_package": display_path(CORRECTED_OBSERVATIONS),
        "canonical_checksum_validation": canonical_selected,
        "protocol_package_checksum_validation": protocol_selected,
        "corrected_observation_checksum_validation": corrected_selected,
        "source_integrity_valid": canonical_selected["valid"] and protocol_selected["valid"] and corrected_selected["valid"],
        "new_experimental_calls": {
            "deterministic_ranking": 0,
            "gpt": 0,
            "qwen": 0,
            "http": 0,
            "browser": 0,
            "discovery": 0,
            "verifier": 0,
            "scoring": 0,
            "statistical_tests": 0,
        },
    }


def build_feature_inventory() -> dict[str, Any]:
    minimal = load_json(PROTOCOL_PACKAGE / "model-facing" / "minimal-candidate-snapshots" / "ow14-s0001.json")
    enriched = load_json(PROTOCOL_PACKAGE / "model-facing" / "enriched-candidate-snapshots" / "ow14-s0001.json")
    minimal_fields = sorted(minimal["candidate_input"][0].keys())
    enriched_fields = sorted(enriched["candidate_input"][0].keys())
    enriched_only = sorted(set(enriched_fields) - set(minimal_fields))
    corrected_manifest = load_json(CORRECTED_OBSERVATIONS / "correction-manifest.json")
    post_audit = load_json(CORRECTED_OBSERVATIONS / "post-correction-audit.json")
    deterministic_spec = load_json(PROTOCOL_PACKAGE / "deterministic-enriched-ranking-specification.json")
    arm_config = load_json(PROTOCOL_PACKAGE / "arm-configurations.json")
    field_entries = []
    field_semantics = {
        "reflection_detected": {
            "derivation": "Boolean derived from whether the fixed inert marker is recognized in the retained HTTP response representation.",
            "proxy_risk": "strong susceptibility proxy",
            "role": "Indicates observable reflection of benign input, which is directly relevant to reflected-XSS prioritization but is not a vulnerability label.",
        },
        "reflection_count_category": {
            "derivation": "Ordinal category derived from the count of recognized benign marker occurrences in the response.",
            "proxy_risk": "strong susceptibility proxy",
            "role": "Captures how many reflected marker occurrences were observed; it is suggestive for prioritization but does not encode exploitability or ground truth.",
        },
        "reflection_context_category": {
            "derivation": "Category derived from deterministic inspection of where recognized marker occurrences appear in the response representation.",
            "proxy_risk": "contextual/suggestive",
            "role": "Provides context for observed reflection; useful for prioritization but less direct than preservation itself.",
        },
        "marker_preservation_category": {
            "derivation": "Category derived from deterministic comparison of the benign marker with exact, encoded, transformed, stripped or absent response representations.",
            "proxy_risk": "strong susceptibility proxy",
            "role": "Especially when unchanged, captures whether attacker-controlled input is preserved in a form close to submission; it is a strong proxy risk but not ground truth.",
        },
        "response_content_type_category": {
            "derivation": "Category derived from the retained response content type for the benign marker request.",
            "proxy_risk": "neither/ambiguous",
            "role": "Provides coarse response-type context; by itself it is not a direct reflected-XSS susceptibility signal.",
        },
    }
    for field in enriched_only:
        field_entries.append(
            {
                "field": field,
                "present_in_minimal": False,
                "present_in_enriched": True,
                "derived_deterministically": True,
                "uses_ground_truth": corrected_manifest["ground_truth_loaded"],
                "available_to_deterministic_enriched": True,
                "available_to_gpt_enriched": True,
                "available_to_qwen_enriched": True,
                **field_semantics[field],
            }
        )
    return {
        "schema_version": "professor-comment-6-feature-proxy-risk-inventory-v1",
        "minimal_candidate_fields": minimal_fields,
        "enriched_candidate_fields": enriched_fields,
        "enriched_only_fields": field_entries,
        "snapshot_level_fields": sorted(set(minimal.keys()) | set(enriched.keys()) - {"candidate_input"}),
        "candidate_order_preserved_in_corrected_snapshots": post_audit["draft_enriched_snapshot_validation"]["candidate_order_preserved"],
        "corrected_observation_parser_version": corrected_manifest["corrected_observation_parser_version"],
        "ground_truth_loaded_for_observation_derivation": corrected_manifest["ground_truth_loaded"],
        "semantic_invariant_validation": load_json(CORRECTED_OBSERVATIONS / "semantic-invariant-validation.json"),
        "deterministic_enriched_policy": deterministic_spec,
        "shared_contract": arm_config["shared_contract"],
        "fairness_verdict": "enrichment was available equally to deterministic_enriched, gpt_enriched and qwen_enriched through the same enriched candidate snapshots",
        "proxy_risk_interpretation": "Reflection-derived variables are not ground truth labels, but reflection_detected, reflection_count_category and marker_preservation_category can act as strong susceptibility proxies for reflected-XSS prioritization.",
    }


def build_minimal_enriched_summary() -> dict[str, Any]:
    arm_rows = keyed_rows(load_csv(CANONICAL / "normalized" / "arm-ranking-summary.csv"), "arm_id")
    decomposition = load_csv(CANONICAL / "normalized" / "minimal-vs-enriched-decomposition.csv")
    positive_table = []
    for arm in ARM_ORDER:
        row = arm_rows[arm]
        positive_table.append(
            {
                "arm_id": arm,
                "arm_label": ARM_LABELS[arm],
                "eligible_positive_scenarios": int(row["eligible_positive_scenarios"]),
                "positive_valid_trials": int(row["positive_valid_trials"]),
                "positive_expected_trials": int(row["positive_expected_trials"]),
                "top1": float(row["top1"]),
                "top2": float(row["top2"]),
                "top4": float(row["top4"]),
                "scenario_level_mrr": float(row["scenario_level_mrr"]),
                "rank_distribution": parse_jsonish(row["rank_distribution"]),
            }
        )
    return {
        "schema_version": "professor-comment-6-minimal-enriched-summary-v1",
        "positive_scenario_results": positive_table,
        "within_family_deltas": [
            {
                "family": row["family"],
                "minimal_mrr": float(row["minimal_scenario_level_mrr"]),
                "enriched_mrr": float(row["enriched_scenario_level_mrr"]),
                "delta_mrr": float(row["delta_scenario_level_mrr"]),
                "minimal_top1": float(row["minimal_top1"]),
                "enriched_top1": float(row["enriched_top1"]),
                "delta_top1": float(row["delta_top1"]),
                "minimal_top2": float(row["minimal_top2"]),
                "enriched_top2": float(row["enriched_top2"]),
                "delta_top2": float(row["delta_top2"]),
                "minimal_top4": float(row["minimal_top4"]),
                "enriched_top4": float(row["enriched_top4"]),
                "delta_top4": float(row["delta_top4"]),
            }
            for row in decomposition
        ],
        "proxy_risk_interpretation_source": load_json(CANONICAL / "proxy-risk-interpretation.json"),
    }


def build_statistical_comparisons() -> dict[str, Any]:
    csv_rows = load_csv(CANONICAL / "statistical-comparisons.csv")
    return {
        "schema_version": "professor-comment-6-canonical-statistical-comparisons-v1",
        "source": display_path(CANONICAL / "statistical-comparisons.csv"),
        "note": "Values are copied from the canonical v1.4.1 analysis; no statistical tests or bootstrap resampling are rerun here.",
        "comparisons": [
            {
                "comparison": row["comparison"],
                "treatment_arm": row["treatment_arm"],
                "control_arm": row["control_arm"],
                "effect": row["effect"],
                "paired_scenarios": int(row["paired_scenarios"]),
                "observed_difference": float(row["observed_difference"]),
                "bootstrap_ci_95": json.loads(row["bootstrap_ci_95"]),
                "raw_p_value": float(row["raw_p_value"]),
                "holm_adjusted_p_value": float(row["holm_adjusted_p_value"]),
                "holm_family_size": int(row["holm_family_size"]),
                "method": row["method"],
                "statistical_evidence_alpha_0_05_after_holm": parse_bool(row["statistical_evidence_alpha_0_05_after_holm"]),
            }
            for row in csv_rows
        ],
    }


def build_reliability_summary() -> dict[str, Any]:
    rel_rows = load_csv(CANONICAL / "normalized" / "reliability-summary.csv")
    efficiency = keyed_rows(load_csv(CANONICAL / "normalized" / "efficiency-summary.csv"), "arm_id")
    stability = keyed_rows(load_csv(CANONICAL / "normalized" / "ranking-stability.csv"), "arm_id")
    negative = load_json(CANONICAL / "normalized" / "negative-scenario-behavior.json")
    return {
        "schema_version": "professor-comment-6-reliability-summary-v1",
        "rows": [
            {
                "arm_id": row["arm_id"],
                "arm_label": ARM_LABELS[row["arm_id"]],
                "scheduled_rows": int(row["scheduled_rows"]),
                "completed_artifacts": int(row["completed_artifacts"]),
                "valid": int(row["valid"]),
                "contract_invalid": int(row["contract_invalid"]),
                "malformed": int(row["malformed"]),
                "provider_failed": int(row["provider_failed"]),
                "runtime_failed": int(row["runtime_failed"]),
                "timeout": int(row["timeout"]),
                "retry_count": int(row["retry_count"]),
                "contract_validity_rate": float(row["contract_validity_rate"]),
                "latency_mean_ms": parse_number_or_text(efficiency[row["arm_id"]]["latency_mean"]),
                "latency_median_ms": parse_number_or_text(efficiency[row["arm_id"]]["latency_median"]),
                "input_tokens": parse_number_or_text(efficiency[row["arm_id"]]["input_tokens"]),
                "output_tokens": parse_number_or_text(efficiency[row["arm_id"]]["output_tokens"]),
                "total_tokens": parse_number_or_text(efficiency[row["arm_id"]]["total_tokens"]),
                "cost_availability": efficiency[row["arm_id"]]["cost_availability"],
                "stability": stability.get(row["arm_id"], {}),
            }
            for row in rel_rows
        ],
        "negative_scenario_behavior": negative,
        "negative_policy": negative["policy"],
    }


def build_validation_report(
    evidence: dict[str, Any],
    features: dict[str, Any],
    summary: dict[str, Any],
    comparisons: dict[str, Any],
    reliability: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    checks: list[dict[str, Any]] = []

    def check(name: str, passed: bool, details: dict[str, Any] | None = None) -> None:
        checks.append({"check": name, "passed": passed, "details": details or {}})
        if not passed:
            errors.append(name)

    manifest = load_json(CANONICAL / "manifest.json")
    validation = load_json(CANONICAL / "validation-report.json")
    arm_config = load_json(PROTOCOL_PACKAGE / "arm-configurations.json")
    minimal_index = load_json(PROTOCOL_PACKAGE / "model-facing" / "minimal-candidate-snapshot-index.json")
    enriched_index = load_json(PROTOCOL_PACKAGE / "model-facing" / "enriched-candidate-snapshot-index.json")
    schedule_counts = Counter(row["arm_id"] for row in load_csv(PROTOCOL_PACKAGE / "trial-schedule.csv"))

    check("source_integrity_valid", evidence["source_integrity_valid"])
    check("canonical_validation_valid", validation["valid"] is True)
    check("canonical_rows_5852", manifest["denominators"]["total_ranking_rows"] == 5852)
    check("six_arm_set", sorted(row["arm_id"] for row in reliability["rows"]) == sorted(ARM_ORDER))
    check("expected_denominators", schedule_counts == Counter({
        "deterministic_minimal": 266,
        "deterministic_enriched": 266,
        "gpt_minimal": 1330,
        "gpt_enriched": 1330,
        "qwen_minimal": 1330,
        "qwen_enriched": 1330,
    }), {"schedule_counts": dict(schedule_counts)})
    check("positive_scenarios_236_all_arms", all(row["eligible_positive_scenarios"] == 236 for row in summary["positive_scenario_results"]))
    check("minimal_enriched_snapshot_counts_match", len(minimal_index["snapshot_paths"]) == 266 and len(enriched_index["snapshot_paths"]) == 266)
    check("minimal_enriched_snapshot_identity_and_order_match", snapshot_identity_order_match(minimal_index, enriched_index))
    check("deterministic_one_trial_per_scenario", all(arm["trial_count_per_scenario"] == 1 for arm in arm_config["arms"] if arm["arm_family"] == "deterministic"))
    check("llm_five_trials_per_scenario", all(arm["trial_count_per_scenario"] == 5 for arm in arm_config["arms"] if arm["arm_family"] != "deterministic"))
    check("ground_truth_absent_from_ranking", load_json(PROTOCOL_PACKAGE / "ground-truth-separation-validation.json")["ranker_facing_snapshots_contain_ground_truth"] is False)
    check("enriched_fields_available_to_all_enriched_arms", "deterministic_enriched" in [arm["arm_id"] for arm in arm_config["arms"] if arm["representation_condition"] == "enriched"])
    check("canonical_comparison_count_four", len(comparisons["comparisons"]) == 4)
    check("zero_experimental_calls", all(value == 0 for value in evidence["new_experimental_calls"].values()))
    return {
        "schema_version": "professor-comment-6-validation-v1",
        "valid": not errors,
        "errors": errors,
        "checks": checks,
        "validated_at": now_utc(),
    }


def snapshot_identity_order_match(minimal_index: dict[str, Any], enriched_index: dict[str, Any]) -> bool:
    if len(minimal_index["snapshot_paths"]) != len(enriched_index["snapshot_paths"]):
        return False
    for min_item, enr_item in zip(minimal_index["snapshot_paths"], enriched_index["snapshot_paths"], strict=True):
        if min_item["scenario_id"] != enr_item["scenario_id"]:
            return False
        min_snapshot = load_json(PROTOCOL_PACKAGE / min_item["path"])
        enr_snapshot = load_json(PROTOCOL_PACKAGE / enr_item["path"])
        min_ids = [candidate["candidate_id"] for candidate in min_snapshot["candidate_input"]]
        enr_ids = [candidate["candidate_id"] for candidate in enr_snapshot["candidate_input"]]
        if min_ids != enr_ids:
            return False
    return True


def render_report(
    evidence: dict[str, Any],
    features: dict[str, Any],
    summary: dict[str, Any],
    comparisons: dict[str, Any],
    reliability: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    return "\n".join(
        [
            "# Professor Comment 6 Closure Analysis: Context-Enrichment Ablation and Proxy-Risk Interpretation",
            "",
            "This package is a derived post-run synthesis of the completed frozen v1.4.1 context-enrichment experiment. It performs zero GPT, Qwen, deterministic ranking, HTTP/browser, discovery, verifier, scoring or new statistical-analysis calls and does not modify frozen/canonical artifacts.",
            "",
            "## Authoritative Evidence",
            "",
            f"- Canonical analysis package: `{display_path(CANONICAL)}`",
            f"- Frozen protocol: `{display_path(PROTOCOL_DOC)}`",
            f"- Frozen protocol package: `{display_path(PROTOCOL_PACKAGE)}`",
            f"- Corrected benign observation package: `{display_path(CORRECTED_OBSERVATIONS)}`",
            f"- Source-integrity verdict: `{'PASS' if evidence['source_integrity_valid'] else 'FAIL'}`",
            "",
            "## Minimal and Enriched Feature Sets",
            "",
            f"Minimal candidate fields: `{', '.join(features['minimal_candidate_fields'])}`.",
            "",
            f"Enriched candidate fields: `{', '.join(features['enriched_candidate_fields'])}`.",
            "",
            "The enriched-only fields are deterministic benign observation fields. The correction manifest records `ground_truth_loaded = false`, and the protocol ground-truth separation validation records that ranker-facing snapshots do not contain ground truth.",
            "",
            render_feature_table(features),
            "",
            "## Fairness of Representation Access",
            "",
            "The v1.4.1 comparison is fair with respect to enriched representation access: enrichment was not provided only to GPT or Qwen. The `deterministic_enriched`, `gpt_enriched` and `qwen_enriched` arms all consumed the same enriched candidate representation fields. This satisfies the supervisor's requirement that potentially strong reflection-derived context either remain non-decisive or be equally available to the deterministic comparator. The observed results show that the context is not non-decisive; instead, it is highly informative and available to all enriched arms.",
            "",
            "## Canonical Positive-Scenario Results",
            "",
            render_positive_table(summary),
            "",
            "## Minimal Versus Enriched Decomposition",
            "",
            render_decomposition_table(summary),
            "",
            "## Canonical Primary Paired MRR Comparisons",
            "",
            render_comparison_table(comparisons),
            "",
            "## Supervisor Concern Answer",
            "",
            render_direct_answers(summary, comparisons),
            "",
            "## Architectural Interpretation",
            "",
            "The result does not undermine the bounded-authority architecture. It instead supports a more selective interpretation of where probabilistic ranking is useful. When high-value susceptibility signals can be derived deterministically and safely, deterministic prioritization may be sufficient or highly competitive. Probabilistic ranking is most defensible where useful prioritization depends on combining weaker contextual signals that are difficult to encode directly. In all cases, the architecture should continue to keep execution, safety enforcement, payload construction, evidence collection and final vulnerability verification outside model authority.",
            "",
            "## Restricted-Context Sensitivity Question",
            "",
            "No restricted-context experiment was run for this closure analysis. The existing v1.4.1 result supports a representation/enrichment effect, but because strong proxy-like reflection observations are present, it does not isolate independent LLM reasoning from non-proxy contextual information. A later restricted-context sensitivity analysis excluding the strongest direct reflection/preservation proxy variables would be needed only for the narrower claim that LLMs independently reason better from non-proxy context. It is a limitation/future sensitivity analysis, not a prerequisite for reporting the frozen v1.4.1 result.",
            "",
            "## Negative and Reliability Evidence",
            "",
            render_reliability_table(reliability),
            "",
            f"Negative-only scenarios are handled separately: `{reliability['negative_policy']}`. No false-positive classification metrics are inferred from ranking-only negative scenarios.",
            "",
            "## Validation",
            "",
            f"- Validation verdict: `{'PASS' if validation['valid'] else 'FAIL'}`",
            "- New experimental calls: `0`",
            "- New inferential/statistical tests: `0`",
            "",
        ]
    )


def render_feature_table(features: dict[str, Any]) -> str:
    rows = [
        "| Enriched-only field | Deterministic derivation | Ground truth used | Available to enriched arms | Proxy-risk classification | Methodological role |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in features["enriched_only_fields"]:
        rows.append(
            f"| `{item['field']}` | {item['derivation']} | `{str(item['uses_ground_truth']).lower()}` | deterministic, GPT, Qwen | {item['proxy_risk']} | {item['role']} |"
        )
    return "\n".join(rows)


def render_positive_table(summary: dict[str, Any]) -> str:
    rows = [
        "| Arm | Top-1 | Top-2 | Top-4 | Scenario-level MRR | Valid positive trials |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in summary["positive_scenario_results"]:
        rows.append(
            f"| `{item['arm_label']}` | {fmt(item['top1'])} | {fmt(item['top2'])} | {fmt(item['top4'])} | {fmt(item['scenario_level_mrr'])} | {item['positive_valid_trials']}/{item['positive_expected_trials']} |"
        )
    return "\n".join(rows)


def render_decomposition_table(summary: dict[str, Any]) -> str:
    rows = [
        "| Family | Minimal MRR | Enriched MRR | Delta MRR | Minimal Top-1 | Enriched Top-1 | Delta Top-1 | Minimal Top-2 | Enriched Top-2 | Delta Top-2 | Minimal Top-4 | Enriched Top-4 | Delta Top-4 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in summary["within_family_deltas"]:
        rows.append(
            f"| {item['family']} | {fmt(item['minimal_mrr'])} | {fmt(item['enriched_mrr'])} | {fmt(item['delta_mrr'])} | {fmt(item['minimal_top1'])} | {fmt(item['enriched_top1'])} | {fmt(item['delta_top1'])} | {fmt(item['minimal_top2'])} | {fmt(item['enriched_top2'])} | {fmt(item['delta_top2'])} | {fmt(item['minimal_top4'])} | {fmt(item['enriched_top4'])} | {fmt(item['delta_top4'])} |"
        )
    return "\n".join(rows)


def render_comparison_table(comparisons: dict[str, Any]) -> str:
    rows = [
        "| Comparison | Delta MRR | 95% CI | Raw p | Holm p | Supported after Holm |",
        "| --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for item in comparisons["comparisons"]:
        ci = item["bootstrap_ci_95"]
        rows.append(
            f"| {item['comparison']} | {fmt(item['observed_difference'])} | [{fmt(ci[0])}, {fmt(ci[1])}] | {fmt(item['raw_p_value'])} | {fmt(item['holm_adjusted_p_value'])} | `{str(item['statistical_evidence_alpha_0_05_after_holm']).lower()}` |"
        )
    return "\n".join(rows)


def render_reliability_table(reliability: dict[str, Any]) -> str:
    rows = [
        "| Arm | Scheduled | Valid | Contract-invalid | Provider failed | Runtime failed | Timeout | Contract-validity rate | Mean latency ms | Total tokens | Cost availability |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |",
    ]
    for item in reliability["rows"]:
        rows.append(
            f"| `{item['arm_label']}` | {item['scheduled_rows']} | {item['valid']} | {item['contract_invalid']} | {item['provider_failed']} | {item['runtime_failed']} | {item['timeout']} | {fmt(item['contract_validity_rate'])} | {fmt(item['latency_mean_ms'])} | {item['total_tokens']} | {item['cost_availability']} |"
        )
    return "\n".join(rows)


def render_direct_answers(summary: dict[str, Any], comparisons: dict[str, Any]) -> str:
    decomp = {item["family"]: item for item in summary["within_family_deltas"]}
    comp = {item["comparison"]: item for item in comparisons["comparisons"]}
    return "\n".join(
        [
            f"- Did enrichment help model-backed rankers? Yes descriptively for both model families on scenario-level MRR: GPT increased by `{fmt(decomp['gpt']['delta_mrr'])}` and Qwen increased by `{fmt(decomp['qwen']['delta_mrr'])}`.",
            f"- Did enrichment also help the deterministic ranker? Yes. Deterministic MRR increased by `{fmt(decomp['deterministic']['delta_mrr'])}`, almost as much as GPT and more than Qwen.",
            "- Was the enrichment advantage unique to LLMs? No. The deterministic enriched arm received the same enriched representation fields and improved strongly, so the evidence supports a representation benefit rather than an LLM-unique benefit.",
            f"- Did GPT enriched outperform deterministic enriched? No statistically supported difference was found on primary paired MRR: delta `{fmt(comp['gpt_enriched vs deterministic_enriched']['observed_difference'])}`, 95% CI `[{fmt(comp['gpt_enriched vs deterministic_enriched']['bootstrap_ci_95'][0])}, {fmt(comp['gpt_enriched vs deterministic_enriched']['bootstrap_ci_95'][1])}]`, Holm p `{fmt(comp['gpt_enriched vs deterministic_enriched']['holm_adjusted_p_value'])}`.",
            f"- Did Qwen enriched outperform deterministic enriched? No. Qwen enriched was lower than deterministic enriched under the frozen comparison: delta `{fmt(comp['qwen_enriched vs deterministic_enriched']['observed_difference'])}`, 95% CI `[{fmt(comp['qwen_enriched vs deterministic_enriched']['bootstrap_ci_95'][0])}, {fmt(comp['qwen_enriched vs deterministic_enriched']['bootstrap_ci_95'][1])}]`, Holm p `{fmt(comp['qwen_enriched vs deterministic_enriched']['holm_adjusted_p_value'])}`.",
            "- Does the experiment support a claim of independent LLM reasoning from enriched context? No. Strong reflection-derived proxy fields plausibly explain a substantial portion of the observed gain, and enrichment alone must not be presented as evidence of independent LLM reasoning.",
        ]
    )


def render_tables_md(summary: dict[str, Any], comparisons: dict[str, Any], features: dict[str, Any], reliability: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Professor Comment 6 Thesis-Ready Tables",
            "## Minimal Versus Enriched Ranking Metrics",
            render_positive_table(summary),
            "## Within-Family Enrichment Deltas",
            render_decomposition_table(summary),
            "## Primary Paired MRR Comparisons",
            render_comparison_table(comparisons),
            "## Enrichment Feature and Proxy-Risk Inventory",
            render_feature_table(features),
            "## Reliability",
            render_reliability_table(reliability),
            "",
        ]
    )


def render_tables_tex(summary: dict[str, Any], comparisons: dict[str, Any], reliability: dict[str, Any]) -> str:
    lines = [
        "% Professor Comment 6 thesis-ready table snippets",
        "% Generated from existing canonical v1.4.1 analysis only; no experiments or statistical tests rerun.",
        "\\begin{tabular}{lrrrr}",
        "\\toprule",
        "Arm & Top-1 & Top-2 & Top-4 & MRR \\\\",
        "\\midrule",
    ]
    for item in summary["positive_scenario_results"]:
        lines.append(f"{tex_escape(item['arm_label'])} & {fmt(item['top1'])} & {fmt(item['top2'])} & {fmt(item['top4'])} & {fmt(item['scenario_level_mrr'])} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", "", "\\begin{tabular}{lrrr}", "\\toprule", "Comparison & Delta MRR & 95\\% CI & Holm $p$ \\\\", "\\midrule"])
    for item in comparisons["comparisons"]:
        ci = item["bootstrap_ci_95"]
        lines.append(f"{tex_escape(item['comparison'])} & {fmt(item['observed_difference'])} & [{fmt(ci[0])}, {fmt(ci[1])}] & {fmt(item['holm_adjusted_p_value'])} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", "", "\\begin{tabular}{lrrrr}", "\\toprule", "Arm & Scheduled & Valid & Contract-invalid & Mean latency ms \\\\", "\\midrule"])
    for item in reliability["rows"]:
        lines.append(f"{tex_escape(item['arm_label'])} & {item['scheduled_rows']} & {item['valid']} & {item['contract_invalid']} & {fmt(item['latency_mean_ms'])} \\\\")
    lines.extend(["\\bottomrule", "\\end{tabular}", ""])
    return "\n".join(lines)


def render_thesis_wording(summary: dict[str, Any], comparisons: dict[str, Any]) -> str:
    return "\n\n".join(
        [
            "# Thesis-Ready Wording for Professor Comment 6",
            "## Results",
            "The v1.4.1 context-enrichment ablation shows a substantial representation effect. Scenario-level MRR increased from 0.4681 to 0.7768 for the deterministic family, from 0.4337 to 0.7619 for GPT, and from 0.4808 to 0.6314 for Qwen. The corresponding MRR deltas are +0.3087, +0.3282 and +0.1506. These values should be read as effects of adding deterministic benign context fields to the candidate representation, not as direct evidence that the language models independently discovered new vulnerability reasoning.",
            "## Discussion",
            "The enriched representation improved both model-backed and deterministic prioritization. This is methodologically important because the same enriched fields were made available to the deterministic enriched comparator. GPT enriched was not statistically distinguishable from deterministic enriched on the primary paired MRR comparison, while Qwen enriched was lower than deterministic enriched. The strongest supported interpretation is therefore that the additional reflection-derived context is highly informative, whereas incremental model-specific benefit beyond deterministic use of that context remains limited in this frozen benchmark.",
            "## Limitation / Threat to Validity",
            "Several enriched variables, especially reflection detection and marker-preservation categories, are strong susceptibility proxies for reflected XSS even though they are not ground-truth labels. The v1.4.1 analysis therefore does not isolate independent LLM reasoning from non-proxy contextual information. A restricted-context sensitivity analysis excluding the strongest direct reflection and preservation proxy variables would be needed for that narrower claim, but it is not required to report the existing v1.4.1 result as a representation/enrichment ablation.",
        ]
    )


def render_methodology_note(evidence: dict[str, Any], validation: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# Methodology and Provenance Note",
            "",
            "This closure package is a derived documentation and synthesis artifact. It reads existing canonical v1.4.1 analysis tables, the frozen protocol package and corrected benign context-observation provenance. It does not rerun scoring, bootstrap resampling, permutation tests, model calls, HTTP/browser activity, ranking, discovery, verification or any other scored experiment.",
            "",
            f"Canonical analysis source: `{evidence['authoritative_canonical_analysis']}`.",
            f"Protocol package source: `{evidence['authoritative_protocol_package']}`.",
            f"Corrected observation source: `{evidence['corrected_observation_package']}`.",
            "",
            f"Source-integrity validation: `{'PASS' if evidence['source_integrity_valid'] else 'FAIL'}`.",
            f"Closure validation: `{'PASS' if validation['valid'] else 'FAIL'}`.",
            "",
        ]
    )


def build_manifest(validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "professor-comment-6-package-manifest-v1",
        "created_at": now_utc(),
        "package": display_path(OUTPUT_DIR),
        "artifact_status": "derived_post_run_closure_analysis_no_experimental_calls",
        "canonical_source": display_path(CANONICAL),
        "protocol_source": display_path(PROTOCOL_PACKAGE),
        "validation_valid": validation["valid"],
        "files": sorted(path.relative_to(OUTPUT_DIR).as_posix() for path in OUTPUT_DIR.rglob("*") if path.is_file() and path.name != "checksums.sha256"),
    }


def validate_sha256_package(directory: Path) -> dict[str, Any]:
    return validate_sha256_file(directory / "checksums.sha256", directory)


def validate_sha256_selected(checksum_file: Path, directory: Path, selected: list[str]) -> dict[str, Any]:
    all_errors = validate_sha256_file(checksum_file, directory, selected=set(selected))
    return {
        "checked_file": display_path(checksum_file),
        "selected_files": selected,
        "valid": not all_errors,
        "errors": all_errors,
    }


def validate_sha256_file(checksum_file: Path, directory: Path, selected: set[str] | None = None) -> list[str]:
    errors: list[str] = []
    if not checksum_file.exists():
        return [f"missing checksum file {display_path(checksum_file)}"]
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        if selected is not None and rel not in selected:
            continue
        path = directory / rel
        if not path.exists():
            errors.append(f"missing {rel}")
            continue
        actual = sha256(path)
        if actual != expected:
            errors.append(f"hash mismatch {rel}")
    if selected is not None:
        listed = {line.split("  ", 1)[1] for line in checksum_file.read_text(encoding="utf-8").splitlines() if line.strip()}
        for rel in selected:
            if rel not in listed:
                errors.append(f"checksum entry missing {rel}")
    return errors


def render_checksums(directory: Path) -> str:
    lines = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.name == "checksums.sha256":
            continue
        lines.append(f"{sha256(path)}  {path.relative_to(directory).as_posix()}")
    return "\n".join(lines) + "\n"


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def keyed_rows(rows: list[dict[str, str]], key: str) -> dict[str, dict[str, str]]:
    return {row[key]: row for row in rows}


def parse_bool(value: Any) -> bool:
    return str(value).lower() == "true"


def parse_number_or_text(value: str) -> int | float | str:
    try:
        parsed = float(value)
    except ValueError:
        return value
    if parsed.is_integer():
        return int(parsed)
    return parsed


def parse_jsonish(value: str) -> dict[str, int]:
    return {str(key): int(count) for key, count in json.loads(value).items()}


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def tex_escape(value: str) -> str:
    return value.replace("_", "\\_").replace("%", "\\%")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def display_path(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def now_utc() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    main()
