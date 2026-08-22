from __future__ import annotations

import argparse
import csv
import hashlib
import json
import statistics
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_DIR = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "owasp-xss-v14-confirmatory-20260821T235804Z"
PROTOCOL_PACKAGE_DIR = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
CANONICAL_DIR = REPO_ROOT / "results" / "owasp-xss-v14-confirmatory-final" / "canonical"
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"
EXPECTED_PROTOCOL_SHA256 = "172a583322cd73e6553ea05d9209a33bf216eed6b62d74f98653e893722e473a"
EXPECTED_DENOMINATORS = {
    "deterministic_structural": 266,
    "proprietary_gpt": 1330,
    "local_qwen": 1330,
    "total_ranking_rows": 2926,
}
ARM_ORDER = ("deterministic_structural", "proprietary_gpt", "local_qwen")
NOT_APPLICABLE = "not_applicable"
NOT_AVAILABLE = "not_available"


def build_canonical_package(
    *,
    run_dir: Path = RUN_DIR,
    protocol_package_dir: Path = PROTOCOL_PACKAGE_DIR,
    output_dir: Path = CANONICAL_DIR,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    protocol = load_protocol_artifacts(protocol_package_dir)
    rows = load_raw_rows(run_dir)
    integrity = audit_integrity(run_dir, protocol, rows)
    if not integrity["valid"]:
        write_json(output_dir / "execution-integrity-report.json", integrity)
        raise RuntimeError("v1.4 run integrity audit failed; canonical scoring stopped")
    scoring = load_json(protocol_package_dir / "ground-truth" / "scoring-data.json")
    scored_rows = score_rows(rows, scoring)
    aggregates = aggregate_results(scored_rows, protocol)
    reliability = reliability_aggregates(scored_rows)
    efficiency = efficiency_aggregates(scored_rows)
    negative = negative_scenario_aggregates(scored_rows, scoring)
    comparison = v13_comparison(aggregates)
    validation = validate_canonical_outputs(scored_rows, aggregates, reliability, integrity)
    package = {
        "manifest": manifest(output_dir, run_dir, protocol_package_dir, integrity, validation),
        "integrity": integrity,
        "aggregates": aggregates,
        "reliability": reliability,
        "negative_scenarios": negative,
        "efficiency": efficiency,
        "v13_comparison": comparison,
        "validation": validation,
        "scored_rows": scored_rows,
    }
    write_package(output_dir, package)
    checksum_errors = validate_checksums(output_dir / "checksums.sha256", output_dir)
    write_json(output_dir / "checksum-validation-report.json", {
        "schema_version": "owasp-xss-v14-canonical-checksum-validation-v1",
        "valid": not checksum_errors,
        "errors": checksum_errors,
    })
    return package


def load_protocol_artifacts(root: Path) -> dict[str, Any]:
    return {
        "root": root,
        "scenario_manifest": load_json(root / "scenario-manifest.json"),
        "snapshot_index": load_json(root / "model-facing" / "candidate-snapshot-index.json"),
        "trial_schedule": load_json(root / "trial-schedule.json"),
        "final_corpus": load_json(root / "final-corpus-manifest.json"),
        "preflight_validation": load_json(root / "preflight-validation-report.json"),
        "snapshots": {
            item["scenario_id"]: load_json(root / item["path"])
            for item in load_json(root / "model-facing" / "candidate-snapshot-index.json")["snapshot_paths"]
        },
    }


def load_raw_rows(run_dir: Path) -> list[dict[str, Any]]:
    row_dir = run_dir / "raw" / "ranking-rows"
    rows = []
    for path in sorted(row_dir.glob("sequence-*.json")):
        row = load_json(path)
        row["_artifact_path"] = display_path(path)
        rows.append(row)
    return rows


def audit_integrity(run_dir: Path, protocol: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    errors: list[str] = []
    protocol_sha = sha256_file(PROTOCOL_PATH)
    if protocol_sha != EXPECTED_PROTOCOL_SHA256:
        errors.append("protocol hash mismatch")
    package_checksum_errors = validate_checksums(protocol["root"] / "checksums.sha256", protocol["root"])
    errors.extend(f"protocol package checksum: {item}" for item in package_checksum_errors)

    schedule_rows = protocol["trial_schedule"]["rows"]
    schedule_by_id = {row_id(row): row for row in schedule_rows}
    raw_by_id: dict[str, dict[str, Any]] = {}
    duplicate_raw_ids: list[str] = []
    malformed_artifacts: list[str] = []
    raw_ground_truth_leaks = []
    inconsistent_rows = []
    for row in rows:
        summary = row.get("summary", {})
        rid = row_id(summary)
        if rid in raw_by_id:
            duplicate_raw_ids.append(rid)
        raw_by_id[rid] = row
        if not row.get("schema_version") or not isinstance(summary, dict):
            malformed_artifacts.append(row.get("_artifact_path", "unknown"))
        if row.get("ground_truth_included") is not False:
            raw_ground_truth_leaks.append(rid)
        serialized_ranker = json.dumps(row.get("ranking_result", {}), sort_keys=True).lower()
        if any(fragment in serialized_ranker for fragment in ("expected_result", "ground_truth", "focal_vulnerable_candidate_id")):
            raw_ground_truth_leaks.append(rid)
        expected = schedule_by_id.get(rid)
        if expected is None:
            inconsistent_rows.append(rid)
            continue
        snapshot = protocol["snapshots"].get(expected["scenario_id"])
        if summary.get("candidate_input_sha256") != sha256_json(snapshot["candidate_input"]):
            inconsistent_rows.append(rid)
        if summary.get("snapshot_path") != expected["snapshot_path"]:
            inconsistent_rows.append(rid)

    missing_ids = sorted(set(schedule_by_id) - set(raw_by_id))
    unexpected_ids = sorted(set(raw_by_id) - set(schedule_by_id))
    counts = Counter(row["summary"]["arm_id"] for row in rows)
    status_counts = Counter(row["summary"]["status"] for row in rows)
    if dict(counts) != {arm: EXPECTED_DENOMINATORS[arm] for arm in ARM_ORDER}:
        errors.append(f"per-arm row denominator mismatch: {dict(counts)}")
    if len(rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append(f"total row denominator mismatch: {len(rows)}")
    if missing_ids:
        errors.append(f"missing scheduled rows: {len(missing_ids)}")
    if unexpected_ids:
        errors.append(f"unexpected row artifacts: {len(unexpected_ids)}")
    if duplicate_raw_ids:
        errors.append(f"duplicate raw row identities: {len(duplicate_raw_ids)}")
    if malformed_artifacts:
        errors.append(f"malformed raw artifacts: {len(malformed_artifacts)}")
    if raw_ground_truth_leaks:
        errors.append(f"ground truth leakage in raw ranker artifacts: {len(raw_ground_truth_leaks)}")
    if inconsistent_rows:
        errors.append(f"inconsistent raw row artifacts: {len(inconsistent_rows)}")

    scoring = load_json(protocol["root"] / "ground-truth" / "scoring-data.json")
    positive = [scenario for scenario in scoring["scenarios"] if scenario["scenario_type"] == "positive"]
    negative = [scenario for scenario in scoring["scenarios"] if scenario["scenario_type"] == "negative_only"]
    focal = [scenario["focal_vulnerable_candidate_id"] for scenario in positive]
    if len(positive) != 236 or len(set(focal)) != 236:
        errors.append("positive focal scenario denominator mismatch")
    if len(negative) != 30:
        errors.append("negative-only scenario denominator mismatch")

    return {
        "schema_version": "owasp-xss-v14-postrun-integrity-v1",
        "valid": not errors,
        "errors": errors,
        "run_dir": display_path(run_dir),
        "protocol_sha256": protocol_sha,
        "protocol_sha256_expected": EXPECTED_PROTOCOL_SHA256,
        "protocol_hash_matches": protocol_sha == EXPECTED_PROTOCOL_SHA256,
        "protocol_package_checksum_errors": package_checksum_errors,
        "scheduled_rows": len(schedule_rows),
        "completed_rows": len(rows),
        "missing_rows": len(missing_ids),
        "unexpected_rows": len(unexpected_ids),
        "duplicate_row_id_count": len(duplicate_raw_ids),
        "malformed_artifact_count": len(malformed_artifacts),
        "raw_ground_truth_leak_count": len(raw_ground_truth_leaks),
        "inconsistent_row_count": len(inconsistent_rows),
        "per_arm_rows": dict(counts),
        "status_counts": dict(status_counts),
        "positive_scenarios": len(positive),
        "negative_only_scenarios": len(negative),
        "unique_focal_vulnerable_candidates": len(set(focal)),
        "preflight": load_json(run_dir / "runtime-preflight.json") if (run_dir / "runtime-preflight.json").exists() else {},
        "execution_manifest": load_json(run_dir / "manifest.json") if (run_dir / "manifest.json").exists() else {},
        "execution_validation": load_json(run_dir / "validation-report.json") if (run_dir / "validation-report.json").exists() else {},
        "git_state": git_state(),
    }


def score_rows(rows: list[dict[str, Any]], scoring: dict[str, Any]) -> list[dict[str, Any]]:
    scenarios = {scenario["scenario_id"]: scenario for scenario in scoring["scenarios"]}
    scored_rows = []
    for row in sorted(rows, key=lambda item: int(item["summary"]["sequence"])):
        summary = row["summary"]
        ranking = row["ranking_result"]
        scenario = scenarios[summary["scenario_id"]]
        ordered = ranking["parsed_ranking"]
        scenario_type = scenario["scenario_type"]
        focal_id = scenario.get("focal_vulnerable_candidate_id")
        contract_valid = bool(summary["contract_valid"])
        rank: int | str = NOT_APPLICABLE
        top1: bool | str = NOT_APPLICABLE
        topk: bool | str = NOT_APPLICABLE
        reciprocal: float | str = NOT_APPLICABLE
        if scenario_type == "positive":
            if contract_valid and focal_id in ordered:
                rank = ordered.index(focal_id) + 1
                top1 = rank == 1
                topk = rank <= int(summary["top_k"])
                reciprocal = 1.0 / rank
            elif not contract_valid:
                rank = NOT_AVAILABLE
                top1 = NOT_AVAILABLE
                topk = NOT_AVAILABLE
                reciprocal = NOT_AVAILABLE
        scored_rows.append(
            {
                "sequence": summary["sequence"],
                "scenario_id": summary["scenario_id"],
                "scenario_type": scenario_type,
                "arm_id": summary["arm_id"],
                "trial_number": summary["trial_number"],
                "candidate_test_budget": summary["candidate_test_budget"],
                "top_k": summary["top_k"],
                "candidate_input_sha256": summary["candidate_input_sha256"],
                "contract_valid": contract_valid,
                "status": summary["status"],
                "provider_failed": bool(summary["provider_failed"]),
                "validation_error_count": len(summary.get("validation_errors", [])),
                "validation_errors": summary.get("validation_errors", []),
                "latency_ms": summary.get("latency_ms"),
                "model_identifier": summary.get("model_identifier"),
                "provider": summary.get("provider"),
                "focal_vulnerable_candidate_id": focal_id if scenario_type == "positive" else NOT_APPLICABLE,
                "vulnerable_rank": rank,
                "top1": top1,
                "topk": topk,
                "reciprocal_rank": reciprocal,
                "parsed_ranking": ordered,
                "raw_artifact_path": row["_artifact_path"],
                "usage": ranking.get("usage"),
                "cost": ranking.get("cost"),
            }
        )
    return scored_rows


def aggregate_results(scored_rows: list[dict[str, Any]], protocol: dict[str, Any]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_ORDER:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        positive = [row for row in rows if row["scenario_type"] == "positive"]
        valid_positive = [row for row in positive if row["contract_valid"]]
        negative = [row for row in rows if row["scenario_type"] == "negative_only"]
        rank_values = [int(row["vulnerable_rank"]) for row in valid_positive if isinstance(row["vulnerable_rank"], int)]
        by_arm[arm] = {
            "scheduled_rows": len(rows),
            "positive_rows": len(positive),
            "negative_rows": len(negative),
            "valid_positive_rows": len(valid_positive),
            "invalid_positive_rows": len(positive) - len(valid_positive),
            "top1": ratio(sum(1 for row in valid_positive if row["top1"] is True), len(valid_positive)),
            "topk": ratio(sum(1 for row in valid_positive if row["topk"] is True), len(valid_positive)),
            "mrr": mean([float(row["reciprocal_rank"]) for row in valid_positive if isinstance(row["reciprocal_rank"], float)]),
            "candidate_coverage_under_budget": ratio(sum(1 for row in valid_positive if row["topk"] is True), len(valid_positive)),
            "rank_distribution": {str(rank): rank_values.count(rank) for rank in range(1, 6)},
            "scenario_level": scenario_level_metrics(rows),
            "ranking_stability": ranking_stability(rows),
        }
    return {
        "schema_version": "owasp-xss-v14-ranking-aggregates-v1",
        "arms": by_arm,
        "scenario_denominators": {
            "positive_scenarios": 236,
            "negative_only_scenarios": 30,
            "total_scenarios": 266,
        },
        "repeated_trials_policy": "LLM trials are repeated observations nested under scenario and arm, not independent benchmark scenarios.",
    }


def reliability_aggregates(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_ORDER:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        status = Counter(row["status"] for row in rows)
        provider_failures = sum(1 for row in rows if row["provider_failed"])
        timeout_count = sum(1 for row in rows if "timeout" in json.dumps(row["validation_errors"]).lower())
        malformed = sum(1 for row in rows if row["status"] == "malformed")
        valid = sum(1 for row in rows if row["contract_valid"])
        by_arm[arm] = {
            "scheduled_rows": len(rows),
            "completed_raw_artifacts": len(rows),
            "attempted_model_calls": 0 if arm == "deterministic_structural" else len(rows),
            "contract_valid_outputs": valid,
            "contract_invalid_outputs": len(rows) - valid,
            "provider_or_runtime_failures": provider_failures,
            "timeouts": timeout_count,
            "malformed_outputs": malformed,
            "retries": 0,
            "contract_validity_rate": ratio(valid, len(rows)),
            "status_counts": dict(status),
        }
    return {"schema_version": "owasp-xss-v14-reliability-aggregates-v1", "arms": by_arm}


def negative_scenario_aggregates(scored_rows: list[dict[str, Any]], scoring: dict[str, Any]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_ORDER:
        rows = [row for row in scored_rows if row["arm_id"] == arm and row["scenario_type"] == "negative_only"]
        by_arm[arm] = {
            "negative_rows": len(rows),
            "negative_scenarios": len({row["scenario_id"] for row in rows}),
            "contract_valid_rows": sum(1 for row in rows if row["contract_valid"]),
            "top1_topk_mrr": NOT_APPLICABLE,
            "verifier_false_positive_evidence": NOT_APPLICABLE,
            "direct_execution_layer": "not_executed_in_v1.4_confirmatory_ranking_run",
        }
    return {"schema_version": "owasp-xss-v14-negative-scenario-aggregates-v1", "arms": by_arm}


def efficiency_aggregates(scored_rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_arm = {}
    for arm in ARM_ORDER:
        rows = [row for row in scored_rows if row["arm_id"] == arm]
        latencies = [int(row["latency_ms"]) for row in rows if isinstance(row.get("latency_ms"), int)]
        token_totals = token_summary(rows)
        by_arm[arm] = {
            "latency_ms": describe(latencies),
            "token_usage": token_totals,
            "cost": cost_summary(rows, arm),
            "requests_actions_candidates_tested": NOT_APPLICABLE,
            "time_to_first_verifier_confirmed_finding": NOT_APPLICABLE,
        }
    return {"schema_version": "owasp-xss-v14-efficiency-aggregates-v1", "arms": by_arm}


def scenario_level_metrics(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario_id"]].append(row)
    for scenario_id, scenario_rows in sorted(by_scenario.items()):
        positive_rows = [row for row in scenario_rows if row["scenario_type"] == "positive" and row["contract_valid"]]
        result.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": scenario_rows[0]["scenario_type"],
                "rows": len(scenario_rows),
                "contract_valid_rows": sum(1 for row in scenario_rows if row["contract_valid"]),
                "top1_rate": ratio(sum(1 for row in positive_rows if row["top1"] is True), len(positive_rows)) if positive_rows else NOT_APPLICABLE,
                "topk_rate": ratio(sum(1 for row in positive_rows if row["topk"] is True), len(positive_rows)) if positive_rows else NOT_APPLICABLE,
                "mean_reciprocal_rank": mean([float(row["reciprocal_rank"]) for row in positive_rows if isinstance(row["reciprocal_rank"], float)]) if positive_rows else NOT_APPLICABLE,
            }
        )
    return result


def ranking_stability(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if rows and rows[0]["arm_id"] == "deterministic_structural":
        return {"applicable": False, "reason": "single deterministic trial per scenario"}
    by_scenario: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_scenario[row["scenario_id"]].append(row)
    unique_counts = []
    unanimous_top1 = 0
    comparable = 0
    for scenario_rows in by_scenario.values():
        valid = [row for row in scenario_rows if row["contract_valid"]]
        if not valid:
            continue
        comparable += 1
        rankings = {tuple(row["parsed_ranking"]) for row in valid}
        top_ids = {row["parsed_ranking"][0] for row in valid if row["parsed_ranking"]}
        unique_counts.append(len(rankings))
        if len(top_ids) == 1 and len(valid) == len(scenario_rows):
            unanimous_top1 += 1
    return {
        "applicable": True,
        "scenario_count_with_valid_trials": comparable,
        "mean_unique_rankings_per_scenario": mean(unique_counts),
        "median_unique_rankings_per_scenario": median(unique_counts),
        "unanimous_top1_scenarios": unanimous_top1,
    }


def token_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    keys = ("input_tokens", "output_tokens", "total_tokens")
    totals = {key: 0 for key in keys}
    counts = {key: 0 for key in keys}
    for row in rows:
        usage = row.get("usage")
        if not isinstance(usage, dict):
            continue
        for key in keys:
            value = usage.get(key)
            if isinstance(value, int):
                totals[key] += value
                counts[key] += 1
    if not any(counts.values()):
        return {key: NOT_AVAILABLE for key in keys}
    return {
        **totals,
        "rows_with_numeric_usage": max(counts.values()),
    }


def cost_summary(rows: list[dict[str, Any]], arm: str) -> dict[str, Any] | str:
    if arm == "deterministic_structural":
        return NOT_APPLICABLE
    observed = [row.get("cost") for row in rows if row.get("cost")]
    numeric = [item for item in observed if isinstance(item, dict) and any(isinstance(v, (int, float)) for v in item.values())]
    if numeric:
        return {"availability": "available", "observed": numeric}
    return {"availability": NOT_AVAILABLE, "reason": "no frozen numeric pricing/cost artifact retained"}


def v13_comparison(v14_aggregates: dict[str, Any]) -> dict[str, Any]:
    v13 = {
        "deterministic_structural": {"top1": 0.2500, "topk": 0.6875, "mrr": 0.3854},
        "proprietary_gpt": {"top1": 0.2179, "topk": 0.7179, "mrr": 0.4060},
        "local_qwen": {"top1": 0.3125, "topk": 0.6875, "mrr": 0.4427},
    }
    rows = []
    for arm in ARM_ORDER:
        v14 = v14_aggregates["arms"][arm]
        rows.append({
            "arm_id": arm,
            "v13_top1": v13[arm]["top1"],
            "v14_top1": v14["top1"],
            "v13_topk": v13[arm]["topk"],
            "v14_topk": v14["topk"],
            "v13_mrr": v13[arm]["mrr"],
            "v14_mrr": v14["mrr"],
        })
    return {
        "schema_version": "owasp-xss-v14-v13-separate-descriptive-comparison-v1",
        "policy": "v1.3.1 and v1.4 denominators are not pooled.",
        "comparison_rows": rows,
        "interpretation": "descriptive_only_no_general_superiority_claim",
    }


def validate_canonical_outputs(
    scored_rows: list[dict[str, Any]],
    aggregates: dict[str, Any],
    reliability: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    if not integrity["valid"]:
        errors.append("integrity invalid")
    for arm in ARM_ORDER:
        expected = EXPECTED_DENOMINATORS[arm]
        if reliability["arms"][arm]["scheduled_rows"] != expected:
            errors.append(f"reliability denominator mismatch for {arm}")
        if aggregates["arms"][arm]["scheduled_rows"] != expected:
            errors.append(f"aggregate denominator mismatch for {arm}")
    if len(scored_rows) != EXPECTED_DENOMINATORS["total_ranking_rows"]:
        errors.append("scored row total mismatch")
    return {
        "schema_version": "owasp-xss-v14-canonical-validation-v1",
        "valid": not errors,
        "errors": errors,
        "scored_rows": len(scored_rows),
        "expected_scored_rows": EXPECTED_DENOMINATORS["total_ranking_rows"],
    }


def write_package(output_dir: Path, package: dict[str, Any]) -> None:
    write_json(output_dir / "manifest.json", package["manifest"])
    write_json(output_dir / "execution-integrity-report.json", package["integrity"])
    write_json(output_dir / "validation-report.json", package["validation"])
    write_json(output_dir / "normalized" / "ranking-aggregates.json", package["aggregates"])
    write_json(output_dir / "normalized" / "reliability-aggregates.json", package["reliability"])
    write_json(output_dir / "normalized" / "negative-scenario-aggregates.json", package["negative_scenarios"])
    write_json(output_dir / "normalized" / "efficiency-aggregates.json", package["efficiency"])
    write_json(output_dir / "normalized" / "v13-comparison.json", package["v13_comparison"])
    write_json(output_dir / "normalized" / "scored-rows.json", package["scored_rows"])
    write_csv(output_dir / "normalized" / "scored-rows.csv", package["scored_rows"])
    write_csv(output_dir / "normalized" / "arm-ranking-summary.csv", arm_summary_rows(package["aggregates"], package["reliability"], package["efficiency"]))
    write_csv(output_dir / "normalized" / "scenario-level-results.csv", scenario_rows(package["aggregates"]))
    write_text(output_dir / "analysis-report.md", render_analysis_report(package))
    write_text(output_dir / "thesis-tables.md", render_thesis_tables_md(package))
    write_text(output_dir / "thesis-tables.tex", render_thesis_tables_tex(package))
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))


def manifest(output_dir: Path, run_dir: Path, protocol_package_dir: Path, integrity: dict[str, Any], validation: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-canonical-analysis-manifest-v1",
        "created_at": now_utc(),
        "output_dir": display_path(output_dir),
        "raw_execution_dir": display_path(run_dir),
        "protocol_package_dir": display_path(protocol_package_dir),
        "protocol_sha256": integrity["protocol_sha256"],
        "validation_valid": validation["valid"],
        "immutable_raw_artifacts_preserved": True,
        "ground_truth_loaded_only_for_post_run_scoring": True,
        "scored_execution_rerun": False,
        "gpt_calls_performed_by_canonicalization": 0,
        "qwen_calls_performed_by_canonicalization": 0,
        "owasp_cases_executed_by_canonicalization": 0,
        "git_state": git_state(),
    }


def arm_summary_rows(aggregates: dict[str, Any], reliability: dict[str, Any], efficiency: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for arm in ARM_ORDER:
        a = aggregates["arms"][arm]
        r = reliability["arms"][arm]
        e = efficiency["arms"][arm]
        rows.append({
            "arm_id": arm,
            "scheduled_rows": a["scheduled_rows"],
            "positive_rows": a["positive_rows"],
            "negative_rows": a["negative_rows"],
            "valid_positive_rows": a["valid_positive_rows"],
            "top1": a["top1"],
            "topk": a["topk"],
            "mrr": a["mrr"],
            "contract_valid_outputs": r["contract_valid_outputs"],
            "contract_invalid_outputs": r["contract_invalid_outputs"],
            "provider_or_runtime_failures": r["provider_or_runtime_failures"],
            "contract_validity_rate": r["contract_validity_rate"],
            "latency_median_ms": e["latency_ms"]["median"],
            "latency_mean_ms": e["latency_ms"]["mean"],
        })
    return rows


def scenario_rows(aggregates: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for arm in ARM_ORDER:
        for row in aggregates["arms"][arm]["scenario_level"]:
            rows.append({"arm_id": arm, **row})
    return rows


def render_analysis_report(package: dict[str, Any]) -> str:
    lines = [
        "# OWASP XSS v1.4 Confirmatory Canonical Analysis",
        "",
        "Status: post-run deterministic scoring and analysis only. No scored observations were rerun or modified.",
        "",
        "## Integrity",
        "",
        f"- Execution complete: `{package['integrity']['completed_rows'] == EXPECTED_DENOMINATORS['total_ranking_rows']}`",
        f"- Completed rows: `{package['integrity']['completed_rows']}`",
        f"- Missing rows: `{package['integrity']['missing_rows']}`",
        f"- Protocol hash matches: `{package['integrity']['protocol_hash_matches']}`",
        f"- Protocol package checksum errors: `{len(package['integrity']['protocol_package_checksum_errors'])}`",
        f"- Raw ground-truth leak count: `{package['integrity']['raw_ground_truth_leak_count']}`",
        "",
        "## Ranking Results",
        "",
        "| Arm | Positive valid rows | Top-1 | Top-k | MRR | Contract-valid outputs | Invalid/failure outputs |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_ORDER:
        a = package["aggregates"]["arms"][arm]
        r = package["reliability"]["arms"][arm]
        lines.append(
            f"| `{arm}` | {a['valid_positive_rows']} | {fmt(a['top1'])} | {fmt(a['topk'])} | {fmt(a['mrr'])} | "
            f"{r['contract_valid_outputs']} | {r['contract_invalid_outputs']} |"
        )
    lines.extend([
        "",
        "Negative-only scenarios do not have Top-1, Top-k or MRR denominators. No direct execution/verifier false-positive evidence was produced in this ranking-only v1.4 run.",
        "",
        "## v1.3.1 Comparison",
        "",
        "The v1.3.1 and v1.4 denominators are kept separate. The external OWASP v1.4 benchmark substantially changes the candidate distribution and scale, so the comparison is descriptive rather than pooled.",
        "",
        "## Interpretation",
        "",
        "The v1.4 results should be interpreted for the frozen OWASP Benchmark XSS candidate-ranking task only. They do not establish general model superiority or autonomous penetration-testing capability.",
    ])
    return "\n".join(lines) + "\n"


def render_thesis_tables_md(package: dict[str, Any]) -> str:
    lines = [
        "# Thesis Tables: OWASP XSS v1.4 Confirmatory Evaluation",
        "",
        "## Ranking Effectiveness",
        "",
        "| Arm | Positive valid rows | Top-1 | Top-4 | MRR |",
        "| --- | ---: | ---: | ---: | ---: |",
    ]
    for arm in ARM_ORDER:
        a = package["aggregates"]["arms"][arm]
        lines.append(f"| `{arm}` | {a['valid_positive_rows']} | {fmt(a['top1'])} | {fmt(a['topk'])} | {fmt(a['mrr'])} |")
    lines.extend([
        "",
        "## Reliability",
        "",
        "| Arm | Scheduled rows | Valid outputs | Malformed outputs | Provider/runtime failures | Contract-validity rate |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ])
    for arm in ARM_ORDER:
        r = package["reliability"]["arms"][arm]
        lines.append(
            f"| `{arm}` | {r['scheduled_rows']} | {r['contract_valid_outputs']} | {r['malformed_outputs']} | "
            f"{r['provider_or_runtime_failures']} | {fmt(r['contract_validity_rate'])} |"
        )
    return "\n".join(lines) + "\n"


def render_thesis_tables_tex(package: dict[str, Any]) -> str:
    rows = []
    for arm in ARM_ORDER:
        a = package["aggregates"]["arms"][arm]
        rows.append(f"{latex_arm(arm)} & {a['valid_positive_rows']} & {fmt(a['top1'])} & {fmt(a['topk'])} & {fmt(a['mrr'])} \\\\")
    return (
        "% OWASP XSS v1.4 confirmatory evaluation. Generated from canonical post-run artifacts.\n"
        "\\begin{table}[ht]\n"
        "\\centering\n"
        "\\caption{OWASP XSS v1.4 candidate-ranking effectiveness.}\n"
        "\\begin{tabular}{lrrrr}\n"
        "\\hline\n"
        "Arm & Positive valid rows & Top-1 & Top-4 & MRR \\\\\n"
        "\\hline\n"
        + "\n".join(rows)
        + "\n\\hline\n\\end{tabular}\n\\end{table}\n"
    )


def ratio(numerator: int, denominator: int) -> float | str:
    if denominator == 0:
        return NOT_APPLICABLE
    return numerator / denominator


def mean(values: list[float] | list[int]) -> float | str:
    return statistics.mean(values) if values else NOT_APPLICABLE


def median(values: list[float] | list[int]) -> float | str:
    return statistics.median(values) if values else NOT_APPLICABLE


def describe(values: list[int]) -> dict[str, Any]:
    if not values:
        return {"count": 0, "min": NOT_AVAILABLE, "median": NOT_AVAILABLE, "mean": NOT_AVAILABLE, "p95": NOT_AVAILABLE, "max": NOT_AVAILABLE}
    sorted_values = sorted(values)
    p95_index = min(len(sorted_values) - 1, int(0.95 * (len(sorted_values) - 1)))
    return {
        "count": len(values),
        "min": min(values),
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "p95": sorted_values[p95_index],
        "max": max(values),
    }


def fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def latex_arm(arm: str) -> str:
    return arm.replace("_", "\\_")


def row_id(row: dict[str, Any]) -> str:
    return f"{row.get('sequence')}|{row.get('arm_id')}|{row.get('scenario_id')}|{row.get('trial_number')}"


def validate_checksums(checksum_path: Path, base_dir: Path) -> list[str]:
    errors = []
    if not checksum_path.exists():
        return [f"missing checksum manifest: {display_path(checksum_path)}"]
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = base_dir / relative
        if not path.exists():
            errors.append(f"missing {relative}")
            continue
        if sha256_file(path) != expected:
            errors.append(f"mismatch {relative}")
    return errors


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name != "checksums.sha256":
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value for key, value in row.items()})


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def now_utc() -> str:
    return datetime.now(UTC).isoformat()


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def git_state() -> dict[str, Any]:
    return {
        "branch": git_output(["branch", "--show-current"]),
        "head": git_output(["rev-parse", "HEAD"]),
        "dirty": bool(git_output(["status", "--porcelain"])),
        "status_short": git_output(["status", "--short"]).splitlines(),
    }


def git_output(args: list[str]) -> str:
    completed = subprocess.run(["git", *args], cwd=REPO_ROOT, capture_output=True, encoding="utf-8", check=False)
    return completed.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the canonical v1.4 OWASP XSS post-run analysis package.")
    parser.add_argument("--run-dir", type=Path, default=RUN_DIR)
    parser.add_argument("--protocol-package", type=Path, default=PROTOCOL_PACKAGE_DIR)
    parser.add_argument("--output-dir", type=Path, default=CANONICAL_DIR)
    args = parser.parse_args()
    package = build_canonical_package(run_dir=args.run_dir, protocol_package_dir=args.protocol_package, output_dir=args.output_dir)
    print(f"v1.4 canonical analysis valid: {package['validation']['valid']}")
    print(f"Canonical analysis written to: {args.output_dir.resolve()}")


if __name__ == "__main__":
    main()
