from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from adstf.discovery import DETERMINISTIC_RANKING_RULESET_VERSION
from adstf.llm_ranking import LLM_RANKING_PROMPT_VERSION
from adstf.owasp_xss_v14 import (
    DEFAULT_AUDIT_DIR,
    DEFAULT_READINESS_DIR,
    OwaspExternalCandidate,
    construct_external_candidate,
    load_case_audit,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "owasp-xss-v14-protocol-freeze"
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.4.md"

PACKAGE_VERSION = "owasp-xss-v14-protocol-freeze-v1"
FINAL_CORPUS_VERSION = "owasp-xss-v14-final-corpus-v1"
CANDIDATE_SNAPSHOT_VERSION = "ow14-candidate-snapshot-v1"
SCENARIO_MANIFEST_VERSION = "ow14-scenario-manifest-v1"
TRIAL_SCHEDULE_VERSION = "owasp-xss-v14-trial-schedule-v1"
PREFLIGHT_VERSION = "owasp-xss-v14-preflight-validation-v1"

PACK_SIZE = 5
TEST_BUDGET = 4
LLM_TRIALS = 5
DETERMINISTIC_TRIALS = 1
POSITIVE_DECOYS_PER_SCENARIO = PACK_SIZE - 1

FINAL_CORPUS_ROLE = "FINAL_CONFIRMATORY_ELIGIBLE"
READINESS_ROLE = "READINESS_ONLY"
EXCLUDED_ROLE = "EXCLUDED"

SCENARIO_ASSIGNMENT_SEED = "owasp-xss-v14-final-scenario-assignment-v1"
CANDIDATE_ORDER_SEED = "owasp-xss-v14-final-candidate-order-v1"
TRIAL_SCHEDULE_SEED = "owasp-xss-v14-final-trial-schedule-v1"

ARM_IDS = ("deterministic_structural", "proprietary_gpt", "local_qwen")
PROPRIETARY_MODEL_IDENTIFIER = "gpt-5.6-luna"
LOCAL_PRIMARY_MODEL_ID = "qwen2_5_7b_instruct_gguf_q4_k_m"
LOCAL_CONTINGENCY_MODEL_ID = "gemma3_4b_it_gguf_q4_k_m"
LOCAL_MODEL_IDENTIFIER = "Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M"

FORBIDDEN_MODELFACING_KEYS = {
    "benchmark_case_id",
    "benchmark_name",
    "benchmark_revision",
    "benchmark_version",
    "compatibility_class",
    "endpoint",
    "evaluation_role",
    "expected_result",
    "ground_truth",
    "label",
    "original_case_id",
    "source_file",
    "vulnerability_label",
}
FORBIDDEN_MODELFACING_FRAGMENTS = [
    "BenchmarkTest",
    ".java",
    "expected_result",
    "ground_truth",
    "non_vulnerable",
    "vulnerable",
    "xss",
]


def build_protocol_freeze_package(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    audit_dir: Path = DEFAULT_AUDIT_DIR,
    readiness_dir: Path = DEFAULT_READINESS_DIR,
    protocol_path: Path = PROTOCOL_PATH,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_case_audit(audit_dir / "case-audit.csv")
    candidates = [construct_external_candidate(row) for row in rows if row["evaluation_role"] == FINAL_CORPUS_ROLE]
    corpus_manifest = build_final_corpus_manifest(candidates, rows, audit_dir, readiness_dir)
    scenario_bundle = build_scenarios(candidates)
    arm_config = build_arm_configurations()
    metrics = build_metric_specification()
    trial_schedule = build_trial_schedule(scenario_bundle["scenario_manifest"]["scenarios"])

    write_json(output_dir / "final-corpus-manifest.json", corpus_manifest)
    write_csv(output_dir / "final-corpus.csv", final_corpus_rows(candidates))
    write_json(output_dir / "scenario-manifest.json", scenario_bundle["scenario_manifest"])
    write_json(output_dir / "model-facing" / "candidate-snapshot-index.json", scenario_bundle["snapshot_index"])
    for snapshot in scenario_bundle["snapshots"]:
        write_json(output_dir / "model-facing" / "candidate-snapshots" / f"{snapshot['scenario_id']}.json", snapshot)
    write_json(output_dir / "ground-truth" / "scoring-data.json", scenario_bundle["scoring_data"])
    write_json(output_dir / "ground-truth" / "decoy-assignment-manifest.json", scenario_bundle["decoy_assignment"])
    write_json(output_dir / "provenance" / "internal-provenance.json", internal_provenance(candidates))
    write_json(output_dir / "execution" / "execution-specifications.json", execution_specifications(candidates))
    write_json(output_dir / "arm-configurations.json", arm_config)
    write_json(output_dir / "trial-schedule.json", trial_schedule)
    write_csv(output_dir / "trial-schedule.csv", trial_schedule["rows"])
    write_csv(output_dir / "candidate-ordering.csv", scenario_bundle["candidate_ordering_rows"])
    write_json(output_dir / "metric-scoring-specification.json", metrics)

    validation = validate_protocol_package(
        output_dir=output_dir,
        rows=rows,
        candidates=candidates,
        corpus_manifest=corpus_manifest,
        scenario_manifest=scenario_bundle["scenario_manifest"],
        snapshots=scenario_bundle["snapshots"],
        scoring_data=scenario_bundle["scoring_data"],
        decoy_assignment=scenario_bundle["decoy_assignment"],
        arm_config=arm_config,
        trial_schedule=trial_schedule,
        protocol_path=protocol_path,
    )
    write_json(output_dir / "preflight-validation-report.json", validation)
    write_text(output_dir / "report.md", render_report(corpus_manifest, scenario_bundle, trial_schedule, validation))
    write_text(output_dir / "thesis-table-v14-protocol-summary.md", render_protocol_summary_table(corpus_manifest, scenario_bundle, trial_schedule))
    write_text(output_dir / "thesis-table-v14-protocol-summary.tex", render_protocol_summary_table_latex())

    package_manifest = build_package_manifest(output_dir, corpus_manifest, scenario_bundle, trial_schedule, validation, protocol_path)
    write_json(output_dir / "manifest.json", package_manifest)
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_validation = validate_checksums(output_dir / "checksums.sha256")
    write_json(output_dir / "checksum-validation-report.json", checksum_validation)
    if not validation["valid"] or not checksum_validation["valid"]:
        raise RuntimeError("v1.4 protocol-freeze package validation failed")
    return package_manifest


def build_final_corpus_manifest(
    candidates: list[OwaspExternalCandidate],
    rows: list[dict[str, str]],
    audit_dir: Path,
    readiness_dir: Path,
) -> dict[str, Any]:
    role_counts = Counter(row["evaluation_role"] for row in rows)
    eligible_rows = [row for row in rows if row["evaluation_role"] == FINAL_CORPUS_ROLE]
    expected_counts = Counter(row["expected_result"] for row in eligible_rows)
    compatible_rows = [row for row in rows if row["compatibility_class"] in {"DIRECT", "ADAPTER_SUPPORTED"}]
    return {
        "schema_version": FINAL_CORPUS_VERSION,
        "artifact_status": "pre_execution_protocol_input",
        "created_at": datetime.now(UTC).isoformat(),
        "source_audit_dir": audit_dir.relative_to(REPO_ROOT).as_posix(),
        "source_readiness_dir": readiness_dir.relative_to(REPO_ROOT).as_posix(),
        "role_policy": "Only FINAL_CONFIRMATORY_ELIGIBLE cases are used for final candidate-pack construction.",
        "corpus_counts": {
            "original_xss_cases": len(rows),
            "compatible_after_adapters": len(compatible_rows),
            "readiness_only": role_counts.get(READINESS_ROLE, 0),
            "final_confirmatory_eligible": len(eligible_rows),
            "final_confirmatory_eligible_vulnerable": expected_counts.get("vulnerable", 0),
            "final_confirmatory_eligible_non_vulnerable": expected_counts.get("non_vulnerable", 0),
            "excluded": role_counts.get(EXCLUDED_ROLE, 0),
        },
        "candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in sorted_candidates(candidates)],
        "compatibility_distribution": dict(Counter(candidate.provenance.compatibility_class for candidate in candidates)),
        "input_source_distribution": dict(Counter(candidate.provenance.input_source for candidate in candidates)),
        "model_facing_identity_policy": "Original OWASP IDs, Java files, endpoints and labels are excluded from model-facing snapshots.",
    }


def build_scenarios(candidates: list[OwaspExternalCandidate]) -> dict[str, Any]:
    vulnerable = sorted_by_seed(
        [candidate for candidate in candidates if candidate.provenance.expected_result == "vulnerable"],
        "vulnerable-pool",
    )
    negatives = sorted_by_seed(
        [candidate for candidate in candidates if candidate.provenance.expected_result == "non_vulnerable"],
        "negative-pool",
    )
    scenarios: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    scoring_scenarios: list[dict[str, Any]] = []
    candidate_ordering_rows: list[dict[str, Any]] = []
    positive_assignments: list[dict[str, Any]] = []
    negative_reuse: Counter[str] = Counter()

    scenario_index = 1
    for focal_index, focal in enumerate(vulnerable):
        decoys = [negatives[(focal_index * POSITIVE_DECOYS_PER_SCENARIO + offset) % len(negatives)] for offset in range(POSITIVE_DECOYS_PER_SCENARIO)]
        for decoy in decoys:
            negative_reuse[decoy.ranker_candidate.candidate_id] += 1
        scenario_id = neutral_scenario_id(scenario_index)
        pack = order_pack(scenario_id, [focal, *decoys])
        snapshot = snapshot_for_pack(scenario_id, pack)
        snapshots.append(snapshot)
        scenarios.append(scenario_manifest_entry(scenario_id, snapshot))
        scoring_scenarios.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": "positive",
                "focal_vulnerable_candidate_id": focal.ranker_candidate.candidate_id,
                "candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in pack],
            }
        )
        positive_assignments.append(
            {
                "scenario_id": scenario_id,
                "focal_vulnerable_candidate_id": focal.ranker_candidate.candidate_id,
                "negative_decoy_candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in decoys],
                "ordered_candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in pack],
            }
        )
        candidate_ordering_rows.extend(candidate_order_rows(scenario_id, "positive", pack, focal.ranker_candidate.candidate_id))
        scenario_index += 1

    negative_only_packs = [negatives[index : index + PACK_SIZE] for index in range(0, (len(negatives) // PACK_SIZE) * PACK_SIZE, PACK_SIZE)]
    unused_negative_only = negatives[len(negative_only_packs) * PACK_SIZE :]
    negative_pack_entries: list[dict[str, Any]] = []
    for pack_index, pack_candidates in enumerate(negative_only_packs, start=1):
        scenario_id = neutral_scenario_id(scenario_index)
        pack = order_pack(scenario_id, pack_candidates)
        snapshot = snapshot_for_pack(scenario_id, pack)
        snapshots.append(snapshot)
        scenarios.append(scenario_manifest_entry(scenario_id, snapshot))
        scoring_scenarios.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": "negative_only",
                "focal_vulnerable_candidate_id": None,
                "candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in pack],
            }
        )
        negative_pack_entries.append(
            {
                "scenario_id": scenario_id,
                "pack_index": pack_index,
                "ordered_candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in pack],
            }
        )
        candidate_ordering_rows.extend(candidate_order_rows(scenario_id, "negative_only", pack, None))
        scenario_index += 1

    snapshot_index = {
        "schema_version": f"{CANDIDATE_SNAPSHOT_VERSION}-index",
        "artifact_status": "pre_execution_model_facing_input_index",
        "scenario_count": len(snapshots),
        "snapshot_paths": [
            {
                "scenario_id": snapshot["scenario_id"],
                "path": f"model-facing/candidate-snapshots/{snapshot['scenario_id']}.json",
                "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
            }
            for snapshot in snapshots
        ],
    }
    scenario_manifest = {
        "schema_version": SCENARIO_MANIFEST_VERSION,
        "artifact_status": "pre_execution_public_scenario_manifest",
        "scenario_count": len(scenarios),
        "pack_size": PACK_SIZE,
        "candidate_test_budget": TEST_BUDGET,
        "top_k_definition": "top_k = min(candidate_test_budget, candidate_count)",
        "scenarios": scenarios,
    }
    scoring_data = {
        "schema_version": "owasp-xss-v14-ground-truth-scoring-data-v1",
        "artifact_status": "post_run_scoring_only_not_model_facing",
        "load_policy": "May be loaded only after scored execution is complete.",
        "positive_scenarios": len(vulnerable),
        "negative_only_scenarios": len(negative_only_packs),
        "scenarios": scoring_scenarios,
        "candidate_ground_truth": [
            {
                "candidate_id": candidate.ranker_candidate.candidate_id,
                "expected_result": candidate.provenance.expected_result,
                "original_case_id": candidate.provenance.benchmark_case_id,
            }
            for candidate in sorted_candidates(candidates)
        ],
    }
    decoy_assignment = {
        "schema_version": "owasp-xss-v14-decoy-assignment-v1",
        "artifact_status": "pre_execution_ground_truth_separated_assignment",
        "assignment_seed": SCENARIO_ASSIGNMENT_SEED,
        "candidate_order_seed": CANDIDATE_ORDER_SEED,
        "positive_decoy_policy": (
            "Sort eligible negative candidates by SHA-256(seed|negative-pool|candidate_id|original_case_id), "
            "then assign four decoys to each positive scenario by contiguous round-robin positions."
        ),
        "negative_only_policy": "Use the same sorted negative pool to form disjoint packs of five; leftover negatives are recorded and not used as partial scenarios.",
        "positive_assignments": positive_assignments,
        "negative_only_packs": negative_pack_entries,
        "unused_negative_only_candidates": [candidate.ranker_candidate.candidate_id for candidate in unused_negative_only],
        "negative_reuse_distribution_for_positive_scenarios": dict(Counter(negative_reuse.values())),
        "negative_reuse_by_candidate": dict(sorted(negative_reuse.items())),
        "candidate_position_distribution_for_focal_vulnerable": focal_position_distribution(candidate_ordering_rows),
    }
    return {
        "scenario_manifest": scenario_manifest,
        "snapshot_index": snapshot_index,
        "snapshots": snapshots,
        "scoring_data": scoring_data,
        "decoy_assignment": decoy_assignment,
        "candidate_ordering_rows": candidate_ordering_rows,
    }


def snapshot_for_pack(scenario_id: str, pack: list[OwaspExternalCandidate]) -> dict[str, Any]:
    candidate_input = [asdict(candidate.ranker_candidate) for candidate in pack]
    return {
        "schema_version": CANDIDATE_SNAPSHOT_VERSION,
        "artifact_status": "pre_execution_model_facing_input",
        "scenario_id": scenario_id,
        "candidate_count": len(candidate_input),
        "candidate_test_budget": TEST_BUDGET,
        "top_k": min(TEST_BUDGET, len(candidate_input)),
        "prompt_version": LLM_RANKING_PROMPT_VERSION,
        "candidate_input_schema": "llm-candidate-ranking-v1.candidate_input",
        "candidate_input": candidate_input,
    }


def scenario_manifest_entry(scenario_id: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "snapshot_path": f"model-facing/candidate-snapshots/{scenario_id}.json",
        "candidate_count": snapshot["candidate_count"],
        "candidate_test_budget": snapshot["candidate_test_budget"],
        "top_k": snapshot["top_k"],
        "candidate_input_sha256": sha256_json(snapshot["candidate_input"]),
    }


def build_trial_schedule(scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    sequence = 1
    for arm_id in ARM_IDS:
        trials = DETERMINISTIC_TRIALS if arm_id == "deterministic_structural" else LLM_TRIALS
        for scenario in scenarios:
            for trial in range(1, trials + 1):
                rows.append(
                    {
                        "sequence": sequence,
                        "arm_id": arm_id,
                        "scenario_id": scenario["scenario_id"],
                        "trial_number": trial,
                        "snapshot_path": scenario["snapshot_path"],
                        "candidate_test_budget": TEST_BUDGET,
                        "top_k": scenario["top_k"],
                        "scored": "true",
                    }
                )
                sequence += 1
    return {
        "schema_version": TRIAL_SCHEDULE_VERSION,
        "artifact_status": "pre_execution_schedule_no_calls_performed",
        "schedule_seed": TRIAL_SCHEDULE_SEED,
        "arm_order": list(ARM_IDS),
        "scenario_order": [scenario["scenario_id"] for scenario in scenarios],
        "retry_policy": "No silent retries. Failed, malformed, timed-out or provider-failed calls remain recorded observations.",
        "resume_policy": "Resume by continuing from the next scheduled row whose artifact is absent; existing scored artifacts must not be regenerated unless a versioned protocol amendment requires a complete affected rerun.",
        "rows": rows,
        "denominators": {
            "deterministic_structural": len(scenarios),
            "proprietary_gpt": len(scenarios) * LLM_TRIALS,
            "local_qwen": len(scenarios) * LLM_TRIALS,
            "total_ranking_rows": len(rows),
        },
    }


def build_arm_configurations() -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-arm-configurations-v1",
        "artifact_status": "pre_execution_configuration_no_calls_performed",
        "shared_contract": {
            "prompt_version": LLM_RANKING_PROMPT_VERSION,
            "task": "rank existing structured candidate IDs; include each candidate exactly once with a brief rationale",
            "candidate_representation": "model-facing/candidate-snapshots/*.json candidate_input",
            "forbidden_authority": [
                "candidate discovery",
                "payload generation",
                "browser or HTTP execution",
                "ground-truth access",
                "vulnerability verification",
            ],
        },
        "arms": [
            {
                "arm_id": "deterministic_structural",
                "arm_type": "deterministic",
                "ranking_ruleset_version": DETERMINISTIC_RANKING_RULESET_VERSION,
                "trial_count_per_scenario": DETERMINISTIC_TRIALS,
                "configuration": {
                    "input": "same sanitized candidate_input as LLM arms",
                    "provider_cost": "not_applicable",
                    "model_output": "not_applicable",
                },
            },
            {
                "arm_id": "proprietary_gpt",
                "arm_type": "hosted_proprietary_llm",
                "provider": "OpenAI",
                "model_identifier": PROPRIETARY_MODEL_IDENTIFIER,
                "prompt_version": LLM_RANKING_PROMPT_VERSION,
                "structured_output_schema": "candidate_ranking_json_schema",
                "parser": "adstf.llm_ranking.parse_model_ranking",
                "trial_count_per_scenario": LLM_TRIALS,
                "settings": {
                    "OPENAI_RANKING_MODEL": PROPRIETARY_MODEL_IDENTIFIER,
                    "OPENAI_SEND_TEMPERATURE": "unset_or_false",
                    "temperature_parameter": "omitted",
                    "provider_default_temperature": "used",
                    "timeout_seconds": 60,
                    "max_output_tokens": 1200,
                },
            },
            {
                "arm_id": "local_qwen",
                "arm_type": "local_open_weights_llm",
                "provider": "local llama.cpp",
                "model_identifier": LOCAL_MODEL_IDENTIFIER,
                "primary_model_candidate_id": LOCAL_PRIMARY_MODEL_ID,
                "contingency_model_candidate_id": LOCAL_CONTINGENCY_MODEL_ID,
                "prompt_version": LLM_RANKING_PROMPT_VERSION,
                "structured_output_schema": "local-ranking-readiness-json-schema-v1.3 with scenario-specific candidate_id enum",
                "parser": "llama-completion-transport-parser-v1.3 followed by adstf.llm_ranking.parse_model_ranking",
                "trial_count_per_scenario": LLM_TRIALS,
                "settings_source": "results/local-runtime-output-boundary-v1.3/transport-settings.json",
                "model_metadata_source": "results/local-runtime-provisioning-v1.3/model-metadata/qwen2_5_7b_instruct_gguf_q4_k_m.json",
                "settings": {
                    "runtime": "llama.cpp",
                    "runtime_executable": "llama-completion.exe",
                    "runtime_executable_sha256": "2272eaaf8bb9477257790835d7b25aaf8fd22941e44ac3fcc9f2df389d1ef7b4",
                    "model_files": [
                        {
                            "filename": "qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf",
                            "sha256": "dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db",
                        },
                        {
                            "filename": "qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf",
                            "sha256": "539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a",
                        },
                    ],
                    "context_size_tokens": 4096,
                    "max_output_tokens": 768,
                    "temperature": 0.0,
                    "top_p": 1.0,
                    "seed": 42,
                    "threads": 8,
                    "timeout_seconds": 300,
                    "process_policy": "one scored command invocation per scheduled trial; non-scored warm-up must not use final snapshots",
                },
                "fallback_rule": {
                    "silent_qwen_to_gemma_substitution": False,
                    "gemma_activation_condition": "documented pre-execution technical failure preventing Qwen from participating",
                    "activation_requirement": "versioned protocol amendment and complete rerun of affected local-model experiment",
                },
            },
        ],
    }


def build_metric_specification() -> dict[str, Any]:
    return {
        "schema_version": "owasp-xss-v14-metric-scoring-specification-v1",
        "artifact_status": "pre_execution_metric_specification",
        "ranking_metrics_positive_scenarios": {
            "vulnerable_candidate_rank": "1-based rank of focal vulnerable candidate in a valid ranking",
            "top_1_success": "true when focal vulnerable candidate rank is 1",
            "top_k_success": f"true when focal vulnerable candidate rank <= {TEST_BUDGET}",
            "reciprocal_rank": "1 / vulnerable_candidate_rank",
            "mrr": "mean reciprocal rank over applicable valid positive ranking rows",
            "candidate_coverage_under_budget": "whether focal vulnerable candidate is within the fixed candidate-test budget",
        },
        "negative_only_scenarios": {
            "applicable_ranking_metrics": "contract validity, latency, candidate coverage and downstream no-finding behavior where execution is later authorized",
            "not_applicable": ["vulnerable_candidate_rank", "top_1_success", "top_k_success", "reciprocal_rank", "mrr"],
            "correct_behavior": "no verifier-confirmed finding after testing candidates within budget in later execution phase",
        },
        "reliability_metrics": [
            "scheduled calls",
            "attempted calls",
            "valid structured outputs",
            "malformed outputs",
            "provider failures",
            "runtime failures",
            "timeouts",
            "retry count",
            "contract-valid output rate",
        ],
        "efficiency_metrics": [
            "ranking latency",
            "token usage where available",
            "cost availability",
            "requests/actions to first verifier-confirmed finding when execution is later authorized",
            "time to first verifier-confirmed finding when execution is later authorized",
        ],
        "failure_denominator_policy": {
            "invalid_or_failed_model_output": "retained in reliability denominators; excluded from valid ranking-performance aggregates",
            "no_silent_repair": True,
            "no_silent_retry": True,
            "repeated_trials": "nested under scenario and arm; not independent benchmark scenarios",
        },
        "undefined_value_policy": {
            "not_applicable": "metric does not apply to an arm/scenario type",
            "not_available": "metric applies but required measurement is absent",
        },
    }


def validate_protocol_package(
    *,
    output_dir: Path,
    rows: list[dict[str, str]],
    candidates: list[OwaspExternalCandidate],
    corpus_manifest: dict[str, Any],
    scenario_manifest: dict[str, Any],
    snapshots: list[dict[str, Any]],
    scoring_data: dict[str, Any],
    decoy_assignment: dict[str, Any],
    arm_config: dict[str, Any],
    trial_schedule: dict[str, Any],
    protocol_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    eligible_rows = [row for row in rows if row["evaluation_role"] == FINAL_CORPUS_ROLE]
    counts = corpus_manifest["corpus_counts"]
    if len(eligible_rows) != 388:
        errors.append(f"expected 388 final eligible rows, found {len(eligible_rows)}")
    if counts["final_confirmatory_eligible_vulnerable"] != 236:
        errors.append("expected 236 final eligible vulnerable rows")
    if counts["final_confirmatory_eligible_non_vulnerable"] != 152:
        errors.append("expected 152 final eligible non-vulnerable rows")
    if counts["readiness_only"] != 20:
        errors.append("expected 20 readiness-only rows")
    if counts["excluded"] != 47:
        errors.append("expected 47 excluded rows")
    if any(candidate.provenance.evaluation_role != FINAL_CORPUS_ROLE for candidate in candidates):
        errors.append("non-final-eligible candidate entered final corpus")
    if len({candidate.ranker_candidate.candidate_id for candidate in candidates}) != len(candidates):
        errors.append("final candidate IDs are not unique")

    if scenario_manifest["scenario_count"] != 266:
        errors.append(f"expected 266 scenarios, found {scenario_manifest['scenario_count']}")
    if len(snapshots) != 266:
        errors.append("expected 266 candidate snapshots")
    if any(snapshot["candidate_count"] != PACK_SIZE for snapshot in snapshots):
        errors.append("one or more snapshots do not have pack size 5")
    if any(snapshot["candidate_test_budget"] != TEST_BUDGET for snapshot in snapshots):
        errors.append("one or more snapshots do not have candidate-test budget 4")
    if any(snapshot["top_k"] != min(TEST_BUDGET, PACK_SIZE) for snapshot in snapshots):
        errors.append("one or more snapshots have incorrect top_k")

    positive = [scenario for scenario in scoring_data["scenarios"] if scenario["scenario_type"] == "positive"]
    negative_only = [scenario for scenario in scoring_data["scenarios"] if scenario["scenario_type"] == "negative_only"]
    if len(positive) != 236:
        errors.append("expected 236 positive scenarios")
    if len(negative_only) != 30:
        errors.append("expected 30 negative-only scenarios")
    focal_ids = [scenario["focal_vulnerable_candidate_id"] for scenario in positive]
    if len(set(focal_ids)) != 236:
        errors.append("not every vulnerable candidate appears exactly once as focal")
    if len(decoy_assignment["unused_negative_only_candidates"]) != 2:
        errors.append("expected exactly two negatives left after complete negative-only packs")
    if sum(int(key) * value for key, value in decoy_assignment["negative_reuse_distribution_for_positive_scenarios"].items()) != 236 * 4:
        errors.append("negative reuse distribution does not sum to required positive decoy assignments")

    snapshot_leaks = [snapshot["scenario_id"] for snapshot in snapshots if model_facing_snapshot_leaks(snapshot)]
    if snapshot_leaks:
        errors.append(f"model-facing snapshot leakage detected: {', '.join(snapshot_leaks[:5])}")
    if scenario_manifest_contains_ground_truth(scenario_manifest):
        errors.append("ground-truth-free scenario manifest contains ground-truth fields")

    denominators = trial_schedule["denominators"]
    if denominators != {
        "deterministic_structural": 266,
        "proprietary_gpt": 1330,
        "local_qwen": 1330,
        "total_ranking_rows": 2926,
    }:
        errors.append(f"unexpected trial denominators: {denominators}")
    if len(trial_schedule["rows"]) != 2926:
        errors.append("trial schedule row count is not 2926")
    if [arm["arm_id"] for arm in arm_config["arms"]] != list(ARM_IDS):
        errors.append("arm configuration does not freeze the expected three arms")
    if not protocol_path.exists():
        warnings.append("final protocol document does not exist yet when validation ran")

    return {
        "schema_version": PREFLIGHT_VERSION,
        "artifact_status": "pre_execution_validation_no_final_cases_executed",
        "created_at": datetime.now(UTC).isoformat(),
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "final_confirmatory_cases_executed": False,
        "browser_verification_executed": False,
        "gpt_calls_executed": False,
        "qwen_calls_executed": False,
        "ground_truth_exposed_to_ranker": False,
        "model_facing_snapshot_leak_count": len(snapshot_leaks),
        "readiness_only_in_final_corpus": any(candidate.provenance.evaluation_role == READINESS_ROLE for candidate in candidates),
        "excluded_in_final_corpus": any(candidate.provenance.evaluation_role == EXCLUDED_ROLE for candidate in candidates),
        "counts": counts,
        "scenario_count": scenario_manifest["scenario_count"],
        "trial_denominators": denominators,
        "protocol_path": protocol_path.relative_to(REPO_ROOT).as_posix(),
        "protocol_sha256": sha256_file(protocol_path) if protocol_path.exists() else "not_available",
    }


def model_facing_snapshot_leaks(snapshot: dict[str, Any]) -> bool:
    return value_leaks(snapshot, include_keys=True)


def scenario_manifest_contains_ground_truth(value: Any) -> bool:
    serialized = json.dumps(value, sort_keys=True).lower()
    return any(fragment in serialized for fragment in ["expected_result", "vulnerable", "non_vulnerable", "ground_truth", "focal"])


def value_leaks(value: Any, *, include_keys: bool) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if include_keys and str(key) in FORBIDDEN_MODELFACING_KEYS:
                return True
            if value_leaks(item, include_keys=include_keys):
                return True
    elif isinstance(value, list):
        return any(value_leaks(item, include_keys=include_keys) for item in value)
    elif isinstance(value, str):
        return any(fragment in value for fragment in FORBIDDEN_MODELFACING_FRAGMENTS)
    return False


def build_package_manifest(
    output_dir: Path,
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
    validation: dict[str, Any],
    protocol_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": PACKAGE_VERSION,
        "artifact_status": "pre_execution_protocol_freeze_package",
        "created_at": datetime.now(UTC).isoformat(),
        "output_dir": display_path(output_dir),
        "protocol": {
            "path": protocol_path.relative_to(REPO_ROOT).as_posix(),
            "sha256": sha256_file(protocol_path) if protocol_path.exists() else "not_available",
            "status": "frozen_pre_execution_no_scored_run",
        },
        "counts": corpus_manifest["corpus_counts"],
        "scenario_counts": {
            "total": scenario_bundle["scenario_manifest"]["scenario_count"],
            "positive": scenario_bundle["scoring_data"]["positive_scenarios"],
            "negative_only": scenario_bundle["scoring_data"]["negative_only_scenarios"],
        },
        "trial_denominators": trial_schedule["denominators"],
        "validation_valid": validation["valid"],
        "included_artifacts": [
            path.relative_to(output_dir).as_posix()
            for path in sorted(output_dir.rglob("*"))
            if path.is_file() and path.name not in {"manifest.json", "checksums.sha256", "checksum-validation-report.json"}
        ],
    }


def final_corpus_rows(candidates: list[OwaspExternalCandidate]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "action_path": candidate.ranker_candidate.action_path,
            "method": candidate.ranker_candidate.method,
            "parameter_name": candidate.ranker_candidate.parameter_name,
            "source": candidate.ranker_candidate.source,
            "input_type": candidate.ranker_candidate.input_type,
            "editable_input_count": candidate.ranker_candidate.editable_input_count,
            "required_input_count": candidate.ranker_candidate.required_input_count,
            "parameter_count": candidate.ranker_candidate.parameter_count,
            "evaluation_role": candidate.provenance.evaluation_role,
            "compatibility_class": candidate.provenance.compatibility_class,
        }
        for candidate in sorted_candidates(candidates)
    ]


def internal_provenance(candidates: list[OwaspExternalCandidate]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "original_case_id": candidate.provenance.benchmark_case_id,
            "benchmark_name": candidate.provenance.benchmark_name,
            "benchmark_version": candidate.provenance.benchmark_version,
            "benchmark_revision": candidate.provenance.benchmark_revision,
            "source_file": candidate.provenance.source_file,
            "endpoint": candidate.provenance.endpoint,
            "input_source": candidate.provenance.input_source,
            "input_name": candidate.provenance.input_name,
            "compatibility_class": candidate.provenance.compatibility_class,
            "evaluation_role": candidate.provenance.evaluation_role,
        }
        for candidate in sorted_candidates(candidates)
    ]


def execution_specifications(candidates: list[OwaspExternalCandidate]) -> list[dict[str, Any]]:
    return [asdict(candidate.execution) for candidate in sorted_candidates(candidates)]


def candidate_order_rows(
    scenario_id: str,
    scenario_type: str,
    pack: list[OwaspExternalCandidate],
    focal_candidate_id: str | None,
) -> list[dict[str, Any]]:
    rows = []
    for position, candidate in enumerate(pack, start=1):
        rows.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": scenario_type,
                "candidate_id": candidate.ranker_candidate.candidate_id,
                "position": position,
                "is_focal_vulnerable": str(candidate.ranker_candidate.candidate_id == focal_candidate_id).lower(),
            }
        )
    return rows


def focal_position_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(str(row["position"]) for row in rows if row["is_focal_vulnerable"] == "true")
    return {str(index): counts.get(str(index), 0) for index in range(1, PACK_SIZE + 1)}


def sorted_by_seed(candidates: list[OwaspExternalCandidate], salt: str) -> list[OwaspExternalCandidate]:
    return sorted(candidates, key=lambda candidate: stable_key(salt, candidate))


def sorted_candidates(candidates: list[OwaspExternalCandidate]) -> list[OwaspExternalCandidate]:
    return sorted(candidates, key=lambda candidate: candidate.ranker_candidate.candidate_id)


def order_pack(scenario_id: str, candidates: list[OwaspExternalCandidate]) -> list[OwaspExternalCandidate]:
    return sorted(
        candidates,
        key=lambda candidate: hashlib.sha256(
            "|".join([CANDIDATE_ORDER_SEED, scenario_id, candidate.ranker_candidate.candidate_id]).encode("utf-8")
        ).hexdigest(),
    )


def stable_key(salt: str, candidate: OwaspExternalCandidate) -> str:
    return hashlib.sha256(
        "|".join(
            [
                SCENARIO_ASSIGNMENT_SEED,
                salt,
                candidate.ranker_candidate.candidate_id,
                candidate.provenance.benchmark_case_id,
            ]
        ).encode("utf-8")
    ).hexdigest()


def neutral_scenario_id(index: int) -> str:
    return f"ow14-s{index:04d}"


def render_report(
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    counts = corpus_manifest["corpus_counts"]
    reuse = scenario_bundle["decoy_assignment"]["negative_reuse_distribution_for_positive_scenarios"]
    focal_positions = scenario_bundle["decoy_assignment"]["candidate_position_distribution_for_focal_vulnerable"]
    lines = [
        "# OWASP XSS v1.4 Protocol Freeze Package",
        "",
        "Status: pre-execution protocol package. No final OWASP case execution, browser verification, GPT call or Qwen call was performed.",
        "",
        "## Corpus",
        "",
        f"- Original OWASP XSS cases: `{counts['original_xss_cases']}`",
        f"- Compatible after deterministic adapters: `{counts['compatible_after_adapters']}`",
        f"- READINESS_ONLY: `{counts['readiness_only']}`",
        f"- FINAL_CONFIRMATORY_ELIGIBLE: `{counts['final_confirmatory_eligible']}`",
        f"- Final eligible vulnerable: `{counts['final_confirmatory_eligible_vulnerable']}`",
        f"- Final eligible non-vulnerable: `{counts['final_confirmatory_eligible_non_vulnerable']}`",
        f"- Excluded: `{counts['excluded']}`",
        "",
        "## Core Ranking Scenarios",
        "",
        f"- Pack size: `{PACK_SIZE}`",
        f"- Candidate-test budget k: `{TEST_BUDGET}`",
        f"- Positive scenarios: `{scenario_bundle['scoring_data']['positive_scenarios']}`",
        f"- Negative-only scenarios: `{scenario_bundle['scoring_data']['negative_only_scenarios']}`",
        f"- Total core scenarios: `{scenario_bundle['scenario_manifest']['scenario_count']}`",
        f"- Negative reuse distribution in positive scenarios: `{reuse}`",
        f"- Focal vulnerable candidate position distribution: `{focal_positions}`",
        f"- Unused negatives after complete negative-only packs: `{scenario_bundle['decoy_assignment']['unused_negative_only_candidates']}`",
        "",
        "## Trial Denominators",
        "",
        f"- Deterministic structural rows: `{trial_schedule['denominators']['deterministic_structural']}`",
        f"- Proprietary GPT rows: `{trial_schedule['denominators']['proprietary_gpt']}`",
        f"- Local Qwen rows: `{trial_schedule['denominators']['local_qwen']}`",
        f"- Total ranking rows: `{trial_schedule['denominators']['total_ranking_rows']}`",
        "",
        "## Validation",
        "",
        f"- Valid: `{validation['valid']}`",
        f"- Errors: `{len(validation['errors'])}`",
        f"- Warnings: `{len(validation['warnings'])}`",
        f"- Final confirmatory cases executed: `{validation['final_confirmatory_cases_executed']}`",
        f"- GPT calls executed: `{validation['gpt_calls_executed']}`",
        f"- Qwen calls executed: `{validation['qwen_calls_executed']}`",
    ]
    if validation["errors"]:
        lines.extend(["", "### Errors", ""])
        lines.extend(f"- {error}" for error in validation["errors"])
    if validation["warnings"]:
        lines.extend(["", "### Warnings", ""])
        lines.extend(f"- {warning}" for warning in validation["warnings"])
    return "\n".join(lines) + "\n"


def render_protocol_summary_table(
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
) -> str:
    counts = corpus_manifest["corpus_counts"]
    return "\n".join(
        [
            "# Thesis Table: v1.4 OWASP XSS Pre-Execution Protocol Summary",
            "",
            "| Item | Value |",
            "| --- | ---: |",
            f"| Final eligible original cases | {counts['final_confirmatory_eligible']} |",
            f"| Eligible vulnerable cases | {counts['final_confirmatory_eligible_vulnerable']} |",
            f"| Eligible non-vulnerable cases | {counts['final_confirmatory_eligible_non_vulnerable']} |",
            f"| Positive ranking scenarios | {scenario_bundle['scoring_data']['positive_scenarios']} |",
            f"| Negative-only ranking scenarios | {scenario_bundle['scoring_data']['negative_only_scenarios']} |",
            f"| Total core ranking scenarios | {scenario_bundle['scenario_manifest']['scenario_count']} |",
            f"| Pack size | {PACK_SIZE} |",
            f"| Candidate-test budget | {TEST_BUDGET} |",
            f"| Deterministic rows | {trial_schedule['denominators']['deterministic_structural']} |",
            f"| GPT rows | {trial_schedule['denominators']['proprietary_gpt']} |",
            f"| Qwen rows | {trial_schedule['denominators']['local_qwen']} |",
            f"| Total ranking rows | {trial_schedule['denominators']['total_ranking_rows']} |",
            "",
        ]
    )


def render_protocol_summary_table_latex() -> str:
    return (
        "% Status: pre-execution protocol summary only. No experimental results are included.\n"
        "\\begin{table}[ht]\n"
        "\\centering\n"
        "\\caption{Pre-execution v1.4 OWASP XSS confirmatory protocol summary.}\n"
        "\\label{tab:v14-owasp-xss-protocol-summary}\n"
        "\\begin{tabular}{lr}\n"
        "\\hline\n"
        "Item & Value \\\\\n"
        "\\hline\n"
        "Final eligible original cases & 388 \\\\\n"
        "Eligible vulnerable cases & 236 \\\\\n"
        "Eligible non-vulnerable cases & 152 \\\\\n"
        "Positive ranking scenarios & 236 \\\\\n"
        "Negative-only ranking scenarios & 30 \\\\\n"
        "Total core ranking scenarios & 266 \\\\\n"
        "Pack size & 5 \\\\\n"
        "Candidate-test budget & 4 \\\\\n"
        "Deterministic rows & 266 \\\\\n"
        "GPT rows & 1330 \\\\\n"
        "Qwen rows & 1330 \\\\\n"
        "Total ranking rows & 2926 \\\\\n"
        "\\hline\n"
        "\\end{tabular}\n"
        "\\end{table}\n"
    )


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        if not rows:
            return
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def render_checksums(root: Path) -> str:
    lines = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.name not in {"checksums.sha256", "checksum-validation-report.json"}:
            lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def validate_checksums(checksum_path: Path) -> dict[str, Any]:
    root = checksum_path.parent
    errors: list[str] = []
    count = 0
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = root / relative
        count += 1
        if not path.exists():
            errors.append(f"missing checksum target: {relative}")
        elif sha256_file(path) != expected:
            errors.append(f"checksum mismatch: {relative}")
    return {
        "schema_version": "owasp-xss-v14-checksum-validation-v1",
        "valid": not errors,
        "errors": errors,
        "entries": count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare the v1.4 OWASP XSS pre-execution protocol package.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()
    manifest = build_protocol_freeze_package(output_dir=args.output_dir)
    print(f"OWASP XSS v1.4 protocol-freeze package written to: {args.output_dir}")
    print(f"Validation valid: {manifest['validation_valid']}")


if __name__ == "__main__":
    main()
