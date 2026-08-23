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
from adstf.owasp_sqli_v15 import (
    DEFAULT_BENCHMARK_ROOT,
    DEFAULT_READINESS_DIR,
    FALSE_PROBE_VALUE,
    TRUE_PROBE_VALUE,
    OwaspSqliCandidate,
    construct_candidate,
    load_case_audit,
    parse_crawler_inputs,
    readiness_adapter_class,
)
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUTPUT_DIR = REPO_ROOT / "results" / "owasp-sqli-v15-protocol-freeze"
PROTOCOL_PATH = REPO_ROOT / "docs" / "evaluation-protocol-v1.5.md"

PACKAGE_VERSION = "owasp-sqli-v15-protocol-freeze-v1"
FINAL_CORPUS_VERSION = "owasp-sqli-v15-final-corpus-v1"
CANDIDATE_SNAPSHOT_VERSION = "os15-candidate-snapshot-v1"
SCENARIO_MANIFEST_VERSION = "os15-scenario-manifest-v1"
TRIAL_SCHEDULE_VERSION = "owasp-sqli-v15-trial-schedule-v1"
DIRECT_EXECUTION_SCHEDULE_VERSION = "owasp-sqli-v15-direct-execution-schedule-v1"
PREFLIGHT_VERSION = "owasp-sqli-v15-preflight-validation-v1"

FINAL_CORPUS_ROLE = "FINAL_CONFIRMATORY_ELIGIBLE"
READINESS_ROLE = "READINESS_ONLY"
EXCLUDED_ROLE = "EXCLUDED"

PACK_SIZE = 5
TEST_BUDGET = 4
LLM_TRIALS = 5
DETERMINISTIC_TRIALS = 1
POSITIVE_DECOYS_PER_SCENARIO = PACK_SIZE - 1

SCENARIO_ASSIGNMENT_SEED = "owasp-sqli-v15-final-scenario-assignment-v1"
CANDIDATE_ORDER_SEED = "owasp-sqli-v15-final-candidate-order-v1"
TRIAL_SCHEDULE_SEED = "owasp-sqli-v15-final-trial-schedule-v1"
DIRECT_EXECUTION_SCHEDULE_SEED = "owasp-sqli-v15-direct-execution-schedule-v1"

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
    "sql_operation",
    "sql_operation_category",
    "sql_statement",
    "vulnerability_label",
}
FORBIDDEN_MODELFACING_FRAGMENTS = [
    "BenchmarkTest",
    ".java",
    "expected_result",
    "ground_truth",
    "non_vulnerable",
    "vulnerable",
    "sqli",
    "select",
    "insert",
    "update",
    "delete",
    "call",
    TRUE_PROBE_VALUE,
    FALSE_PROBE_VALUE,
]


def build_protocol_freeze_package(
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    readiness_dir: Path = DEFAULT_READINESS_DIR,
    benchmark_root: Path = DEFAULT_BENCHMARK_ROOT,
    protocol_path: Path = PROTOCOL_PATH,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = load_case_audit(readiness_dir / "updated-compatibility-inventory.csv")
    rows = ensure_evaluation_roles(rows, readiness_dir)
    crawler_inputs = parse_crawler_inputs(benchmark_root)
    candidates = [
        construct_candidate(row, crawler_inputs[row["benchmark_case_id"]])
        for row in rows
        if row["evaluation_role"] == FINAL_CORPUS_ROLE
    ]

    corpus_manifest = build_final_corpus_manifest(candidates, rows, readiness_dir)
    scenario_bundle = build_scenarios(candidates)
    arm_config = build_arm_configurations()
    metric_spec = build_metric_specification()
    trial_schedule = build_trial_schedule(scenario_bundle["scenario_manifest"]["scenarios"])
    direct_schedule = build_direct_execution_schedule(candidates)

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
    write_json(output_dir / "direct-execution-schedule.json", direct_schedule)
    write_csv(output_dir / "direct-execution-schedule.csv", direct_schedule["rows"])
    write_csv(output_dir / "candidate-ordering.csv", scenario_bundle["candidate_ordering_rows"])
    write_json(output_dir / "metric-scoring-specification.json", metric_spec)

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
        direct_schedule=direct_schedule,
        protocol_path=protocol_path,
    )
    write_json(output_dir / "preflight-validation-report.json", validation)
    write_text(output_dir / "report.md", render_report(corpus_manifest, scenario_bundle, trial_schedule, direct_schedule, validation))
    write_text(output_dir / "thesis-table-v15-protocol-summary.md", render_protocol_summary_table(corpus_manifest, scenario_bundle, trial_schedule, direct_schedule))
    write_text(output_dir / "thesis-table-v15-protocol-summary.tex", render_protocol_summary_table_latex())

    manifest = build_package_manifest(output_dir, corpus_manifest, scenario_bundle, trial_schedule, direct_schedule, validation, protocol_path)
    write_json(output_dir / "manifest.json", manifest)
    write_text(output_dir / "checksums.sha256", render_checksums(output_dir))
    checksum_validation = validate_checksums(output_dir / "checksums.sha256")
    write_json(output_dir / "checksum-validation-report.json", checksum_validation)
    if not validation["valid"] or not checksum_validation["valid"]:
        raise RuntimeError("v1.5 SQLi protocol-freeze package validation failed")
    return manifest


def ensure_evaluation_roles(rows: list[dict[str, str]], readiness_dir: Path) -> list[dict[str, str]]:
    if rows and "evaluation_role" in rows[0]:
        return rows
    selection_manifest = json.loads((readiness_dir / "selection-manifest.json").read_text(encoding="utf-8"))
    readiness_case_ids = {item["benchmark_case_id"] for item in selection_manifest["selected_cases"]}
    assigned: list[dict[str, str]] = []
    for row in rows:
        item = dict(row)
        if item["benchmark_case_id"] in readiness_case_ids:
            item["evaluation_role"] = READINESS_ROLE
        elif item["compatibility_class"] == "ADAPTER_SUPPORTED":
            item["evaluation_role"] = FINAL_CORPUS_ROLE
        else:
            item["evaluation_role"] = EXCLUDED_ROLE
        assigned.append(item)
    return assigned


def build_final_corpus_manifest(
    candidates: list[OwaspSqliCandidate],
    rows: list[dict[str, str]],
    readiness_dir: Path,
) -> dict[str, Any]:
    role_counts = Counter(row["evaluation_role"] for row in rows)
    final_rows = [row for row in rows if row["evaluation_role"] == FINAL_CORPUS_ROLE]
    expected_counts = Counter(row["expected_result"] for row in final_rows)
    compatible_rows = [row for row in rows if row["compatibility_class"] == "ADAPTER_SUPPORTED"]
    return {
        "schema_version": FINAL_CORPUS_VERSION,
        "artifact_status": "pre_execution_protocol_input",
        "created_at": datetime.now(UTC).isoformat(),
        "source_readiness_dir": readiness_dir.relative_to(REPO_ROOT).as_posix(),
        "role_policy": "Only FINAL_CONFIRMATORY_ELIGIBLE cases are used for final candidate-pack construction and direct execution schedule.",
        "corpus_counts": {
            "original_sqli_cases": len(rows),
            "adapter_supported_after_readiness": len(compatible_rows),
            "readiness_only": role_counts.get(READINESS_ROLE, 0),
            "final_confirmatory_eligible": len(final_rows),
            "final_confirmatory_eligible_vulnerable": expected_counts.get("vulnerable", 0),
            "final_confirmatory_eligible_non_vulnerable": expected_counts.get("non_vulnerable", 0),
            "excluded": role_counts.get(EXCLUDED_ROLE, 0),
        },
        "candidate_ids": [candidate.ranker_candidate.candidate_id for candidate in sorted_candidates(candidates)],
        "compatibility_distribution": dict(Counter(candidate.provenance.compatibility_class for candidate in candidates)),
        "adapter_class_distribution": dict(Counter(candidate.execution.adapter_class for candidate in candidates)),
        "input_carrier_distribution": dict(Counter(candidate.ranker_candidate.input_carrier for candidate in candidates)),
        "model_facing_identity_policy": "Original OWASP IDs, Java files, endpoints, payloads, SQL operations and labels are excluded from model-facing snapshots.",
    }


def build_scenarios(candidates: list[OwaspSqliCandidate]) -> dict[str, Any]:
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
        decoys = [
            negatives[(focal_index * POSITIVE_DECOYS_PER_SCENARIO + offset) % len(negatives)]
            for offset in range(POSITIVE_DECOYS_PER_SCENARIO)
        ]
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
        "schema_version": "owasp-sqli-v15-ground-truth-scoring-data-v1",
        "artifact_status": "post_run_scoring_only_not_model_facing",
        "load_policy": "May be loaded only after scored ranking/direct execution is complete.",
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
        "schema_version": "owasp-sqli-v15-decoy-assignment-v1",
        "artifact_status": "pre_execution_ground_truth_separated_assignment",
        "assignment_seed": SCENARIO_ASSIGNMENT_SEED,
        "candidate_order_seed": CANDIDATE_ORDER_SEED,
        "positive_decoy_policy": (
            "Sort eligible negative candidates by SHA-256(seed|negative-pool|candidate_id|original_case_id), "
            "then assign four decoys to each positive scenario by contiguous round-robin positions."
        ),
        "negative_only_policy": "Use the same sorted negative pool to form disjoint packs of five; leftover negatives are recorded and not used as partial scenarios.",
        "position_bias_policy": "Candidate order within each pack is SHA-256 sorted by neutral scenario ID and candidate ID, not by label or original case identity.",
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


def snapshot_for_pack(scenario_id: str, pack: list[OwaspSqliCandidate]) -> dict[str, Any]:
    candidate_input = [asdict(candidate.ranker_candidate) for candidate in pack]
    return {
        "schema_version": CANDIDATE_SNAPSHOT_VERSION,
        "artifact_status": "pre_execution_model_facing_input",
        "scenario_id": scenario_id,
        "candidate_count": len(candidate_input),
        "candidate_test_budget": TEST_BUDGET,
        "top_k": min(TEST_BUDGET, len(candidate_input)),
        "prompt_version": LLM_RANKING_PROMPT_VERSION,
        "candidate_input_schema": "sql-candidate-ranking-v1.candidate_input",
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
        "retry_policy": "No silent retries. Failed, malformed, timed-out or provider/runtime-failed calls remain recorded observations.",
        "resume_policy": "Resume by continuing from the next scheduled row whose artifact is absent; existing scored artifacts must not be regenerated unless a versioned protocol amendment requires a complete affected rerun.",
        "rows": rows,
        "denominators": {
            "deterministic_structural": len(scenarios),
            "proprietary_gpt": len(scenarios) * LLM_TRIALS,
            "local_qwen": len(scenarios) * LLM_TRIALS,
            "total_ranking_rows": len(rows),
        },
    }


def build_direct_execution_schedule(candidates: list[OwaspSqliCandidate]) -> dict[str, Any]:
    rows = [
        {
            "sequence": index,
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "execution_specification_ref": candidate.ranker_candidate.candidate_id,
            "adapter_class": candidate.execution.adapter_class,
            "phases": ["baseline_1", "baseline_2", "true_1", "true_2", "false_1", "false_2"],
            "expected_runtime_requests": 6,
            "scored": "true",
        }
        for index, candidate in enumerate(sorted_candidates(candidates), start=1)
    ]
    return {
        "schema_version": DIRECT_EXECUTION_SCHEDULE_VERSION,
        "artifact_status": "pre_execution_direct_validation_schedule_no_cases_executed",
        "schedule_seed": DIRECT_EXECUTION_SCHEDULE_SEED,
        "case_denominator": len(candidates),
        "expected_http_request_count": len(candidates) * 6,
        "outcome_categories": [
            "baseline_stable",
            "baseline_unstable",
            "true_false_difference_reproducible",
            "no_reproducible_difference",
            "verified",
            "rejected",
            "inconclusive",
            "runtime_error",
        ],
        "ground_truth_policy": "OWASP expected results are loaded only after direct execution and verifier decisions are complete.",
        "inconclusive_policy": "Inconclusive is a legitimate outcome and remains in the denominator.",
        "rows": rows,
    }


def build_arm_configurations() -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-arm-configurations-v1",
        "artifact_status": "pre_execution_configuration_no_calls_performed",
        "shared_contract": {
            "prompt_version": LLM_RANKING_PROMPT_VERSION,
            "task": "rank existing structured SQLi candidate IDs; include each candidate exactly once with a brief rationale",
            "candidate_representation": "model-facing/candidate-snapshots/*.json candidate_input",
            "forbidden_authority": [
                "candidate discovery",
                "SQL payload/probe construction",
                "HTTP request construction",
                "header/cookie/parameter selection",
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
        "schema_version": "owasp-sqli-v15-metric-scoring-specification-v1",
        "artifact_status": "pre_execution_metric_specification",
        "ranking_layer": {
            "positive_scenario_metrics": [
                "vulnerable_candidate_rank",
                "top_1_success",
                "top_k_success_at_k_4",
                "reciprocal_rank",
                "mrr",
                "candidate_coverage_under_budget",
            ],
            "negative_only_not_applicable": [
                "vulnerable_candidate_rank",
                "top_1_success",
                "top_k_success_at_k_4",
                "reciprocal_rank",
                "mrr",
            ],
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
                "latency",
            ],
        },
        "direct_execution_layer": {
            "denominator": "all 200 FINAL_CONFIRMATORY_ELIGIBLE original OWASP SQLi cases",
            "runtime_observations": [
                "baseline stability",
                "true/false reproducibility",
                "server-error observation",
                "reflected-payload-only rejection",
                "verifier state",
                "runtime error state",
            ],
            "post_run_ground_truth_comparison": "OWASP labels are applied after verifier outcomes are stored.",
            "inconclusive_policy": "Inconclusive remains in the denominator and is not removed post hoc.",
        },
        "failure_denominator_policy": {
            "invalid_or_failed_model_output": "retained in reliability denominators; excluded from valid ranking-performance aggregates",
            "no_silent_repair": True,
            "no_silent_retry": True,
            "repeated_trials": "nested under scenario and arm; not independent benchmark scenarios",
        },
        "undefined_value_policy": {
            "not_applicable": "metric does not apply to an arm/scenario/layer",
            "not_available": "metric applies but required measurement is absent",
        },
    }


def validate_protocol_package(
    *,
    output_dir: Path,
    rows: list[dict[str, str]],
    candidates: list[OwaspSqliCandidate],
    corpus_manifest: dict[str, Any],
    scenario_manifest: dict[str, Any],
    snapshots: list[dict[str, Any]],
    scoring_data: dict[str, Any],
    decoy_assignment: dict[str, Any],
    arm_config: dict[str, Any],
    trial_schedule: dict[str, Any],
    direct_schedule: dict[str, Any],
    protocol_path: Path,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    final_rows = [row for row in rows if row["evaluation_role"] == FINAL_CORPUS_ROLE]
    counts = corpus_manifest["corpus_counts"]
    if len(final_rows) != 200:
        errors.append(f"expected 200 final eligible rows, found {len(final_rows)}")
    if counts["final_confirmatory_eligible_vulnerable"] != 105:
        errors.append("expected 105 final eligible vulnerable rows")
    if counts["final_confirmatory_eligible_non_vulnerable"] != 95:
        errors.append("expected 95 final eligible non-vulnerable rows")
    if counts["readiness_only"] != 20:
        errors.append("expected 20 readiness-only rows")
    if counts["excluded"] != 284:
        errors.append("expected 284 excluded rows")
    if any(candidate.provenance.evaluation_role != FINAL_CORPUS_ROLE for candidate in candidates):
        errors.append("non-final-eligible candidate entered final corpus")
    if len({candidate.ranker_candidate.candidate_id for candidate in candidates}) != len(candidates):
        errors.append("final candidate IDs are not unique")

    if scenario_manifest["scenario_count"] != 124:
        errors.append(f"expected 124 scenarios, found {scenario_manifest['scenario_count']}")
    if len(snapshots) != 124:
        errors.append("expected 124 candidate snapshots")
    if any(snapshot["candidate_count"] != PACK_SIZE for snapshot in snapshots):
        errors.append("one or more snapshots do not have pack size 5")
    if any(snapshot["candidate_test_budget"] != TEST_BUDGET for snapshot in snapshots):
        errors.append("one or more snapshots do not have candidate-test budget 4")
    if any(snapshot["top_k"] != min(TEST_BUDGET, PACK_SIZE) for snapshot in snapshots):
        errors.append("one or more snapshots have incorrect top_k")

    positive = [scenario for scenario in scoring_data["scenarios"] if scenario["scenario_type"] == "positive"]
    negative_only = [scenario for scenario in scoring_data["scenarios"] if scenario["scenario_type"] == "negative_only"]
    if len(positive) != 105:
        errors.append("expected 105 positive scenarios")
    if len(negative_only) != 19:
        errors.append("expected 19 negative-only scenarios")
    focal_ids = [scenario["focal_vulnerable_candidate_id"] for scenario in positive]
    if len(set(focal_ids)) != 105:
        errors.append("not every vulnerable candidate appears exactly once as focal")
    if len(decoy_assignment["unused_negative_only_candidates"]) != 0:
        errors.append("expected zero negatives left after complete negative-only packs")
    if sum(int(key) * value for key, value in decoy_assignment["negative_reuse_distribution_for_positive_scenarios"].items()) != 105 * 4:
        errors.append("negative reuse distribution does not sum to required positive decoy assignments")

    snapshot_leaks = [snapshot["scenario_id"] for snapshot in snapshots if model_facing_snapshot_leaks(snapshot)]
    if snapshot_leaks:
        errors.append(f"model-facing snapshot leakage detected: {', '.join(snapshot_leaks[:5])}")
    if scenario_manifest_contains_ground_truth(scenario_manifest):
        errors.append("ground-truth-free scenario manifest contains ground-truth fields")

    denominators = trial_schedule["denominators"]
    if denominators != {
        "deterministic_structural": 124,
        "proprietary_gpt": 620,
        "local_qwen": 620,
        "total_ranking_rows": 1364,
    }:
        errors.append(f"unexpected trial denominators: {denominators}")
    if len(trial_schedule["rows"]) != 1364:
        errors.append("trial schedule row count is not 1364")
    if direct_schedule["case_denominator"] != 200:
        errors.append("direct execution denominator is not 200")
    if len(direct_schedule["rows"]) != 200:
        errors.append("direct execution schedule row count is not 200")
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
        "final_confirmatory_sqli_runtime_executions": 0,
        "scored_ranking_rows_executed": 0,
        "gpt_calls_executed": 0,
        "qwen_calls_executed": 0,
        "ground_truth_exposed_to_ranker": False,
        "model_facing_snapshot_leak_count": len(snapshot_leaks),
        "readiness_only_in_final_corpus": any(candidate.provenance.evaluation_role == READINESS_ROLE for candidate in candidates),
        "excluded_in_final_corpus": any(candidate.provenance.evaluation_role == EXCLUDED_ROLE for candidate in candidates),
        "counts": counts,
        "scenario_count": scenario_manifest["scenario_count"],
        "trial_denominators": denominators,
        "direct_execution_denominator": direct_schedule["case_denominator"],
        "protocol_path": protocol_path.relative_to(REPO_ROOT).as_posix(),
        "protocol_sha256": sha256_file(protocol_path) if protocol_path.exists() else "not_available",
    }


def model_facing_snapshot_leaks(snapshot: dict[str, Any]) -> bool:
    return value_leaks(snapshot, include_keys=True)


def scenario_manifest_contains_ground_truth(value: Any) -> bool:
    serialized = json.dumps(value, sort_keys=True)
    forbidden = [
        "expected_result",
        "ground_truth",
        "original_case_id",
        "vulnerable",
        "non_vulnerable",
        "BenchmarkTest",
    ]
    return any(fragment in serialized for fragment in forbidden)


def value_leaks(value: Any, *, include_keys: bool = False) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if include_keys and key in FORBIDDEN_MODELFACING_KEYS:
                return True
            if value_leaks(item, include_keys=include_keys):
                return True
        return False
    if isinstance(value, list):
        return any(value_leaks(item, include_keys=include_keys) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(fragment.lower() in lowered for fragment in FORBIDDEN_MODELFACING_FRAGMENTS if fragment)
    return False


def sorted_by_seed(candidates: list[OwaspSqliCandidate], pool_name: str) -> list[OwaspSqliCandidate]:
    return sorted(
        candidates,
        key=lambda candidate: sha256_text(
            "|".join(
                [
                    SCENARIO_ASSIGNMENT_SEED,
                    pool_name,
                    candidate.ranker_candidate.candidate_id,
                    candidate.provenance.benchmark_case_id,
                ]
            )
        ),
    )


def order_pack(scenario_id: str, pack: list[OwaspSqliCandidate]) -> list[OwaspSqliCandidate]:
    return sorted(
        pack,
        key=lambda candidate: sha256_text(
            "|".join([CANDIDATE_ORDER_SEED, scenario_id, candidate.ranker_candidate.candidate_id])
        ),
    )


def neutral_scenario_id(index: int) -> str:
    return f"os15-s{index:04d}"


def candidate_order_rows(
    scenario_id: str,
    scenario_type: str,
    pack: list[OwaspSqliCandidate],
    focal_candidate_id: str | None,
) -> list[dict[str, Any]]:
    rows = []
    for position, candidate in enumerate(pack, start=1):
        rows.append(
            {
                "scenario_id": scenario_id,
                "scenario_type": scenario_type,
                "position": position,
                "candidate_id": candidate.ranker_candidate.candidate_id,
                "is_focal_vulnerable": candidate.ranker_candidate.candidate_id == focal_candidate_id,
                "candidate_order_key": sha256_text(
                    "|".join([CANDIDATE_ORDER_SEED, scenario_id, candidate.ranker_candidate.candidate_id])
                ),
            }
        )
    return rows


def focal_position_distribution(rows: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(str(row["position"]) for row in rows if row["is_focal_vulnerable"]))


def sorted_candidates(candidates: list[OwaspSqliCandidate]) -> list[OwaspSqliCandidate]:
    return sorted(candidates, key=lambda candidate: candidate.ranker_candidate.candidate_id)


def final_corpus_rows(candidates: list[OwaspSqliCandidate]) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": candidate.ranker_candidate.candidate_id,
            "adapter_class": candidate.execution.adapter_class,
            "input_carrier": candidate.ranker_candidate.input_carrier,
            "evaluation_role": candidate.provenance.evaluation_role,
        }
        for candidate in sorted_candidates(candidates)
    ]


def internal_provenance(candidates: list[OwaspSqliCandidate]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-internal-provenance-v1",
        "artifact_status": "internal_not_model_facing",
        "records": [asdict(candidate.provenance) for candidate in sorted_candidates(candidates)],
    }


def execution_specifications(candidates: list[OwaspSqliCandidate]) -> dict[str, Any]:
    return {
        "schema_version": "owasp-sqli-v15-execution-specifications-v1",
        "artifact_status": "deterministic_execution_input_not_model_facing",
        "records": [asdict(candidate.execution) for candidate in sorted_candidates(candidates)],
    }


def build_package_manifest(
    output_dir: Path,
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
    direct_schedule: dict[str, Any],
    validation: dict[str, Any],
    protocol_path: Path,
) -> dict[str, Any]:
    return {
        "schema_version": PACKAGE_VERSION,
        "artifact_status": "frozen_pre_execution_protocol_package",
        "created_at": datetime.now(UTC).isoformat(),
        "protocol_path": protocol_path.relative_to(REPO_ROOT).as_posix(),
        "protocol_sha256": sha256_file(protocol_path) if protocol_path.exists() else "not_available",
        "output_dir": display_path(output_dir),
        "corpus_counts": corpus_manifest["corpus_counts"],
        "scenario_count": scenario_bundle["scenario_manifest"]["scenario_count"],
        "ranking_denominators": trial_schedule["denominators"],
        "direct_execution_denominator": direct_schedule["case_denominator"],
        "validation_valid": validation["valid"],
        "scored_execution_performed": False,
        "gpt_calls_performed": False,
        "qwen_calls_performed": False,
        "final_sqli_runtime_execution_performed": False,
    }


def render_report(
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
    direct_schedule: dict[str, Any],
    validation: dict[str, Any],
) -> str:
    counts = corpus_manifest["corpus_counts"]
    lines = [
        "# OWASP SQLi v1.5 Protocol Freeze Report",
        "",
        "Status: frozen pre-execution package. No final SQLi cases, GPT calls, Qwen calls or scored rankings were executed.",
        "",
        "## Final Corpus",
        "",
        f"- Original SQLi cases: `{counts['original_sqli_cases']}`",
        f"- READINESS_ONLY cases: `{counts['readiness_only']}`",
        f"- FINAL_CONFIRMATORY_ELIGIBLE cases: `{counts['final_confirmatory_eligible']}`",
        f"- Final eligible vulnerable: `{counts['final_confirmatory_eligible_vulnerable']}`",
        f"- Final eligible non-vulnerable: `{counts['final_confirmatory_eligible_non_vulnerable']}`",
        f"- Excluded evaluation role: `{counts['excluded']}`",
        "",
        "## Ranking Design",
        "",
        f"- Pack size: `{PACK_SIZE}`",
        f"- Candidate-test budget: `k={TEST_BUDGET}`",
        f"- Positive scenarios: `{scenario_bundle['scoring_data']['positive_scenarios']}`",
        f"- Negative-only scenarios: `{scenario_bundle['scoring_data']['negative_only_scenarios']}`",
        f"- Total scenarios: `{scenario_bundle['scenario_manifest']['scenario_count']}`",
        f"- Ranking denominators: `{trial_schedule['denominators']}`",
        "",
        "## Direct Execution Layer",
        "",
        f"- Direct execution denominator: `{direct_schedule['case_denominator']}`",
        f"- Expected HTTP requests if authorized: `{direct_schedule['expected_http_request_count']}`",
        "- Inconclusive outcomes remain valid observations and remain in the denominator.",
        "",
        "## Validation",
        "",
        f"- Valid: `{validation['valid']}`",
        f"- Errors: `{len(validation['errors'])}`",
        f"- Warnings: `{len(validation['warnings'])}`",
    ]
    return "\n".join(lines) + "\n"


def render_protocol_summary_table(
    corpus_manifest: dict[str, Any],
    scenario_bundle: dict[str, Any],
    trial_schedule: dict[str, Any],
    direct_schedule: dict[str, Any],
) -> str:
    counts = corpus_manifest["corpus_counts"]
    return "\n".join(
        [
            "| Item | Value |",
            "| --- | ---: |",
            f"| Final eligible SQLi cases | {counts['final_confirmatory_eligible']} |",
            f"| Final eligible vulnerable | {counts['final_confirmatory_eligible_vulnerable']} |",
            f"| Final eligible non-vulnerable | {counts['final_confirmatory_eligible_non_vulnerable']} |",
            f"| Ranking scenarios | {scenario_bundle['scenario_manifest']['scenario_count']} |",
            f"| Deterministic rows | {trial_schedule['denominators']['deterministic_structural']} |",
            f"| GPT rows | {trial_schedule['denominators']['proprietary_gpt']} |",
            f"| Qwen rows | {trial_schedule['denominators']['local_qwen']} |",
            f"| Total ranking rows | {trial_schedule['denominators']['total_ranking_rows']} |",
            f"| Direct execution denominator | {direct_schedule['case_denominator']} |",
            "",
        ]
    )


def render_protocol_summary_table_latex() -> str:
    return (
        "\\begin{tabular}{lr}\n"
        "\\toprule\n"
        "Item & Value \\\\\n"
        "\\midrule\n"
        "Final eligible SQLi cases & 200 \\\\\n"
        "Final eligible vulnerable cases & 105 \\\\\n"
        "Final eligible non-vulnerable cases & 95 \\\\\n"
        "Ranking scenarios & 124 \\\\\n"
        "Deterministic ranking rows & 124 \\\\\n"
        "GPT ranking rows & 620 \\\\\n"
        "Qwen ranking rows & 620 \\\\\n"
        "Total ranking rows & 1364 \\\\\n"
        "Direct execution denominator & 200 \\\\\n"
        "\\bottomrule\n"
        "\\end{tabular}\n"
    )


def sha256_json(value: Any) -> str:
    return sha256_text(json.dumps(to_json_value(value), sort_keys=True, separators=(",", ":")))


def display_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return str(path)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_json_value(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def render_checksums(root: Path) -> str:
    lines: list[str] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file() and item.name != "checksums.sha256"):
        lines.append(f"{sha256_file(path)}  {path.relative_to(root).as_posix()}")
    return "\n".join(lines) + "\n"


def validate_checksums(path: Path) -> dict[str, Any]:
    errors: list[str] = []
    root = path.parent
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        actual = sha256_file(root / rel)
        if expected != actual:
            errors.append(f"{rel}: expected {expected}, got {actual}")
    return {
        "schema_version": "owasp-sqli-v15-checksum-validation-v1",
        "valid": not errors,
        "errors": errors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the frozen OWASP SQLi v1.5 protocol package.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--readiness-dir", type=Path, default=DEFAULT_READINESS_DIR)
    parser.add_argument("--benchmark-root", type=Path, default=DEFAULT_BENCHMARK_ROOT)
    parser.add_argument("--protocol-path", type=Path, default=PROTOCOL_PATH)
    args = parser.parse_args()
    manifest = build_protocol_freeze_package(
        output_dir=args.output_dir,
        readiness_dir=args.readiness_dir,
        benchmark_root=args.benchmark_root,
        protocol_path=args.protocol_path,
    )
    print(f"OWASP SQLi v1.5 protocol package valid: {manifest['validation_valid']}")
    print(f"Artifacts written to: {args.output_dir}")


if __name__ == "__main__":
    main()
