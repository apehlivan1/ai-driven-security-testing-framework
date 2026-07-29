from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from statistics import median
from typing import Any

from adstf.discovery import ReflectedInputCandidate
from adstf.llm_ranking import (
    LLM_RANKING_PROMPT_VERSION,
    ModelCompletion,
    ModelProviderError,
    ModelTimeoutError,
    rank_candidates_with_model,
    ranking_result_artifact,
)
from adstf.metrics import NOT_APPLICABLE, NOT_AVAILABLE
from adstf.serialization import to_json_value


REPO_ROOT = Path(__file__).resolve().parents[2]
BAKEOFF_VERSION = "local-model-bakeoff-v1.3"
CALIBRATION_SET_VERSION = "local-model-calibration-xss-v1.3"
SELECTION_RULE_VERSION = "local-model-selection-rules-v1.3"
OUTPUT_ROOT = REPO_ROOT / "results" / "local-model-bakeoff-v1.3"
TRIALS_PER_MODEL_PER_SCENARIO = 3
CALIBRATION_TEST_BUDGET = 4
MODEL_SETTINGS = {
    "temperature": 0.0,
    "top_p": 1.0,
    "seed": 42,
    "context_size_tokens": 4096,
    "max_output_tokens": 512,
    "timeout_seconds": 120,
}
FORBIDDEN_BOUNDARY_KEYS = {
    "api_key",
    "browser_state",
    "credentials",
    "ground_truth",
    "html",
    "raw_html",
    "screenshot",
    "session",
    "source_code",
}


@dataclass(frozen=True)
class ModelCandidateSpec:
    candidate_id: str
    family: str
    display_name: str
    model_identifier: str
    runtime: str
    quantization: str
    expected_memory_gb: float
    timeout_seconds: int
    metadata_completeness_score: float
    license_note: str


@dataclass(frozen=True)
class CalibrationScenario:
    scenario_id: str
    purpose: str
    outcome_class: str
    candidates: tuple[ReflectedInputCandidate, ...]
    vulnerable_candidate_ids: tuple[str, ...]
    tags: tuple[str, ...]
    test_budget: int = CALIBRATION_TEST_BUDGET


@dataclass(frozen=True)
class FakeLocalModelClient:
    model_identifier: str
    default_strategy: str = "as_listed"
    strategy_overrides: dict[tuple[str, int], str] | None = None
    latency_ms: int = 100

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        scenario_id = str(settings.get("scenario_id", ""))
        trial_number = int(settings.get("trial_number", 1))
        strategy = (self.strategy_overrides or {}).get(
            (scenario_id, trial_number),
            self.default_strategy,
        )
        if strategy == "provider_failure":
            raise ModelProviderError("fake local runtime failure")
        if strategy == "timeout":
            raise ModelTimeoutError("fake local runtime timeout")
        if strategy == "malformed":
            return ModelCompletion(
                self.model_identifier,
                "not-json",
                provider="fake-local",
                latency_ms=self.latency_ms,
                metadata={"fake_data": True, "strategy": strategy},
            )

        candidates = list(candidate_input)
        if strategy == "reverse":
            candidates.reverse()
        ranking = [
            {
                "candidate_id": candidate["candidate_id"],
                "rationale": "Fake local-model bake-off response for harness validation only.",
            }
            for candidate in candidates
        ]
        if strategy == "duplicate_first" and ranking:
            ranking.insert(1, dict(ranking[0]))
        if strategy == "unknown_first":
            ranking.insert(0, {"candidate_id": "unknown-candidate", "rationale": "invalid id"})
        if strategy == "omit_last" and ranking:
            ranking = ranking[:-1]
        return ModelCompletion(
            self.model_identifier,
            json.dumps({"ranking": ranking}),
            usage={"input_tokens": len(prompt.split()), "output_tokens": len(ranking) * 8},
            provider="fake-local",
            latency_ms=self.latency_ms,
            metadata={"fake_data": True, "strategy": strategy},
        )


def _candidate(
    scenario_id: str,
    route: str,
    parameter_name: str,
    source: str,
    input_type: str,
    editable_input_count: int,
    required_input_count: int,
) -> ReflectedInputCandidate:
    candidate_id = f"{scenario_id}-{route}-{parameter_name}"
    return ReflectedInputCandidate(
        candidate_id=candidate_id,
        page_url=f"http://127.0.0.1:4394/calibration/{scenario_id}/seed",
        action_url=f"http://127.0.0.1:4394/calibration/{scenario_id}/{route}",
        method="GET",
        parameter_name=parameter_name,
        source=source,
        input_type=input_type,
        editable_input_count=editable_input_count,
        required_input_count=required_input_count,
        parameter_count=editable_input_count,
    )


SHORTLISTED_MODELS: tuple[ModelCandidateSpec, ...] = (
    ModelCandidateSpec(
        "qwen2_5_7b_instruct_gguf_q4_k_m",
        "Qwen",
        "Qwen2.5 7B Instruct GGUF Q4_K_M",
        "Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M",
        "llama.cpp",
        "Q4_K_M",
        7.0,
        120,
        1.0,
        "Apache 2.0 model card; exact file hash required before live bake-off.",
    ),
    ModelCandidateSpec(
        "phi3_5_mini_instruct_gguf_q4_k_m",
        "Phi",
        "Phi-3.5 Mini Instruct GGUF Q4_K_M",
        "bartowski/Phi-3.5-mini-instruct-GGUF:Q4_K_M",
        "llama.cpp",
        "Q4_K_M",
        4.0,
        120,
        0.9,
        "MIT base model; community GGUF quant provenance required.",
    ),
    ModelCandidateSpec(
        "mistral_7b_instruct_v0_3_gguf_q4_k_m",
        "Mistral",
        "Mistral 7B Instruct v0.3 GGUF Q4_K_M",
        "mistralai/Mistral-7B-Instruct-v0.3 GGUF Q4_K_M",
        "llama.cpp",
        "Q4_K_M",
        7.0,
        120,
        0.95,
        "Apache 2.0 model card; exact GGUF source must be pinned.",
    ),
    ModelCandidateSpec(
        "gemma3_4b_it_gguf_q4_k_m",
        "Gemma",
        "Gemma 3 4B IT GGUF Q4_K_M",
        "tensorblock/gemma-3-4b-it-GGUF:Q4_K_M",
        "llama.cpp",
        "Q4_K_M",
        4.0,
        120,
        0.85,
        "Gemma license terms and community quant provenance must be recorded.",
    ),
)


CALIBRATION_SCENARIOS: tuple[CalibrationScenario, ...] = (
    CalibrationScenario(
        "cal-xss-001",
        "Structurally favoured vulnerable text form.",
        "vulnerable",
        (
            _candidate("cal-xss-001", "alpha", "term", "get_form", "text", 1, 0),
            _candidate("cal-xss-001", "bravo", "memo", "get_form", "text", 1, 0),
            _candidate("cal-xss-001", "cedar", "ref", "query_parameter", "query_parameter", 1, 0),
            _candidate("cal-xss-001", "delta", "line", "get_form", "text", 1, 0),
        ),
        ("cal-xss-001-alpha-term",),
        ("favoured-positive",),
    ),
    CalibrationScenario(
        "cal-xss-002",
        "Unfavoured vulnerable query parameter behind stronger form decoys.",
        "vulnerable",
        (
            _candidate("cal-xss-002", "atlas", "query", "get_form", "search", 1, 0),
            _candidate("cal-xss-002", "brook", "name", "get_form", "text", 1, 0),
            _candidate("cal-xss-002", "cabin", "ref", "query_parameter", "query_parameter", 1, 0),
            _candidate("cal-xss-002", "dune", "memo", "get_form", "text", 2, 1),
            _candidate("cal-xss-002", "dune", "kind", "get_form", "text", 2, 1),
        ),
        ("cal-xss-002-cabin-ref",),
        ("query-positive", "adversarial-structure"),
    ),
    CalibrationScenario(
        "cal-xss-003",
        "Required-field form decoy where optional companion field is vulnerable.",
        "vulnerable",
        (
            _candidate("cal-xss-003", "ember", "name", "get_form", "text", 2, 1),
            _candidate("cal-xss-003", "ember", "memo", "get_form", "text", 2, 1),
            _candidate("cal-xss-003", "fable", "search", "get_form", "search", 1, 0),
            _candidate("cal-xss-003", "grove", "page", "query_parameter", "query_parameter", 2, 0),
            _candidate("cal-xss-003", "grove", "mode", "query_parameter", "query_parameter", 2, 0),
            _candidate("cal-xss-003", "harbor", "line", "get_form", "textarea", 1, 0),
        ),
        ("cal-xss-003-ember-memo",),
        ("required-field-decoy", "form-structure-decoy"),
    ),
    CalibrationScenario(
        "cal-xss-004",
        "Multi-seed style candidate set with vulnerable candidate late in structural order.",
        "vulnerable",
        (
            _candidate("cal-xss-004", "iris", "search", "get_form", "search", 1, 0),
            _candidate("cal-xss-004", "juniper", "query", "get_form", "text", 1, 0),
            _candidate("cal-xss-004", "krypton", "name", "get_form", "text", 1, 0),
            _candidate("cal-xss-004", "lagoon", "slot", "query_parameter", "query_parameter", 3, 0),
            _candidate("cal-xss-004", "lagoon", "page", "query_parameter", "query_parameter", 3, 0),
            _candidate("cal-xss-004", "lagoon", "mode", "query_parameter", "query_parameter", 3, 0),
            _candidate("cal-xss-004", "mesa", "comment", "get_form", "textarea", 1, 0),
        ),
        ("cal-xss-004-lagoon-slot",),
        ("multi-seed", "adversarial-structure"),
    ),
    CalibrationScenario(
        "cal-xss-005",
        "Negative scenario with strong-looking reflected candidates.",
        "negative",
        (
            _candidate("cal-xss-005", "north", "search", "get_form", "search", 1, 0),
            _candidate("cal-xss-005", "east", "query", "get_form", "text", 1, 0),
            _candidate("cal-xss-005", "south", "name", "get_form", "text", 1, 0),
            _candidate("cal-xss-005", "west", "ref", "query_parameter", "query_parameter", 2, 0),
            _candidate("cal-xss-005", "west", "page", "query_parameter", "query_parameter", 2, 0),
        ),
        (),
        ("negative", "strong-looking-safe-candidates"),
    ),
    CalibrationScenario(
        "cal-xss-006",
        "Negative required-field and query-parameter decoy scenario.",
        "negative",
        (
            _candidate("cal-xss-006", "olive", "name", "get_form", "text", 2, 1),
            _candidate("cal-xss-006", "olive", "memo", "get_form", "text", 2, 1),
            _candidate("cal-xss-006", "pearl", "line", "get_form", "textarea", 1, 0),
            _candidate("cal-xss-006", "quill", "ref", "query_parameter", "query_parameter", 3, 0),
            _candidate("cal-xss-006", "quill", "mode", "query_parameter", "query_parameter", 3, 0),
            _candidate("cal-xss-006", "quill", "kind", "query_parameter", "query_parameter", 3, 0),
        ),
        (),
        ("negative", "required-field-decoy", "query-distractor"),
    ),
)


def run_fake_bakeoff(output_root: Path = OUTPUT_ROOT) -> dict[str, Any]:
    package = run_bakeoff(fake_clients(), fake_data=True)
    write_bakeoff_package(package, output_root)
    return package


def run_bakeoff(
    clients: dict[str, FakeLocalModelClient],
    *,
    fake_data: bool,
) -> dict[str, Any]:
    validate_bakeoff_design()
    trial_results: list[dict[str, Any]] = []
    raw_artifacts: list[dict[str, Any]] = []
    for model in SHORTLISTED_MODELS:
        client = clients[model.candidate_id]
        for scenario in CALIBRATION_SCENARIOS:
            for trial_number in range(1, TRIALS_PER_MODEL_PER_SCENARIO + 1):
                result = rank_candidates_with_model(
                    candidates=list(scenario.candidates),
                    scenario_id=scenario.scenario_id,
                    trial_number=trial_number,
                    model_client=client,
                    settings={
                        **MODEL_SETTINGS,
                        "scenario_id": scenario.scenario_id,
                        "trial_number": trial_number,
                        "model_candidate_id": model.candidate_id,
                    },
                )
                raw_artifact = {
                    **ranking_result_artifact(result),
                    "model_candidate_id": model.candidate_id,
                    "fake_data": fake_data,
                    "artifact_status": "non_experimental_fake_model_response",
                }
                raw_artifacts.append(raw_artifact)
                trial_results.append(evaluate_trial(model, scenario, result, fake_data=fake_data))
    summaries = summarize_models(trial_results)
    selection = apply_selection_rules(summaries, fake_data=fake_data)
    return {
        "schema_version": BAKEOFF_VERSION,
        "artifact_status": "non_experimental_fake_model_bakeoff" if fake_data else "live_model_bakeoff",
        "fake_data": fake_data,
        "calibration_set": calibration_manifest(),
        "model_shortlist": [model_metadata(model) for model in SHORTLISTED_MODELS],
        "settings": MODEL_SETTINGS,
        "trial_results": trial_results,
        "model_summaries": summaries,
        "selection_decision": selection,
        "raw_artifacts": raw_artifacts,
        "validation_report": validate_package_data(trial_results, summaries, selection, fake_data=fake_data),
    }


def evaluate_trial(
    model: ModelCandidateSpec,
    scenario: CalibrationScenario,
    result,
    *,
    fake_data: bool,
) -> dict[str, Any]:
    expected_ids = [candidate.candidate_id for candidate in scenario.candidates]
    ranking = [candidate_id for candidate_id in result.ordered_candidate_ids if candidate_id in expected_ids]
    top = ranking[0] if ranking else None
    vulnerable_ranks = [
        ranking.index(candidate_id) + 1
        for candidate_id in scenario.vulnerable_candidate_ids
        if candidate_id in ranking
    ]
    vulnerable_rank = min(vulnerable_ranks) if vulnerable_ranks else None
    is_positive = bool(scenario.vulnerable_candidate_ids)
    valid = result.is_valid
    return {
        "artifact_status": "non_experimental_fake_model_response" if fake_data else "live_model_response",
        "fake_data": fake_data,
        "model_candidate_id": model.candidate_id,
        "family": model.family,
        "model_identifier": model.model_identifier,
        "scenario_id": scenario.scenario_id,
        "scenario_outcome_class": scenario.outcome_class,
        "trial_number": result.trial_number,
        "candidate_count": len(expected_ids),
        "test_budget": scenario.test_budget,
        "valid": valid,
        "provider_failed": result.provider_failed,
        "timeout": _is_timeout(result.validation_errors, result.provider_failed),
        "malformed": any("malformed" in error.lower() for error in result.validation_errors),
        "duplicate_id": any("duplicate" in error.lower() for error in result.validation_errors),
        "unknown_id": any("unknown" in error.lower() for error in result.validation_errors),
        "omitted_id": any("omitted" in error.lower() for error in result.validation_errors),
        "validation_errors": result.validation_errors,
        "parsed_ranking": result.ordered_candidate_ids,
        "top_rank_candidate_id": top,
        "top_rank_is_vulnerable": (top in scenario.vulnerable_candidate_ids) if is_positive else NOT_APPLICABLE,
        "vulnerable_candidate_rank": vulnerable_rank if is_positive else NOT_APPLICABLE,
        "top_k_recall": (
            any(candidate_id in scenario.vulnerable_candidate_ids for candidate_id in ranking[: scenario.test_budget])
            if is_positive
            else NOT_APPLICABLE
        ),
        "reciprocal_rank": (1 / vulnerable_rank if vulnerable_rank else 0.0) if is_positive else NOT_APPLICABLE,
        "negative_scenario_behavior": (
            "ranking_only_no_verifier_false_positive_not_applicable"
            if not is_positive
            else NOT_APPLICABLE
        ),
        "latency_ms": result.latency_ms if result.latency_ms is not None else NOT_AVAILABLE,
        "estimated_peak_memory_gb": model.expected_memory_gb,
        "metadata_completeness_score": model.metadata_completeness_score,
        "prompt_version": result.prompt_version,
        "candidate_input_keys": sorted(result.candidate_input[0].keys()) if result.candidate_input else [],
        "authority_boundary_preserved": authority_boundary_preserved(result.candidate_input),
    }


def summarize_models(trial_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries = []
    for model in SHORTLISTED_MODELS:
        rows = [row for row in trial_results if row["model_candidate_id"] == model.candidate_id]
        valid_rows = [row for row in rows if row["valid"]]
        positive_rows = [row for row in rows if row["scenario_outcome_class"] == "vulnerable"]
        valid_positive_rows = [row for row in positive_rows if row["valid"]]
        scenario_ids = {row["scenario_id"] for row in rows}
        valid_output_rate = _rate(len(valid_rows), len(rows))
        timeout_failure_count = sum(1 for row in rows if row["timeout"] or row["provider_failed"])
        provider_failure_rate = _rate(timeout_failure_count, len(rows))
        summary = {
            "model_candidate_id": model.candidate_id,
            "family": model.family,
            "model_identifier": model.model_identifier,
            "trial_count": len(rows),
            "required_trial_count": len(CALIBRATION_SCENARIOS) * TRIALS_PER_MODEL_PER_SCENARIO,
            "completed_required_calibration_scenarios": len(scenario_ids),
            "required_calibration_scenarios": len(CALIBRATION_SCENARIOS),
            "valid_trial_count": len(valid_rows),
            "valid_output_rate": valid_output_rate,
            "malformed_output_rate": _rate(sum(1 for row in rows if row["malformed"]), len(rows)),
            "invalid_candidate_id_rate": _rate(
                sum(1 for row in rows if row["duplicate_id"] or row["unknown_id"] or row["omitted_id"]),
                len(rows),
            ),
            "timeout_provider_failure_rate": provider_failure_rate,
            "memory_feasible": True,
            "memory_feasibility_note": "fake data; live bake-off must measure actual memory pressure",
            "top_1_accuracy": _mean(
                1.0 if row["top_rank_is_vulnerable"] is True else 0.0
                for row in valid_positive_rows
            ),
            "top_k_recall": _mean(
                1.0 if row["top_k_recall"] is True else 0.0
                for row in valid_positive_rows
            ),
            "mean_reciprocal_rank": _mean(row["reciprocal_rank"] for row in valid_positive_rows),
            "ranking_stability": ranking_stability(rows),
            "median_latency_ms": _median(row["latency_ms"] for row in rows),
            "p90_latency_ms": _percentile([row["latency_ms"] for row in rows if isinstance(row["latency_ms"], int)], 0.9),
            "estimated_peak_memory_gb": model.expected_memory_gb,
            "metadata_completeness_score": model.metadata_completeness_score,
        }
        summary["eligible"] = model_is_eligible(summary)
        summary["eligibility_reasons"] = eligibility_reasons(summary)
        summaries.append(summary)
    return summaries


def apply_selection_rules(summaries: list[dict[str, Any]], *, fake_data: bool) -> dict[str, Any]:
    ranked = sorted(summaries, key=selection_sort_key)
    eligible = [summary for summary in ranked if summary["eligible"]]
    if fake_data:
        return {
            "selection_rule_version": SELECTION_RULE_VERSION,
            "artifact_status": "selection_logic_exercised_on_fake_data_no_model_selected",
            "final_selection_made": False,
            "primary_model_candidate_id": NOT_APPLICABLE,
            "fallback_model_candidate_id": NOT_APPLICABLE,
            "ranked_candidates_for_logic_validation_only": [summary["model_candidate_id"] for summary in ranked],
            "eligible_candidates_for_logic_validation_only": [summary["model_candidate_id"] for summary in eligible],
            "reason": "Fake responses validate harness, metrics and selection logic only. Live calibration bake-off required before selection.",
            "hard_eligibility_gates": selection_gates(),
            "tie_breaking_order": selection_criteria(),
        }
    primary = eligible[0] if eligible else None
    fallback = next(
        (
            summary
            for summary in eligible[1:]
            if summary["estimated_peak_memory_gb"] < primary["estimated_peak_memory_gb"]
            or summary["median_latency_ms"] < primary["median_latency_ms"]
        ),
        eligible[1] if len(eligible) > 1 else None,
    ) if primary else None
    return {
        "selection_rule_version": SELECTION_RULE_VERSION,
        "final_selection_made": primary is not None,
        "primary_model_candidate_id": primary["model_candidate_id"] if primary else NOT_AVAILABLE,
        "fallback_model_candidate_id": fallback["model_candidate_id"] if fallback else NOT_AVAILABLE,
        "ranked_candidates": [summary["model_candidate_id"] for summary in ranked],
        "eligible_candidates": [summary["model_candidate_id"] for summary in eligible],
        "hard_eligibility_gates": selection_gates(),
        "tie_breaking_order": selection_criteria(),
    }


def selection_sort_key(summary: dict[str, Any]) -> tuple:
    return (
        not summary["eligible"],
        -_number(summary["mean_reciprocal_rank"]),
        -_number(summary["top_1_accuracy"]),
        -_number(summary["top_k_recall"]),
        -_number(summary["ranking_stability"]),
        _number(summary["malformed_output_rate"]),
        _number(summary["median_latency_ms"]),
        _number(summary["estimated_peak_memory_gb"]),
        -_number(summary["metadata_completeness_score"]),
        summary["model_candidate_id"],
    )


def model_is_eligible(summary: dict[str, Any]) -> bool:
    return not eligibility_reasons(summary)


def eligibility_reasons(summary: dict[str, Any]) -> list[str]:
    reasons = []
    if summary["valid_output_rate"] < 0.90:
        reasons.append("valid_output_rate_below_0_90")
    if summary["timeout_provider_failure_rate"] > 0.10:
        reasons.append("timeout_or_provider_failure_rate_above_0_10")
    if not summary["memory_feasible"]:
        reasons.append("memory_not_feasible")
    if summary["completed_required_calibration_scenarios"] != summary["required_calibration_scenarios"]:
        reasons.append("did_not_complete_all_required_calibration_scenarios")
    return reasons


def validate_bakeoff_design() -> dict[str, Any]:
    errors = []
    if len(CALIBRATION_SCENARIOS) != 6:
        errors.append("calibration scenario count must be exactly 6")
    vulnerable = [scenario for scenario in CALIBRATION_SCENARIOS if scenario.outcome_class == "vulnerable"]
    negative = [scenario for scenario in CALIBRATION_SCENARIOS if scenario.outcome_class == "negative"]
    if len(vulnerable) != 4:
        errors.append("calibration set must contain exactly 4 vulnerable scenarios")
    if len(negative) != 2:
        errors.append("calibration set must contain exactly 2 negative scenarios")
    for scenario in CALIBRATION_SCENARIOS:
        if scenario.scenario_id.startswith("x13-"):
            errors.append(f"{scenario.scenario_id} overlaps final v1.3 held-out naming")
        if not 4 <= len(scenario.candidates) <= 8:
            errors.append(f"{scenario.scenario_id} candidate count must be 4-8")
        for candidate in scenario.candidates:
            if "/suite-v13/" in candidate.action_url:
                errors.append(f"{scenario.scenario_id} uses final held-out XSS benchmark URL")
    if len(SHORTLISTED_MODELS) != 4:
        errors.append("model shortlist must contain exactly 4 candidates")
    return {"valid": not errors, "errors": errors}


def validate_package_data(
    trial_results: list[dict[str, Any]],
    summaries: list[dict[str, Any]],
    selection: dict[str, Any],
    *,
    fake_data: bool,
) -> dict[str, Any]:
    design = validate_bakeoff_design()
    errors = list(design["errors"])
    expected_trials = len(SHORTLISTED_MODELS) * len(CALIBRATION_SCENARIOS) * TRIALS_PER_MODEL_PER_SCENARIO
    if len(trial_results) != expected_trials:
        errors.append(f"expected {expected_trials} trial rows")
    if len(summaries) != len(SHORTLISTED_MODELS):
        errors.append("model summary row count does not match shortlist")
    if fake_data and selection.get("final_selection_made"):
        errors.append("fake bake-off package must not make a final model selection")
    if not all(row["authority_boundary_preserved"] for row in trial_results):
        errors.append("candidate input violated local-model authority boundary")
    return {
        "validation_id": "local-model-bakeoff-package-validation-v1.3",
        "valid": not errors,
        "errors": errors,
        "fake_data": fake_data,
        "expected_trial_count": expected_trials,
        "actual_trial_count": len(trial_results),
        "selection_finalized": selection.get("final_selection_made", False),
    }


def write_bakeoff_package(package: dict[str, Any], output_root: Path = OUTPUT_ROOT) -> None:
    _ensure_dirs(output_root)
    (output_root / "manifest.json").write_text(
        json.dumps(package_manifest(package), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_root / "hardware-report.json").write_text(
        json.dumps(hardware_report(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for model in SHORTLISTED_MODELS:
        (output_root / "model-metadata" / f"{model.candidate_id}.json").write_text(
            json.dumps(model_metadata(model), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    for artifact in package["raw_artifacts"]:
        raw_path = (
            output_root
            / "raw"
            / artifact["model_candidate_id"]
            / artifact["scenario_id"]
            / f"trial-{artifact['trial_number']}.json"
        )
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(json.dumps(to_json_value(artifact), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    normalized = {
        "schema_version": BAKEOFF_VERSION,
        "artifact_status": package["artifact_status"],
        "fake_data": package["fake_data"],
        "trial_count": len(package["trial_results"]),
        "model_count": len(package["model_summaries"]),
        "selection_decision": package["selection_decision"],
    }
    (output_root / "normalized" / "summary.json").write_text(
        json.dumps(normalized, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _write_csv(output_root / "trial-results.csv", package["trial_results"])
    _write_csv(output_root / "normalized" / "trial-results.csv", package["trial_results"])
    _write_csv(output_root / "model-summary.csv", package["model_summaries"])
    _write_csv(output_root / "normalized" / "model-summary.csv", package["model_summaries"])
    (output_root / "selection-decision.json").write_text(
        json.dumps(to_json_value(package["selection_decision"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_root / "validation-report.json").write_text(
        json.dumps(to_json_value(package["validation_report"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_root / "analysis-report.md").write_text(render_analysis_report(package), encoding="utf-8")
    (output_root / "thesis-tables.md").write_text(render_thesis_tables_markdown(package), encoding="utf-8")
    (output_root / "thesis-tables.tex").write_text(render_thesis_tables_latex(), encoding="utf-8")
    write_figure_templates(output_root / "figures", package)
    checksum_paths = [path for path in sorted(output_root.rglob("*")) if path.is_file() and path.name != "checksums.sha256"]
    (output_root / "checksums.sha256").write_text(
        render_checksums(checksum_paths, base_dir=output_root),
        encoding="utf-8",
    )


def fake_clients() -> dict[str, FakeLocalModelClient]:
    return {
        "qwen2_5_7b_instruct_gguf_q4_k_m": FakeLocalModelClient(
            "fake-qwen2.5-7b-instruct-gguf-q4-k-m",
            "as_listed",
            latency_ms=480,
        ),
        "phi3_5_mini_instruct_gguf_q4_k_m": FakeLocalModelClient(
            "fake-phi-3.5-mini-instruct-gguf-q4-k-m",
            "reverse",
            latency_ms=240,
        ),
        "mistral_7b_instruct_v0_3_gguf_q4_k_m": FakeLocalModelClient(
            "fake-mistral-7b-instruct-v0.3-gguf-q4-k-m",
            "as_listed",
            strategy_overrides={("cal-xss-003", 2): "duplicate_first", ("cal-xss-005", 3): "unknown_first"},
            latency_ms=520,
        ),
        "gemma3_4b_it_gguf_q4_k_m": FakeLocalModelClient(
            "fake-gemma-3-4b-it-gguf-q4-k-m",
            "as_listed",
            strategy_overrides={("cal-xss-002", 1): "timeout", ("cal-xss-004", 2): "malformed", ("cal-xss-006", 3): "omit_last"},
            latency_ms=300,
        ),
    }


def calibration_manifest() -> dict[str, Any]:
    return {
        "schema_version": CALIBRATION_SET_VERSION,
        "status": "calibration_only_not_final_heldout_xss_v13",
        "scenario_count": len(CALIBRATION_SCENARIOS),
        "vulnerable_scenario_count": sum(1 for item in CALIBRATION_SCENARIOS if item.outcome_class == "vulnerable"),
        "negative_scenario_count": sum(1 for item in CALIBRATION_SCENARIOS if item.outcome_class == "negative"),
        "trials_per_model_per_scenario": TRIALS_PER_MODEL_PER_SCENARIO,
        "test_budget": CALIBRATION_TEST_BUDGET,
        "scenarios": [
            {
                "scenario_id": scenario.scenario_id,
                "purpose": scenario.purpose,
                "outcome_class": scenario.outcome_class,
                "candidate_count": len(scenario.candidates),
                "vulnerable_candidate_ids": list(scenario.vulnerable_candidate_ids),
                "tags": list(scenario.tags),
            }
            for scenario in CALIBRATION_SCENARIOS
        ],
    }


def model_metadata(model: ModelCandidateSpec) -> dict[str, Any]:
    return {
        "candidate_id": model.candidate_id,
        "family": model.family,
        "display_name": model.display_name,
        "model_identifier": model.model_identifier,
        "runtime": model.runtime,
        "quantization": model.quantization,
        "expected_memory_gb": model.expected_memory_gb,
        "timeout_seconds": model.timeout_seconds,
        "metadata_completeness_score": model.metadata_completeness_score,
        "license_note": model.license_note,
        "artifact_status": "shortlist_metadata_no_model_downloaded",
        "model_file_sha256": NOT_AVAILABLE,
        "runtime_binary_sha256": NOT_AVAILABLE,
    }


def package_manifest(package: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": BAKEOFF_VERSION,
        "artifact_status": package["artifact_status"],
        "fake_data": package["fake_data"],
        "calibration_set_version": CALIBRATION_SET_VERSION,
        "selection_rule_version": SELECTION_RULE_VERSION,
        "model_count": len(SHORTLISTED_MODELS),
        "scenario_count": len(CALIBRATION_SCENARIOS),
        "trials_per_model_per_scenario": TRIALS_PER_MODEL_PER_SCENARIO,
        "trial_count": len(package["trial_results"]),
        "final_heldout_xss_v13_used": False,
        "live_model_execution_performed": False,
        "model_download_performed": False,
        "final_model_selection_made": package["selection_decision"]["final_selection_made"],
    }


def hardware_report() -> dict[str, Any]:
    return {
        "schema_version": "local-model-bakeoff-hardware-report-v1.3",
        "artifact_status": "static_selection_milestone_snapshot",
        "operating_system": "Windows 10 10.0.19045",
        "architecture": "AMD64",
        "cpu_model": "11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz",
        "usable_logical_processors": 8,
        "total_ram_bytes": 16895107072,
        "available_ram_bytes_at_selection_inspection": 3470745600,
        "gpu_model": "Intel(R) Iris(R) Xe Graphics",
        "dedicated_vram_bytes": NOT_AVAILABLE,
        "cuda_detected": False,
        "python_version": "3.14.0",
        "installed_runtime_status": {
            "ollama": False,
            "llama_cpp_cli_or_server": False,
            "lm_studio_cli": False,
            "transformers": False,
            "vllm": False,
            "llama_cpp_python": False,
        },
    }


def selection_gates() -> list[dict[str, Any]]:
    return [
        {"metric": "valid_output_rate", "operator": ">=", "threshold": 0.90},
        {"metric": "timeout_provider_failure_rate", "operator": "<=", "threshold": 0.10},
        {"metric": "memory_feasible", "operator": "==", "threshold": True},
        {"metric": "completed_required_calibration_scenarios", "operator": "==", "threshold": "required_calibration_scenarios"},
    ]


def selection_criteria() -> list[str]:
    return [
        "higher_mean_reciprocal_rank",
        "higher_top_1_accuracy",
        "higher_top_k_recall",
        "higher_ranking_stability",
        "lower_malformed_output_rate",
        "lower_median_latency_ms",
        "lower_estimated_peak_memory_gb",
        "higher_metadata_completeness_score",
        "lexicographic_model_candidate_id",
    ]


def authority_boundary_preserved(candidate_input: list[dict[str, Any]]) -> bool:
    for item in candidate_input:
        keys = {key.lower() for key in item}
        if keys & FORBIDDEN_BOUNDARY_KEYS:
            return False
    return True


def ranking_stability(rows: list[dict[str, Any]]) -> Any:
    valid_rows = [row for row in rows if row["valid"]]
    if not valid_rows:
        return NOT_AVAILABLE
    scenario_scores = []
    for scenario_id in sorted({row["scenario_id"] for row in valid_rows}):
        rankings = [tuple(row["parsed_ranking"]) for row in valid_rows if row["scenario_id"] == scenario_id]
        if not rankings:
            continue
        modal = max(rankings.count(ranking) for ranking in set(rankings))
        scenario_scores.append(modal / len(rankings))
    return _mean(scenario_scores)


def render_analysis_report(package: dict[str, Any]) -> str:
    lines = [
        "# Local Model Bake-Off v1.3 Harness Report",
        "",
        "Report status: non-experimental fake model data. This package validates the bake-off harness, metrics, reporting layout and selection logic only.",
        "",
        f"- Models in shortlist: `{len(SHORTLISTED_MODELS)}`",
        f"- Calibration scenarios: `{len(CALIBRATION_SCENARIOS)}`",
        f"- Trials per model per scenario: `{TRIALS_PER_MODEL_PER_SCENARIO}`",
        f"- Total fake trial rows: `{len(package['trial_results'])}`",
        f"- Final model selected: `{package['selection_decision']['final_selection_made']}`",
        f"- Final held-out XSS v1.3 benchmark used: `false`",
        "",
        "## Selection Rules",
        "",
    ]
    for gate in selection_gates():
        lines.append(f"- Gate: `{gate['metric']} {gate['operator']} {gate['threshold']}`")
    lines.extend(["", "Tie-breaking order:"])
    lines.extend(f"- `{criterion}`" for criterion in selection_criteria())
    lines.extend(["", "## Model Summaries", ""])
    lines.append("| Model | Eligible | Valid rate | Timeout/failure rate | MRR | Median latency ms |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
    for summary in package["model_summaries"]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                summary["model_candidate_id"],
                summary["eligible"],
                summary["valid_output_rate"],
                summary["timeout_provider_failure_rate"],
                summary["mean_reciprocal_rank"],
                summary["median_latency_ms"],
            )
        )
    return "\n".join(lines) + "\n"


def render_thesis_tables_markdown(package: dict[str, Any]) -> str:
    return """# Local Model Bake-Off Thesis Table Templates

Template status: fake/non-experimental harness data only. Do not use these rows
as live model results.

## Bake-Off Eligibility

| Model | Valid output rate | Timeout/failure rate | Eligible | Notes |
| --- | ---: | ---: | --- | --- |
""" + "\n".join(
        f"| `{summary['model_candidate_id']}` | `{summary['valid_output_rate']}` | `{summary['timeout_provider_failure_rate']}` | `{summary['eligible']}` | fake data only |"
        for summary in package["model_summaries"]
    ) + "\n"


def render_thesis_tables_latex() -> str:
    return r"""% Local model bake-off thesis table template.
% Template status: fake/non-experimental harness data only.

\begin{table}[htbp]
\centering
\caption{Local open-weights model bake-off eligibility}
\label{tab:local-model-bakeoff-eligibility}
\begin{tabular}{lrrl}
\hline
Model & Valid output rate & Timeout/failure rate & Eligible \\
\hline
% Insert live bake-off rows after measured execution.
\hline
\end{tabular}
\end{table}
"""


def write_figure_templates(figures_dir: Path, package: dict[str, Any]) -> None:
    figures_dir.mkdir(parents=True, exist_ok=True)
    source = {
        "schema_version": "local-model-bakeoff-figure-source-v1.3",
        "artifact_status": "fake_non_experimental_source_data",
        "metric": "valid_output_rate_by_model",
        "rows": [
            {
                "model_candidate_id": summary["model_candidate_id"],
                "valid_output_rate": summary["valid_output_rate"],
                "fake_data": True,
            }
            for summary in package["model_summaries"]
        ],
    }
    (figures_dir / "valid-output-rate-source.json").write_text(json.dumps(source, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _write_csv(figures_dir / "valid-output-rate-source.csv", source["rows"])
    (figures_dir / "valid-output-rate-placeholder.png").write_bytes(
        base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+P+/HgAFeAJ5sqtT8QAAAABJRU5ErkJggg==")
    )
    (figures_dir / "valid-output-rate-placeholder.pdf").write_bytes(
        b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
        b"2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj\n"
        b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 80]/Contents 4 0 R>>endobj\n"
        b"4 0 obj<</Length 74>>stream\nBT /F1 10 Tf 20 40 Td (Fake bake-off figure placeholder) Tj ET\nendstream endobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000198 00000 n \n"
        b"trailer<</Root 1 0 R/Size 5>>\nstartxref\n322\n%%EOF\n"
    )


def _ensure_dirs(output_root: Path) -> None:
    for directory in ("model-metadata", "raw", "normalized", "figures"):
        (output_root / directory).mkdir(parents=True, exist_ok=True)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: _csv_value(row.get(key)) for key in fieldnames})


def _csv_value(value: Any) -> Any:
    if isinstance(value, (list, dict)):
        return json.dumps(to_json_value(value), sort_keys=True)
    return value


def _is_timeout(errors: list[str], provider_failed: bool) -> bool:
    return provider_failed and any("timeout" in error.lower() or "timed out" in error.lower() for error in errors)


def _mean(values) -> Any:
    items = [value for value in values if isinstance(value, (int, float))]
    return sum(items) / len(items) if items else NOT_APPLICABLE


def _median(values) -> Any:
    items = [value for value in values if isinstance(value, (int, float))]
    return median(items) if items else NOT_AVAILABLE


def _percentile(values: list[int], percentile: float) -> Any:
    if not values:
        return NOT_AVAILABLE
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile)))
    return ordered[index]


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _number(value: Any) -> float:
    return float(value) if isinstance(value, (int, float)) else -1.0


def render_checksums(paths: list[Path], *, base_dir: Path = REPO_ROOT) -> str:
    lines = []
    for path in paths:
        try:
            label = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            label = path.relative_to(base_dir).as_posix()
        lines.append(f"{sha256_file(path)}  {label}\n")
    return "".join(lines)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate fake local-model bake-off harness artifacts.")
    parser.add_argument("--output-root", type=Path, default=OUTPUT_ROOT)
    args = parser.parse_args()
    package = run_fake_bakeoff(args.output_root)
    if not package["validation_report"]["valid"]:
        raise SystemExit("fake bake-off package validation failed")
    print(f"Local-model fake bake-off artifacts written to: {args.output_root}")


if __name__ == "__main__":
    main()
