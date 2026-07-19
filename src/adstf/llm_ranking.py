from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlparse

from adstf.discovery import ReflectedInputCandidate


LLM_RANKING_PROMPT_VERSION = "llm-candidate-ranking-v1"


class ModelProviderError(RuntimeError):
    pass


class ModelTimeoutError(ModelProviderError):
    pass


@dataclass(frozen=True)
class ModelCompletion:
    model_identifier: str
    raw_response: str
    usage: dict | None = None
    cost: dict | None = None


class ModelClient(Protocol):
    model_identifier: str

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        ...


@dataclass(frozen=True)
class FakeModelClient:
    model_identifier: str = "fake-llm-as-listed"
    strategy: str = "as_listed"

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        if self.strategy == "provider_failure":
            raise ModelProviderError("fake provider failure")
        if self.strategy == "timeout":
            raise ModelTimeoutError("fake provider timeout")
        if self.strategy == "malformed":
            return ModelCompletion(self.model_identifier, "not-json", usage={"prompt_tokens": 0, "completion_tokens": 0})

        candidates = list(candidate_input)
        if self.strategy == "reverse":
            candidates.reverse()
        ranking = [
            {
                "candidate_id": candidate["candidate_id"],
                "rationale": "Fake model ranking for deterministic plumbing validation.",
            }
            for candidate in candidates
        ]
        if self.strategy == "duplicate_first" and ranking:
            ranking.insert(1, dict(ranking[0]))
        if self.strategy == "omit_last" and ranking:
            ranking = ranking[:-1]
        if self.strategy == "unknown_first":
            ranking.insert(0, {"candidate_id": "unknown-candidate", "rationale": "invalid id"})
        return ModelCompletion(
            self.model_identifier,
            json.dumps({"ranking": ranking}),
            usage={"prompt_tokens": len(prompt.split()), "completion_tokens": len(ranking) * 6},
        )


@dataclass(frozen=True)
class CommandModelClient:
    command: list[str]
    model_identifier: str = "command-model"
    timeout_seconds: float = 30.0

    def complete(self, prompt: str, candidate_input: list[dict], settings: dict) -> ModelCompletion:
        request = {
            "prompt": prompt,
            "candidate_input": candidate_input,
            "settings": settings,
        }
        try:
            completed = subprocess.run(
                self.command,
                input=json.dumps(request),
                capture_output=True,
                check=False,
                encoding="utf-8",
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise ModelTimeoutError(f"model command timed out after {self.timeout_seconds} seconds") from exc
        if completed.returncode != 0:
            raise ModelProviderError(completed.stderr.strip() or f"model command exited with {completed.returncode}")
        return ModelCompletion(
            self.model_identifier,
            completed.stdout,
            usage=None,
            cost=None,
        )


@dataclass(frozen=True)
class LLMRankingResult:
    ordered_candidate_ids: list[str]
    rationales: dict[str, str]
    validation_errors: list[str]
    raw_response: str | None
    model_identifier: str
    prompt_version: str
    model_settings: dict
    candidate_input: list[dict]
    prompt: str
    usage: dict | None
    cost: dict | None
    timestamp: str
    trial_number: int
    scenario_id: str
    provider_failed: bool = False

    @property
    def is_valid(self) -> bool:
        return not self.validation_errors and not self.provider_failed


def rank_candidates_with_model(
    *,
    candidates: list[ReflectedInputCandidate],
    scenario_id: str,
    trial_number: int,
    model_client: ModelClient,
    settings: dict | None = None,
) -> LLMRankingResult:
    model_settings = settings or {"temperature": 0.0}
    candidate_input = candidate_input_for_prompt(candidates)
    prompt = build_ranking_prompt(candidate_input)
    try:
        completion = model_client.complete(prompt, candidate_input, model_settings)
    except (ModelProviderError, ModelTimeoutError) as exc:
        return LLMRankingResult(
            ordered_candidate_ids=[candidate["candidate_id"] for candidate in candidate_input],
            rationales={},
            validation_errors=[str(exc)],
            raw_response=None,
            model_identifier=getattr(model_client, "model_identifier", "unknown-model"),
            prompt_version=LLM_RANKING_PROMPT_VERSION,
            model_settings=model_settings,
            candidate_input=candidate_input,
            prompt=prompt,
            usage=None,
            cost=None,
            timestamp=datetime.now(UTC).isoformat(),
            trial_number=trial_number,
            scenario_id=scenario_id,
            provider_failed=True,
        )

    ordered_ids, rationales, validation_errors = parse_model_ranking(
        completion.raw_response,
        [candidate["candidate_id"] for candidate in candidate_input],
    )
    return LLMRankingResult(
        ordered_candidate_ids=ordered_ids,
        rationales=rationales,
        validation_errors=validation_errors,
        raw_response=completion.raw_response,
        model_identifier=completion.model_identifier,
        prompt_version=LLM_RANKING_PROMPT_VERSION,
        model_settings=model_settings,
        candidate_input=candidate_input,
        prompt=prompt,
        usage=completion.usage,
        cost=completion.cost,
        timestamp=datetime.now(UTC).isoformat(),
        trial_number=trial_number,
        scenario_id=scenario_id,
    )


def candidate_input_for_prompt(candidates: list[ReflectedInputCandidate]) -> list[dict]:
    return [
        {
            "candidate_id": candidate.candidate_id,
            "action_path": urlparse(candidate.action_url).path,
            "method": candidate.method,
            "parameter_name": candidate.parameter_name,
            "source": candidate.source,
            "input_type": candidate.input_type,
            "editable_input_count": candidate.editable_input_count,
            "required_input_count": candidate.required_input_count,
            "parameter_count": candidate.parameter_count,
        }
        for candidate in sorted(candidates, key=lambda item: item.candidate_id)
    ]


def build_ranking_prompt(candidate_input: list[dict]) -> str:
    return (
        "You rank reflected-input candidates for authorized local security testing.\n"
        "You may only choose from the supplied candidate_id values. Do not create payloads, "
        "do not request execution, do not verify findings, and do not use ground truth.\n"
        "Return strict JSON in this exact shape: "
        '{"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}.\n'
        "Include every candidate exactly once.\n"
        "Candidates:\n"
        + json.dumps(candidate_input, indent=2, sort_keys=True)
    )


def parse_model_ranking(raw_response: str, candidate_ids: list[str]) -> tuple[list[str], dict[str, str], list[str]]:
    validation_errors: list[str] = []
    rationales: dict[str, str] = {}
    known = set(candidate_ids)
    ordered: list[str] = []
    try:
        data = json.loads(raw_response)
    except json.JSONDecodeError as exc:
        return candidate_ids, rationales, [f"malformed JSON response: {exc.msg}"]

    ranking = data.get("ranking") if isinstance(data, dict) else None
    if not isinstance(ranking, list):
        return candidate_ids, rationales, ["response must contain a ranking list"]

    seen: set[str] = set()
    for index, item in enumerate(ranking):
        if isinstance(item, str):
            candidate_id = item
            rationale = ""
        elif isinstance(item, dict):
            candidate_id = str(item.get("candidate_id", ""))
            rationale = str(item.get("rationale", ""))
        else:
            validation_errors.append(f"ranking item {index} is not an object or string")
            continue

        if candidate_id not in known:
            validation_errors.append(f"unknown candidate_id: {candidate_id}")
            continue
        if candidate_id in seen:
            validation_errors.append(f"duplicate candidate_id: {candidate_id}")
            continue
        seen.add(candidate_id)
        ordered.append(candidate_id)
        rationales[candidate_id] = rationale

    omitted = [candidate_id for candidate_id in candidate_ids if candidate_id not in seen]
    if omitted:
        validation_errors.append("omitted candidate_id values: " + ", ".join(omitted))
        ordered.extend(omitted)

    return ordered, rationales, validation_errors


def ranking_result_artifact(result: LLMRankingResult) -> dict:
    return {
        "scenario_id": result.scenario_id,
        "trial_number": result.trial_number,
        "timestamp": result.timestamp,
        "model_identifier": result.model_identifier,
        "prompt_version": result.prompt_version,
        "model_settings": result.model_settings,
        "candidate_input": result.candidate_input,
        "prompt": result.prompt,
        "raw_response": result.raw_response,
        "parsed_ranking": result.ordered_candidate_ids,
        "rationales": result.rationales,
        "validation_errors": result.validation_errors,
        "provider_failed": result.provider_failed,
        "usage": result.usage,
        "cost": result.cost,
    }
