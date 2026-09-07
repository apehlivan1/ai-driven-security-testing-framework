# Thesis Prompt Reproducibility Appendix Source Report

## Purpose

This package extracts exact retained prompt, schema, model-facing input and model-output examples for the thesis reproducibility appendix. It is a derived documentation package only. It does not modify frozen protocols, raw artifacts, canonical results, prompts, schemas or framework behavior.

## Verified Sources

- v1.4 protocol: `docs/evaluation-protocol-v1.4.md`.
- v1.4 protocol/sample freeze commit: `b4674bd3cc7e301764cee977fde542260182ef4e` (`Freeze v1.4 OWASP XSS confirmatory evaluation setup`, 2026-08-22 01:18:34 +0200).
- v1.4 protocol package: `results/owasp-xss-v14-protocol-freeze`.
- v1.4 arm configuration: `results/owasp-xss-v14-protocol-freeze/arm-configurations.json`.
- v1.4 example candidate snapshot: `results/owasp-xss-v14-protocol-freeze/model-facing/candidate-snapshots/ow14-s0001.json`.
- v1.4 final run manifest: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/manifest.json`.
- v1.4 execution manifest: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/execution-manifest.json`.
- v1.4 GPT raw ranking row: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-0267__proprietary_gpt__ow14-s0001__trial-1.json`.
- v1.4 Qwen raw ranking row: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-1597__local_qwen__ow14-s0001__trial-1.json`.
- v1.4 local Qwen scenario schema: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/runtime/local-qwen-schemas/ow14-s0001.schema.json`.
- prompt builder: `src/adstf/llm_ranking.py`, function `build_ranking_prompt`.
- parser: `src/adstf/llm_ranking.py`, function `parse_model_ranking`.
- OpenAI schema wrapper: `src/adstf/openai_ranking_wrapper.py`, function `build_request_payload`.
- v1.4.1 protocol: `docs/evaluation-protocol-v1.4.1.md`.
- v1.4.1 minimal/enriched snapshot examples: `results/owasp-xss-v14-1-protocol-freeze/model-facing/*candidate-snapshots/ow14-s0001.json`.
- v1.5.1 protocol: `docs/evaluation-protocol-v1.5.1.md`.
- v1.5.1 SQLi prompt builder: `src/adstf/owasp_sqli_v15_confirmatory.py`, function `build_sqli_ranking_prompt`.
- v1.5.1 retained GPT row: `results/owasp-sqli-v15-1-confirmatory-final/owasp-sqli-v15-1-confirmatory-20260823T131208Z/raw/ranking-rows/sequence-0125__proprietary_gpt__os15-s0001__trial-1.json`.

## Exact v1.4 Prompt

The complete assembled prompt for scenario `ow14-s0001` is stored in `exact-prompt-v14.txt`. It was extracted from the retained valid GPT row and verified to match the retained valid Qwen row for the same scenario.

Prompt version: `llm-candidate-ranking-v1`.

Template source:

```text
You rank reflected-input candidates for authorized local security testing.
You may only choose from the supplied candidate_id values. Do not create payloads, do not request execution, do not verify findings, and do not use ground truth.
Return strict JSON in this exact shape: {"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}.
Include every candidate exactly once.
Candidates:
<JSON-serialized candidate_input, sorted by key and indented>
```

The final prompt is assembled by serializing the frozen `candidate_input` with `json.dumps(candidate_input, indent=2, sort_keys=True)` and appending it after `Candidates:`.

## Model-Facing Input Construction

For v1.4, model-facing candidate packs are frozen under `results/owasp-xss-v14-protocol-freeze/model-facing/candidate-snapshots/*.json`. The candidate pack used here is scenario `ow14-s0001`. It contains only model-facing fields and no ground-truth label. The raw GPT and Qwen rows both record `ground_truth_included: false`.

Source snapshot SHA-256: `8a17b87cff9e0c7148d651d1b9145ce8b47ce6868cff261783afb70b28cd1c0e`.
Candidate-input canonical JSON SHA-256: `19b41cfe326866453ce3fdf1581e86ed9ee25a221aa9352641d56dddc978cb8e`.
Protocol index candidate-input SHA-256: `19b41cfe326866453ce3fdf1581e86ed9ee25a221aa9352641d56dddc978cb8e`.

## JSON Response Schema and Parser Contract

The response schema package is stored in `response-schema-v14.json`.

The common response shape is:

```json
{"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}
```

The application parser validates that the response parses as JSON, contains a ranking list, contains known candidate IDs, contains no duplicate IDs and includes every supplied candidate ID. Omitted IDs are appended for safe continuation after recording validation errors; this continuation is not valid LLM-ranking evidence.

The OpenAI provider schema and local Qwen schema differ at the provider/runtime layer. OpenAI uses the Responses API `json_schema` wrapper to constrain the object shape. Local Qwen uses a scenario-specific llama.cpp schema containing an enum of the supplied candidate IDs, exact ranking length and rationale length limit. Both outputs still pass through the same application-side parser.

## Example Model Output

The example model-output file contains one retained valid GPT output and one retained valid Qwen output for the same candidate pack:

- GPT source: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-0267__proprietary_gpt__ow14-s0001__trial-1.json`; SHA-256 `55db3908f313ddf4dc46f5d21186f3e8b376f14333c1166427ecd1d8bfeea6bb`.
- Qwen source: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-1597__local_qwen__ow14-s0001__trial-1.json`; SHA-256 `b386f29a0c2c0050fc95f5f2a05cd55093ac1199685c78c1b6734bde104b0482`.

Both raw responses are retained and safe to display in the appendix package because they contain only candidate IDs and brief rationales, with no credentials, API keys, authorization headers or ground-truth labels.


## Exact v1.5.1 SQLi Prompt

The SQLi confirmatory evaluation used prompt version `llm-sqli-candidate-ranking-v1`. The complete retained assembled prompt for scenario `os15-s0001`, trial 1, is stored in `exact-prompt-v15.1-sqli.txt`. It was extracted from the retained hosted GPT raw row and verified previously against the prompt builder in `src/adstf/owasp_sqli_v15_confirmatory.py`, function `build_sqli_ranking_prompt`.

Template source:

```text
You rank structured SQL injection candidate records for authorized local security-testing evaluation.
You may only choose from the supplied candidate_id values. Do not create payloads, do not construct HTTP requests, do not request execution, do not verify findings, and do not use ground truth.
Return strict JSON in this exact shape: {"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}.
Include every candidate exactly once.
Candidates:
<JSON-serialized candidate_input, sorted by key and indented>
```

The final SQLi prompt is assembled by serializing the retained `candidate_input` with `json.dumps(candidate_input, indent=2, sort_keys=True)` and appending it after `Candidates:`. The retained example files are `example-candidate-pack-v15.1-sqli.json` and `example-model-output-v15.1-sqli.json`.

## Version Coverage Recommendation

A single appendix is sufficient if it is organized by prompt/input version rather than by experiment. The appendix should include the exact v1.4/v1.4.1 XSS prompt and a separate v1.5.1 SQLi prompt subsection. The common JSON response contract can be shown once, with notes distinguishing the OpenAI provider-side schema wrapper, local Qwen scenario-specific schema and shared application parser.

## Missing Historical Elements

No missing historical prompt or raw response artifact was identified for the selected v1.4 example. The v1.4.1 and v1.5.1 coverage is based on retained protocol text, source code and retained raw rows where available. This package does not attempt to reproduce prompts by rerunning code against live models.
