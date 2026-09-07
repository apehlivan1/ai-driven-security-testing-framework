# Prompt Version Comparison

This document compares the model-facing ranking prompt and response-schema usage across the evaluated model-backed ranking studies. It is derived only from retained repository source and artifacts.

## v1.4 OWASP XSS main ranking evaluation

- Prompt version: `llm-candidate-ranking-v1`.
- Prompt source: `src/adstf/llm_ranking.py`, function `build_ranking_prompt`.
- Retained assembled example: `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-0267__proprietary_gpt__ow14-s0001__trial-1.json` and `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/raw/ranking-rows/sequence-1597__local_qwen__ow14-s0001__trial-1.json`.
- Candidate representation source: `results/owasp-xss-v14-protocol-freeze/model-facing/candidate-snapshots/ow14-s0001.json`.
- Candidate input schema: `llm-candidate-ranking-v1.candidate_input`.
- GPT and Qwen receive the same assembled prompt text and the same `candidate_input` for the same scenario.
- Response shape: `{"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}`.

The v1.4 prompt begins with reflected-input terminology because v1.4 is a reflected-XSS ranking evaluation.

## v1.4.1 XSS context-enrichment ablation

- Prompt version remains `llm-candidate-ranking-v1`.
- Protocol source: `docs/evaluation-protocol-v1.4.1.md`.
- The instruction text and strict response shape are unchanged from v1.4.
- Difference from v1.4: candidate representation. v1.4.1 has `minimal` and `enriched` model-facing snapshots.
- Minimal example snapshot: `results/owasp-xss-v14-1-protocol-freeze/model-facing/minimal-candidate-snapshots/ow14-s0001.json`.
- Enriched example snapshot: `results/owasp-xss-v14-1-protocol-freeze/model-facing/enriched-candidate-snapshots/ow14-s0001.json`.
- Minimal candidate fields include abstract structural fields only, such as `candidate_id`, `http_method`, `input_carrier_category`, `input_type_category`, counts, `multiple_parameters`, and `request_shape_category`.
- Enriched candidate fields add benign context observations including `reflection_detected`, `reflection_count_category`, `reflection_context_category`, `marker_preservation_category`, and `response_content_type_category`.

## v1.5.1 OWASP SQLi confirmatory evaluation

- Prompt version: `llm-sqli-candidate-ranking-v1`.
- Protocol source: `docs/evaluation-protocol-v1.5.1.md`.
- Code source: `src/adstf/owasp_sqli_v15_confirmatory.py`, function `build_sqli_ranking_prompt`.
- Retained assembled example: `results/owasp-sqli-v15-1-confirmatory-final/owasp-sqli-v15-1-confirmatory-20260823T131208Z/raw/ranking-rows/sequence-0125__proprietary_gpt__os15-s0001__trial-1.json`.
- Candidate input schema in retained snapshot: `sql-candidate-ranking-v1.candidate_input`.
- The response shape remains the same strict ranking JSON object.
- Main prompt-text difference: SQLi-specific opening and explicit prohibition on HTTP request construction.

## Smallest accurate appendix structure

A single appendix section can document the common ranking-output contract, but it should contain version-specific prompt/input subsections:

1. v1.4/v1.4.1 XSS prompt `llm-candidate-ranking-v1`, with v1.4 minimal structural candidate-pack example and a short note that v1.4.1 reuses the prompt while changing candidate representation into minimal/enriched conditions.
2. v1.5.1 SQLi prompt `llm-sqli-candidate-ranking-v1`, because its exact wording differs and was introduced to correct the SQLi prompt wording.
3. Shared parser/contract subsection explaining candidate ID validity, uniqueness, completeness and retained invalid-output behavior.
