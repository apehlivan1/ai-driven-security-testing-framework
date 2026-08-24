# Evaluation Protocol v1.4.1

Status: **frozen pre-execution protocol**.

This protocol freezes the `v1.4.1 OWASP XSS Context-Enrichment Ablation` study. It is a separately versioned explanatory follow-up to `evaluation-protocol-v1.4`; it does not modify or supersede the canonical v1.4 OWASP XSS results, the v1.3.1 local XSS ablation evidence, or the v1.5.1 SQLi evidence.

No scored ranking row, GPT call, Qwen call, local inference, browser verification, XSS payload execution, HTTP benchmark request or ground-truth scoring is authorized by this protocol-freeze milestone. Any later methodological change to scenarios, candidate snapshots, representation fields, prompts, parsers, models, budgets, ranking rules, metric definitions or scoring rules requires a separately versioned protocol amendment.

## Motivation and Scope

The frozen v1.4 external-validation study evaluated candidate ranking over sanitized minimal structural candidate metadata. The v1.4.1 study asks whether adding deterministic benign context observations changes candidate-ranking behavior under the same bounded authority model. The study remains ranking-only: models may rank supplied candidate IDs and provide bounded rationales, but they must not generate payloads, construct requests, execute tests, inspect source code, access ground truth or verify vulnerabilities.

The study uses the same v1.4 OWASP Benchmark XSS final-confirmatory corpus and the same scenario packs, candidate IDs, candidate ordering and candidate-test budget. It adds a second candidate-representation condition, not a new vulnerability-testing procedure.

## Provenance

The v1.4.1 protocol package is `results/owasp-xss-v14-1-protocol-freeze/`. It is derived from:

- frozen v1.4 protocol package: `results/owasp-xss-v14-protocol-freeze/`;
- corrected benign context observations: `results/owasp-xss-v14-1-context-corrected-observations/owasp-xss-v14-1-context-collection-20260824T120106Z-corrected-20260824T122934Z`;
- semantic correction commit: `039de7b0114162b92288f50371c171955b245957`.

The timestamped raw benign collection run remains local raw evidence and is not committed by this protocol freeze. The corrected observation package is the committed deterministic derivation used for enriched model-facing snapshots.

## Candidate Representations

Two representation conditions are frozen.

The `minimal` condition uses abstracted minimal structural fields derived from v1.4 snapshots after removing case-derived action-path and parameter-name strings. The retained fields are opaque candidate ID, method, input carrier category, input type category, editable input count, required input count, parameter count, multiple-parameter flag and request-shape category.

The `enriched` condition uses the same abstracted fields and adds only corrected benign context fields: reflection detected, reflection count category, reflection context category, marker preservation category and response content-type category. The benign marker is `ADSTF_CTX_V141/SAFE`. Its slash delimiter is intentional: it is a non-executable, encodable delimiter used to observe transport and encoding behavior.

Model-facing snapshots must not contain OWASP expected results, vulnerability labels, original `BenchmarkTest` identifiers, Java source paths, original endpoints, original parameter names, verifier outcomes, payloads, raw HTTP bodies or benchmark ground truth.

## Scenario and Budget Denominators

The frozen corpus and scenario construction remain unchanged from v1.4:

| Unit | Count |
| --- | ---: |
| Final eligible XSS cases | 388 |
| Positive ranking scenarios | 236 |
| Negative-only ranking scenarios | 30 |
| Total ranking scenarios | 266 |
| Candidate references | 1330 |
| Unique candidates | 388 |
| Pack size | 5 |
| Candidate-test budget | 4 |

`top_k = min(candidate_test_budget, candidate_count)`, which is 4 for every frozen v1.4.1 scenario.

## Ranking Arms

The frozen arms are:

| Arm | Candidate representation | Ranking method | Trials per scenario |
| --- | --- | --- | ---: |
| `deterministic_minimal` | minimal | deterministic abstract structural ranking | 1 |
| `deterministic_enriched` | enriched | deterministic enriched context ranking | 1 |
| `gpt_minimal` | minimal | hosted GPT ranking | 5 |
| `gpt_enriched` | enriched | hosted GPT ranking | 5 |
| `qwen_minimal` | minimal | local Qwen ranking | 5 |
| `qwen_enriched` | enriched | local Qwen ranking | 5 |

The hosted GPT configuration remains the v1.4 configuration: OpenAI `gpt-5.6-luna`, prompt version `llm-candidate-ranking-v1`, temperature parameter omitted, provider default temperature used, `OPENAI_SEND_TEMPERATURE` unset or false, maximum output 1200 tokens and timeout 60 seconds.

The local model configuration remains the v1.4 Qwen configuration: `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M` through local `llama.cpp` `llama-completion.exe`, temperature 0.0, top-p 1.0, seed 42, context size 4096 tokens, maximum output 768 tokens, 8 threads and timeout 300 seconds. Gemma remains only a contingency model and may not silently replace invalid, failed or timed-out Qwen rows. Any activation requires a versioned protocol amendment and complete rerun of the affected local-model experiment.

## Deterministic Enriched Baseline

The deterministic enriched baseline is frozen as `deterministic-enriched-context-v1`. It uses a transparent lexicographic/ordinal policy:

1. reflection detected: true before false;
2. reflection context: `script_like > html_attribute > url_like > html_text > other > none`;
3. marker preservation: `unchanged > encoded > transformed > stripped > not_reflected`;
4. reflection count: `3_or_more > 2 > 1 > 0`;
5. response content type: `html > text > json > redirect > other > not_available`;
6. abstract structural fallback using only permitted minimal fields;
7. final stable tie-break by candidate ID.

The fallback does not use the original v1.4 URL or parameter-name fields because v1.4.1 removes case-derived identity-bearing strings from ranker-facing snapshots.

## Trial Schedule and Failure Handling

The frozen schedule contains 5852 ranking rows:

| Row group | Count |
| --- | ---: |
| Deterministic rows | 532 |
| GPT rows | 2660 |
| Qwen rows | 2660 |
| Total ranking rows | 5852 |

Deterministic rows execute first. GPT and Qwen rows pair minimal and enriched conditions by scenario and trial to reduce temporal separation between representation conditions. Scenarios execute in ascending neutral scenario-ID order and LLM trials execute in trial-number order from 1 to 5.

No silent retry, repair, replacement or selective rerun is allowed. Invalid structured outputs, duplicate IDs, unknown IDs, omitted IDs, malformed JSON, provider failures, runtime failures and timeouts remain retained observations. Valid ranking-performance aggregates exclude invalid or failed model outputs, while reliability denominators retain them.

If execution is interrupted, it may resume only from the next scheduled row whose artifact is absent. Existing scored artifacts must not be regenerated unless a versioned protocol amendment requires a complete affected rerun.

## Metrics and Statistical Plan

The primary outcome is scenario-level MRR over positive scenarios. Repeated LLM trials are nested under scenario and arm and are not independent benchmark scenarios. The primary paired comparisons are:

- `gpt_enriched` versus `gpt_minimal`;
- `qwen_enriched` versus `qwen_minimal`;
- `gpt_enriched` versus `deterministic_enriched`;
- `qwen_enriched` versus `deterministic_enriched`.

Secondary metrics include Top-1, Top-2, Top-4, vulnerable-candidate rank distribution, ranking stability, malformed-output rate, provider/runtime failures, latency, token usage and cost availability. Negative-only scenarios have no vulnerable-candidate rank, Top-1, Top-k, reciprocal-rank or MRR denominator.

Inference must use scenario-level paired bootstrap confidence intervals and paired permutation tests where methodologically valid. Holm correction applies across the four primary paired MRR comparisons. Ordinary overlap between descriptive confidence intervals must not be treated as a formal paired hypothesis test.

Cost may be reported only where provider artifacts expose cost directly or where a frozen numeric pricing basis is recorded before execution; otherwise monetary cost remains `not_available`.

## Ground-Truth Boundary

Separated ground truth is retained only for post-run scoring under `results/owasp-xss-v14-1-protocol-freeze/ground-truth/`. Ground truth must not be loaded during candidate ranking, model prompting, deterministic ranking, or runtime execution. Post-run scoring may combine completed ranking artifacts with the separated ground-truth data only after raw execution closes.

## Interpretive Categories

Before execution, the following interpretation boundaries are frozen:

- if enriched LLM arms improve over their minimal counterparts and over deterministic enriched ranking, the result supports the interpretation that additional safe context enables useful LLM-specific prioritization on this benchmark;
- if enriched LLM arms improve over their minimal counterparts but not over deterministic enriched ranking, the result suggests the additional context is useful while incremental LLM value remains limited;
- if enriched arms do not materially improve over minimal arms, the result supports the conclusion that richer safe context does not materially strengthen bounded LLM ranking under this design;
- if GPT and Qwen differ, the result indicates that different model families respond differently to enrichment under the same restricted contract.

These categories are benchmark- and protocol-scoped. They do not authorize broad claims of model superiority or autonomous security-testing capability.

## Validation Requirements

Before any scored execution, validation must confirm:

- v1.4 source protocol checksums valid;
- corrected observation package checksums valid;
- 266 scenarios, 236 positive scenarios and 30 negative-only scenarios;
- exactly 5 candidates per scenario;
- candidate-test budget 4 and top-k 4;
- minimal and enriched snapshots preserve identical candidate IDs and ordering;
- model-facing snapshots contain no ground truth or benchmark identity leakage;
- expected denominators exactly 532 deterministic rows, 2660 GPT rows, 2660 Qwen rows and 5852 total ranking rows;
- no HTTP benchmark requests, GPT calls, Qwen calls, local inference, browser verification or scored ranking rows were executed during protocol preparation.
