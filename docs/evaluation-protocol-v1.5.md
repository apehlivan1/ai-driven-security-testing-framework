# Evaluation Protocol v1.5

Status: **frozen pre-execution protocol**.

This protocol freezes the final preparation state for the `v1.5 OWASP
Benchmark SQL Injection External Validation` study. It does not run or
authorize the scored experiment. Any later methodological change to the final
corpus, scenario construction, candidate snapshots, candidate representation,
prompts, parsers, models, budgets, verifier rules, metrics, scheduling or
scoring requires a separately versioned protocol amendment.

This protocol is separate from `evaluation-protocol-v1.4` and does not modify
the frozen v1.4 XSS evidence.

## Provenance

Benchmark source:

- official remote: `https://github.com/OWASP-Benchmark/BenchmarkJava`;
- local ignored checkout: `.external/owasp-benchmark-java`;
- declared benchmark version: `1.2`;
- pinned Git revision: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f`;
- expected-results file: `expectedresults-1.2.csv`;
- expected-results SHA-256:
  `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`.

The deterministic compatibility audit identified 504 SQL-injection-labelled
cases: 272 vulnerable and 232 non-vulnerable. Static compatibility
classification produced 220 adapter-supported cases, 127 excluded cases and
157 unresolved manual-review cases. No direct cases and no derived/adapted cases
are used in this protocol.

The completed non-scored readiness phase reserved 20 adapter-supported cases as
`READINESS_ONLY`: 10 vulnerable and 10 non-vulnerable, covering the five
deterministic adapter classes used by the readiness implementation. The
readiness phase executed those 20 cases only. It confirmed stable baseline
execution for 20 out of 20 readiness cases, reproducible boolean true/false
differences for 6 out of 20 cases, verifier-confirmed findings for 6 out of 20
cases, inconclusive outcomes for 14 out of 20 cases and zero server errors. It
performed zero final-confirmatory case executions, zero GPT calls and zero Qwen
calls.

The readiness result is interpreted narrowly. It establishes that the
deterministic transports, adapters, evidence path and verifier lifecycle can run
without infrastructure failure on a stratified readiness subset. It does not
show that all final-eligible cases will be verifier-confirmable. The 14
inconclusive readiness outcomes are preserved as a methodological observation,
and the boolean verifier criteria must not be weakened to increase confirmation
rate.

The final confirmatory corpus contains only cases with
`evaluation_role = FINAL_CONFIRMATORY_ELIGIBLE`:

- 200 original OWASP SQLi cases;
- 105 vulnerable cases;
- 95 non-vulnerable cases;
- zero `READINESS_ONLY` cases;
- zero excluded cases.

The 20 `READINESS_ONLY` cases remain permanently outside final confirmatory
denominators. The unresolved manual-review cases remain excluded unless a later
separately justified protocol amendment changes their role before execution.

## Study Layers

The v1.5 evaluation line distinguishes three layers.

First, the already completed readiness layer validated deterministic
compatibility over 20 `READINESS_ONLY` cases. It did not run GPT, Qwen or final
ranking, and it did not execute any final-confirmatory case.

Second, the core confirmatory ranking experiment evaluates candidate
prioritization over multi-candidate SQLi snapshots constructed only from
`FINAL_CONFIRMATORY_ELIGIBLE` cases. This layer measures whether the
deterministic, hosted GPT and local Qwen ranking arms prioritize
OWASP-labelled vulnerable SQLi candidates under a fixed budget.

Third, direct deterministic execution/verifier validation over the same 200
original OWASP final-eligible cases is a separate external execution layer. This
layer measures how often the existing non-destructive boolean SQLi execution
and verifier design can produce stable and confirmatory evidence on previously
untouched external OWASP cases. It must not be conflated with ranking scenario
counts.

The protocol therefore keeps OWASP vulnerability ground truth, ranking
correctness, runtime testability and deterministic verifier confirmation as
separate concepts.

## Candidate-Pack Construction

The core confirmatory ranking experiment uses:

- pack size: 5 candidates;
- candidate-test budget: `k = 4`;
- `top_k = min(candidate_test_budget, candidate_count)`;
- one focal vulnerable candidate per positive scenario;
- four non-vulnerable decoys per positive scenario;
- disjoint negative-only packs where possible.

All 105 final-eligible vulnerable cases serve exactly once as the focal case of
one positive ranking scenario. The 95 final-eligible non-vulnerable cases are
also used to form 19 disjoint negative-only packs of five candidates. There are
no leftover negative candidates after complete negative-only packing.

Negative decoys for positive scenarios are assigned by a deterministic balanced
round-robin algorithm over a SHA-256-sorted negative pool using seed
`owasp-sqli-v15-final-scenario-assignment-v1`. This produces 420 positive
decoy assignments across 95 negative candidates: 55 negative candidates are
used four times as positive decoys and 40 negative candidates are used five
times as positive decoys.

Candidate order within each pack is determined by SHA-256 over
`owasp-sqli-v15-final-candidate-order-v1`, the neutral scenario ID and
candidate ID. This gives reproducible order without sorting candidates by
vulnerability status or original OWASP identity.

The final core scenario denominators are:

| Unit | Count |
| --- | ---: |
| Positive ranking scenarios | 105 |
| Negative-only ranking scenarios | 19 |
| Total core ranking scenarios | 124 |

## Ranking Inputs

All ranking arms receive the same sanitized candidate snapshot for a scenario.
The SQLi ranker-facing snapshot contains only:

- opaque candidate ID;
- sanitized action path;
- HTTP method;
- input carrier;
- input-count category;
- editable-input count;
- multiple-parameter indicator;
- deterministic transport-adapter category;
- sanitized request shape.

Model-facing snapshots must not contain original `BenchmarkTest` IDs, Java
source paths, original endpoints, expected results, vulnerability labels, SQL
statements, SQL operation categories, probe values, sink details, verifier
outcomes, response-oracle results, hidden provenance mappings or ground truth.

Execution specifications, internal provenance and ground-truth scoring data are
stored separately. Ground truth may be loaded only after scored ranking and
direct execution are complete.

## Ranking Arms

The frozen arms are:

| Arm | Trials per scenario | Role |
| --- | ---: | --- |
| `deterministic_structural` | 1 | deterministic structural ranking baseline |
| `proprietary_gpt` | 5 | hosted GPT ranking through the restricted candidate-ranking contract |
| `local_qwen` | 5 | local Qwen open-weights ranking through the same contract |

The deterministic baseline uses `deterministic-structural-v1` over the same
sanitized candidate inputs as the LLM arms.

The hosted GPT arm uses:

- provider: OpenAI;
- model identifier: `gpt-5.6-luna`;
- prompt version: `llm-candidate-ranking-v1`;
- parser: `adstf.llm_ranking.parse_model_ranking`;
- temperature parameter: omitted;
- provider default temperature: used;
- `OPENAI_SEND_TEMPERATURE`: unset or false;
- timeout: 60 seconds;
- maximum output tokens: 1200;
- structured output: candidate-ranking JSON schema;
- retry policy: no silent retries.

The local Qwen arm uses:

- model: `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M`;
- selected local candidate ID: `qwen2_5_7b_instruct_gguf_q4_k_m`;
- runtime: local `llama.cpp` through `llama-completion.exe`;
- runtime executable SHA-256:
  `2272eaaf8bb9477257790835d7b25aaf8fd22941e44ac3fcc9f2df389d1ef7b4`;
- model file hashes:
  - `qwen2.5-7b-instruct-q4_k_m-00001-of-00002.gguf`:
    `dfce12e3862a5283ccfb88221b48480e58745165de856439950d0f22590580db`;
  - `qwen2.5-7b-instruct-q4_k_m-00002-of-00002.gguf`:
    `539cf93f78e887edea1c04e2d7d8cdaca9d01dae9c9025bcb8accbe29df3d72a`;
- prompt version: `llm-candidate-ranking-v1`;
- parser: `llama-completion-transport-parser-v1.3` followed by
  `adstf.llm_ranking.parse_model_ranking`;
- context size: 4096 tokens;
- maximum output tokens: 768;
- temperature: 0.0;
- top-p: 1.0;
- seed: 42;
- threads: 8;
- timeout: 300 seconds;
- retry policy: no silent retries.

Gemma remains a contingency model only. It may not silently replace failed,
invalid or timed-out Qwen trials. Gemma activation requires a documented
pre-execution technical failure, a versioned protocol amendment and a complete
rerun of the affected local-model experiment.

The LLM authority boundary is unchanged: the LLM may only order supplied
candidate IDs and provide bounded rationales. It may not construct SQL probes,
requests, headers, cookies, parameters, evidence or verifier decisions.

## Trial Schedule

The frozen execution order is:

1. `deterministic_structural`;
2. `proprietary_gpt`;
3. `local_qwen`.

Within each arm, scenarios are executed in ascending neutral scenario-ID order.
LLM trials are executed in trial-number order from 1 to 5. The schedule seed is
`owasp-sqli-v15-final-trial-schedule-v1`.

Expected ranking denominators:

| Arm | Rows |
| --- | ---: |
| `deterministic_structural` | 124 |
| `proprietary_gpt` | 620 |
| `local_qwen` | 620 |
| Total | 1364 |

Repeated LLM trials are nested under scenario and arm. They are not independent
benchmark scenarios.

If execution is interrupted, it may resume only from the next scheduled row
whose artifact is absent. Existing scored artifacts must not be silently
regenerated. Any methodological correction after partial results requires a
versioned amendment.

## Direct Execution and Verifier Schedule

The direct deterministic SQLi execution/verifier layer uses all 200
`FINAL_CONFIRMATORY_ELIGIBLE` cases as the predeclared denominator.

Each scheduled case has six deterministic request phases:

- `baseline_1`;
- `baseline_2`;
- `true_1`;
- `true_2`;
- `false_1`;
- `false_2`.

The expected direct-execution request count, if explicitly authorized later, is
1200 HTTP requests. Ground truth remains unavailable to deterministic request
construction and runtime verifier decisions. OWASP expected results are loaded
only after direct execution and verifier decisions are complete.

The direct execution/verifier outcome categories are:

- baseline stable;
- baseline unstable;
- true/false difference reproducible;
- no reproducible difference;
- verified;
- rejected;
- inconclusive;
- runtime error.

Inconclusive is a legitimate experimental outcome and remains in the
denominator. A case must not be removed post hoc because its final execution is
inconclusive, and the boolean verifier must not be relaxed after observing final
results.

## Metrics and Failure Handling

Positive-scenario ranking metrics:

- vulnerable candidate rank;
- Top-1 success;
- Top-k success at `k = 4`;
- reciprocal rank and MRR;
- candidate coverage under the fixed execution budget.

Negative-only scenarios do not have vulnerable-candidate rank, Top-1, Top-k,
reciprocal-rank or MRR denominators. They are used for contract validity,
reliability and downstream no-finding behavior where execution is later
authorized.

Reliability metrics include scheduled calls, attempted calls, valid structured
outputs, malformed outputs, provider failures, runtime failures, timeouts,
retry count, contract-valid output rate and latency.

Invalid structured outputs, duplicate IDs, unknown IDs, omitted IDs, malformed
JSON, provider failures, runtime failures and timeouts are retained in
reliability denominators. They are excluded from valid ranking-performance
aggregates and must not be silently repaired.

Undefined metric values use `not_applicable` when the metric does not apply and
`not_available` when the metric applies but the required measurement is absent.

## Protocol-Critical Artifacts

The pre-execution package is:

`results/owasp-sqli-v15-protocol-freeze/`

It contains:

- final corpus manifest;
- final scenario manifest;
- sanitized candidate snapshots;
- candidate-snapshot index;
- decoy-assignment manifest;
- candidate-ordering table;
- internal provenance mapping;
- execution specifications;
- separated ground-truth scoring data;
- arm configurations;
- trial schedule;
- direct-execution schedule;
- metric/scoring specification;
- preflight validation report;
- checksum manifest;
- human-readable report and thesis table templates.

These artifacts are protocol-critical. Once frozen, they must not be silently
regenerated differently.

## Validation Requirements

Before any scored v1.5 execution, deterministic preflight validation must
confirm:

- 200 final eligible cases;
- 105 final eligible vulnerable cases;
- 95 final eligible non-vulnerable cases;
- zero readiness-only cases in the final corpus;
- zero excluded cases in the final corpus;
- 124 core ranking scenarios;
- 105 positive scenarios;
- 19 negative-only scenarios;
- pack size exactly 5;
- candidate-test budget exactly 4;
- all 105 vulnerable cases appear exactly once as focal positive cases;
- no ground truth or original benchmark identity in model-facing snapshots;
- deterministic decoy assignment and candidate ordering;
- expected trial denominators exactly 124, 620, 620 and 1364;
- direct-execution denominator exactly 200 cases;
- protocol-critical checksums valid;
- no final SQLi case execution;
- no GPT call;
- no Qwen call.

Only after these checks pass may the final v1.5 confirmatory execution be
authorized explicitly.
