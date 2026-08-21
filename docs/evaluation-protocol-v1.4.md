# Evaluation Protocol v1.4

Status: **frozen pre-execution protocol**.

This protocol freezes the final preparation state for the `v1.4 OWASP
Benchmark XSS External Validation` study. It does not run or authorize the
scored experiment. Any later methodological change to scenarios, snapshots,
candidate representation, prompts, parsers, models, budgets, verifier rules,
metrics or scoring requires a separately versioned protocol amendment.

This protocol is separate from `evaluation-protocol-v1.3.1` and does not
modify the frozen v1.3.1 XSS ablation evidence.

## Provenance

Benchmark source:

- official remote: `https://github.com/OWASP-Benchmark/BenchmarkJava`;
- local ignored checkout: `.external/owasp-benchmark-java`;
- declared benchmark version: `1.2`;
- pinned Git revision: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f`;
- expected-results file: `expectedresults-1.2.csv`;
- expected-results SHA-256:
  `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`.

The deterministic compatibility audit identified 455 XSS-labelled cases: 246
vulnerable and 209 non-vulnerable. After deterministic adapters, 408 original
cases are compatible and 47 are excluded. The completed non-scored readiness
phase reserved 20 compatible cases as `READINESS_ONLY` and passed across all 20
cases. Those readiness cases are excluded from this final confirmatory corpus.

The final confirmatory corpus contains only cases with
`evaluation_role = FINAL_CONFIRMATORY_ELIGIBLE`:

- 388 original OWASP XSS cases;
- 236 vulnerable cases;
- 152 non-vulnerable cases;
- zero `READINESS_ONLY` cases;
- zero `EXCLUDED` cases.

## Study Layers

The v1.4 evaluation line distinguishes three layers.

First, the already completed readiness layer validated deterministic
compatibility over 20 `READINESS_ONLY` cases. It did not run GPT, Qwen or final
ranking.

Second, the core confirmatory ranking experiment evaluates candidate
prioritization over multi-candidate snapshots constructed only from
`FINAL_CONFIRMATORY_ELIGIBLE` cases.

Third, direct deterministic execution/verifier validation over original OWASP
cases is a separate external execution layer. It must not be conflated with
ranking scenario counts and is not executed by this protocol-freeze milestone.

## Candidate-Pack Construction

The core confirmatory ranking experiment uses:

- pack size: 5 candidates;
- candidate-test budget: `k = 4`;
- `top_k = min(candidate_test_budget, candidate_count)`;
- one focal vulnerable candidate per positive scenario;
- four negative decoys per positive scenario;
- disjoint negative-only packs where possible.

All 236 final-eligible vulnerable cases serve exactly once as the focal case of
one positive ranking scenario. Negative candidates are assigned as decoys by a
deterministic balanced round-robin algorithm over a SHA-256-sorted negative
pool using seed `owasp-xss-v14-final-scenario-assignment-v1`.

The 152 final-eligible non-vulnerable cases are also used to form 30 disjoint
negative-only packs of five candidates. The remaining two non-vulnerable cases
are recorded as unused for negative-only packs rather than used to create a
partial extra scenario.

Candidate order within each pack is determined by SHA-256 over
`owasp-xss-v14-final-candidate-order-v1`, the neutral scenario ID and candidate
ID. This gives a reproducible order without sorting candidates by vulnerability
status or original OWASP identity.

The final core scenario denominators are:

| Unit | Count |
| --- | ---: |
| Positive ranking scenarios | 236 |
| Negative-only ranking scenarios | 30 |
| Total core ranking scenarios | 266 |

## Ranking Inputs

All ranking arms receive the same sanitized candidate snapshot for a scenario.
The model-facing snapshot contains only:

- opaque candidate ID;
- sanitized action path;
- method;
- sanitized parameter/input name;
- structural input source;
- input type;
- editable input count;
- required input count;
- parameter count.

Model-facing snapshots must not contain expected results, vulnerability labels,
original `BenchmarkTest` IDs, Java source paths, original endpoints, original
input names, explicit OWASP XSS identity, hidden provenance mappings or ground
truth.

Execution specifications, internal provenance and ground-truth scoring data are
stored separately. Ground truth may be loaded only after scored execution is
complete.

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

## Trial Schedule

The frozen execution order is:

1. `deterministic_structural`;
2. `proprietary_gpt`;
3. `local_qwen`.

Within each arm, scenarios are executed in ascending neutral scenario-ID order.
LLM trials are executed in trial-number order from 1 to 5. The schedule seed is
`owasp-xss-v14-final-trial-schedule-v1`.

Expected ranking denominators:

| Arm | Rows |
| --- | ---: |
| `deterministic_structural` | 266 |
| `proprietary_gpt` | 1330 |
| `local_qwen` | 1330 |
| Total | 2926 |

Repeated LLM trials are nested under scenario and arm. They are not independent
benchmark scenarios.

If execution is interrupted, it may resume only from the next scheduled row
whose artifact is absent. Existing scored artifacts must not be silently
regenerated. Any methodological correction after partial results requires a
versioned amendment.

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
retry count and contract-valid output rate. Latency is recorded where
available.

Invalid structured outputs, duplicate IDs, unknown IDs, omitted IDs, malformed
JSON, provider failures, runtime failures and timeouts are retained in
reliability denominators. They are excluded from valid ranking-performance
aggregates and must not be silently repaired.

Undefined metric values use `not_applicable` when the metric does not apply and
`not_available` when the metric applies but the required measurement is absent.

## Protocol-Critical Artifacts

The pre-execution package is:

`results/owasp-xss-v14-protocol-freeze/`

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
- metric/scoring specification;
- preflight validation report;
- checksum manifest;
- human-readable report and thesis table templates.

These artifacts are protocol-critical. Once frozen, they must not be silently
regenerated differently.

## Validation Requirements

Before any scored v1.4 execution, deterministic preflight validation must
confirm:

- 388 final eligible cases;
- 236 final eligible vulnerable cases;
- 152 final eligible non-vulnerable cases;
- zero readiness-only cases in the final corpus;
- zero excluded cases in the final corpus;
- 266 core ranking scenarios;
- 236 positive scenarios;
- 30 negative-only scenarios;
- pack size exactly 5;
- candidate-test budget exactly 4;
- all 236 vulnerable cases appear exactly once as focal positive cases;
- no ground truth or original benchmark identity in model-facing snapshots;
- deterministic decoy assignment and candidate ordering;
- expected trial denominators exactly 266, 1330, 1330 and 2926;
- protocol-critical checksums valid;
- no final case execution;
- no GPT call;
- no Qwen call.

Only after these checks pass may the final v1.4 confirmatory execution be
authorized explicitly.
