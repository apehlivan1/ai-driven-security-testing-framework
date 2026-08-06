# Evaluation Protocol v1.3

Status: **frozen executable protocol**.

This document defines the executable protocol for the v1.3 reflected-XSS
ranking ablation study. The authoritative frozen repository state is the commit
pointed to by the annotated Git tag `evaluation-protocol-v1.3`.

Any later methodological change requires a separately versioned protocol
revision. The frozen protocol must not be edited in place after the tag is
created.

## Relationship To v1.2

`evaluation-protocol-v1.2`, the v1.2 canonical result package and the v1.2
descriptive analysis remain frozen historical evidence. v1.3 must not modify,
overwrite or re-score those artifacts.

v1.3 is a separate extended reflected-XSS study whose purpose is to evaluate the
candidate-ranking boundary more carefully. It does not revise v1.2 results.

## Research Boundary

The central architectural contribution remains the auditable separation of:

- deterministic discovery;
- bounded ranking of existing candidates;
- deterministic safety approval;
- deterministic execution;
- evidence collection;
- deterministic verification;
- post-run ground-truth evaluation.

The LLM ranking arms may receive only structured discovered-candidate metadata.
They may return only an ordering of existing candidate IDs with brief rationales.
They must not generate payloads, execute actions, control the browser, verify
findings, access raw HTML, access credentials, access session values, access
source code or access semantic ground truth.

## Benchmark Scope

Benchmark:

- benchmark ID: `xss-v13-expanded-reflected-input`;
- manifest version: `xss-v13-manifest-v1`;
- target configuration: `examples/targets/xss-v13-local.json`;
- scenario manifest: `examples/benchmarks/xss-v13-manifest.json`;
- semantic ground truth: `examples/benchmarks/xss-v13-ground-truth.json`;
- candidate snapshot version: `xss-v13-candidate-snapshot-v1`.

Protocol-critical artifact hashes recorded before tagging:

| Artifact | SHA-256 |
| --- | --- |
| `examples/benchmarks/xss-v13-manifest.json` | `afc598b4e8abf050b6fa8ef49998950ea7c3ccde1029d3155b92aa3a6758365b` |
| `examples/targets/xss-v13-local.json` | `f48ab88eead31af322f8edf7af0e4bf17f67a4475e3450bebeb0f80aeaafbe82` |
| `docs/metrics-definition-v1.3.md` | `b089cceb5eddb5400c4eb9d6661226873222d1c372e9230345c7709fb8e411ca` |
| `src/adstf/llm_ranking.py` | `7f39e73faf024eec0c7bf03e995e63572ad4ccc9c8f895f44bd6ae9a1de89e25` |
| `src/adstf/openai_ranking_wrapper.py` | `78db929df3ab691cbaa36fdae5a799c68e3dc8f6850b8e1edc0fe4b9f7a3f0df` |
| `src/adstf/local_runtime.py` | `f663557b94396bc22b7931a40f3981e2c91effb283fa92f91ec571e201210986` |
| `src/adstf/local_runtime_output_boundary.py` | `d875c00ecea5629d488582343976e0c25c7a85ca95e3297d1382fe4a1ace865c` |
| `results/local-runtime-output-boundary-v1.3/transport-settings.json` | `36c8dfa71b26b655226abec9dbf1a8188f5f915e4accbea672a7e0f86afacfa7` |
| `results/local-runtime-provisioning-v1.3/model-metadata/qwen2_5_7b_instruct_gguf_q4_k_m.json` | `6c9d90954bf1ceb5933c002fa306dd2455a83e74c642675d463a36f4bb075b6e` |
| `results/local-model-calibration-bakeoff-v1.3/selection-decision.json` | `c049479d0ea5a375661d91eb28713c448e82bba9403e985a2f85c078674b5a5c` |

The v1.3 XSS benchmark contains exactly 24 independent scenarios:

- 16 intentionally vulnerable scenarios;
- 8 negative/control scenarios;
- 4-8 discoverable candidates per scenario.

Semantic ground truth must remain inaccessible to discovery, ranking, safety,
execution and verification. It may be loaded only after execution is complete
for post-run scoring.

## Candidate Snapshots

Before scored execution, one immutable candidate snapshot is generated for each
of the 24 scenarios. Each snapshot is produced from the existing deterministic
reflected-input discovery output over the configured seed pages.

Each snapshot contains only the `llm-candidate-ranking-v1` structured candidate
input schema:

- `candidate_id`;
- `action_path`;
- `method`;
- `parameter_name`;
- `source`;
- `input_type`;
- `editable_input_count`;
- `required_input_count`;
- `parameter_count`.

Snapshots must not contain:

- vulnerability labels;
- expected outcomes;
- semantic case definitions;
- ground-truth paths;
- raw HTML;
- browser state;
- credentials;
- session values;
- API keys;
- local model paths;
- unrelated workspace content.

Every ranking arm must consume the same per-scenario snapshot by SHA-256
reference. Candidate IDs, candidate ordering and candidate metadata must be
identical across arms.

## Ranking Arms

The v1.3 XSS ablation compares exactly three ranking arms.

| Arm | Type | Trials per scenario | Authority |
| --- | --- | ---: | --- |
| `deterministic_structural` | deterministic | 1 | deterministic structural ranking only |
| `proprietary_gpt` | hosted LLM | 5 | ordering of existing candidate IDs only |
| `local_qwen` | local open-weights LLM | 5 | ordering of existing candidate IDs only |

The deterministic arm uses:

- ranking ruleset: `deterministic-structural-v1`.

The proprietary GPT arm uses:

- provider: OpenAI;
- model identifier: `gpt-5.6-luna`;
- command-client wrapper: `python -m adstf.openai_ranking_wrapper`;
- prompt version: `llm-candidate-ranking-v1`;
- parser: `adstf.llm_ranking.parse_model_ranking`;
- structured output: Responses API JSON schema;
- `OPENAI_RANKING_MODEL=gpt-5.6-luna`;
- `OPENAI_SEND_TEMPERATURE` must be unset, empty, `0`, `false` or `no`;
- temperature parameter: omitted;
- provider/model default temperature: used;
- maximum output tokens: 1200;
- timeout: 60 seconds per call.

The local Qwen arm uses:

- provider: local llama.cpp;
- primary model: `qwen2_5_7b_instruct_gguf_q4_k_m`;
- model identifier: `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M`;
- quantization: `Q4_K_M`;
- runtime: llama.cpp release `b9637`, Windows CPU x64 build;
- transport: `llama-completion` stdout/stderr boundary;
- transport parser: `llama-completion-transport-parser-v1.3`;
- prompt version: `llm-candidate-ranking-v1`;
- constrained output: `--json-schema-file`;
- context size: 4096 tokens;
- maximum output tokens: 768;
- temperature: 0.0;
- top-p: 1.0;
- seed: 42;
- threads: 8;
- timeout: 300 seconds per call.

The complete four-model calibration bake-off remains preserved. The selected
primary model for the final local arm is Qwen2.5 7B Instruct GGUF Q4_K_M. Gemma
3 4B IT GGUF Q4_K_M is a contingency model only under the fallback rule below.

## Candidate-Test Budget And Top-k

The candidate-test budget is read from the v1.3 manifest. The current frozen
candidate-test budget is:

- `test_budget = 4` for every v1.3 XSS scenario.

Top-k is defined as:

```text
top_k = min(test_budget, discovered_candidate_count)
```

With the current manifest, this means `top_k = 4` for every scenario.

Ranking metrics are computed from candidate order before post-run ground-truth
classification. Browser execution and verifier-confirmed findings must use the
same candidate-test budget for all arms.

## Failure Handling

Malformed output, duplicate candidate IDs, unknown candidate IDs, omitted
candidate IDs, provider failures and timeouts must be recorded explicitly.

Invalid or failed model trials:

- are retained in raw artifacts;
- are excluded from valid LLM ranking-performance aggregates;
- must not be silently repaired;
- must not be replaced by deterministic rankings in a way that improves LLM
  metrics.

If deterministic fallback is used only to continue a safe workflow after an LLM
failure, that fallback must be reported separately and must not count as a valid
LLM ranking trial.

No silent retry is permitted for scored trials. A retry is allowed only for a
predeclared infrastructure interruption rule, and both the original attempt and
retry must remain in artifacts.

## Local Fallback Rule

Qwen is the only scored local-model arm.

Gemma must never silently replace an invalid, malformed, failed or timed-out
Qwen trial.

Gemma may be activated only for a documented pre-execution technical failure
that prevents Qwen from participating at all. Activation requires:

1. a protocol revision;
2. clear defect documentation;
3. complete rerun of the affected local-model experiment.

## Metrics

Metric definitions are inherited from `docs/metrics-definition-v1.3.md`.

The v1.3 XSS ablation must report:

- top-1 accuracy;
- top-k recall;
- MRR;
- vulnerable-candidate rank distribution;
- ranking stability across repeated LLM trials;
- selected-candidate distribution;
- candidates tested before first verifier-confirmed finding;
- requests to first verifier-confirmed finding;
- time to first verifier-confirmed finding;
- no-vulnerability false-positive behavior;
- provider latency;
- input, output and total tokens where available;
- provider cost availability;
- cost per ranking trial where a defensible cost source exists;
- cost per verified finding where a defensible cost source exists;
- malformed-output count and rate;
- timeout count and rate;
- provider-failure count and rate;
- total requested, approved, blocked, executed and failed actions.

Undefined values must use:

- `not_available` when the metric is meaningful but the artifact lacks the
  required data;
- `not_applicable` when the metric has no meaningful denominator for the arm or
  case.

Repeated LLM trials are not independent benchmark cases.

## Post-run Scoring

Semantic ground truth may be loaded only after all ranking, candidate testing,
browser execution, evidence collection and verifier decisions for the relevant
run have completed.

Post-run scoring must:

- use the frozen v1.3 ground-truth file only in the evaluation/scoring phase;
- classify verifier-confirmed findings against the ground truth;
- keep ranking metrics separate from verifier-confirmed findings;
- keep negative-scenario metrics separate where vulnerable-candidate ranking
  metrics are not applicable;
- exclude invalid, malformed, timed-out or provider-failed model trials from
  valid LLM ranking-performance aggregates while retaining them in artifact
  counts;
- count repeated LLM trials as model trials, not as independent benchmark
  cases.

## Reporting And Provenance

Every v1.3 XSS ablation package must contain:

- manifest;
- checksums;
- protocol and Git-tag provenance;
- candidate snapshots and snapshot ledger;
- arm input ledger;
- raw ranking artifacts;
- raw execution and verification artifacts where applicable;
- normalized JSON summaries;
- CSV case-level and trial-level tables;
- human-readable report;
- thesis-ready Markdown and LaTeX tables;
- figure source data for every generated figure.

Every included artifact must have a SHA-256 checksum.

Reports must clearly distinguish:

- discovered candidates;
- ranked candidates;
- tested vulnerability hypotheses;
- verifier-confirmed findings;
- model-output validation errors;
- post-run ground-truth classifications.

## Tuning Freeze

After `evaluation-protocol-v1.3` is frozen and tagged, the following must not be
changed based on results:

- scenario definitions;
- candidate snapshots;
- prompt text;
- prompt version;
- parser rules;
- deterministic ranking rules;
- model identifiers;
- local runtime settings;
- proprietary provider settings;
- payload strategy;
- verifier criteria;
- candidate-test budgets;
- top-k definition;
- metric definitions;
- failure-handling rules.

Any genuine integration defect requires a documented protocol revision and a
complete rerun of affected experiments.

## Protocol Revision Rule

The protocol is frozen at the annotated Git tag `evaluation-protocol-v1.3`.
After that tag is created, the following require a new protocol version rather
than an edit to this file:

- any scenario or candidate snapshot change;
- any prompt, parser, model, provider or runtime setting change;
- any payload, verifier, budget, top-k or metric-definition change;
- any fallback activation that replaces the Qwen local arm;
- any post-run scoring or reporting-rule change;
- any correction required by a genuine integration defect.
