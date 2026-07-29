# Extended Evaluation v1.3 Study Design

## Status

This document is a planning artifact for the next evaluation phase. It is not an executable frozen protocol and does not supersede `evaluation-protocol-v1.2`.

`evaluation-protocol-v1.2`, its canonical results package, and the derived descriptive analysis are frozen historical evidence. They must not be edited, reinterpreted in place, or overwritten by the extended study. Any v1.3 implementation, experiment execution, result package, and analysis must use new versioned files and new result directories.

The purpose of v1.3 is to strengthen the thesis evaluation without expanding the vulnerability scope beyond reflected XSS, read-only IDOR, and non-destructive boolean-based SQL injection.

## Central Research Contribution

The central contribution is the auditable architectural boundary that separates:

1. deterministic discovery of candidate attack-surface elements;
2. bounded candidate ranking by an LLM;
3. deterministic safety checks and action approval;
4. deterministic execution through approved tools;
5. evidence collection and artifact retention;
6. deterministic vulnerability verification;
7. post-run ground-truth evaluation.

The LLM is intentionally limited to ranking existing structured candidates and providing brief rationales. It must not generate payloads, execute actions, control browsers or HTTP clients, inspect source code, access ground truth, or decide finding status.

This boundary is stronger than a generic "LLM pentester" claim because every security-sensitive transition remains deterministic, reproducible, and auditable.

## Research Questions

**RQ1: Architecture and Safety Boundary**

Does the framework preserve a clear separation between candidate discovery, bounded LLM ranking, deterministic safety, evidence collection, deterministic verification, and post-run scoring across a larger benchmark?

**RQ2: XSS Candidate Ranking**

When all ranking arms receive the same discovered candidate data, does bounded LLM ranking improve reflected-XSS candidate prioritization compared with the frozen deterministic structural ranker?

**RQ3: Proprietary vs Local Ranking Models**

Can a local open-weights model be evaluated through the same candidate-ranking boundary as the proprietary model, while preserving reproducibility metadata and preventing expanded LLM authority?

**RQ4: Framework vs ZAP on Common Scope**

On the supported XSS and SQLi scope only, how do verifier-confirmed framework findings compare with ZAP passive and bounded ZAP active scanner alerts under common case definitions, budgets, and pre-frozen mappings?

**RQ5: Efficiency and Cost**

How many candidates, requests, seconds, tokens, and provider-cost units are required before the first verified finding, and how should unavailable values be reported without inventing data?

## What Must Remain Frozen from v1.2

The following are frozen historical evidence and must not be modified:

- `docs/evaluation-protocol-v1.2.md`;
- the annotated Git tag `evaluation-protocol-v1.2`;
- `results/heldout-evaluation-v1.2-canonical/`;
- `results/heldout-evaluation-v1.2-analysis/`;
- all v1.2 raw artifacts copied into the canonical package;
- v1.2 included/excluded result ledgers;
- v1.2 canonical TP/FP/FN/TN counts and analysis tables.

The v1.3 study may reuse implementation ideas and code paths, but it must write new manifests, target definitions, mapping versions, protocol hashes, run artifacts, canonical result packages, and analysis outputs.

## Study Phases

The work must remain separated into these phases:

1. **Study-design phase**: define scope, research questions, benchmark matrix, metrics, metadata requirements, and open decisions.
2. **Instrumentation implementation**: add only measurement and reporting support needed for time/request/cost metrics.
3. **Benchmark implementation**: add expanded XSS, IDOR, and SQLi cases without executing final experiments.
4. **Structural validation**: validate startup, reset, scope, manifest schema, mapping coverage, metadata schemas, and artifact schemas without semantic ground-truth scoring.
5. **Final protocol freezing**: create executable `evaluation-protocol-v1.3`, record hashes, freeze prompts, models, mappings, budgets, and metric definitions, then tag.
6. **Experiment execution**: run deterministic framework, proprietary LLM ranking, local open-weights ranking, ZAP passive, and ZAP active as defined by the frozen protocol.
7. **Canonical result packaging and analysis**: package raw and normalized artifacts, generate descriptive analysis, and preserve provenance.

No final v1.3 experiment should run before phase 5 is complete.

## XSS Ablation Study

### Scope

The XSS ablation study is the main evaluation expansion. It should use a minimum of 24 genuinely distinct independent scenarios. A stretch target of 30 scenarios is acceptable only if the extra scenarios add meaningful structural variation rather than near-duplicates.

The minimum target distribution is approximately:

- 24 independent scenarios;
- 16 vulnerable scenarios;
- 8 negative scenarios;
- 4 to 8 discovered candidates per scenario;
- 5 proprietary-model trials per scenario;
- 5 local-model trials per scenario;
- 1 deterministic ranking run per scenario.

This yields, at minimum:

- 24 deterministic ranking observations;
- 120 proprietary LLM ranking trials;
- 120 local-model ranking trials.

The repeated LLM trials measure model-output stability and ranking behavior under a frozen prompt and settings. They must not be described as 120 independent benchmark cases.

### Ranking Arms

All arms receive the same discovered candidate list for a scenario and use the same payloads, safety rules, executor, verifier, budgets, and post-run ground truth.

| Arm | Authority | Expected Output |
| --- | --- | --- |
| `deterministic-structural` | Deterministic ranking based on frozen structural features | Ordered list of candidate IDs |
| `proprietary-llm-ranking` | Frozen proprietary provider/model through the existing ranking boundary | Ordered list of existing candidate IDs plus rationales |
| `local-open-weights-ranking` | Frozen local model through the same command-client ranking boundary | Ordered list of existing candidate IDs plus rationales |

The two LLM arms must not return payloads, action requests, verification claims, exploit descriptions, or new candidate IDs.

### Proposed 24-Scenario Matrix

The route and parameter names below are placeholders for design only. Final names should remain neutral and must not reveal which candidate is vulnerable.

| ID | Expected Outcome | Candidates | Vulnerable Candidate Position Design | Structural Challenge | Purpose |
| --- | --- | ---: | --- | --- | --- |
| `x13-001` | vulnerable | 4 | structurally favored GET text input | one safe reflected distractor | Basic positive control with multiple candidates |
| `x13-002` | vulnerable | 5 | structurally unfavored query parameter | forms look more promising than query param | Tests whether ranker over-prefers forms |
| `x13-003` | vulnerable | 6 | second form on second seed page | first seed contains safe reflections | Multi-seed prioritization |
| `x13-004` | vulnerable | 6 | required-field form with vulnerable optional text field | required decoy looks dominant | Required-field decoy |
| `x13-005` | vulnerable | 7 | textarea candidate | several text input distractors | Input-type variation |
| `x13-006` | vulnerable | 8 | query parameter on neutral detail page | many editable form distractors | High candidate-count case |
| `x13-007` | vulnerable | 5 | structurally favored search input | safe reflected query parameter distractor | Checks favored structural signal |
| `x13-008` | vulnerable | 6 | unfavored candidate with generic parameter name | parameter names do not reveal intent | Neutral naming under ambiguity |
| `x13-009` | vulnerable | 4 | form action on second page | first page has only escaped reflections | Escaped-reflection distractor |
| `x13-010` | vulnerable | 7 | vulnerable candidate after two non-reflecting candidates | discovery includes non-reflecting inputs | Non-reflection decoys |
| `x13-011` | vulnerable | 6 | vulnerable query parameter requiring stable baseline | response shape similar to safe case | Evidence robustness |
| `x13-012` | vulnerable | 8 | structurally unfavored candidate among many safe reflections | simple structural ranking likely misleading | Adversarial structural case |
| `x13-013` | vulnerable | 5 | form with two editable fields where only one executes | companion field is escaped | Parameter-level distinction |
| `x13-014` | vulnerable | 6 | hidden behind seed page ordering | seed order puts safe page first | Seed-order robustness |
| `x13-015` | vulnerable | 7 | safe-looking route with vulnerable field | route name not security-revealing | Route-neutral positive |
| `x13-016` | vulnerable | 5 | vulnerable candidate appears after stable safe reflection | safe candidate has stronger generic features | Ranker adversarial positive |
| `x13-017` | negative | 4 | none | all reflections escaped | Escaped negative control |
| `x13-018` | negative | 5 | none | no submitted values are reflected | Non-reflection negative control |
| `x13-019` | negative | 6 | none | multiple safe reflections across two seed pages | Multi-seed negative |
| `x13-020` | negative | 7 | none | many candidates, all non-executing | High candidate-count negative |
| `x13-021` | negative | 5 | none | required fields and query params are decoys | Decoy-rich negative |
| `x13-022` | negative | 6 | none | response includes literal-like but escaped payload text | Reflection-is-not-execution control |
| `x13-023` | negative | 8 | none | structurally strong candidates are all safe | Adversarial negative |
| `x13-024` | negative | 4 | none | stable pages with no executable sink | Simple negative sanity case |

### Stretch Scenarios

Only add stretch scenarios if time permits and each adds a distinct structure:

| ID | Expected Outcome | Added Variation |
| --- | --- | --- |
| `x13-025` | vulnerable | candidate discovered from repeated query parameters |
| `x13-026` | vulnerable | vulnerable candidate appears only on later seed page with same parameter name as safe page |
| `x13-027` | vulnerable | safe and vulnerable candidates share route but differ by parameter |
| `x13-028` | negative | multiple parameters reflected in different escaped contexts |
| `x13-029` | negative | form submission changes layout but not executable behavior |
| `x13-030` | vulnerable | structurally least-favored candidate is the vulnerable one |

## XSS Metrics

The following metrics must be frozen before any v1.3 XSS execution:

- top-1 accuracy;
- top-k recall, where `k` is the frozen candidate test budget for the scenario;
- mean reciprocal rank;
- vulnerable-candidate rank;
- rank distribution of vulnerable candidates;
- selected-candidate distribution;
- ranking stability across repeated LLM trials;
- candidates tested before first verified finding;
- requests to first verified finding;
- time to first verified finding;
- no-vulnerability false-positive behavior;
- provider latency;
- token usage;
- malformed-output rate;
- timeout rate;
- provider-failure rate;
- estimated cost per trial where a defensible cost source exists;
- estimated cost per verified finding where a defensible cost source exists.

Undefined values must be reported as `not_available` or `not_applicable`, never as zero.

## Trial Counts and Failure Handling

Minimum trial counts:

- deterministic structural ranker: 1 run per scenario;
- proprietary LLM: 5 trials per scenario;
- local open-weights model: 5 trials per scenario.

For 24 scenarios this means 24 deterministic rankings, 120 proprietary LLM rankings, and 120 local-model rankings.

Malformed LLM output, duplicate IDs, unknown IDs, omitted IDs, provider failures, and timeouts must be recorded explicitly. Invalid or failed model outputs may use deterministic fallback only for safe continuation, but fallback-supported continuation must remain separate from valid LLM ranking metrics.

Inconclusive verifier outcomes must remain inconclusive in final scoring. They must not be silently converted to false positives or false negatives unless the v1.3 protocol defines a separate post-run classification rule before execution.

## Proprietary-Model Reproducibility

The proprietary provider may not expose all internal settings. The study must document exactly what is known and avoid claiming unsupported reproducibility.

Required metadata:

- provider name;
- exact returned model identifier;
- requested model identifier;
- prompt version;
- full prompt text;
- candidate input schema version;
- structured candidate input;
- request settings actually sent;
- settings explicitly omitted, such as temperature if omitted;
- provider response ID when available;
- provider status when available;
- usage fields returned by provider;
- cost fields returned by provider, or `not_available`;
- latency in milliseconds;
- execution timestamp;
- trial number;
- validation errors;
- raw response;
- parsed ranking.

If a model setting is not accepted by the provider or intentionally omitted, the report must state `omitted; provider/model default used`.

## Local Open-Weights Ranking Provider

The local provider must use the same `ModelClient`/command-client boundary as the proprietary provider. It may receive only the structured candidate-ranking request and may return only the same ranking JSON shape.

Required metadata:

- model family and exact model identifier;
- model file name or model repository identifier;
- SHA-256 hash or immutable digest of the model artifact where feasible;
- quantization format and bit depth;
- inference engine;
- inference engine version;
- prompt/template format;
- decoding settings;
- context size;
- maximum output tokens;
- device type and hardware description;
- operating system/runtime notes if relevant;
- execution timestamp;
- latency;
- raw response;
- parsed ranking;
- malformed-output and timeout status.

Open decisions before freezing v1.3:

- which local model to use;
- whether the machine can run the selected model with acceptable latency;
- which inference engine to use;
- whether model artifact hashing is feasible for the selected distribution;
- whether local execution should be CPU-only or GPU-accelerated;
- maximum local-model timeout per ranking call.

The local model must not be given source code, screenshots, browser state, raw HTML, credentials, API keys, session values, ground truth, or unrelated workspace content.

## IDOR Expansion Design

The IDOR expansion should be moderate: 8 total cases, with 4 vulnerable and 4 secure. This is enough to make the representative category less fragile without turning the thesis into an access-control benchmark project.

Proposed case families:

| Family | Count | Expected Outcome | Purpose |
| --- | ---: | --- | --- |
| Cross-user read allowed | 2 | vulnerable | Positive IDOR cases with explicit ownership evidence |
| Cross-user read denied | 2 | secure | Secure controls with same response shape where possible |
| Missing or invalid session | 1 | secure | Ensures auth failure is not mistaken for IDOR evidence |
| Nonexistent resource | 1 | secure | Ensures 404-style behavior does not become a finding |
| Same-owner read | 1 | secure/control | Establishes legitimate access baseline |
| Similar-resource decoy | 1 | vulnerable or secure, pre-frozen | Tests ownership/resource comparison robustness |

The exact 4/4 vulnerable-secure split must be finalized before protocol freeze.

IDOR should continue to require two isolated sessions, ownership evidence, own-read evidence, cross-user-read evidence, response comparison, credential redaction, and deterministic verifier classification.

## SQLi Expansion Design

The SQLi expansion should be moderate: 8 total cases, with 4 vulnerable and 4 secure. Keep the scope limited to non-destructive boolean-based SQL injection.

Proposed case families:

| Family | Count | Expected Outcome | Purpose |
| --- | ---: | --- | --- |
| Stable boolean true/false differential | 2 | vulnerable | Positive cases with reproducible semantic difference |
| Parameterized query secure control | 2 | secure | Controls that resist the same bounded payloads |
| Reflected payload but no SQLi | 1 | secure | Prevents reflected payload from counting as proof |
| Server error but no proof | 1 | secure | Prevents error-only confirmation |
| Same response-length decoy | 1 | secure | Prevents length-only confirmation |
| Alternate neutral parameter pattern | 1 | vulnerable | Adds structural variation without new SQLi technique |

SQLi verification must continue to require stable baseline behavior and reproducible true/false differences. It must not rely on server error, response length, or reflected payload alone.

## Fair ZAP Comparison Rules

ZAP comparisons must remain limited to supported common scope:

- reflected XSS;
- boolean-based SQLi.

IDOR remains unsupported for ZAP unless a future protocol explicitly defines a fair authenticated two-user ZAP setup. For this v1.3 study design, IDOR should remain unsupported and excluded from ZAP TP/FP/FN/TN calculations.

Passive and active ZAP baselines must remain separate:

- `zap_passive`: spider/passive alert workflow only;
- `zap_active`: bounded active scan with frozen policy and mappings.

Required ZAP fairness rules:

- freeze ZAP image and digest before execution;
- freeze passive and active mapping versions before execution;
- freeze active policy, enabled rules, thresholds, strengths, and time limits before execution;
- record raw alerts separately from normalized case-level results;
- retain unmatched alerts separately;
- do not proxy framework-crafted attack traffic through ZAP for baseline scoring;
- do not treat scanner alerts as verifier-confirmed framework findings;
- define supported and unsupported case denominators before execution;
- do not tune mappings after seeing scanner results.

## Efficiency Metrics

The v1.3 implementation should add measurement support before benchmark expansion is executed.

Required fields per case where applicable:

- start timestamp;
- candidate discovery completion timestamp;
- ranking start and completion timestamps;
- first action timestamp;
- first verifier decision timestamp;
- first verified finding timestamp;
- total actions requested;
- total actions approved;
- total actions blocked;
- total actions executed;
- total action failures;
- HTTP request count;
- browser navigation count;
- candidates tested before first verified finding;
- requests to first verified finding;
- time to first verified finding;
- verifier outcome;
- reason when not applicable.

Cost metrics:

- cost per ranking trial where provider cost is available;
- cost per verified finding where provider cost is available;
- `not_available` when provider cost is absent;
- `not_applicable` for deterministic arms with no model-provider cost.

## Milestone Dependency Table

| Milestone | Reuses | Smallest Necessary Additions | Dependencies | Research Risks | Success Criteria | Explicitly Deferred |
| --- | --- | --- | --- | --- | --- | --- |
| M2: Measurement instrumentation | action/result/evidence/verifier artifacts; LLM usage fields; ZAP timing fields | per-case timing/request counters; first-verification metrics; cost availability fields; consistency tests | current lifecycle and storage format | inconsistent request counting across HTTP/browser/ZAP; unavailable cost data | metrics generated without changing TP/FP/FN/TN; undefined values explicit | new benchmarks, model runs, ZAP reruns |
| M3: XSS benchmark expansion implementation | discovery, deterministic ranker, browser executor, XSS verifier | 24 scenario definitions; neutral routes/params; ground-truth entries; structural validation | M2 metrics schema | accidental benchmark leakage; duplicate scenario structures | 24 structurally distinct scenarios validate without ground truth loading | experiment execution, prompt changes |
| M4: Local open-weights provider | command-client boundary; ranking parser; artifact schema | one local command wrapper; metadata capture; fake/offline tests | local model and hardware choice | malformed outputs; high latency; model hash unavailable | local provider can produce valid/invalid artifacts under same schema | model authority expansion, tool calling |
| M5: Moderate IDOR/SQLi expansion | existing IDOR/SQLi modules and verifiers | 8 IDOR and 8 SQLi case definitions; manifest/ground-truth updates; structural validation | M2 metrics schema | overfitting cases; accidental category drift | 4 vulnerable and 4 secure cases per category are structurally validated | new vulnerability categories |
| M6: v1.3 executable protocol freeze | v1.3 study design; implemented metrics and benchmarks | protocol doc; hashes; model metadata; mapping versions; ZAP policy versions; annotated tag | M2-M5 complete | freezing too early; unresolved local-model metadata | all protocol-critical hashes recorded; no ground truth semantic execution | final experiments |
| M7: v1.3 execution and packaging | v1.2 packaging pattern; v1.3 protocol | run deterministic, proprietary LLM, local LLM, ZAP passive/active; package artifacts; descriptive analysis | frozen v1.3 tag | failed provider runs; scanner nondeterminism | canonical v1.3 package validates; analysis reproduces counts | thesis-level conclusions beyond descriptive evidence |

## Decisions Required Before Freezing v1.3

The executable v1.3 protocol cannot be frozen until these decisions are resolved:

- final XSS scenario count: 24 minimum or justified stretch to 30;
- exact candidate test budget for XSS scenarios;
- exact `top-k` definition;
- proprietary model identifier and provider wrapper settings;
- whether the proprietary prompt remains `llm-candidate-ranking-v1` or is versioned to a new prompt before execution;
- local open-weights model selection;
- local model inference engine and version;
- local model quantization and model artifact hash/digest strategy;
- available hardware and timeout budget for local model trials;
- number of repeated trials per model arm, currently proposed as 5;
- request-counting rules for HTTP executor, browser executor, and ZAP;
- whether ZAP active rules remain `40012` and `40018` or are versioned to a new frozen policy before execution;
- whether the v1.3 SQLi and IDOR expansions are included in the same protocol run as the XSS ablation or a later sub-study.

## Success Criteria

The v1.3 study design is successful when:

- the LLM authority boundary remains unchanged;
- the study design is separate from v1.2 protocol and results;
- at least 24 XSS scenarios are defined with clear structural variation;
- IDOR and SQLi expansion plans remain moderate and within existing categories;
- local-model metadata requirements are explicit before selecting a model;
- ZAP common-scope fairness rules are defined before mapping or execution;
- time/request/cost metrics are defined before instrumentation;
- unresolved decisions are listed before protocol freeze;
- the next implementation task is narrow and does not execute experiments.

## Exclusions

The v1.3 study must not add:

- new vulnerability categories;
- LLM payload generation;
- LLM action execution;
- LLM browser control;
- LLM verification of findings;
- source-code access for the LLM;
- ground-truth access for the LLM;
- prompt optimization after inspecting results;
- ZAP mapping changes after scanner execution;
- authenticated ZAP IDOR scoring unless a future protocol explicitly designs it;
- broad crawling or agent frameworks.

## Recommended Milestone 2 Task

The next narrow task should be:

Create v1.3 measurement instrumentation and reporting support only. Add per-case metrics for time to first verified finding, requests to first verified finding, candidates tested before first verification, provider latency, token/cost availability, malformed-output rate, timeout/failure counts, and not_available/not_applicable handling. Add offline tests proving these metrics are derived from stored action/result/verifier/model artifacts and do not change TP/FP/FN/TN classifications. Do not add benchmark cases, run experiments, change prompts, change verifier rules, or modify v1.2 artifacts.
