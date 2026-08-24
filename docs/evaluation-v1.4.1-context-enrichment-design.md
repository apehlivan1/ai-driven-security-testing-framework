# v1.4.1 XSS Context-Enrichment Ablation Design

Status: **design and feasibility package only**.

This document defines a proposed follow-up evaluation line for the OWASP
Benchmark XSS external-validation study. It does not modify
`evaluation-protocol-v1.4`, the v1.4 canonical result package, the v1.5.1 SQLi
evidence, or any frozen experimental artifact.

The v1.4.1 study is motivated by the final v1.4 finding that the three ranking
arms were evaluated on a large, frozen OWASP XSS corpus using only minimal
sanitized structural candidate metadata. The proposed follow-up asks whether a
strictly bounded increase in candidate context changes ranking behavior while
preserving the thesis authority boundary: models may rank existing candidate
IDs only; they must not generate payloads, construct requests, execute tests,
inspect source code, receive ground truth, or verify vulnerabilities.

## Relationship to v1.4

The v1.4 protocol and canonical results remain frozen historical evidence. The
v1.4.1 study must be treated as a separate explanatory ablation, not as a
replacement or tuning pass over v1.4.

The proposed study reuses these v1.4 constants unchanged:

- 388 final-confirmatory-eligible OWASP XSS cases;
- 236 positive ranking scenarios;
- 30 negative-only ranking scenarios;
- 266 total ranking scenarios;
- pack size of five candidates;
- candidate-test budget `k = 4`;
- `top_k = min(candidate_test_budget, discovered_candidate_count)`;
- deterministic scenario construction, decoy assignment and candidate order;
- existing candidate IDs, scenario IDs and scenario membership;
- ground-truth separation and post-run scoring boundary;
- three ranking families: deterministic structural, hosted GPT and local Qwen.

The v1.4.1 study would add only a second candidate-representation condition:
minimal v1.4 metadata versus enriched context metadata. This creates a
within-scenario comparison over identical scenario packs and budgets.

## Research Question

The proposed v1.4.1 research question is:

> When the same frozen OWASP XSS candidate packs are ranked under the same
> testing budget, does adding deterministic, benignly observed input/reflection
> context change candidate-ranking effectiveness relative to the minimal
> structural representation used in v1.4?

This question is intentionally narrower than a claim that any model is generally
better than another model or better than a scanner. It targets the information
available to the bounded ranking component.

## Proposed Feature Categories

The enriched representation may include only features that are observable
without exploit payloads, benchmark labels, source code, verifier outcomes or
ground truth. The feature set should be frozen before any v1.4.1 scored
ranking run.

### Existing Minimal Fields

The v1.4 snapshots already contain:

- opaque candidate ID;
- method;
- structural source category;
- input type;
- editable input count;
- required input count;
- parameter count;
- sanitized action path;
- sanitized parameter name.

For v1.4.1, the action path and parameter name require additional caution. The
existing v1.4 values are sanitized relative to original OWASP identifiers, but
they still contain numeric case-derived tokens such as `case-000348` and
`input_000348`. These values should not be forwarded directly into enriched
ranker-facing snapshots. The enriched schema should retain candidate IDs as the
only stable identifiers and should replace raw path/name strings with
categorical transport and carrier fields.

### Safe Enrichment Candidates

The following feature families are methodologically feasible:

- input carrier category, such as query parameter, header, query-string or
  dynamic parameter-name transport;
- input type category, such as text-like input or header value;
- arity and form/request-shape fields, such as parameter count, required input
  count and whether the candidate requires an auxiliary value;
- benign marker reflection presence;
- benign marker reflection count, capped to avoid exposing raw response detail;
- reflection context category, such as HTML text, HTML attribute, script-like
  context, URL-like context, other reflected context or no reflection;
- marker preservation category, such as unchanged, encoded, transformed,
  stripped or not reflected;
- response content-type category, if observable from the response metadata.

The following fields should be deferred unless they are demonstrably available
from existing discovery artifacts without source inspection or ground-truth
inference:

- HTML form `maxlength`, pattern or client-side validation constraints;
- complete raw HTML snippets;
- Java source identifiers, servlet names or original OWASP `BenchmarkTest`
  identifiers;
- full endpoint paths or full parameter names when they contain case-derived
  numeric identity;
- any field derived from payload execution, verifier outcome or post-run
  ground-truth scoring.

## Benign Marker Collection Design

Context enrichment should be collected by deterministic framework code before
ranking and before ground truth is loaded. It should use one fixed, non-
executing marker per unique candidate. The marker must be alphanumeric or
otherwise inert, contain no script syntax, no angle brackets, no quotes and no
control characters. Its only purpose is to observe whether a candidate value is
reflected and how it is transformed.

The collector should use the existing local OWASP Benchmark target and existing
safety scope controls. It should construct requests from the existing execution
specifications, not from model output. Each final-eligible unique candidate
should be probed at most once for context enrichment, and the resulting
candidate-level observation should be reused by every scenario in which that
candidate appears.

The ranker-facing enriched snapshot must contain only normalized context
features. Raw responses, headers and any parsing diagnostics should be retained
as internal evidence artifacts with checksums, but they must not be transmitted
to GPT or Qwen.

## Leakage-Risk Controls

The v1.4.1 implementation should include explicit leak checks before protocol
freeze. Ranker-facing enriched snapshots must not contain:

- OWASP expected-result labels;
- strings such as `vulnerable`, `non_vulnerable`, `ground_truth` or
  `expected_result`;
- original `BenchmarkTest` identifiers;
- Java source filenames or source paths;
- original servlet endpoint names;
- verifier outcomes or browser execution markers;
- payloads used for vulnerability verification;
- raw HTML or raw HTTP body excerpts;
- complete unsanitized URLs;
- full parameter names or action paths if they encode case identity.

Reflection features are allowed only because they are obtained by a benign,
predeclared runtime observation that is available without ground truth. They
should be interpreted as part of the enriched-information treatment rather than
as a hidden label.

## Proposed Arms

The proposed v1.4.1 ablation contains six arms:

| Arm | Candidate representation | Ranking method | Trials per scenario |
| --- | --- | --- | ---: |
| `deterministic_minimal` | v1.4 minimal snapshot | deterministic structural ranking | 1 |
| `gpt_minimal` | v1.4 minimal snapshot | hosted GPT ranking | 5 |
| `qwen_minimal` | v1.4 minimal snapshot | local Qwen ranking | 5 |
| `deterministic_enriched` | enriched context snapshot | deterministic enriched baseline | 1 |
| `gpt_enriched` | enriched context snapshot | hosted GPT ranking | 5 |
| `qwen_enriched` | enriched context snapshot | local Qwen ranking | 5 |

The minimal arms should be rerun contemporaneously with the enriched arms rather
than compared only against historical v1.4 results. This is especially important
for the hosted GPT arm because the proprietary model service is not a fully
immutable local artifact. Historical v1.4 metrics remain useful for context,
but a clean paired ablation should measure both representation conditions under
one versioned protocol.

## Deterministic Enriched Baseline

The enriched deterministic baseline should be frozen before execution and should
remain target-independent. The readiness implementation uses a transparent
lexicographic/ordinal policy rather than arbitrary additive weights. The policy
orders candidates by generic reflected-XSS reasoning signals:

- reflected marker before no reflected marker;
- reflection context according to a predeclared order;
- marker preservation according to a predeclared order;
- capped reflection-count category;
- response content-type category;
- an abstract structural fallback using only permitted minimal fields;
- stable candidate-ID tie-breaking.

The fallback cannot call the original deterministic structural ranker directly,
because that ranker depends on URL and parameter-name fields that v1.4.1
deliberately removes from ranker-facing records. Instead, the fallback uses the
permitted abstract structural fields corresponding to the same generic
structural signals. The policy must not use OWASP case labels, observed final
outcomes or post-run performance.

## Projected Scale and Runtime

The frozen v1.4 package contains 266 scenarios, 1,330 candidate references and
388 unique candidates. A candidate-level enrichment pass therefore requires one
benign marker request per unique candidate under the proposed design.

Projected v1.4.1 ranking rows if minimal and enriched conditions are both rerun:

| Arm family | Rows |
| --- | ---: |
| deterministic minimal and enriched | 532 |
| GPT minimal and enriched | 2,660 |
| Qwen minimal and enriched | 2,660 |
| Total ranking rows | 5,852 |

The v1.4 final package recorded GPT median latency of approximately 3.63 seconds
over 1,330 scheduled calls and Qwen median latency of approximately 55.15
seconds over 1,330 scheduled calls. A full six-arm v1.4.1 run is therefore
operationally feasible but time-consuming, especially for local Qwen. The
runtime plan should treat Qwen as a long unattended local run and should include
resume validation, denominator checks and no silent retry.

## Statistical Plan

The inferential unit should remain the scenario, with LLM trials nested under
scenario and arm. Repeated trials must not be treated as independent benchmark
scenarios.

Primary paired comparisons should focus on scenario-level MRR:

- `gpt_enriched` versus `gpt_minimal`;
- `qwen_enriched` versus `qwen_minimal`;
- `gpt_enriched` versus `deterministic_enriched`;
- `qwen_enriched` versus `deterministic_enriched`.

Secondary outcomes may include Top-1, Top-2, Top-4, vulnerable-candidate rank,
ranking stability, malformed-output rate, provider/runtime failures, latency,
token usage and cost availability. Negative-only scenarios should remain
excluded from vulnerable-candidate ranking denominators and should be reported
for reliability and no-vulnerability behavior.

Bootstrap or paired permutation methods should operate at scenario level. Any
multiple-comparison correction should be declared before execution. Ordinary
overlap between descriptive confidence intervals must not be treated as a
formal paired hypothesis test.

## Compatibility and Methodological Issues

The proposed direction is feasible, but it has important caveats:

- v1.4.1 is no longer a pristine external validation after the v1.4 result is
  known; it should be framed as a follow-up explanatory ablation;
- benign reflection observation adds request traffic before ranking and must be
  documented as part of the enriched-condition treatment;
- the current v1.4 model-facing path and parameter values should be abstracted
  further before enrichment to avoid case-identity leakage;
- local Qwen runtime cost is mostly wall-clock time rather than monetary cost;
- GPT pricing/cost per finding should remain unavailable unless a frozen numeric
  pricing basis is recorded before the v1.4.1 protocol is frozen;
- enrichment can improve all arms, including deterministic ranking, so the study
  should not be framed as an LLM-only benefit test.

## Recommended Next Implementation Milestone

The next implementation milestone should not run ranking arms. It should build
and dry-validate the v1.4.1 context-enrichment collector and snapshot-preparation
pipeline only.

Minimum scope:

- define a versioned enriched candidate schema;
- derive abstracted minimal candidate fields from the frozen v1.4 snapshots;
- execute no final ranking rows;
- collect no model outputs;
- implement leak checks against ranker-facing enriched snapshots;
- define the deterministic enriched ranker without using ground truth;
- add fixture-based tests for marker parsing, context classification, snapshot
  stability and leakage prevention;
- produce a dry-validation package with projected denominators and checksums.

The executable v1.4.1 protocol should be frozen only after enriched snapshots,
leak checks, request budgets and deterministic-enriched ranking rules are
dry-validated.

## Feasibility Verdict

**READY WITH METHODOLOGICAL CAVEATS**

The repository has sufficient v1.4 protocol structure, candidate snapshots,
execution specifications, ranking infrastructure, local Qwen integration and
canonical reporting conventions to support a v1.4.1 context-enrichment ablation.
However, the study must be framed as an explanatory follow-up, must sanitize
case-derived path/name artifacts more aggressively than v1.4, and must freeze
the enriched schema and deterministic-enriched baseline before any scored run.
