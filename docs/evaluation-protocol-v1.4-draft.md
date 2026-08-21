# Evaluation Protocol v1.4 Draft

Status: **SUPERSEDED DRAFT**.

This draft is preserved as historical planning context. The frozen
pre-execution protocol is `docs/evaluation-protocol-v1.4.md`, and the
protocol-critical package is `results/owasp-xss-v14-protocol-freeze/`.

This is a draft protocol for `v1.4 OWASP Benchmark XSS External Validation`.
It is not executable, not tagged, and not authorized for scored experiments.
It must not modify `evaluation-protocol-v1.3.1`, the frozen v1.3.1 candidate
snapshots, final v1.3.1 model outputs, canonical results, or scoring.

## Scope

The v1.4 evaluation line uses the audited OWASP Benchmark Java XSS corpus from
the pinned source revision recorded below. The goal is to include every
methodologically compatible original OWASP XSS case under predeclared inclusion
rules and report all exclusions with reasons.

The central thesis claim remains bounded candidate-ranking effectiveness:

- deterministic structural ranking;
- hosted proprietary GPT ranking;
- local Qwen ranking.

The LLMs may only rank existing structured candidate IDs and provide bounded
rationales. They must not discover inputs, generate payloads, execute actions,
access ground truth, inspect source code, control the browser or HTTP client,
or decide finding status.

## Current Benchmark Provenance

Audit source:

- official remote: `https://github.com/OWASP-Benchmark/BenchmarkJava`;
- local ignored checkout: `.external/owasp-benchmark-java`;
- declared benchmark version: `1.2`;
- pinned Git revision: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f`;
- branch at acquisition: `master`;
- repository status at audit: `clean`;
- expected-results file: `expectedresults-1.2.csv`;
- expected-results SHA-256:
  `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`.

Audited XSS population:

- total XSS-labelled cases: `455`;
- vulnerable cases: `246`;
- non-vulnerable cases: `209`;
- category representation: `xss`;
- CWE representation: `79`;
- expected-result representation: boolean source values normalized to
  `vulnerable` and `non_vulnerable`.

## Evaluation Layers

Layer 1: direct external case execution over compatible original OWASP XSS
cases. Unit: original labelled case.

Layer 2: external candidate-ranking evaluation over multi-candidate ranking
snapshots constructed from compatible original OWASP XSS cases. Unit: ranking
snapshot.

The two layers must use separate denominators.

## Candidate Snapshot Policy

Draft decision:

- ranking snapshots will be constructed from sanitized external candidate
  records;
- all ranking arms receive identical snapshot inputs;
- snapshots must be ground-truth-free;
- snapshots must use opaque candidate IDs;
- internal provenance maps opaque IDs to original OWASP case IDs and labels;
- provenance and ground truth may be loaded only during post-run scoring.

Draft resolved from audit:

- recommended candidate count per snapshot: `5`;
- compatible cases reserved as `READINESS_ONLY`: `20`;
- recommended positive ranking scenarios from `FINAL_CONFIRMATORY_ELIGIBLE`
  cases: `236`;
- recommended disjoint negative ranking scenarios from
  `FINAL_CONFIRMATORY_ELIGIBLE` cases: `30`;
- recommended core ranking scenario count: `266`;
- recommended core stratum: balanced deterministic decoy assignment.

Still unresolved: whether structurally matched or adversarial candidate packs
are added later as a separate robustness analysis.

## Ranking Arms

Proposed arms:

| Arm | Description | Trials |
| --- | --- | --- |
| `deterministic_structural` | Frozen deterministic structural ranker over sanitized candidate metadata | 1 per ranking scenario |
| `proprietary_gpt` | Hosted GPT provider through restricted ranking contract | draft recommendation: 5 per ranking scenario |
| `local_qwen` | Selected local Qwen model through same restricted ranking contract | draft recommendation: 5 per ranking scenario |

The v1.3.1 proprietary model and local Qwen settings should remain the starting
point unless a protocol amendment explicitly changes them before any v1.4
scored run.

Draft trial recommendation: five LLM trials per ranking scenario. With the
recommended `266` ranking scenarios, this projects `1330` GPT calls and `1330`
Qwen calls.

## Candidate-Test Budget

Draft recommendation: keep candidate-test budget `k = 4`.

Draft resolved from audit:

- candidate-pack size: `5`;
- `top_k = min(test_budget, candidate_count)`;
- negative scenarios use the same budget but do not have vulnerable-rank,
  Top-1, Top-k or MRR denominators.

## Direct External Execution Matrix

Draft decision: include a separate direct execution matrix over all compatible
original OWASP XSS cases if ground-truth mapping is valid.

This matrix does not use GPT or Qwen ranking. It evaluates deterministic
transport, execution, evidence collection and reflected-XSS verification
against original external cases.

## Compatibility Classes

Every original XSS case must be classified as:

- `DIRECT`;
- `ADAPTER_SUPPORTED`;
- `DERIVED_ADAPTED`;
- `EXCLUDED`.

The final protocol must freeze classifications and exclusions before scored
execution.

Evaluation role is separate from compatibility class. The deterministic
readiness milestone assigns:

- `READINESS_ONLY` to the 20 selected compatibility-readiness cases;
- `FINAL_CONFIRMATORY_ELIGIBLE` to compatible original cases not reserved for
  readiness;
- `EXCLUDED` to incompatible original cases.

Final candidate packs must be constructed only from
`FINAL_CONFIRMATORY_ELIGIBLE` cases.

## Sanitization

The final protocol must freeze deterministic sanitization rules for:

- benchmark case IDs;
- Java class names;
- servlet names;
- source filenames;
- original benchmark URLs;
- parameter names if they encode labels;
- any other benchmark-identity fields.

The rankers receive only sanitized structural metadata.

## Metrics

Ranking metrics:

- Top-1 accuracy;
- Top-k recall;
- MRR;
- vulnerable-candidate rank distribution;
- ranking stability across repeated LLM trials;
- negative-scenario false-positive behavior.

Reliability metrics:

- attempted model calls;
- valid outputs;
- malformed outputs;
- provider failures;
- runtime failures;
- timeout counts;
- contract-validity rate.

Direct execution metrics:

- verifier outcome by original case;
- TP/FP/FN/TN where ground-truth mapping is valid;
- rejected and inconclusive counts.

Efficiency metrics:

- ranking latency;
- token usage where available;
- cost availability;
- requests/actions to first verifier-confirmed finding;
- candidates tested before first verification;
- time to first verifier-confirmed finding where instrumentation supports a
  valid arm/scenario comparison.

Undefined values must use `not_available` or `not_applicable`, never zero.

## Statistical Analysis

Unresolved. The larger benchmark may support confidence intervals or
scenario-aware inferential comparison. If used, the independent unit must be
the original case or ranking scenario, not repeated LLM trials. Repeated trials
are nested observations and must not be treated as independent benchmark cases.

## Freeze Requirements

Before final scored execution, freeze:

- OWASP Benchmark revision;
- compatibility audit;
- exclusions;
- adapter implementation;
- candidate representation;
- sanitization and opaque remapping;
- candidate packs;
- decoy assignment;
- difficulty strata;
- ground-truth mapping;
- ranking prompt/schema;
- model identities;
- decoding/runtime settings;
- candidate-test budget;
- verifier logic;
- trial count;
- metrics;
- statistical analysis plan, if any.

After freeze, no behavior may be tuned based on v1.4 results. Infrastructure
defects must be handled by a separately versioned amendment.

## Deterministic Readiness Status

The deterministic compatibility-readiness milestone is complete. It implemented
metadata-constructed candidate records, separated provenance/execution/ranker
structures, opaque ranker-facing candidate metadata, deterministic `header`
transport, deterministic `parameter_name_enumeration` transport, per-action
header execution evidence, and non-scored runtime readiness against the local
OWASP Benchmark Java target.

Readiness subset:

- selection seed: `owasp-xss-v14-readiness-selection-v1`;
- selected cases: `20`;
- distribution: `10` vulnerable and `10` non-vulnerable;
- input-source coverage: `4` cases each for `parameter`, `parameter_map`,
  `query_string`, `header`, and `parameter_name_enumeration`;
- readiness status: `PASS`;
- GPT calls executed: `false`;
- Qwen calls executed: `false`;
- final confirmatory cases executed: `false`.

Reconciled corpus after reserving readiness cases:

- original XSS cases: `455`;
- compatible after deterministic adapters: `408`;
- READINESS_ONLY: `20`;
- FINAL_CONFIRMATORY_ELIGIBLE: `388`;
- FINAL_CONFIRMATORY_ELIGIBLE vulnerable: `236`;
- FINAL_CONFIRMATORY_ELIGIBLE non-vulnerable: `152`;
- excluded: `47`.

## Open Blockers Before Protocol Freeze

1. Freeze final candidate packs and decoy assignment using
   `FINAL_CONFIRMATORY_ELIGIBLE` cases only.
2. Freeze trial count, candidate-test budget, top-k definition, metrics,
   model/runtime settings and implementation hashes.
3. Decide whether direct external execution over all final-eligible original
   cases belongs in the same v1.4 protocol or in a separate deterministic
   execution matrix.
4. Validate operational feasibility for the projected `1330` GPT and `1330`
   Qwen ranking calls.
5. Create protocol-critical checksum manifests and structural validation for
   final snapshots before any scored execution.
