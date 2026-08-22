# Evaluation v1.4 Final Results

Status: durable human-readable closure summary for the completed OWASP Benchmark
XSS v1.4 confirmatory ranking experiment. The authoritative machine-readable
evidence remains the canonical package at
`results/owasp-xss-v14-confirmatory-final/canonical/`.

This document summarizes the final post-run analysis. It does not replace the
canonical artifacts, frozen protocol package, or immutable raw scored
observations. Every numerical value below was cross-checked against the
canonical package files listed in the evidence hierarchy.

## Purpose and Relationship to v1.3.1

The v1.4 study is an external-confirmatory extension of the earlier v1.3.1 XSS
ablation. The v1.3.1 study used a controlled local 24-scenario reflected-XSS
benchmark. The v1.4 study moves the same bounded candidate-ranking question to
a larger external OWASP Benchmark XSS corpus while preserving the same core
authority boundary: deterministic framework artifacts define the candidate
snapshots, and the ranking arms only order existing structured candidate IDs.

The v1.4 results are reported separately from v1.3.1. The denominators are not
pooled because the benchmark source, scenario scale, and candidate distribution
are different.

## Evidence Hierarchy

The v1.4 evidence should be read in the following order:

1. Frozen pre-execution protocol package:
   `results/owasp-xss-v14-protocol-freeze/`.
2. Immutable raw execution observations:
   `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/`.
3. Post-run ground-truth/scoring stage:
   `results/owasp-xss-v14-protocol-freeze/ground-truth/scoring-data.json`.
4. Canonical derived analysis package:
   `results/owasp-xss-v14-confirmatory-final/canonical/`.
5. Human-readable documentation summary: this document.

Ground truth is introduced only at the post-run scoring stage. It is not present
in model-facing candidate snapshots or raw ranker artifacts.

## Frozen Benchmark Design

The frozen protocol package defines 266 scored ranking scenarios derived from
the OWASP Benchmark XSS corpus:

- 236 positive focal-vulnerable scenarios.
- 30 negative-only scenarios.
- Candidate pack size: 5.
- Candidate-test budget and Top-k definition: k = 4.
- Ranking arms: `deterministic_structural`, `proprietary_gpt`, and
  `local_qwen`.
- Repeated LLM trials are nested observations under scenario and arm, not
  independent benchmark scenarios.

The final protocol hash recorded by the execution and canonical package is:

`172a583322cd73e6553ea05d9209a33bf216eed6b62d74f98653e893722e473a`

The Git commit recorded for the execution is:

`b9f98d42dba2df9a70de686209686ea84c50ac41`

Available execution timestamps are:

- Runtime preflight created at `2026-08-21T23:58:04.532981+00:00`.
- First raw ranking-row timestamp: `2026-08-21T23:58:04.650055+00:00`.
- Last raw ranking-row timestamp: `2026-08-22T22:42:59.867835+00:00`.
- Execution manifest created at `2026-08-22T22:43:50.389390+00:00`.
- Canonical package manifest created at `2026-08-22T23:02:48.993566+00:00`.

## Execution Integrity

The final execution completed exactly the frozen scheduled row denominators:

| Arm | Scheduled rows | Completed rows | Missing rows |
| --- | ---: | ---: | ---: |
| `deterministic_structural` | 266 | 266 | 0 |
| `proprietary_gpt` | 1330 | 1330 | 0 |
| `local_qwen` | 1330 | 1330 | 0 |
| **Total** | **2926** | **2926** | **0** |

The canonical integrity audit reports:

- Duplicate row identities: 0.
- Malformed raw result artifacts: 0.
- Inconsistent raw row artifacts: 0.
- Unexpected row artifacts: 0.
- Protocol package checksum errors: 0.
- Raw ground-truth leak count: 0.
- No `READINESS_ONLY` or `EXCLUDED` cases entered the scored schedule.
- All 236 positive scenarios map to 236 unique focal vulnerable candidates and
  236 unique original OWASP cases through the separated scoring data.

## Effectiveness Results

Ranking effectiveness is computed only over contract-valid positive ranking
rows. Invalid or failed model outputs are retained in reliability denominators
and excluded from valid ranking-performance aggregates according to the frozen
metric specification.

| Arm | Valid positive rows | Top-1 | Top-4 | MRR |
| --- | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 236 | 0.2034 | 0.7881 | 0.4573 |
| `proprietary_gpt` | 1179 | 0.2332 | 0.7812 | 0.4732 |
| `local_qwen` | 1175 | 0.2468 | 0.8298 | 0.4926 |

Vulnerable-candidate rank distributions for valid positive rows:

| Arm | Rank 1 | Rank 2 | Rank 3 | Rank 4 | Rank 5 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 48 | 50 | 35 | 53 | 50 |
| `proprietary_gpt` | 275 | 209 | 211 | 226 | 258 |
| `local_qwen` | 290 | 235 | 225 | 225 | 200 |

Candidate coverage under the fixed budget is identical to Top-4 in this
ranking-only experiment because the fixed candidate-test budget is four.

## Reliability Results

| Arm | Scheduled rows | Attempted model calls | Contract-valid outputs | Contract-invalid outputs | Malformed outputs | Provider/runtime failures | Timeouts | Retries | Contract-validity rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 266 | 0 | 266 | 0 | 0 | 0 | 0 | 0 | 1.0000 |
| `proprietary_gpt` | 1330 | 1330 | 1329 | 1 | 0 | 1 | 0 | 0 | 0.9992 |
| `local_qwen` | 1330 | 1330 | 1325 | 5 | 5 | 0 | 0 | 0 | 0.9962 |

The GPT arm preserved one provider failure. The Qwen arm preserved five
malformed outputs. All five Qwen malformed outputs occurred on scenario
`ow14-s0232`, trials 1--5, caused by duplicate and omitted candidate-ID
contract violations. No failed or malformed observation was silently repaired or
retried.

## Negative-Only Scenario Treatment

The 30 negative-only scenarios do not have a focal vulnerable candidate.
Therefore Top-1, Top-4 and MRR are not applicable for those scenarios.

| Arm | Negative rows | Negative scenarios | Contract-valid negative rows | Ranking metrics |
| --- | ---: | ---: | ---: | --- |
| `deterministic_structural` | 30 | 30 | 30 | not applicable |
| `proprietary_gpt` | 150 | 30 | 150 | not applicable |
| `local_qwen` | 150 | 30 | 150 | not applicable |

No direct OWASP execution/verifier phase was performed in the final v1.4 run, so
verifier-confirmed false-positive behavior is not applicable for v1.4.

## Latency and Resource Observations

The deterministic arm records a ranking latency value of 0 ms. This is the
recorded instrumentation value only and should not be interpreted as literal
zero computational cost.

| Arm | Latency count | Median latency | Mean latency | P95 latency | Token usage | Cost |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| `deterministic_structural` | 266 | 0 ms | 0 ms | 0 ms | not available | not applicable |
| `proprietary_gpt` | 1330 | 3630 ms | 3989.81 ms | 6080 ms | 1,186,754 total tokens | not available |
| `local_qwen` | 1330 | 55150 ms | 57567.45 ms | 75872 ms | not available | not available |

GPT token usage was recorded for 1329 rows and totals 783,460 input tokens,
403,294 output tokens and 1,186,754 total tokens. Monetary cost remains
`not_available` because no frozen numeric pricing or cost artifact was retained.

Requests/actions/candidates tested and time to first verifier-confirmed finding
are not applicable to the final v1.4 ranking-only execution.

## Relationship to Direct Execution and Verification

The final v1.4 execution is a confirmatory candidate-ranking experiment. It did
not perform the separate direct OWASP execution/verifier layer over original
OWASP cases. Therefore its results must not be reported as verifier-confirmed
vulnerability findings, false positives or false negatives. Those concepts
belong to execution/verifier studies, not to this ranking-only v1.4 package.

## v1.3.1 Versus v1.4

The following comparison is descriptive only and keeps denominators separate.

| Arm | v1.3.1 Top-1 | v1.4 Top-1 | v1.3.1 Top-k | v1.4 Top-4 | v1.3.1 MRR | v1.4 MRR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 0.2500 | 0.2034 | 0.6875 | 0.7881 | 0.3854 | 0.4573 |
| `proprietary_gpt` | 0.2179 | 0.2332 | 0.7179 | 0.7812 | 0.4060 | 0.4732 |
| `local_qwen` | 0.3125 | 0.2468 | 0.6875 | 0.8298 | 0.4427 | 0.4926 |

The pattern is mixed rather than uniformly favorable to one arm. On the larger
external v1.4 benchmark, `local_qwen` has the highest Top-1, Top-4 and MRR among
the three arms. `proprietary_gpt` has higher Top-1 and MRR than
`deterministic_structural`, but slightly lower Top-4. These observations are
limited to the frozen v1.4 ranking task and recorded environment.

## Interpretation Relative to the Thesis Hypothesis

The v1.4 result provides metric-dependent support for the thesis hypothesis that
an LLM restricted to ranking already discovered structured candidates can improve
candidate prioritization effectiveness relative to a deterministic structural
baseline under a fixed testing budget. The local Qwen arm improves over the
deterministic baseline on Top-1, Top-4 and MRR. The hosted GPT arm improves on
Top-1 and MRR but does not improve on Top-4.

This should not be stated as general LLM superiority, scanner superiority, or
autonomous penetration-testing capability. The conclusion is limited to the
frozen OWASP Benchmark XSS candidate-ranking task, the valid-output denominator
rules, and the recorded execution environment.

## Canonical Evidence Locations

Primary canonical package:

- `results/owasp-xss-v14-confirmatory-final/canonical/manifest.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/execution-integrity-report.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/validation-report.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/checksum-validation-report.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/checksums.sha256`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/ranking-aggregates.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/reliability-aggregates.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/efficiency-aggregates.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/negative-scenario-aggregates.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/v13-comparison.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/scored-rows.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/scored-rows.csv`

Selected canonical checksums:

- `manifest.json`:
  `112e7ae2bbd8fa762c7b659fa285eb031cb1e07f6df09f038442d1f83b752841`
- `execution-integrity-report.json`:
  `510642072fa6903f4a8de77f4624b81c78d874fbbf39c34818cf2b4a3697f162`
- `validation-report.json`:
  `03e8e1c7434ccbd6b5c48759dc5dba29a2173e36569574721b987185881a22cc`
- `normalized/ranking-aggregates.json`:
  `b665ec1e7f97fa07cb6b411d01f5b7a263379ca12d625f7156deab6887819cd2`
- `normalized/reliability-aggregates.json`:
  `1474f95289f988b94d08e7eeb73380e5e824dbdd6662cca4c97d71827bb524fd`
- `normalized/efficiency-aggregates.json`:
  `ec5df7a7767a6ae54a375afc534c54ca38f946cf74c570ed8ae63c4efc93b2d7`

Raw execution observations:

- `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/`

The raw directory contains immutable per-row observations and should remain
available for audit. It should not be manually edited, regenerated or pruned.

## Preservation Recommendation

The canonical package is compact enough to version-control and should be kept as
primary thesis evidence. The full raw run is larger and contains thousands of
per-row artifacts; it should remain intact as local raw experimental evidence
unless a deliberate raw-evidence archival decision is made. It should not be
committed casually with broad staging commands.

