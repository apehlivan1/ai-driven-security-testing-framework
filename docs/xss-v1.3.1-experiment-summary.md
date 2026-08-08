# XSS v1.3.1 Experiment Summary

Status: final corrected XSS ablation package generated from the completed run
`results/xss-v13-ablation-v1.3.1-final/xss-v13-ablation-20260808T103409Z`.

Frozen protocol: `evaluation-protocol-v1.3.1`

Canonical package:
`results/xss-v13-ablation-v1.3.1-final/canonical/`

## Purpose

This experiment evaluates the thesis framework's bounded AI role for reflected
XSS candidate ranking. The LLMs do not discover inputs, generate payloads,
execute browser actions, inspect ground truth, or verify findings. Each ranking
arm receives the same frozen candidate snapshots and may only return an ordered
list of existing candidate IDs with rationales.

The separation under evaluation is:

- deterministic discovery and frozen candidate snapshots
- bounded ranking by `deterministic_structural`, `proprietary_gpt`, or
  `local_qwen`
- deterministic safety and browser execution
- deterministic evidence collection
- deterministic verifier decisions
- post-run ground-truth scoring

## Experimental Arms

| Arm | Role |
| --- | --- |
| `deterministic_structural` | Frozen structural ranking baseline |
| `proprietary_gpt` | OpenAI `gpt-5.6-luna` through the restricted ranking contract |
| `local_qwen` | Local Qwen2.5 7B Instruct GGUF Q4_K_M through the same ranking contract |

The Gemma fallback was not activated.

## Denominators

| Arm | Expected ranking rows | Produced ranking rows |
| --- | ---: | ---: |
| `deterministic_structural` | 24 | 24 |
| `proprietary_gpt` | 120 | 120 |
| `local_qwen` | 120 | 120 |
| Total | 264 | 264 |

The 24 scenarios are the frozen v1.3 XSS snapshots. They include 16 vulnerable
scenarios and 8 negative scenarios.

## Valid Ranking Metrics

| Arm | Valid rows | Top-1 accuracy | Top-k recall | MRR |
| --- | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 24 | 0.2500 | 0.6875 | 0.3854 |
| `proprietary_gpt` | 116 | 0.2179 | 0.7179 | 0.4060 |
| `local_qwen` | 120 | 0.3125 | 0.6875 | 0.4427 |

The GPT arm produced 4 schema-invalid rankings. These observations are retained
as malformed-output evidence and are excluded from valid ranking-performance
aggregates. They are not provider failures and are not interpreted as scanner or
verifier failures.

## Reliability

| Arm | Attempted | Valid | Schema-invalid | Provider failures | Runtime failures | Retries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 24 | 24 | 0 | 0 | 0 | 0 |
| `proprietary_gpt` | 120 | 116 | 4 | 0 | 0 | 0 |
| `local_qwen` | 120 | 120 | 0 | 0 | 0 | 0 |

All 120 GPT calls reached the provider and retained response identifiers. The
OpenAI API key is not present in the canonical artifacts.

## End-To-End Findings

| Arm | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 11 | 0 | 0 | 69 |
| `proprietary_gpt` | 58 | 0 | 0 | 328 |
| `local_qwen` | 55 | 0 | 0 | 320 |

These counts are candidate-test classifications, not independent benchmark-case
counts. Repeated LLM trials are repeated ranking observations over the same 24
scenario set and must not be treated as independent vulnerable applications.

The negative-scenario false-positive rate is 0.0 for all three arms.

## Efficiency And Measurements

| Metric | Value |
| --- | ---: |
| Time to first verifier-confirmed finding, ms | 8858 |
| Requests to first verifier-confirmed finding | 3 |
| Candidates tested before first verifier-confirmed finding | 1 |
| Total action requests | 1683 |
| Browser navigations | 1682 |
| HTTP requests | 1 |
| GPT input tokens | 96185 |
| GPT output tokens | 60857 |
| GPT total tokens | 157042 |

`verification_completed_at` is retained for all 841 verifier results, so the
time-to-first-verified-finding metric is now available. The final canonical
package also includes per-arm and per-scenario/per-trial timing tables derived
from retained timestamps, scenario summaries and action results. Negative
scenarios and trials with no verifier-confirmed finding use `not_applicable`.

Valid-row comparative timing:

| Arm | Verified trials | Median ms | Mean ms | Median requests | Median candidates |
| --- | ---: | ---: | ---: | ---: | ---: |
| Deterministic structural | 11 | 1140 | 1004.818 | 6 | 3 |
| Proprietary GPT | 56 | 354.5 | 511.268 | 4.0 | 2.0 |
| Local Qwen | 55 | 323 | 345.618 | 4 | 2 |

For LLM arms, model/provider latency is reported separately in provider
metrics and is not silently folded into the timestamp-derived timing table.

GPT cost is `not_available` because no numeric USD cost artifact was retained.
Local Qwen cost is also `not_available`; provider cost is not applicable for the
deterministic arm.

## Canonical Outputs

The canonical package contains:

- `manifest.json`
- `checksums.sha256`
- `validation-report.json`
- `analysis-report.md`
- normalized JSON and CSV tables under `normalized/`
- thesis-ready Markdown and LaTeX tables under `tables/`
- PNG/PDF figures and machine-readable source data under `figures/`

Raw run evidence remains under the source run directory and should remain local
unless a separate archival decision is made.

## Limitations

The results are valid for the frozen 24-scenario reflected-XSS ablation,
restricted ranking contract, selected models, local benchmark implementation and
recorded hardware/runtime environment. They do not establish general model
superiority or broad web-application security performance.
