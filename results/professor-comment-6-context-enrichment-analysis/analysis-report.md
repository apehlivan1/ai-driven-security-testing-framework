# Professor Comment 6 Closure Analysis: Context-Enrichment Ablation and Proxy-Risk Interpretation

This package is a derived post-run synthesis of the completed frozen v1.4.1 context-enrichment experiment. It performs zero GPT, Qwen, deterministic ranking, HTTP/browser, discovery, verifier, scoring or new statistical-analysis calls and does not modify frozen/canonical artifacts.

## Authoritative Evidence

- Canonical analysis package: `results/owasp-xss-v14-1-confirmatory-final/canonical-analysis/owasp-xss-v14-1-context-enrichment-analysis-20260827T111459Z`
- Frozen protocol: `docs/evaluation-protocol-v1.4.1.md`
- Frozen protocol package: `results/owasp-xss-v14-1-protocol-freeze`
- Corrected benign observation package: `results/owasp-xss-v14-1-context-corrected-observations/owasp-xss-v14-1-context-collection-20260824T120106Z-corrected-20260824T122934Z`
- Source-integrity verdict: `PASS`

## Minimal and Enriched Feature Sets

Minimal candidate fields: `candidate_id, editable_input_count, http_method, input_carrier_category, input_type_category, multiple_parameters, parameter_count, request_shape_category, required_input_count`.

Enriched candidate fields: `candidate_id, editable_input_count, http_method, input_carrier_category, input_type_category, marker_preservation_category, multiple_parameters, parameter_count, reflection_context_category, reflection_count_category, reflection_detected, request_shape_category, required_input_count, response_content_type_category`.

The enriched-only fields are deterministic benign observation fields. The correction manifest records `ground_truth_loaded = false`, and the protocol ground-truth separation validation records that ranker-facing snapshots do not contain ground truth.

| Enriched-only field | Deterministic derivation | Ground truth used | Available to enriched arms | Proxy-risk classification | Methodological role |
| --- | --- | --- | --- | --- | --- |
| `marker_preservation_category` | Category derived from deterministic comparison of the benign marker with exact, encoded, transformed, stripped or absent response representations. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Especially when unchanged, captures whether attacker-controlled input is preserved in a form close to submission; it is a strong proxy risk but not ground truth. |
| `reflection_context_category` | Category derived from deterministic inspection of where recognized marker occurrences appear in the response representation. | `false` | deterministic, GPT, Qwen | contextual/suggestive | Provides context for observed reflection; useful for prioritization but less direct than preservation itself. |
| `reflection_count_category` | Ordinal category derived from the count of recognized benign marker occurrences in the response. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Captures how many reflected marker occurrences were observed; it is suggestive for prioritization but does not encode exploitability or ground truth. |
| `reflection_detected` | Boolean derived from whether the fixed inert marker is recognized in the retained HTTP response representation. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Indicates observable reflection of benign input, which is directly relevant to reflected-XSS prioritization but is not a vulnerability label. |
| `response_content_type_category` | Category derived from the retained response content type for the benign marker request. | `false` | deterministic, GPT, Qwen | neither/ambiguous | Provides coarse response-type context; by itself it is not a direct reflected-XSS susceptibility signal. |

## Fairness of Representation Access

The v1.4.1 comparison is fair with respect to enriched representation access: enrichment was not provided only to GPT or Qwen. The `deterministic_enriched`, `gpt_enriched` and `qwen_enriched` arms all consumed the same enriched candidate representation fields. This satisfies the supervisor's requirement that potentially strong reflection-derived context either remain non-decisive or be equally available to the deterministic comparator. The observed results show that the context is not non-decisive; instead, it is highly informative and available to all enriched arms.

## Canonical Positive-Scenario Results

| Arm | Top-1 | Top-2 | Top-4 | Scenario-level MRR | Valid positive trials |
| --- | ---: | ---: | ---: | ---: | ---: |
| `det_minimal` | 0.2119 | 0.4364 | 0.7797 | 0.4681 | 236/236 |
| `det_enriched` | 0.6356 | 0.8136 | 0.9576 | 0.7768 | 236/236 |
| `gpt_minimal` | 0.1814 | 0.3517 | 0.7525 | 0.4337 | 1180/1180 |
| `gpt_enriched` | 0.6042 | 0.8076 | 0.9771 | 0.7619 | 1171/1180 |
| `qwen_minimal` | 0.2308 | 0.4145 | 0.8590 | 0.4808 | 1170/1180 |
| `qwen_enriched` | 0.4110 | 0.6610 | 0.9237 | 0.6314 | 1180/1180 |

## Minimal Versus Enriched Decomposition

| Family | Minimal MRR | Enriched MRR | Delta MRR | Minimal Top-1 | Enriched Top-1 | Delta Top-1 | Minimal Top-2 | Enriched Top-2 | Delta Top-2 | Minimal Top-4 | Enriched Top-4 | Delta Top-4 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic | 0.4681 | 0.7768 | 0.3087 | 0.2119 | 0.6356 | 0.4237 | 0.4364 | 0.8136 | 0.3771 | 0.7797 | 0.9576 | 0.1780 |
| gpt | 0.4337 | 0.7619 | 0.3282 | 0.1814 | 0.6042 | 0.4229 | 0.3517 | 0.8076 | 0.4559 | 0.7525 | 0.9771 | 0.2246 |
| qwen | 0.4808 | 0.6314 | 0.1506 | 0.2308 | 0.4110 | 0.1802 | 0.4145 | 0.6610 | 0.2465 | 0.8590 | 0.9237 | 0.0648 |

## Canonical Primary Paired MRR Comparisons

| Comparison | Delta MRR | 95% CI | Raw p | Holm p | Supported after Holm |
| --- | ---: | ---: | ---: | ---: | --- |
| gpt_enriched vs gpt_minimal | 0.3282 | [0.2834, 0.3739] | 0.0001 | 0.0004 | `true` |
| qwen_enriched vs qwen_minimal | 0.1531 | [0.1010, 0.2049] | 0.0001 | 0.0004 | `true` |
| gpt_enriched vs deterministic_enriched | -0.0149 | [-0.0480, 0.0181] | 0.3825 | 0.3825 | `false` |
| qwen_enriched vs deterministic_enriched | -0.1454 | [-0.1941, -0.0991] | 0.0001 | 0.0004 | `true` |

## Supervisor Concern Answer

- Did enrichment help model-backed rankers? Yes descriptively for both model families on scenario-level MRR: GPT increased by `0.3282` and Qwen increased by `0.1506`.
- Did enrichment also help the deterministic ranker? Yes. Deterministic MRR increased by `0.3087`, almost as much as GPT and more than Qwen.
- Was the enrichment advantage unique to LLMs? No. The deterministic enriched arm received the same enriched representation fields and improved strongly, so the evidence supports a representation benefit rather than an LLM-unique benefit.
- Did GPT enriched outperform deterministic enriched? No statistically supported difference was found on primary paired MRR: delta `-0.0149`, 95% CI `[-0.0480, 0.0181]`, Holm p `0.3825`.
- Did Qwen enriched outperform deterministic enriched? No. Qwen enriched was lower than deterministic enriched under the frozen comparison: delta `-0.1454`, 95% CI `[-0.1941, -0.0991]`, Holm p `0.0004`.
- Does the experiment support a claim of independent LLM reasoning from enriched context? No. Strong reflection-derived proxy fields plausibly explain a substantial portion of the observed gain, and enrichment alone must not be presented as evidence of independent LLM reasoning.

## Architectural Interpretation

The result does not undermine the bounded-authority architecture. It instead supports a more selective interpretation of where probabilistic ranking is useful. When high-value susceptibility signals can be derived deterministically and safely, deterministic prioritization may be sufficient or highly competitive. Probabilistic ranking is most defensible where useful prioritization depends on combining weaker contextual signals that are difficult to encode directly. In all cases, the architecture should continue to keep execution, safety enforcement, payload construction, evidence collection and final vulnerability verification outside model authority.

## Restricted-Context Sensitivity Question

No restricted-context experiment was run for this closure analysis. The existing v1.4.1 result supports a representation/enrichment effect, but because strong proxy-like reflection observations are present, it does not isolate independent LLM reasoning from non-proxy contextual information. A later restricted-context sensitivity analysis excluding the strongest direct reflection/preservation proxy variables would be needed only for the narrower claim that LLMs independently reason better from non-proxy context. It is a limitation/future sensitivity analysis, not a prerequisite for reporting the frozen v1.4.1 result.

## Negative and Reliability Evidence

| Arm | Scheduled | Valid | Contract-invalid | Provider failed | Runtime failed | Timeout | Contract-validity rate | Mean latency ms | Total tokens | Cost availability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `det_minimal` | 266 | 266 | 0 | 0 | 0 | 0 | 1.0000 | 0.0113 | not_available | not_applicable |
| `det_enriched` | 266 | 266 | 0 | 0 | 0 | 0 | 1.0000 | 0 | not_available | not_applicable |
| `gpt_minimal` | 1330 | 1330 | 0 | 0 | 0 | 0 | 1.0000 | 4969.2053 | 1177955 | not_available |
| `gpt_enriched` | 1330 | 1318 | 12 | 0 | 0 | 0 | 0.9910 | 4319.3850 | 1422745 | not_available |
| `qwen_minimal` | 1330 | 1320 | 10 | 0 | 0 | 0 | 0.9925 | 58403.5218 | not_available | not_available |
| `qwen_enriched` | 1330 | 1330 | 0 | 0 | 0 | 0 | 1.0000 | 71167.3737 | not_available | not_available |

Negative-only scenarios are handled separately: `negative-only scenarios have no vulnerable-candidate rank, Top-k, reciprocal-rank or MRR denominator`. No false-positive classification metrics are inferred from ranking-only negative scenarios.

## Validation

- Validation verdict: `PASS`
- New experimental calls: `0`
- New inferential/statistical tests: `0`
