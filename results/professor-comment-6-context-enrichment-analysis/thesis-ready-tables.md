# Professor Comment 6 Thesis-Ready Tables

## Minimal Versus Enriched Ranking Metrics

| Arm | Top-1 | Top-2 | Top-4 | Scenario-level MRR | Valid positive trials |
| --- | ---: | ---: | ---: | ---: | ---: |
| `det_minimal` | 0.2119 | 0.4364 | 0.7797 | 0.4681 | 236/236 |
| `det_enriched` | 0.6356 | 0.8136 | 0.9576 | 0.7768 | 236/236 |
| `gpt_minimal` | 0.1814 | 0.3517 | 0.7525 | 0.4337 | 1180/1180 |
| `gpt_enriched` | 0.6042 | 0.8076 | 0.9771 | 0.7619 | 1171/1180 |
| `qwen_minimal` | 0.2308 | 0.4145 | 0.8590 | 0.4808 | 1170/1180 |
| `qwen_enriched` | 0.4110 | 0.6610 | 0.9237 | 0.6314 | 1180/1180 |

## Within-Family Enrichment Deltas

| Family | Minimal MRR | Enriched MRR | Delta MRR | Minimal Top-1 | Enriched Top-1 | Delta Top-1 | Minimal Top-2 | Enriched Top-2 | Delta Top-2 | Minimal Top-4 | Enriched Top-4 | Delta Top-4 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic | 0.4681 | 0.7768 | 0.3087 | 0.2119 | 0.6356 | 0.4237 | 0.4364 | 0.8136 | 0.3771 | 0.7797 | 0.9576 | 0.1780 |
| gpt | 0.4337 | 0.7619 | 0.3282 | 0.1814 | 0.6042 | 0.4229 | 0.3517 | 0.8076 | 0.4559 | 0.7525 | 0.9771 | 0.2246 |
| qwen | 0.4808 | 0.6314 | 0.1506 | 0.2308 | 0.4110 | 0.1802 | 0.4145 | 0.6610 | 0.2465 | 0.8590 | 0.9237 | 0.0648 |

## Primary Paired MRR Comparisons

| Comparison | Delta MRR | 95% CI | Raw p | Holm p | Supported after Holm |
| --- | ---: | ---: | ---: | ---: | --- |
| gpt_enriched vs gpt_minimal | 0.3282 | [0.2834, 0.3739] | 0.0001 | 0.0004 | `true` |
| qwen_enriched vs qwen_minimal | 0.1531 | [0.1010, 0.2049] | 0.0001 | 0.0004 | `true` |
| gpt_enriched vs deterministic_enriched | -0.0149 | [-0.0480, 0.0181] | 0.3825 | 0.3825 | `false` |
| qwen_enriched vs deterministic_enriched | -0.1454 | [-0.1941, -0.0991] | 0.0001 | 0.0004 | `true` |

## Enrichment Feature and Proxy-Risk Inventory

| Enriched-only field | Deterministic derivation | Ground truth used | Available to enriched arms | Proxy-risk classification | Methodological role |
| --- | --- | --- | --- | --- | --- |
| `marker_preservation_category` | Category derived from deterministic comparison of the benign marker with exact, encoded, transformed, stripped or absent response representations. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Especially when unchanged, captures whether attacker-controlled input is preserved in a form close to submission; it is a strong proxy risk but not ground truth. |
| `reflection_context_category` | Category derived from deterministic inspection of where recognized marker occurrences appear in the response representation. | `false` | deterministic, GPT, Qwen | contextual/suggestive | Provides context for observed reflection; useful for prioritization but less direct than preservation itself. |
| `reflection_count_category` | Ordinal category derived from the count of recognized benign marker occurrences in the response. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Captures how many reflected marker occurrences were observed; it is suggestive for prioritization but does not encode exploitability or ground truth. |
| `reflection_detected` | Boolean derived from whether the fixed inert marker is recognized in the retained HTTP response representation. | `false` | deterministic, GPT, Qwen | strong susceptibility proxy | Indicates observable reflection of benign input, which is directly relevant to reflected-XSS prioritization but is not a vulnerability label. |
| `response_content_type_category` | Category derived from the retained response content type for the benign marker request. | `false` | deterministic, GPT, Qwen | neither/ambiguous | Provides coarse response-type context; by itself it is not a direct reflected-XSS susceptibility signal. |

## Reliability

| Arm | Scheduled | Valid | Contract-invalid | Provider failed | Runtime failed | Timeout | Contract-validity rate | Mean latency ms | Total tokens | Cost availability |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| `det_minimal` | 266 | 266 | 0 | 0 | 0 | 0 | 1.0000 | 0.0113 | not_available | not_applicable |
| `det_enriched` | 266 | 266 | 0 | 0 | 0 | 0 | 1.0000 | 0 | not_available | not_applicable |
| `gpt_minimal` | 1330 | 1330 | 0 | 0 | 0 | 0 | 1.0000 | 4969.2053 | 1177955 | not_available |
| `gpt_enriched` | 1330 | 1318 | 12 | 0 | 0 | 0 | 0.9910 | 4319.3850 | 1422745 | not_available |
| `qwen_minimal` | 1330 | 1320 | 10 | 0 | 0 | 0 | 0.9925 | 58403.5218 | not_available | not_available |
| `qwen_enriched` | 1330 | 1330 | 0 | 0 | 0 | 0 | 1.0000 | 71167.3737 | not_available | not_available |

