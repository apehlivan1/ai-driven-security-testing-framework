# Thesis-Ready Tables: v1.4.1 OWASP XSS Context Enrichment

## Candidate-Ranking Effectiveness

| Arm | Representation | Positive scenarios | Valid/expected positive trials | Top-1 | Top-2 | Top-4 | MRR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic | minimal | 236 | 236/236 | 0.2119 | 0.4364 | 0.7797 | 0.4681 |
| deterministic | enriched | 236 | 236/236 | 0.6356 | 0.8136 | 0.9576 | 0.7768 |
| gpt | minimal | 236 | 1180/1180 | 0.1814 | 0.3517 | 0.7525 | 0.4337 |
| gpt | enriched | 236 | 1171/1180 | 0.6042 | 0.8076 | 0.9771 | 0.7619 |
| qwen | minimal | 236 | 1170/1180 | 0.2308 | 0.4145 | 0.8590 | 0.4808 |
| qwen | enriched | 236 | 1180/1180 | 0.4110 | 0.6610 | 0.9237 | 0.6314 |

## Minimal-to-Enriched Decomposition

| Family | MRR minimal | MRR enriched | Delta | Top-1 minimal | Top-1 enriched | Delta | Top-2 minimal | Top-2 enriched | Delta | Top-4 minimal | Top-4 enriched | Delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic | 0.4681 | 0.7768 | 0.3087 | 0.2119 | 0.6356 | 0.4237 | 0.4364 | 0.8136 | 0.3771 | 0.7797 | 0.9576 | 0.1780 |
| gpt | 0.4337 | 0.7619 | 0.3282 | 0.1814 | 0.6042 | 0.4229 | 0.3517 | 0.8076 | 0.4559 | 0.7525 | 0.9771 | 0.2246 |
| qwen | 0.4808 | 0.6314 | 0.1506 | 0.2308 | 0.4110 | 0.1802 | 0.4145 | 0.6610 | 0.2465 | 0.8590 | 0.9237 | 0.0648 |

## Primary Paired MRR Comparisons

| Comparison | Paired scenarios | MRR difference | 95% CI | Raw p | Holm p |
| --- | ---: | ---: | ---: | ---: | ---: |
| gpt_enriched vs gpt_minimal | 236 | 0.3282 | [0.2834, 0.3739] | 0.0001 | 0.0004 |
| qwen_enriched vs qwen_minimal | 234 | 0.1531 | [0.1010, 0.2049] | 0.0001 | 0.0004 |
| gpt_enriched vs deterministic_enriched | 236 | -0.0149 | [-0.0480, 0.0181] | 0.3825 | 0.3825 |
| qwen_enriched vs deterministic_enriched | 236 | -0.1454 | [-0.1941, -0.0991] | 0.0001 | 0.0004 |
