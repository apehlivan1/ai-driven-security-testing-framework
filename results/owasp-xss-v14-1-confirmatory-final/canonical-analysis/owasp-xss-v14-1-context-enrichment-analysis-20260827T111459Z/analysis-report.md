# v1.4.1 OWASP XSS Context-Enrichment Post-Run Analysis

This package contains derived post-run scoring and statistical analysis only. It was produced after the complete pre-scoring integrity audit passed and after ground truth was authorized for post-run scoring. No ranking call, HTTP request, browser action, retry, repair or scored-artifact modification was performed by this analysis step.

## Integrity

- Total ranking rows: `5852` / `5852`
- Missing sequences: `0`
- Duplicate sequences: `0`
- Candidate snapshot checksum errors: `0`
- Ground-truth leak count before scoring: `0`
- Package validation: `True`

## Ranking Effectiveness

| Arm | Positive scenarios | Valid positive trials | Top-1 | Top-2 | Top-4 | Scenario-level MRR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_minimal` | 236 | 236 / 236 | 0.2119 | 0.4364 | 0.7797 | 0.4681 |
| `deterministic_enriched` | 236 | 236 / 236 | 0.6356 | 0.8136 | 0.9576 | 0.7768 |
| `gpt_minimal` | 236 | 1180 / 1180 | 0.1814 | 0.3517 | 0.7525 | 0.4337 |
| `gpt_enriched` | 236 | 1171 / 1180 | 0.6042 | 0.8076 | 0.9771 | 0.7619 |
| `qwen_minimal` | 236 | 1170 / 1180 | 0.2308 | 0.4145 | 0.8590 | 0.4808 |
| `qwen_enriched` | 236 | 1180 / 1180 | 0.4110 | 0.6610 | 0.9237 | 0.6314 |

## Primary Paired MRR Comparisons

| Comparison | Difference | 95% bootstrap CI | raw p | Holm-adjusted p | Evidence after Holm |
| --- | ---: | ---: | ---: | ---: | --- |
| `gpt_enriched vs gpt_minimal` | 0.3282 | [0.2834, 0.3739] | 0.0001 | 0.0004 | True |
| `qwen_enriched vs qwen_minimal` | 0.1531 | [0.1010, 0.2049] | 0.0001 | 0.0004 | True |
| `gpt_enriched vs deterministic_enriched` | -0.0149 | [-0.0480, 0.0181] | 0.3825 | 0.3825 | False |
| `qwen_enriched vs deterministic_enriched` | -0.1454 | [-0.1941, -0.0991] | 0.0001 | 0.0004 | True |

## Minimal vs. Enriched Decomposition

| Family | Minimal MRR | Enriched MRR | Delta MRR | Minimal Top-1 | Enriched Top-1 | Delta Top-1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic` | 0.4681 | 0.7768 | 0.3087 | 0.2119 | 0.6356 | 0.4237 |
| `gpt` | 0.4337 | 0.7619 | 0.3282 | 0.1814 | 0.6042 | 0.4229 |
| `qwen` | 0.4808 | 0.6314 | 0.1506 | 0.2308 | 0.4110 | 0.1802 |

## Proxy-Risk Interpretation

Deterministic enrichment increased MRR by +0.3087, GPT enrichment increased MRR by +0.3282, and Qwen enrichment increased MRR by +0.1506. GPT enriched was not statistically distinguishable from deterministic enriched on primary MRR (Delta = -0.0149, 95% CI [-0.0480, 0.0181], Holm p = 0.3825), while Qwen enriched was significantly lower than deterministic enriched (Delta = -0.1454, 95% CI [-0.1941, -0.0991], Holm p = 0.0004).

These results indicate that much of the observed enrichment benefit is attributable to the added reflection-derived context itself rather than clear LLM-specific reasoning. Because some enriched variables may act as proxies for reflected-XSS susceptibility, enrichment alone must not be interpreted as evidence of independent LLM reasoning; a restricted-context sensitivity analysis would be required for that narrower claim.

## Negative/Control Scenarios

Negative-only scenarios are reported separately. They do not contribute to vulnerable-candidate rank, Top-1, Top-2, Top-4 or MRR denominators.

## Cost

Cost per finding remains `not_available` because no frozen numeric pricing basis exists for this evaluation.
