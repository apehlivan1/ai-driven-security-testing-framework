# Professor Comment 3 Closure Analysis: v1.4 Scenario-Level Inference

This is a derived post-run inferential analysis of the original frozen OWASP XSS v1.4 ranking evaluation. It follows the frozen post-run statistical plan and performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier, or scored experimental calls.

## Source and Denominator Validation

- Validation valid: `True`
- Positive scenarios: `236`
- Negative-only scenarios: `30`
- Primary paired denominator: `235`
- Missing Qwen positive scenario: `ow14-s0232`
- Repeated LLM trials are aggregated within scenario; trial rows are not treated as independent observations.

## Primary Comparison

| Comparison | n | Arm A mean | Arm B mean | Mean diff | Median diff | 95% bootstrap CI | W | raw p | rank-biserial |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen - Deterministic MRR | 235 | 0.4926 | 0.4571 | +0.0355 | +0.0000 | [-0.0207, +0.0922] | 12665.5000 | 0.659123 | +0.0348 |

The primary comparison is Qwen minus deterministic structural ranking on scenario-level mean reciprocal rank. Qwen mean RR over the paired scenarios is `0.4926` and deterministic mean RR over the same paired scenarios is `0.4571`. The mean paired difference is `+0.0355` with a 95% paired-bootstrap percentile CI of `[-0.0207, +0.0922]`. The two-sided Wilcoxon signed-rank p-value is `0.659123`.

The primary paired-difference orientation is `local_qwen - deterministic_structural`; the paired differences contain `84` positive, `97` negative, and `54` zero values. The matched-pairs rank-biserial correlation uses `(positive_rank_sum - negative_rank_sum) / (positive_rank_sum + negative_rank_sum)`, with zero-difference ranks excluded from the denominator after Pratt ranking.

The primary Qwen-versus-deterministic MRR difference is not statistically supported at alpha 0.05 under the frozen scenario-level paired test. This does not prove equivalence, but it does mean the thesis should not claim that Qwen outperformed the deterministic structural baseline on the frozen OWASP XSS v1.4 scenario class.

## Exploratory Comparisons

| Comparison | n | Arm A mean | Arm B mean | Mean diff | Median diff | 95% bootstrap CI | W | raw p | rank-biserial | Holm p | Holm < 0.05 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen - GPT MRR | 235 | 0.4926 | 0.4742 | +0.0183 | +0.0000 | [-0.0292, +0.0660] | 13082.0000 | 0.851072 | +0.0147 | 1 | False |
| GPT - Deterministic MRR | 236 | 0.4733 | 0.4573 | +0.0160 | +0.0000 | [-0.0323, +0.0638] | 12717.5000 | 0.547765 | +0.0471 | 1 | False |
| GPT - Deterministic TOP1 | 236 | 0.2333 | 0.2034 | +0.0299 | +0.0000 | [-0.0396, +0.0975] | 7969.5000 | 0.100787 | +0.1635 | 1 | False |
| Qwen - Deterministic TOP1 | 235 | 0.2468 | 0.2043 | +0.0426 | +0.0000 | [-0.0340, +0.1191] | 7620.0000 | 0.291841 | +0.1111 | 1 | False |
| Qwen - GPT TOP1 | 235 | 0.2468 | 0.2343 | +0.0126 | +0.0000 | [-0.0523, +0.0774] | 9038.5000 | 0.856999 | -0.0183 | 1 | False |
| GPT - Deterministic TOP2 | 236 | 0.4108 | 0.4153 | -0.0044 | +0.0000 | [-0.0831, +0.0733] | 11756.0000 | 0.8951 | -0.0113 | 1 | False |
| Qwen - Deterministic TOP2 | 235 | 0.4468 | 0.4128 | +0.0340 | +0.0000 | [-0.0553, +0.1234] | 9585.0000 | 0.457614 | +0.0690 | 1 | False |
| Qwen - GPT TOP2 | 235 | 0.4468 | 0.4126 | +0.0343 | +0.0000 | [-0.0413, +0.1113] | 10894.0000 | 0.435673 | +0.0673 | 1 | False |
| GPT - Deterministic TOP4 | 236 | 0.7814 | 0.7881 | -0.0068 | +0.0000 | [-0.0508, +0.0381] | 4904.0000 | 0.388346 | -0.1188 | 1 | False |
| Qwen - Deterministic TOP4 | 235 | 0.8298 | 0.7872 | +0.0426 | +0.0000 | [-0.0298, +0.1149] | 6352.0000 | 0.245042 | +0.1351 | 1 | False |
| Qwen - GPT TOP4 | 235 | 0.8298 | 0.7813 | +0.0485 | +0.0000 | [-0.0136, +0.1115] | 5710.0000 | 0.0202887 | +0.2625 | 0.223176 | False |

Exactly `11` exploratory p-values entered the Holm procedure.

Exploratory differences supported after Holm correction: `0`.

Differences without Holm-adjusted support should remain descriptive trends rather than statistically supported conclusions: local_qwen_vs_proprietary_gpt_mrr, proprietary_gpt_vs_deterministic_structural_mrr, proprietary_gpt_vs_deterministic_structural_top1, local_qwen_vs_deterministic_structural_top1, local_qwen_vs_proprietary_gpt_top1, proprietary_gpt_vs_deterministic_structural_top2, local_qwen_vs_deterministic_structural_top2, local_qwen_vs_proprietary_gpt_top2, proprietary_gpt_vs_deterministic_structural_top4, local_qwen_vs_deterministic_structural_top4, local_qwen_vs_proprietary_gpt_top4.

## Random Reference Context

The analytic random reference from Professor Comment 1 is included only descriptively: Top-1 `0.2000`, Top-2 `0.4000`, Top-4 `0.8000`, and MRR `0.4567`. No new random-baseline hypothesis test is performed in this package.

## Reliability and Invalid Outputs

GPT scenario-level values are available for all `236` positive scenarios, although one GPT positive scenario has four valid trials. Qwen scenario-level values are available for `235/236` positive scenarios; the omitted scenario contains five malformed terminal Qwen outputs and no valid Qwen ranking. These invalid/failure outcomes remain part of reliability reporting and are not repaired, retried, imputed, or counted as successful rankings.

## Thesis Interpretation

The primary scenario-level MRR comparison does not support a claim that Qwen outperformed the deterministic structural baseline under the frozen analysis plan. The estimated mean paired difference is +0.0355, with a 95% paired-bootstrap CI of [-0.0207, +0.0922]. Exploratory comparisons supported after Holm correction: none. All other exploratory differences should remain descriptive trends, and no non-significant comparison should be interpreted as equivalence.

## Claims to Avoid

- Do not treat repeated GPT or Qwen trial rows as independent scenarios.
- Do not describe non-significant comparisons as evidence of equivalence.
- Do not claim broad LLM, GPT, or Qwen superiority beyond the frozen OWASP XSS v1.4 scenario class.
- Do not report v1.4 ranking-only evidence as verifier-confirmed vulnerability findings.

## Validation

- Source validation: `True`
- Denominator validation: `True`
- New experimental/scored calls: `0`
