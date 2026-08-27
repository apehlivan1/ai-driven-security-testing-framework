# Professor Comment 4 Closure Analysis: Negative/Control Evidence and SQLi Results

This derived package synthesizes existing frozen evidence only. It performs zero model, HTTP, browser, discovery, verifier, ranking or scored experimental calls, and it does not modify frozen v1.4, v1.4.1 or v1.5.1 artifacts.

## Evidence Semantics

- Original OWASP XSS v1.4 negative-only evidence is ranking-only evidence. The rankers return ordered candidate IDs and do not make an abstention or vulnerability/no-vulnerability claim.
- XSS verifier-backed negative/control evidence is available from the frozen v1.3.1 eight negative scenarios and from OWASP v1.4 readiness-only controls; these must not be merged with v1.4 ranking-only metrics.
- SQLi v1.5.1 contains both ranking-only evidence and a separate direct deterministic runtime verifier/post-run classification layer.

## XSS Negative and Control Evidence

| Evidence source | Arm | Scenarios | Rows | Valid rows | FP/specificity status |
| --- | --- | ---: | ---: | ---: | --- |
| OWASP XSS v1.4 negative-only ranking | deterministic_structural | 30 | 30 | 30 | not applicable for ranking-only outputs |
| OWASP XSS v1.4 negative-only ranking | proprietary_gpt | 30 | 150 | 150 | not applicable for ranking-only outputs |
| OWASP XSS v1.4 negative-only ranking | local_qwen | 30 | 150 | 150 | not applicable for ranking-only outputs |
| XSS v1.3.1 eight negative controls | deterministic_structural | 8 | 8 | not_applicable | FPR 0.0000; specificity 1.0000 |
| XSS v1.3.1 eight negative controls | proprietary_gpt | 8 | 40 | not_applicable | FPR 0.0000; specificity 1.0000 |
| XSS v1.3.1 eight negative controls | local_qwen | 8 | 40 | not_applicable | FPR 0.0000; specificity 1.0000 |

The 30 original OWASP XSS v1.4 negative-only packs exercise behavior when no candidate in the pack is vulnerable, but false-positive rate and specificity are not mathematically meaningful for those ranking-only outputs. The ranking contract requires an ordering rather than a binary finding or abstention decision.

The 152 unique non-vulnerable OWASP XSS candidates contribute 944 distractor placements in positive scenarios and 150 placements in negative-only scenarios, for 1094 total non-vulnerable placements. All 152 non-vulnerable candidates are used at least once; total reuse is deterministic and balanced with counts ranging from 6 to 8 placements.

The frozen v1.3.1 XSS ablation supplies the verifier-backed eight unique negative/control scenarios. The deterministic arm contributes one retained outcome per negative scenario, while GPT and Qwen contribute repeated trial-level outcomes. No verifier-confirmed false positive occurred in any retained outcome. The point estimate for specificity is therefore 1.0000 and the point estimate for FPR is 0.0000, but the repeated GPT/Qwen trial rows must not be interpreted as additional independent negative scenarios beyond the eight controls.

## SQLi Ranking Evidence

| Arm | Valid positive n | Top-1 | Top-4 | MRR | Reliability |
| --- | ---: | ---: | ---: | ---: | --- |
| deterministic_structural | 105 | 20/105 = 0.1905 | 91/105 = 0.8667 | 0.4552 | valid 124/124; malformed 0; provider-failed 0 |
| proprietary_gpt | 522 | 99/522 = 0.1897 | 411/522 = 0.7874 | 0.4447 | valid 617/620; malformed 0; provider-failed 3 |
| local_qwen | 520 | 75/520 = 0.1442 | 415/520 = 0.7981 | 0.4274 | valid 615/620; malformed 5; provider-failed 0 |

The SQLi ranking data do not show the same descriptive model-backed advantage observed in the OWASP XSS ranking study; this is a scoped descriptive observation, not an inferential claim of model inferiority.

## SQLi Direct Verifier and Classification Evidence

| Ground truth | Verified | Inconclusive | Rejected | Post-run classification |
| --- | ---: | ---: | ---: | --- |
| Vulnerable | 84 | 21 | 0 | TP=84, FN=21 |
| Non-vulnerable | 0 | 95 | 0 | FP=0, TN=95 |

| Metric | Numerator | Denominator | Value |
| --- | ---: | ---: | ---: |
| sensitivity_recall | 84 | 105 | 0.8000 |
| specificity | 95 | 95 | 1.0000 |
| false_positive_rate | 0 | 95 | 0.0000 |
| false_negative_rate | 21 | 105 | 0.2000 |
| precision_ppv | 84 | 84 | 1.0000 |
| negative_predictive_value | 95 | 116 | 0.8190 |
| accuracy | 179 | 200 | 0.8950 |
| f1_score | 168 | 189 | 0.8889 |
| balanced_accuracy | mean(sensitivity,specificity) | not_applicable | 0.9000 |

Runtime verifier states remain distinct from post-run classification. The direct SQLi layer produced 84 verified and 116 inconclusive outcomes; only after applying frozen ground truth did those map to TP=84, FP=0, FN=21 and TN=95.

## Thesis Interpretation

The thesis can present the evaluation symmetrically: XSS positive ranking effectiveness, XSS negative/control behavior, SQLi ranking effectiveness, and SQLi direct verifier/classification behavior. The evidence supports a cautious statement that the model-backed ranking benefit observed in the XSS ranking study is not universal across evaluated vulnerability categories: in SQLi, both GPT and Qwen have lower descriptive MRR than the deterministic structural ranker under the frozen valid-observation denominators. This remains a scoped descriptive conclusion, not a general model-quality or statistical-significance claim.

## Claims to Avoid

- Do not compute XSS v1.4 false-positive rate or specificity from ranking-only negative packs.
- Do not treat repeated model trials as independent benchmark scenarios.
- Do not equate SQLi runtime inconclusive outcomes with false negatives except under the frozen post-run classification mapping.
- Do not claim broad superiority or inferiority of GPT, Qwen, or deterministic ranking beyond the frozen evaluation settings.

## Validation

- Evidence-input checksum validation: `PASS`
- Derived package validation: `PASS`
- New experimental calls: `0`

All evidence-bearing v1.3.1 normalized/control artifacts used in this analysis passed source-integrity validation. The retained v1.3.1 package has two checksum mismatches in presentation-only artifacts: `results/xss-v13-ablation-v1.3.1-final/canonical/analysis-report.md` and `results/xss-v13-ablation-v1.3.1-final/canonical/figures/ranking-metrics-valid-only.pdf`. These files were not used to derive the Comment 4 numerical findings. This legacy package-level provenance limitation is retained transparently and does not affect the validated evidence inputs used here.
