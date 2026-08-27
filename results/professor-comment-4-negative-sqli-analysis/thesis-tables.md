# Professor Comment 4 Thesis-Ready Tables

## XSS Negative/Control Evidence

| Evidence source | Arm | Scenarios | Rows | Valid rows | FP/specificity status |
| --- | --- | ---: | ---: | ---: | --- |
| OWASP XSS v1.4 negative-only ranking | deterministic_structural | 30 | 30 | 30 | not applicable for ranking-only outputs |
| OWASP XSS v1.4 negative-only ranking | proprietary_gpt | 30 | 150 | 150 | not applicable for ranking-only outputs |
| OWASP XSS v1.4 negative-only ranking | local_qwen | 30 | 150 | 150 | not applicable for ranking-only outputs |
| XSS v1.3.1 eight negative controls | deterministic_structural | 8 | 8 | not_applicable | FPR 0.0000; specificity 1.0000 |
| XSS v1.3.1 eight negative controls | proprietary_gpt | 8 | 40 | not_applicable | FPR 0.0000; specificity 1.0000 |
| XSS v1.3.1 eight negative controls | local_qwen | 8 | 40 | not_applicable | FPR 0.0000; specificity 1.0000 |

## SQLi Ranking Results

| Arm | Valid positive n | Top-1 | Top-4 | MRR | Reliability |
| --- | ---: | ---: | ---: | ---: | --- |
| deterministic_structural | 105 | 20/105 = 0.1905 | 91/105 = 0.8667 | 0.4552 | valid 124/124; malformed 0; provider-failed 0 |
| proprietary_gpt | 522 | 99/522 = 0.1897 | 411/522 = 0.7874 | 0.4447 | valid 617/620; malformed 0; provider-failed 3 |
| local_qwen | 520 | 75/520 = 0.1442 | 415/520 = 0.7981 | 0.4274 | valid 615/620; malformed 5; provider-failed 0 |

## SQLi Direct Classification

| Ground truth | Verified | Inconclusive | Rejected | Post-run classification |
| --- | ---: | ---: | ---: | --- |
| Vulnerable | 84 | 21 | 0 | TP=84, FN=21 |
| Non-vulnerable | 0 | 95 | 0 | FP=0, TN=95 |

## SQLi Classification Metrics

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
