# Professor Comment 2 Closure Analysis: v1.4 Repeated-Trial Stability

This is a derived post-run stability audit of the original frozen OWASP XSS v1.4 evaluation. It performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier or scored calls and does not modify frozen/canonical v1.4 or v1.4.1 artifacts.

## Headline Metrics Context

| Arm | Top-1 | Top-4 | MRR |
| --- | ---: | ---: | ---: |
| deterministic | 0.2034 | 0.7881 | 0.4573 |
| GPT | 0.2332 | 0.7812 | 0.4732 |
| Qwen | 0.2468 | 0.8298 | 0.4926 |

These values are reproduced only as descriptive context. This audit does not perform a model-superiority test.

## Exact Complete-Ranking Stability

| Arm | Subset | Scenarios | Valid trials | Invalid/failed trials | 1 unique ranking | 2 | 3 | 4 | 5 | All five identical | At least one valid ranking differs |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | all | 266 | 1329 | 1 | 91 (34.21%) | 99 (37.22%) | 55 (20.68%) | 20 (7.52%) | 1 (0.38%) | 91 (34.21%) | 175 (65.79%) |
| GPT | positive | 236 | 1179 | 1 | 80 (33.90%) | 88 (37.29%) | 50 (21.19%) | 17 (7.20%) | 1 (0.42%) | 80 (33.90%) | 156 (66.10%) |
| GPT | negative_only | 30 | 150 | 0 | 11 (36.67%) | 11 (36.67%) | 5 (16.67%) | 3 (10.00%) | 0 (0.00%) | 11 (36.67%) | 19 (63.33%) |
| Qwen | all | 266 | 1325 | 5 | 265 (99.62%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 265 (99.62%) | 0 (0.00%) |
| Qwen | positive | 236 | 1175 | 5 | 235 (99.58%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 235 (99.58%) | 0 (0.00%) |
| Qwen | negative_only | 30 | 150 | 0 | 30 (100.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 0 (0.00%) | 30 (100.00%) | 0 (0.00%) |

## Vulnerable-Candidate Rank Stability

| Arm | Positive scenarios | Stable identical rank | Varies by 1 | Varies by >=2 | Incomplete rank trials | Rank stdev mean | Rank stdev max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | 236 | 113 (47.88%) | 51 (21.61%) | 71 (30.08%) | 1 (0.42%) | 0.4266 | 1.9596 |
| Qwen | 236 | 235 (99.58%) | 0 (0.00%) | 0 (0.00%) | 1 (0.42%) | 0.0000 | 0.0000 |

## Pairwise Within-Scenario Agreement

| Arm | Subset | Valid pairs | Exact agreement | Scenario mean exact agreement | Mean Spearman | Mean Kendall tau | Vulnerable-rank pair agreement |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | all | 2656 | 0.6005 | 0.5999 | 0.7402 | 0.7344 | not_applicable |
| GPT | positive | 2356 | 0.5980 | 0.5973 | 0.7393 | 0.7326 | 0.7101 |
| GPT | negative_only | 300 | 0.6200 | 0.6200 | 0.7473 | 0.7480 | not_applicable |
| Qwen | all | 2650 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | not_applicable |
| Qwen | positive | 2350 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Qwen | negative_only | 300 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | not_applicable |

## Threshold Consistency

| Arm | Threshold | 0/5 | 1/5 | 2/5 | 3/5 | 4/5 | 5/5 | Incomplete scenarios |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | Top-1 | 154 | 16 | 11 | 11 | 16 | 28 | 1 |
| GPT | Top-2 | 98 | 20 | 24 | 15 | 24 | 55 | 1 |
| GPT | Top-4 | 39 | 5 | 5 | 7 | 15 | 165 | 1 |
| Qwen | Top-1 | 178 | 0 | 0 | 0 | 0 | 58 | 1 |
| Qwen | Top-2 | 131 | 0 | 0 | 0 | 0 | 105 | 1 |
| Qwen | Top-4 | 41 | 0 | 0 | 0 | 0 | 195 | 1 |

## Reciprocal-Rank Variability

| Arm | Positive scenarios | With valid RR | Mean scenario-mean RR | Mean within-scenario RR stdev | Max RR range |
| --- | ---: | ---: | ---: | ---: | ---: |
| GPT | 236 | 236 | 0.4733 | 0.0869 | 0.8000 |
| Qwen | 236 | 235 | 0.4926 | 0.0000 | 0.0000 |

The original GPT trial-row-weighted MRR is 0.4732, while the mean of per-scenario mean reciprocal rank is 0.4733. This small difference is expected because one positive GPT scenario has only four valid trials. Professor Comment 3 should use the per-scenario mean reciprocal-rank dataset so that each scenario remains the independent unit and receives equal weight.

## Reliability and Invalid-Output Handling

| Arm | Expected rows | Actual rows | Contract-valid | Contract-invalid | Provider-failed | Malformed | Timeout | Retries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | 1330 | 1330 | 1329 | 1 | 1 | 0 | 0 | 0 |
| Qwen | 1330 | 1330 | 1325 | 5 | 0 | 5 | 0 | 0 |

Invalid or failed terminal outcomes are retained in reliability denominators and were not retried. They do not provide valid complete rankings, so they are excluded from complete-ranking, vulnerable-rank, threshold and reciprocal-rank stability denominators while remaining visible as incomplete scenarios.

## Interpretation

GPT showed material variability in exact complete rankings despite substantial ordinal agreement across trials: its complete rankings differed in a majority of scenarios, while positive-scenario pairwise agreement remained substantial by rank correlation (mean Spearman 0.7393; Kendall tau 0.7326). Repeated GPT trials therefore provide useful information about within-scenario model variability, and averaging can reduce measurement noise for a scenario-level expected ranking estimate, but the trials do not create additional independent benchmark scenarios.

Qwen showed a different stability profile. All valid repeated rankings were identical within scenario: 235 positive scenarios had five valid identical rankings, while one positive scenario had five malformed terminal outputs and no valid ranking. Repeated Qwen trials therefore contributed evidence of stability and reliability, but essentially no additional within-scenario ranking variation from which independent precision could be obtained.

The five repeated LLM trials therefore provide information about model variability and reliability, but they do not increase the independent experimental unit beyond the scenario level. The independent unit remains the 236 positive scenarios for ranking-performance comparisons.

## Source Integrity

- Source-integrity verdict: `verified_source_integrity`
- Ranking rows checked: `2660`
- Rows covered by raw checksum: `2660`
- Raw checksum errors: `0`
- Canonical checksum errors: `0`
- Missing sequences: `0`
- Duplicate sequences: `0`

## Validation

- Validation valid: `True`
- New experimental/scored calls: `0`
