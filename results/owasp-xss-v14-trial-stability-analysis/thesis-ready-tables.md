# Thesis-Ready Tables: v1.4 Repeated-Trial Stability

## Headline Context

| Arm | Top-1 | Top-4 | MRR |
| --- | ---: | ---: | ---: |
| Deterministic | 0.2034 | 0.7881 | 0.4573 |
| GPT | 0.2332 | 0.7812 | 0.4732 |
| Qwen | 0.2468 | 0.8298 | 0.4926 |

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

## Pairwise Agreement

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

## Reliability

| Arm | Expected rows | Actual rows | Contract-valid | Contract-invalid | Provider-failed | Malformed | Timeout | Retries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT | 1330 | 1330 | 1329 | 1 | 1 | 0 | 0 | 0 |
| Qwen | 1330 | 1330 | 1325 | 5 | 0 | 5 | 0 | 0 |
