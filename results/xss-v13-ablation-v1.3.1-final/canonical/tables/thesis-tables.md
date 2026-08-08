# Thesis Tables: XSS v1.3.1 Ablation

## Ranking Metrics, Valid Ranking Rows

| Arm | Valid rows | Top-1 accuracy | Top-k recall | MRR |
| --- | ---: | ---: | ---: | ---: |
| Deterministic structural | 24 | 0.2500 | 0.6875 | 0.3854 |
| Proprietary GPT | 116 | 0.2179 | 0.7179 | 0.4060 |
| Local Qwen | 120 | 0.3125 | 0.6875 | 0.4427 |

## Reliability

| Arm | Attempted | Valid | Schema-invalid | Provider failures | Runtime failures | Retries |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Deterministic structural | 24 | 24 | 0 | 0 | 0 | 0 |
| Proprietary GPT | 120 | 116 | 4 | 0 | 0 | 0 |
| Local Qwen | 120 | 120 | 0 | 0 | 0 | 0 |

## End-to-End Classification, All Retained Candidate Tests

| Arm | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| Deterministic structural | 11 | 0 | 0 | 69 |
| Proprietary GPT | 58 | 0 | 0 | 328 |
| Local Qwen | 55 | 0 | 0 | 320 |

## Efficiency

| Metric | Value |
| --- | ---: |
| Time to first verifier-confirmed finding, ms | 8858 |
| Requests to first verifier-confirmed finding | 3 |
| Action requests | 1683 |
| Browser navigations | 1682 |
| HTTP requests | 1 |
