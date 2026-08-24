# v1.5.1 OWASP SQLi Thesis Tables

## Ranking Effectiveness on Valid Positive Scenario Observations

| Arm | n | Top-1 | Top-4 | MRR |
|---|---:|---:|---:|---:|
| deterministic structural | 105 | 20/105 = 19.05% | 91/105 = 86.67% | 0.4552 |
| GPT | 522 | 99/522 = 18.97% | 411/522 = 78.74% | 0.4447 |
| Qwen | 520 | 75/520 = 14.42% | 415/520 = 79.81% | 0.4274 |

## Ranking Reliability

| Arm | Scheduled | Valid | Malformed | Provider/runtime failed | Timeouts |
|---|---:|---:|---:|---:|---:|
| deterministic structural | 124 | 124 | 0 | 0 | 0 |
| GPT | 620 | 617 | 0 | 3 | 1 |
| Qwen | 620 | 615 | 5 | 0 | 0 |

## Direct SQLi Verification Outcomes

| Ground truth | Verified | Inconclusive | Rejected | Total |
|---|---:|---:|---:|---:|
| vulnerable | 84 | 21 | 0 | 105 |
| non_vulnerable | 0 | 95 | 0 | 95 |

## Direct SQLi Full-Denominator Summary

| Metric | Value |
|---|---:|
| TP / FP / FN / TN | 84 / 0 / 21 / 95 |
| Vulnerable detection rate | 84/105 = 80.00% |
| False verified rate on non-vulnerable cases | 0/95 = 0.00% |
| Inconclusive rate | 116/200 = 58.00% |
| Verified-correct over all cases | 84/200 = 42.00% |

Cost-per-finding remains `not_available` because the frozen protocol did not include a numeric pricing basis.
