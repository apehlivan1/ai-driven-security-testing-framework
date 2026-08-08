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

## Timing Appendix

Derived only from retained v1.3.1 timestamps. Repeated LLM trials are model trials, not independent scenarios.

| Arm | Valid rows | Verified trials | Median ms | Mean ms | Median requests | Mean requests | Median candidates | Cost per finding |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Deterministic structural | 24 | 11 | 1140 | 1004.818 | 6 | 5.091 | 3 | not_applicable |
| Proprietary GPT | 116 | 56 | 354.5 | 511.268 | 4.0 | 4.714 | 2.0 | not_available |
| Local Qwen | 120 | 55 | 323 | 345.618 | 4 | 4.182 | 2 | not_available |

Negative scenarios and trials with no verifier-confirmed finding use `not_applicable` for time and request-to-first-finding fields.
For LLM arms, model/provider latency is reported separately in provider metrics and is not silently folded into this timestamp-derived table.
Cost per finding remains `not_available` for model arms because no frozen numeric USD pricing basis exists.
