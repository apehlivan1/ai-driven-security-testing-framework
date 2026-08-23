# OWASP Benchmark SQLi v1.5 Compatibility Audit Summary

Status: non-scored static compatibility audit and protocol-design preparation. No SQLi runtime execution, GPT call, Qwen call or scored ranking was performed.

## Corpus Counts

- Total SQLi cases: `504`
- Vulnerable SQLi cases: `272`
- Non-vulnerable SQLi cases: `232`

## Compatibility Distribution

| Value | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `ADAPTER_SUPPORTED` | 220 | 115 | 105 |
| `DERIVED_ADAPTED` | 0 | 0 | 0 |
| `DIRECT` | 0 | 0 | 0 |
| `EXCLUDED` | 127 | 73 | 54 |
| `MANUAL_REVIEW` | 157 | 84 | 73 |

## Input Carrier Distribution

| Value | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `cookie` | 48 | 31 | 17 |
| `formparam` | 97 | 47 | 50 |
| `formparam+formparam` | 57 | 38 | 19 |
| `formparam+formparam+formparam` | 46 | 26 | 20 |
| `formparam+formparam+formparam+formparam` | 50 | 18 | 32 |
| `getparam+getparam+getparam` | 113 | 65 | 48 |
| `header` | 93 | 47 | 46 |

## SQL Operation Distribution

| Value | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `insert` | 70 | 42 | 28 |
| `select_like` | 377 | 199 | 178 |
| `stored_procedure` | 57 | 31 | 26 |

## Read-vs-Write Distribution

| Value | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `read_like` | 377 | 199 | 178 |
| `stored_procedure_ambiguous` | 57 | 31 | 26 |
| `write_or_state_changing` | 70 | 42 | 28 |

## Original-Case Eligibility

- Original OWASP cases potentially usable for direct external evaluation after deterministic adapters: `220`
- Vulnerable among potentially usable original cases: `115`
- Non-vulnerable among potentially usable original cases: `105`
- Cases potentially usable for candidate-ranking evaluation: `220`

## Major Incompatibility Reasons

| Value | Count |
| --- | ---: |
| `read-like SQL detected but static response oracle is insufficient` | 157 |
| `stored procedure behavior cannot be assumed read-only by static audit` | 57 |
| `write/state-changing SQL conflicts with non-destructive verifier philosophy` | 70 |

## Required Adapters

| Value | Count |
| --- | ---: |
| `cookie_adapter` | 48 |
| `form_parameter_adapter` | 250 |
| `header_adapter` | 93 |
| `multi_form_parameter_adapter` | 153 |
| `multi_query_parameter_adapter` | 113 |

## Required Adapters Among Potentially Compatible Original Cases

| Value | Count |
| --- | ---: |
| `cookie_adapter` | 22 |
| `form_parameter_adapter` | 101 |
| `header_adapter` | 44 |
| `multi_form_parameter_adapter` | 65 |
| `multi_query_parameter_adapter` | 53 |

## Preliminary Ranking Scale

| Pack size | Positive scenarios | Negative-only scenarios | Mean decoy reuse | Max decoy reuse | Candidate tests per arm/trial set |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 4 | 115 | 26 | 3.286 | 4 | 564 |
| 5 | 115 | 21 | 4.381 | 5 | 544 |
| 6 | 115 | 17 | 5.476 | 6 | 528 |

Recommended candidate pack size: `5`.
Recommended candidate-test budget: `k=4`.

## Validation

- Valid: `True`
- Errors: `0`
- Warnings: `1`
- SQLi runtime executions: `0`
- GPT calls: `0`
- Qwen calls: `0`

## Recommended Next Milestone

Proceed to `v1.5 SQLi deterministic adapter + READINESS_ONLY validation` only after reviewing this audit. The readiness milestone should implement deterministic transport adapters and dry/runtime-readiness validation on a small stratified non-scored subset, without consuming the final confirmatory corpus.
