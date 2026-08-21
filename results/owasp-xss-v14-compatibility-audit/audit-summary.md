# OWASP Benchmark XSS v1.4 Compatibility Audit Summary

Status: non-scored compatibility audit. No GPT, Qwen, browser verification or final ranking experiment was executed.

## Benchmark Provenance

- Official remote: `https://github.com/OWASP-Benchmark/BenchmarkJava`
- Declared benchmark version: `1.2`
- Pinned Git revision: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f`
- Repository status: `clean`
- Expected-results file: `expectedresults-1.2.csv`
- Expected-results SHA-256: `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`

## XSS Population

- Total XSS cases: `455`
- Vulnerable XSS cases: `246`
- Non-vulnerable XSS cases: `209`

## HTTP Method Distribution

| Value | Count |
| --- | ---: |
| `GET_delegates_to_POST` | 455 |

## Input Source Distribution

| Value | Count |
| --- | ---: |
| `header` | 87 |
| `no_external_input` | 47 |
| `parameter` | 152 |
| `parameter_map` | 55 |
| `parameter_name_enumeration` | 54 |
| `query_string` | 60 |

## Compatibility Distribution

| Class | Total | Vulnerable | Negative |
| --- | ---: | ---: | ---: |
| `ADAPTER_SUPPORTED` | 141 | 89 | 52 |
| `DERIVED_ADAPTED` | 0 | 0 | 0 |
| `DIRECT` | 267 | 157 | 110 |
| `EXCLUDED` | 47 | 0 | 47 |

## Evaluation Role Distribution

| Class | Total | Vulnerable | Negative |
| --- | ---: | ---: | ---: |
| `EXCLUDED` | 47 | 0 | 47 |
| `FINAL_CONFIRMATORY_ELIGIBLE` | 388 | 236 | 152 |
| `READINESS_ONLY` | 20 | 10 | 10 |

## Projected Compatibility

- Currently usable original cases: `267`
- Projected usable original cases after justified deterministic adapters: `408`
- Projected usable vulnerable cases after adapters: `246`
- Projected usable negative cases after adapters: `162`
- READINESS_ONLY cases: `20`
- FINAL_CONFIRMATORY_ELIGIBLE cases: `388`
- FINAL_CONFIRMATORY_ELIGIBLE vulnerable cases: `236`
- FINAL_CONFIRMATORY_ELIGIBLE negative cases: `152`

## Required Adapters

| Value | Count |
| --- | ---: |
| `header_input` | 87 |
| `parameter_name_value_adapter` | 54 |

## Candidate Representation Gaps

| Value | Count |
| --- | ---: |
| `dynamic_parameter_name_and_value_transport` | 54 |
| `header_name_transport` | 87 |
| `input_source_header` | 87 |

## Verifier and Payload Compatibility

| Value | Count |
| --- | ---: |
| `current_marker_control_likely_sufficient` | 455 |

## Ranking Scale Projections

| Pack size | Positive scenarios | Negative scenarios | Mean decoy reuse | Max decoy reuse | Unique cases represented | Candidate tests/arm |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 246 | 32 | 6.074074074074074 | 7 | 408 | 1112 |
| 6 | 246 | 27 | 7.592592592592593 | 8 | 408 | 1092 |
| 8 | 246 | 20 | 10.62962962962963 | 11 | 408 | 1064 |

Recommended candidate pack size: `5`.
Recommended candidate-test budget: `k=4`.

## Trial Count and Runtime Projections

| LLM trials/scenario | GPT calls | Qwen calls | Total rows | GPT hours reference | Qwen hours reference | Qwen days reference |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 278 | 278 | 834 | 0.347 | 6.394 | 0.266 |
| 3 | 834 | 834 | 1946 | 1.042 | 19.182 | 0.799 |
| 5 | 1390 | 1390 | 3058 | 1.738 | 31.97 | 1.332 |

Recommended final LLM trial count: `5`.

## Direct External Execution

- Current direct execution cases: `267`
- Projected direct execution cases after adapters: `408`

## Validation

- Valid: `True`
- Errors: `0`
- Warnings: `0`

## Next Implementation Recommendation

Implement deterministic v1.4 compatibility extensions for metadata-constructed OWASP XSS candidates, header/cookie/parameter-name transports, opaque sanitization, and non-scored runtime readiness probes before freezing an executable protocol.
