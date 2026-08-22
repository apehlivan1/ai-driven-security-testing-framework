# OWASP XSS v1.4 Confirmatory Canonical Analysis

Status: post-run deterministic scoring and analysis only. No scored observations were rerun or modified.

## Integrity

- Execution complete: `True`
- Completed rows: `2926`
- Missing rows: `0`
- Protocol hash matches: `True`
- Protocol package checksum errors: `0`
- Raw ground-truth leak count: `0`

## Ranking Results

| Arm | Positive valid rows | Top-1 | Top-k | MRR | Contract-valid outputs | Invalid/failure outputs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 236 | 0.2034 | 0.7881 | 0.4573 | 266 | 0 |
| `proprietary_gpt` | 1179 | 0.2332 | 0.7812 | 0.4732 | 1329 | 1 |
| `local_qwen` | 1175 | 0.2468 | 0.8298 | 0.4926 | 1325 | 5 |

Negative-only scenarios do not have Top-1, Top-k or MRR denominators. No direct execution/verifier false-positive evidence was produced in this ranking-only v1.4 run.

## v1.3.1 Comparison

The v1.3.1 and v1.4 denominators are kept separate. The external OWASP v1.4 benchmark substantially changes the candidate distribution and scale, so the comparison is descriptive rather than pooled.

## Interpretation

The v1.4 results should be interpreted for the frozen OWASP Benchmark XSS candidate-ranking task only. They do not establish general model superiority or autonomous penetration-testing capability.
