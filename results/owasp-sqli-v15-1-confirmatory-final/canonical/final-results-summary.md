# v1.5.1 OWASP SQLi Final Results Summary

This canonical package summarizes the completed fresh v1.5.1 OWASP Benchmark SQLi confirmatory execution. It is derived only from the retained raw and normalized artifacts in `results/owasp-sqli-v15-1-confirmatory-final/owasp-sqli-v15-1-confirmatory-20260823T131208Z` and the frozen post-run scoring data in `results/owasp-sqli-v15-protocol-freeze/ground-truth/scoring-data.json`.

## Execution Integrity

- deterministic ranking rows: `124/124`
- GPT ranking rows: `620/620`
- Qwen ranking rows: `620/620`
- total ranking rows: `1364/1364`
- direct SQLi cases: `200/200`
- direct HTTP requests: `1200/1200`
- raw run checksum validation: `PASS`

## Ranking Results

Ranking effectiveness is calculated over valid positive-scenario observations only. Failed or malformed model outputs are retained in reliability denominators and excluded from valid ranking-performance aggregates. Negative-only scenarios do not have vulnerable-candidate rank, Top-1, Top-4 or MRR denominators.

| Arm | n | Top-1 | Top-4 | MRR |
|---|---:|---:|---:|---:|
| deterministic structural | 105 | 20/105 = 19.05% | 91/105 = 86.67% | 0.4552 |
| GPT | 522 | 99/522 = 18.97% | 411/522 = 78.74% | 0.4447 |
| Qwen | 520 | 75/520 = 14.42% | 415/520 = 79.81% | 0.4274 |

## Direct SQLi Results

The direct deterministic SQLi layer completed all 200 final-eligible cases. Ground truth was applied only during post-run scoring.

| Ground truth | Verified | Inconclusive | Rejected |
|---|---:|---:|---:|
| Vulnerable | 84 | 21 | 0 |
| Non-vulnerable | 0 | 95 | 0 |

Full-denominator classification: TP `84`, FP `0`, FN `21`, TN `95`. The vulnerable detection rate is `80.00%`, the false verified rate on non-vulnerable cases is `0.00%`, the inconclusive rate is `58.00%`, and verified-correct over all cases is `42.00%`.

## Scope and Limitations

This package is a confirmatory SQLi evaluation over the frozen v1.5.1 corpus and settings. It does not alter the protocol, candidate snapshots, prompts, probes, verifier criteria or scoring rules. Cost-per-finding remains `not_available` because the frozen protocol did not include a numeric pricing basis. The high inconclusive count reflects the intentionally strict non-destructive boolean-differential verifier: cases without stable reproducible true/false differences are not upgraded to verified findings.
