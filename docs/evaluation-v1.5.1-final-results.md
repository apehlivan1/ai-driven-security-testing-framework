# v1.5.1 OWASP SQLi Final Results

This document summarizes the final canonicalized v1.5.1 OWASP Benchmark SQLi
confirmatory evidence. The authoritative machine-readable evidence is the
canonical package at:

`results/owasp-sqli-v15-1-confirmatory-final/canonical/`

The canonical package was generated offline from the completed raw run:

`results/owasp-sqli-v15-1-confirmatory-final/owasp-sqli-v15-1-confirmatory-20260823T131208Z/`

The raw run remains immutable source evidence and was not modified during
canonicalization. Ground truth was applied only during post-run scoring from the
frozen protocol package:

`results/owasp-sqli-v15-protocol-freeze/ground-truth/scoring-data.json`

## Integrity Summary

The final v1.5.1 execution completed the frozen denominators:

| Area | Expected | Observed |
|---|---:|---:|
| deterministic ranking rows | 124 | 124 |
| GPT ranking rows | 620 | 620 |
| Qwen ranking rows | 620 | 620 |
| total ranking rows | 1364 | 1364 |
| direct SQLi cases | 200 | 200 |
| direct HTTP requests | 1200 | 1200 |

The canonical validation report records `PASS`. The raw run checksum validation
from the completed execution checked 5898 files with 0 bad and 0 missing.

## Ranking Results

Ranking effectiveness is reported only over valid positive-scenario ranking
observations. Failed and malformed model outputs remain in the reliability
denominators and are excluded from valid ranking-performance aggregates.
Negative-only scenarios do not have vulnerable-candidate rank, Top-1, Top-4 or
MRR denominators.

| Arm | Valid positive observations | Top-1 | Top-4 | MRR |
|---|---:|---:|---:|---:|
| deterministic structural | 105 | 20/105 = 19.05% | 91/105 = 86.67% | 0.4552 |
| GPT | 522 | 99/522 = 18.97% | 411/522 = 78.74% | 0.4447 |
| Qwen | 520 | 75/520 = 14.42% | 415/520 = 79.81% | 0.4274 |

Reliability outcomes were:

| Arm | Scheduled | Valid | Malformed | Provider/runtime failed | Timeouts |
|---|---:|---:|---:|---:|---:|
| deterministic structural | 124 | 124 | 0 | 0 | 0 |
| GPT | 620 | 617 | 0 | 3 | 1 |
| Qwen | 620 | 615 | 5 | 0 | 0 |

GPT token usage was recorded for 617 valid provider responses: 380101 input
tokens, 178496 output tokens and 558597 total tokens. Cost remains
`not_available` because the frozen protocol did not include a numeric pricing
basis.

## Direct SQLi Results

The direct deterministic SQLi validation layer completed all 200 frozen
final-eligible cases. Runtime verification produced 84 verified outcomes and
116 inconclusive outcomes. No rejected findings and no runtime/transport errors
were observed.

| Ground truth | Verified | Inconclusive | Rejected |
|---|---:|---:|---:|
| vulnerable | 84 | 21 | 0 |
| non-vulnerable | 0 | 95 | 0 |

The frozen post-run classification is TP 84, FP 0, FN 21 and TN 95. The
vulnerable detection rate is 80.00%, the false verified rate on non-vulnerable
cases is 0.00%, the inconclusive rate is 58.00%, and verified-correct over all
cases is 84/200 = 42.00%.

## Interpretation Boundary

These results are valid for the frozen v1.5.1 OWASP Benchmark SQLi
confirmatory study and the constrained candidate-ranking task evaluated here.
They do not modify or supersede the earlier v1.2, v1.3.1 or v1.4 evidence.
The interrupted v1.5 run remains failed/aborted execution evidence only and was
not reused in this final package.
