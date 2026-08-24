# v1.5.1 OWASP SQLi Post-Run Integrity Audit

This document records the read-only post-run integrity and detection-effectiveness
audit of the completed v1.5.1 OWASP SQLi confirmatory execution. It is a
documentation checkpoint only. Canonicalization has not yet been performed.

## Run and Provenance

- Authoritative run path:
  `results/owasp-sqli-v15-1-confirmatory-final/owasp-sqli-v15-1-confirmatory-20260823T131208Z`
- Execution timestamp: `2026-08-23T13:12:08Z`
- Post-run manifest timestamp: `2026-08-24T03:03:35Z`
- Protocol amendment: `evaluation-protocol-v1.5.1`
- Amendment SHA-256:
  `74085e88c3e57c8cab025dad69698b3b15587fde721eefa3df6cc2d3160dbb10`
- Base v1.5 protocol SHA-256:
  `22f90d9794c796c20e27654662ee893d1fa533bfef16fb87912f18154dac8033`
- Frozen package:
  `results/owasp-sqli-v15-protocol-freeze`

During the post-run audit, the checkout was observed at Git commit
`5905981f54da023faaf80c4bff12fc9e9e671e38`, with tag
`evaluation-protocol-v1.5.1-ready` pointing at that commit. This Git provenance
was observed from the repository checkout during audit. The original execution
manifest records the run, protocol and package metadata, but it does not embed
the Git commit SHA itself.

This run is the fresh v1.5.1 execution. The earlier interrupted v1.5 run in
`results/owasp-sqli-v15-confirmatory-final/` remains failed/aborted execution
evidence and was not reused.

## Integrity Results

| Area | Expected | Observed | Status |
|---|---:|---:|---|
| deterministic ranking | 124 | 124 / 124 | PASS |
| GPT ranking | 620 | 620 / 620 | PASS |
| Qwen ranking | 620 | 620 / 620 | PASS |
| total ranking rows | 1364 | 1364 / 1364 | PASS |
| direct SQLi cases | 200 | 200 / 200 | PASS |
| HTTP requests | 1200 | 1200 / 1200 | PASS |
| duplicate/missing ranking sequences | 0 | 0 | PASS |
| duplicate direct cases | 0 | 0 | PASS |
| ground-truth runtime leakage found | 0 | 0 | PASS |
| checksums | 5898 checked | 0 bad, 0 missing | PASS |
| aborted v1.5 contamination | 0 | 0 | PASS |

Integrity verdict: **PASS**.

## GPT Reliability

- Scheduled/attempted calls: `620`
- Valid outputs: `617`
- Provider failures: `3`
- Malformed/schema-invalid outputs: `0`
- Timeouts: `1`, included among provider failures
- Retries/duplicates: `0`
- Provider response IDs: `617`
- Usage records: `617`
- Input tokens: `380101`
- Output tokens: `178496`
- Total tokens: `558597`
- Cost: not available

The three failed GPT rows were retained as failed observations. They were not
silently retried, repaired or discarded.

## Qwen Reliability

- Scheduled/attempted calls: `620`
- Valid outputs: `615`
- Malformed outputs: `5`
- Runtime/provider failures: `0`
- Timeouts: `0`
- Retries/duplicates: `0`
- Malformed-output concentration: all five malformed observations belong to
  `os15-s0033`
- Duplicate candidate in malformed outputs: `os15-c000388`
- Omitted candidate in malformed outputs: `os15-c000216`
- Median latency: approximately `70.1 s`
- Maximum latency: approximately `166.6 s`

The malformed Qwen rows were retained as malformed observations. They were not
silently repaired or converted into valid ranking evidence.

## Ranking Results

The following ranking results are calculated over valid positive-scenario
observations only. Negative-only scenarios do not have a vulnerable-candidate
rank, Top-1, Top-4 or MRR denominator. Repeated GPT and Qwen trials are repeated
observations nested within scenarios, not independent benchmark cases.

| Arm | n | Top-1 | Top-4 | MRR |
|---|---:|---:|---:|---:|
| deterministic structural | 105 | 20/105 = 19.05% | 91/105 = 86.67% | 0.4552 |
| GPT | 522 | 99/522 = 18.97% | 411/522 = 78.74% | 0.4447 |
| Qwen | 520 | 75/520 = 14.42% | 415/520 = 79.81% | 0.4274 |

In this run, the deterministic structural ranker produced the strongest frozen
SQLi ranking aggregate among the three evaluated arms.

## Direct SQLi Results

The direct deterministic SQLi layer used the frozen post-run scoring data only
after runtime execution was complete.

- Vulnerable ground truth: `105`
- Non-vulnerable ground truth: `95`
- Verified: `84`
- Inconclusive: `116`
- Rejected: `0`
- Runtime/transport errors: `0`

| Ground truth | Verified | Inconclusive | Rejected |
|---|---:|---:|---:|
| Vulnerable | 84 | 21 | 0 |
| Non-vulnerable | 0 | 95 | 0 |
| Total | 84 | 116 | 0 |

Primary full-denominator results:

- Vulnerable detection rate: `84/105 = 80.00%`
- False verified rate on non-vulnerable cases: `0/95 = 0.00%`
- Inconclusive rate: `116/200 = 58.00%`
- Verified-correct over all cases: `84/200 = 42.00%`

Precision, recall and F1 over only the subset receiving binary classifications
are not primary full-denominator effectiveness metrics for this study, because
they exclude the 116 inconclusive cases.

## Adapter Outcomes

| Adapter | Verified | Inconclusive |
|---|---:|---:|
| form | 16 | 16 |
| multi_query | 26 | 23 |
| multi_form | 21 | 40 |
| header | 21 | 19 |
| cookie | 0 | 18 |

## Interpretation

The evaluated capability is the frozen non-destructive reproducible
boolean-differential SQLi slice. No generalization should be made from this run
to other SQLi techniques, including time-based SQLi, error-based SQLi, stacked
queries, destructive/write SQLi or data-extraction attacks.

Transport and execution succeeded for all cases: all 200 direct cases completed,
all 1200 direct HTTP result artifacts were executed, and no runtime or transport
error was recorded. The dominant limiting criterion was absence of
`has_reproducible_boolean_difference`. All direct cases had HTTP exchange
evidence, comparison evidence, passing control cases and stable baseline
behavior; 116 cases were inconclusive because reproducible true/false
differentiation was not satisfied.

No non-vulnerable case was falsely verified. However, all 95 non-vulnerable
cases remained inconclusive rather than receiving a binary safe/rejected
classification.

## Canonicalization Status

Canonicalization status: **REQUIRED AS A SEPARATE OFFLINE MILESTONE**.
