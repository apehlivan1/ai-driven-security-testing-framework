# Professor Comment 1 Closure Analysis: Original OWASP XSS v1.4

This is a derived post-run audit of the original frozen OWASP XSS v1.4 evaluation. It does not modify v1.4 or v1.4.1 frozen/canonical artifacts and performs zero GPT, Qwen, deterministic-ranking, HTTP, browser, discovery, verifier or scored calls.

## Random Reference

| Metric | Random reference | Original deterministic v1.4 | Difference observed - random |
| --- | ---: | ---: | ---: |
| Top-1 | 0.2000 | 0.2034 | +0.0034 |
| Top-2 | 0.4000 | 0.4153 | +0.0153 |
| Top-4 | 0.8000 | 0.7881 | -0.0119 |
| MRR | 0.4567 | 0.4573 | +0.0006 |

The analytically expected random reference follows from the verified positive-scenario structure: each positive scenario has five candidates and exactly one vulnerable candidate. Under uniform random ranking, Top-1 is 1/5 = 0.2000, Top-2 is 2/5 = 0.4000, Top-4 is 4/5 = 0.8000 and expected MRR is mean(1, 1/2, 1/3, 1/4, 1/5) = 0.4567.

## Pre-Tiebreak Discrimination

| Scenario subset | 1 distinct | 2 distinct | 3 distinct | 4 distinct | 5 distinct | All five tied | Partly tie-broken |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All scenarios | 30 (11.28%) | 153 (57.52%) | 83 (31.20%) | 0 (0.00%) | 0 (0.00%) | 30 (11.28%) | 266 (100.00%) |
| Positive | 27 (11.44%) | 135 (57.20%) | 74 (31.36%) | 0 (0.00%) | 0 (0.00%) | 27 (11.44%) | 236 (100.00%) |
| Negative-only | 3 (10.00%) | 18 (60.00%) | 9 (30.00%) | 0 (0.00%) | 0 (0.00%) | 3 (10.00%) | 30 (100.00%) |

Positive scenarios where the vulnerable candidate received no pre-tiebreak discrimination from all four distractors: 27 (11.44%).

Evidence-based verdict: The original v1.4 deterministic ranker discriminates among many OWASP candidates before its final stable tiebreak.

## Vulnerable-Candidate Pre-Tiebreak Alignment

Requested alignment flags:

| Alignment flag | Count | Percentage |
| --- | ---: | ---: |
| Strictly highest | 0 | 0.00% |
| Tied for highest | 151 | 63.98% |
| Neither highest nor lowest / middle | 13 | 5.51% |
| Tied in a middle score class | 4 | 1.69% |
| Strictly lowest | 27 | 11.44% |
| Tied for lowest | 68 | 28.81% |

Exclusive alignment buckets:

| Exclusive bucket | Count | Percentage |
| --- | ---: | ---: |
| Strictly highest | 0 | 0.00% |
| Tied for highest | 124 | 52.54% |
| Middle, unique score | 13 | 5.51% |
| Middle, tied score class | 4 | 1.69% |
| Strictly lowest | 27 | 11.44% |
| Tied for lowest | 41 | 17.37% |
| All candidates tied | 27 | 11.44% |

Distractors sharing the vulnerable candidate's score:

| Distractors sharing score | Count | Percentage |
| ---: | ---: | ---: |
| 0 | 40 | 16.95% |
| 1 | 50 | 21.19% |
| 2 | 53 | 22.46% |
| 3 | 66 | 27.97% |
| 4 | 27 | 11.44% |

Vulnerable candidate score-class rank among distinct classes:

| Score-class rank | Count | Percentage |
| ---: | ---: | ---: |
| 1 | 151 | 63.98% |
| 2 | 64 | 27.12% |
| 3 | 21 | 8.90% |

Pre-tiebreak scoring alone places the vulnerable candidate in the best score class in 151 of 236 positive scenarios (63.98%) and in the worst score class in 95 scenarios (40.25%). The requested tied-for-highest and tied-for-lowest categories are non-exclusive for all-five-tied scenarios.

The original deterministic scoring frequently creates structural score differences, but it never assigns the vulnerable candidate a strictly highest score over all four distractors. Many best-score-class placements are shared ties, and worst-score-class placement is also substantial. This indicates weak alignment between the original structural score and OWASP XSS vulnerability status.

## Candidate-Pack Construction and Reuse

- Eligible unique candidates: 388
- Vulnerable unique candidates: 236
- Non-vulnerable unique candidates: 152
- Positive scenarios: 236
- Negative-only scenarios: 30
- Positive-scenario distractor placements: 944
- Negative-only placements: 150
- Total non-vulnerable placements across all packs: 1094
- Unique non-vulnerable candidates used: 152
- Unused non-vulnerable candidates: 0

Positive decoy reuse counts: min 6, max 7, mean 6.2105, median 6.0. Total non-vulnerable placement counts: min 6, max 8, mean 7.1974, median 7.0.

The frozen construction uses a deterministic balanced round-robin over a SHA-256-sorted negative pool for positive-scenario decoys. Negative-only scenarios use disjoint packs of five from the same sorted negative pool, with two leftover negatives recorded and not used in negative-only packs. Candidate order within each pack is SHA-256-based, but the original deterministic ranker re-sorts candidates; when scores tie, its own stable tiebreak over action URL, parameter name, source and candidate ID determines relative ordering.

## Validation

- Validation valid: True
- Source checksum errors: 0
- Deterministic raw rows checked: 266
- Deterministic raw rows covered by raw checksum: 266
- Raw source-integrity verdict: verified_source_integrity
- New experimental/scored calls: 0
