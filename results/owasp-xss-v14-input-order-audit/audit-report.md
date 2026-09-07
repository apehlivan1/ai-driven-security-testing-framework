# OWASP XSS v1.4 Input-Order Dependence Audit

This is a derived post-run audit of the completed OWASP XSS v1.4 confirmatory ranking evaluation. It uses only retained artifacts and does not rerun deterministic, GPT, Qwen, HTTP, browser, verifier, benchmark, or scored experimental calls.

## Data Sources

- `results/owasp-xss-v14-protocol-freeze/candidate-ordering.csv`
- `results/owasp-xss-v14-protocol-freeze/model-facing/candidate-snapshot-index.json`
- `results/owasp-xss-v14-protocol-freeze/ground-truth/scoring-data.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/scored-rows.json`
- `results/owasp-xss-v14-confirmatory-final/canonical/normalized/reliability-aggregates.json`

The authoritative input order is taken from `candidate-ordering.csv` and checked against the model-facing candidate snapshots. Ground truth is used only after execution to identify the vulnerable candidate's initial input position for positive scenarios.

## Validation

- Total scenarios: `266`.
- Positive scenarios: `236`.
- Negative-only scenarios: `30`.
- Candidate count per scenario: `5`.
- Valid ranking candidate-set mismatches: `0`.
- Spearman unit check: identical order `rho = 1.0`; reversed order `rho = -1.0`.

Valid/invalid observations by arm:

| Arm | Valid | Invalid |
| --- | ---: | ---: |
| `deterministic_structural` | 266 | 0 |
| `proprietary_gpt` | 1329 | 1 |
| `local_qwen` | 1325 | 5 |

## Input-Output Spearman Correlation: All Valid Scenarios

| Arm | Valid observations | Mean rho | Median rho | Std. dev. | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 266 | -0.0071 | -0.1000 | 0.5220 | -1.0000 | 1.0000 |
| `proprietary_gpt` | 1329 | 0.3223 | 0.4000 | 0.4725 | -0.9000 | 1.0000 |
| `local_qwen` | 1325 | 0.3506 | 0.4000 | 0.5040 | -1.0000 | 1.0000 |

## Input-Output Spearman Correlation: Positive Scenarios Only

| Arm | Valid observations | Mean rho | Median rho | Std. dev. | Min | Max |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 236 | -0.0225 | -0.1000 | 0.5302 | -1.0000 | 1.0000 |
| `proprietary_gpt` | 1179 | 0.3131 | 0.4000 | 0.4783 | -0.9000 | 1.0000 |
| `local_qwen` | 1175 | 0.3421 | 0.4000 | 0.5093 | -1.0000 | 1.0000 |

## Vulnerable Candidate Initial Position

| Initial position | Count | Percentage |
| ---: | ---: | ---: |
| 1 | 44 | 0.1864 |
| 2 | 44 | 0.1864 |
| 3 | 62 | 0.2627 |
| 4 | 51 | 0.2161 |
| 5 | 35 | 0.1483 |

Denominator: `236` unique positive scenarios. Each positive scenario has exactly one focal vulnerable candidate.

## Qwen Exact Input-Order Preservation

| Scope | Trial exact matches | Valid trial denominator | Trial match rate | Scenario exact matches | Scenario denominator | Scenario match rate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| All scenarios | 275 | 1325 | 0.2075 | 55 | 265 | 0.2075 |
| Positive only | 235 | 1175 | 0.2000 | 47 | 235 | 0.2000 |

Within-scenario Qwen valid ranking identity:

| Scope | Scenarios with valid Qwen rankings | Identical valid rankings within scenario | Non-identical |
| --- | ---: | ---: | ---: |
| All scenarios | 265 | 265 | 0 |
| Positive only | 235 | 235 | 0 |

## Supplementary Candidate-ID Order Check

Candidate IDs are sorted by their stored opaque prefix and trailing numeric component, for example `ox14-c000001` before `ox14-c000002`. This diagnostic is supplementary and is not mixed with the required input-order analysis.

| Scope | Valid Qwen observations | Ascending exact count | Ascending exact rate | Descending exact count | Descending exact rate | Mean Spearman vs ascending ID | Median Spearman vs ascending ID |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All scenarios | 1325 | 50 | 0.0377 | 20 | 0.0151 | -0.0151 | 0.0000 |
| Positive only | 1175 | 45 | 0.0383 | 15 | 0.0128 | -0.0289 | -0.1000 |

## Interpretation

The Qwen input-output Spearman correlation is low on average and its exact input-order match rate is very low. This provides evidence against a simple explanation that Qwen's stable repeated rankings are primarily copied from the supplied input order. Qwen valid repeated rankings are nevertheless identical within each scenario, so the audit supports the prior reliability observation that Qwen behaved deterministically or near-deterministically under the retained local runtime configuration.

The vulnerable candidate's initial position distribution is not concentrated at the first position. The distribution is not perfectly uniform, but it does not indicate that vulnerable candidates were systematically placed early enough to explain Qwen's ranking behavior by input-order copying alone.

The supplementary candidate-ID diagnostic also does not show a high exact match rate to ascending or descending candidate-ID order. These checks do not establish model superiority or causality; they only address whether retained rankings are trivially explained by preserved input order or simple candidate-ID order.
