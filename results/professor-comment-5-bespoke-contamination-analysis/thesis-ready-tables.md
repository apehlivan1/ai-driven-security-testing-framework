# Professor Comment 5 Thesis-Ready Tables

## Bespoke Scenario-Specific Random Baseline

| Scope | Scenarios | Random Top-1 | Random Top-2 | Random Top-4 | Random MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| All eligible positive bespoke scenarios | 16 | 0.1757 | 0.3515 | 0.7030 | 0.4188 |
| n=4 | 2 | 0.2500 | 0.5000 | 1.0000 | 0.5208 |
| n=5 | 4 | 0.2000 | 0.4000 | 0.8000 | 0.4567 |
| n=6 | 5 | 0.1667 | 0.3333 | 0.6667 | 0.4083 |
| n=7 | 3 | 0.1429 | 0.2857 | 0.5714 | 0.3704 |
| n=8 | 2 | 0.1250 | 0.2500 | 0.5000 | 0.3397 |

## Bespoke Observed-minus-Random Ranking Metrics

| Arm | Valid positive scenario n | Top-1 | Delta vs random | Top-2 | Delta vs random | Top-4 | Delta vs random | MRR | Delta vs random |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic_structural | 16 | 0.2500 | 0.0743 | 0.3125 | -0.0390 | 0.6875 | -0.0155 | 0.3854 | -0.0334 |
| proprietary_gpt | 16 | 0.2250 | 0.0493 | 0.4500 | 0.0985 | 0.7219 | 0.0189 | 0.4604 | 0.0416 |
| local_qwen | 16 | 0.3125 | 0.1368 | 0.3750 | 0.0235 | 0.6875 | -0.0155 | 0.4958 | 0.0770 |

### Top-4 on Positive Scenarios with Candidate Count >4

| Arm | Scenario n | Observed Top-4 | Random Top-4 | Delta |
| --- | ---: | ---: | ---: | ---: |
| deterministic_structural | 14 | 0.6429 | 0.6605 | -0.0177 |
| proprietary_gpt | 14 | 0.6821 | 0.6605 | 0.0216 |
| local_qwen | 14 | 0.6429 | 0.6605 | -0.0177 |

## Public OWASP v1.4 versus Bespoke v1.3.1

| Dataset | Arm | n | Observed Top-1 | Random Top-1 | Delta MRR | Observed MRR | Random MRR |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| public_owasp_xss_v14 | deterministic_structural | 236 | 0.2034 | 0.2000 | 0.0006 | 0.4573 | 0.4567 |
| public_owasp_xss_v14 | proprietary_gpt | 1179 | 0.2332 | 0.2000 | 0.0166 | 0.4732 | 0.4567 |
| public_owasp_xss_v14 | local_qwen | 1175 | 0.2468 | 0.2000 | 0.0359 | 0.4926 | 0.4567 |
| bespoke_xss_v13_1_heldout | deterministic_structural | 16 | 0.2500 | 0.1757 | -0.0334 | 0.3854 | 0.4188 |
| bespoke_xss_v13_1_heldout | proprietary_gpt | 16 | 0.2250 | 0.1757 | 0.0416 | 0.4604 | 0.4188 |
| bespoke_xss_v13_1_heldout | local_qwen | 16 | 0.3125 | 0.1757 | 0.0770 | 0.4958 | 0.4188 |
