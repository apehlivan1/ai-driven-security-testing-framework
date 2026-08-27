# Professor Comment 5 Closure Analysis: OWASP Contamination Caveat and Bespoke Held-Out XSS Evidence

This package is a derived post-run evidence synthesis. It performs zero GPT, Qwen, deterministic ranking, HTTP/browser, discovery, verifier or scored experimental calls and does not modify frozen/canonical artifacts.

## Authoritative Bespoke Held-Out Package

- Protocol/version: `evaluation-protocol-v1.3.1`
- Canonical result path: `results/xss-v13-ablation-v1.3.1-final/canonical`
- Frozen tag: `evaluation-protocol-v1.3.1`
- Tagged commit: `a6fca7e54a0bb3247d6329fd0532178192b51de5`
- Scenario count: `24`
- Positive/negative composition: `16` positive and `8` negative/control scenarios
- Candidate-count distribution: `{4: 4, 5: 5, 6: 8, 7: 4, 8: 3}`
- Ranking budget: `k = 4`
- Arms: `deterministic_structural`, `proprietary_gpt`, `local_qwen`
- Trials: deterministic has one ranking per scenario; GPT and Qwen have five trials per scenario.
- Ranking evidence and runtime verifier evidence are retained separately; ground truth is applied only in post-run scoring.
- Ranking MRR in this report follows the canonical budget-censored v1.3.1 semantics: reciprocal-rank credit is assigned only if the vulnerable candidate is within `top_k = min(test_budget, candidate_count)`. Full-order reciprocal rank is retained only as diagnostic provenance and is not used as the thesis-facing v1.3.1 ranking metric.

## Scenario-Specific Random Reference

| Scope | Scenarios | Random Top-1 | Random Top-2 | Random Top-4 | Random budget-censored MRR |
| --- | ---: | ---: | ---: | ---: | ---: |
| All eligible positive bespoke scenarios | 16 | 0.1757 | 0.3515 | 0.7030 | 0.3661 |
| n=4 | 2 | 0.2500 | 0.5000 | 1.0000 | 0.5208 |
| n=5 | 4 | 0.2000 | 0.4000 | 0.8000 | 0.4167 |
| n=6 | 5 | 0.1667 | 0.3333 | 0.6667 | 0.3472 |
| n=7 | 3 | 0.1429 | 0.2857 | 0.5714 | 0.2976 |
| n=8 | 2 | 0.1250 | 0.2500 | 0.5000 | 0.2604 |

Scenarios with exactly four candidates have random Top-4 = 1.0000 by definition under budget k=4. Observed Top-4 on those scenarios cannot demonstrate prioritization advantage, so the candidate-count >4 subset is reported separately.

| Arm | Valid positive scenario n | Top-1 | Delta vs random | Top-2 | Delta vs random | Top-4 | Delta vs random | Budget-censored MRR | Delta vs random |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| deterministic_structural | 16 | 0.2500 | 0.0743 | 0.3125 | -0.0390 | 0.6875 | -0.0155 | 0.3854 | 0.0193 |
| proprietary_gpt | 16 | 0.2250 | 0.0493 | 0.4500 | 0.0985 | 0.7219 | 0.0189 | 0.4107 | 0.0445 |
| local_qwen | 16 | 0.3125 | 0.1368 | 0.3750 | 0.0235 | 0.6875 | -0.0155 | 0.4427 | 0.0766 |

The corresponding canonical valid-row metrics from `normalized/arm-level-metrics.json` remain the authoritative v1.3.1 historical results: deterministic Top-1 0.2500, Top-4 0.6875 and MRR 0.3854; GPT Top-1 0.2179, Top-4 0.7179 and MRR 0.4060; Qwen Top-1 0.3125, Top-4 0.6875 and MRR 0.4427. The scenario-level table above gives each positive scenario equal weight; for GPT it differs slightly from the canonical valid-row table because two positive scenarios have four valid trials rather than five. Earlier derived full-order MRR values of 0.4604 for GPT and 0.4958 for Qwen credited vulnerable candidates below the fixed budget and are retained only in `bespoke-metric-reconciliation.json` as diagnostic provenance.

### Top-4 on Positive Scenarios with Candidate Count >4

| Arm | Scenario n | Observed Top-4 | Random Top-4 | Delta |
| --- | ---: | ---: | ---: | ---: |
| deterministic_structural | 14 | 0.6429 | 0.6605 | -0.0177 |
| proprietary_gpt | 14 | 0.6821 | 0.6605 | 0.0216 |
| local_qwen | 14 | 0.6429 | 0.6605 | -0.0177 |

## OWASP Versus Bespoke Comparison

| Dataset | Arm | Positive scenarios | Valid positive ranking rows | Metric aggregation | MRR semantics | Observed Top-1 | Random Top-1 | Delta MRR | Observed MRR | Random MRR |
| --- | --- | ---: | ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| public_owasp_xss_v14 | deterministic_structural | 236 | 236 | valid_trial_row_mean | full_order_reciprocal_rank | 0.2034 | 0.2000 | 0.0006 | 0.4573 | 0.4567 |
| public_owasp_xss_v14 | proprietary_gpt | 236 | 1179 | valid_trial_row_mean | full_order_reciprocal_rank | 0.2332 | 0.2000 | 0.0166 | 0.4732 | 0.4567 |
| public_owasp_xss_v14 | local_qwen | 235 | 1175 | valid_trial_row_mean | full_order_reciprocal_rank | 0.2468 | 0.2000 | 0.0359 | 0.4926 | 0.4567 |
| bespoke_xss_v13_1_heldout | deterministic_structural | 16 | 16 | equal_weight_scenario_mean | budget_censored_reciprocal_rank | 0.2500 | 0.1757 | 0.0193 | 0.3854 | 0.3661 |
| bespoke_xss_v13_1_heldout | proprietary_gpt | 16 | 78 | equal_weight_scenario_mean | budget_censored_reciprocal_rank | 0.2250 | 0.1757 | 0.0445 | 0.4107 | 0.3661 |
| bespoke_xss_v13_1_heldout | local_qwen | 16 | 80 | equal_weight_scenario_mean | budget_censored_reciprocal_rank | 0.3125 | 0.1757 | 0.0766 | 0.4427 | 0.3661 |

The public OWASP v1.4 and bespoke v1.3.1 metrics should not be compared by raw Top-k values alone because their candidate-set sizes differ. Observed-minus-random values are more interpretable within each dataset. MRR deltas should still be read with care across the two protocols because original v1.4 uses full-order reciprocal-rank semantics, while v1.3.1 uses budget-censored reciprocal rank.

## Contamination-Risk Interpretation

OWASP Benchmark v1.2 is a public benchmark corpus used as an external validation source in v1.4. Because it was publicly available before this thesis evaluation, potential training-data exposure cannot be ruled out for either the hosted proprietary GPT arm or the local Qwen model. This is a contamination-risk caveat, not evidence of actual contamination. The bespoke v1.3/v1.3.1 held-out scenarios were constructed for this project as local benchmark scenarios, frozen before final scored execution, and excluded from model-selection/calibration runs. Their candidate snapshots explicitly exclude ground truth, labels, raw HTML, browser state and source code from ranking inputs. This provenance makes them substantially lower-contamination-risk evidence than the public OWASP corpus, but it does not prove mathematically impossible contamination.

## Reproducibility Metadata

- GPT model identifier: `gpt-5.6-luna (120)`; provider `openai (120)`; prompt version `llm-candidate-ranking-v1`; temperature parameter omitted/provider default; cost `not_available (120)`.
- Qwen model: `Qwen2.5 7B Instruct GGUF Q4_K_M`; repository `Qwen/Qwen2.5-7B-Instruct-GGUF`; revision `bb5d59e06d9551d752d08b292a50eb208b07ab1f`; quantization `Q4_K_M`; runtime `llama.cpp-b9637-win-cpu-x64-llama-completion`; backend `cpu`; seed `42`; temperature `0.0`; top-p `1.0`; context `4096`; output limit `768`; timeout `300` seconds; threads `8`.
- Qwen latency is an experimental-system measurement under the recorded CPU-only runtime and hardware configuration, not an inherent property of local inference.

## Direct Answers

1. The model-backed trends from public OWASP data appear partially on the bespoke set: under metric-compatible budget-censored random MRR, all three arms are above the bespoke random MRR reference, Qwen remains descriptively strongest, and the small bespoke scenario count and mixed Top-k deltas require cautious interpretation.
2. The best descriptive bespoke arm by scenario-level budget-censored MRR is `local_qwen`.
3. Exceeding random by metric: `{'deterministic_structural': {'top1': True, 'top2': False, 'top4': False, 'mrr': True}, 'proprietary_gpt': {'top1': True, 'top2': True, 'top4': True, 'mrr': True}, 'local_qwen': {'top1': True, 'top2': True, 'top4': False, 'mrr': True}}`.
4. Relative to OWASP, bespoke effects are mixed: all three bespoke arms are above random by budget-censored MRR, with deltas of 0.0193 for deterministic, 0.0445 for GPT and 0.0766 for Qwen. Cross-dataset MRR deltas remain only approximate because v1.4 uses full-order reciprocal-rank semantics and v1.3.1 uses budget-censored MRR.
5. The bespoke evidence strengthens the thesis by adding lower-contamination-risk held-out evidence, but it also qualifies the central claim: bounded model-backed ranking can improve prioritization in some settings, yet the effect is model- and dataset-dependent and uncertain with only 24 bespoke scenarios.

## Validation

- Source-integrity verdict: `PASS`
- New experimental calls: `0`
