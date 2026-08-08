# XSS v1.3.1 Ablation Canonical Package

Protocol: `evaluation-protocol-v1.3.1` recovery amendment to `evaluation-protocol-v1.3`.

Source run: `results/xss-v13-ablation-v1.3.1-final/xss-v13-ablation-20260808T103409Z`

Status: canonicalized deterministic offline package. No scored experiment was run during canonicalization.

## Execution Completeness

| Arm | Expected ranking rows | Valid rankings | Schema-invalid | Provider/runtime failures | Retries |
| --- | ---: | ---: | ---: | ---: | ---: |
| deterministic_structural | 24 | 24 | 0 | 0 | 0 |
| proprietary_gpt | 120 | 116 | 4 | 0 | 0 |
| local_qwen | 120 | 120 | 0 | 0 | 0 |

Gemma contingency activation: `false`.

## Valid-Ranking Metrics

| Arm | Top-1 | Top-k recall | MRR | Verified findings | Negative verified |
| --- | ---: | ---: | ---: | ---: | ---: |
| deterministic_structural | 0.2500 | 0.6875 | 0.3854 | 11 | 0 |
| proprietary_gpt | 0.2179 | 0.7179 | 0.4060 | 56 | 0 |
| local_qwen | 0.3125 | 0.6875 | 0.4427 | 55 | 0 |

## End-to-End Candidate-Test Rows

All retained candidate-test rows: `841`. Classification counts over all retained rows: TP `124`, FP `0`, FN `0`, TN `717`.

The valid-ranking-only tables should be used for LLM ranking-performance claims. All retained rows remain preserved as experimental evidence.

## Timing And Efficiency

Time to first verifier-confirmed finding: `8858` ms.

Requests to first verifier-confirmed finding: `3`.

GPT total tokens: `157042`. GPT cost remains `not_available (120)` because no numeric USD cost artifact was retained.

Qwen median latency: `82839.0` ms. Qwen token usage remains `not_available`; llama.cpp timing and generated-token observations are retained in ranking artifacts and summarized in provider metrics.

## Integrity

Validation status: `True`. See `validation-report.json` and `checksums.sha256`.
