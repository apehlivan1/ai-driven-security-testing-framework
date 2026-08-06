# Local Model Calibration Bake-Off v1.3

Status: measured live calibration bake-off. This is not final v1.3 held-out evaluation and does not execute vulnerability tests.

- Scored calls: `72`
- Models: `4`
- Calibration scenarios: `6`
- Trials per model per scenario: `3`
- Elapsed seconds: `4310.618`
- Primary model: `qwen2_5_7b_instruct_gguf_q4_k_m`
- Fallback model: `gemma3_4b_it_gguf_q4_k_m`

## Execution Policy

- Schedule: model-major deterministic order: shortlisted model order, calibration scenario order, trial 1..3
- Warm-up: no separate warm-up request; every scored call starts a fresh llama-completion process and uses the runtime default warmup behavior
- Process reset: fresh llama-completion process per scored call; no model server or cache shared across scored calls
- Retry policy: no silent retries; scored failures are retained. Retry is allowed only for a clearly identified external infrastructure interruption and both attempts must remain in artifacts.

## Eligibility And Selection

- Gate: `valid_output_rate >= 0.9`
- Gate: `timeout_provider_failure_rate <= 0.1`
- Gate: `memory_feasible == True`
- Gate: `completed_required_calibration_scenarios == required_calibration_scenarios`

Tie-breaking order:
- `higher_mean_reciprocal_rank`
- `higher_top_1_accuracy`
- `higher_top_k_recall`
- `higher_ranking_stability`
- `lower_malformed_output_rate`
- `lower_median_latency_ms`
- `lower_estimated_peak_memory_gb`
- `higher_metadata_completeness_score`
- `lexicographic_model_candidate_id`

| Model | Eligible | Valid | Failure | MRR | Top-1 | Top-k | Stability | Median latency ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `True` | `18/18` | `0.0` | `0.6190476190476191` | `0.5` | `0.75` | `1.0` | `59630.5` |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `True` | `18/18` | `0.0` | `0.5` | `0.25` | `0.75` | `1.0` | `66435.0` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `False` | `15/18` | `0.0` | `0.7777777777777778` | `0.6666666666666666` | `1.0` | `1.0` | `77663.0` |
| `gemma3_4b_it_gguf_q4_k_m` | `True` | `18/18` | `0.0` | `0.5416666666666666` | `0.25` | `1.0` | `1.0` | `32024.5` |

## Negative Scenarios

Negative scenarios are reported separately. Vulnerable-candidate rank, Top-1, Top-k and MRR are not assigned to negative cases.
- `qwen2_5_7b_instruct_gguf_q4_k_m`: 6/6 valid negative trials; top-candidate distribution `{'cal-xss-005-west-ref': 3, 'cal-xss-006-olive-memo': 3}`
- `phi3_5_mini_instruct_gguf_q4_k_m`: 6/6 valid negative trials; top-candidate distribution `{'cal-xss-005-west-ref': 3, 'cal-xss-006-quill-ref': 3}`
- `mistral_7b_instruct_v0_3_gguf_q4_k_m`: 6/6 valid negative trials; top-candidate distribution `{'cal-xss-005-west-page': 3, 'cal-xss-006-quill-ref': 3}`
- `gemma3_4b_it_gguf_q4_k_m`: 6/6 valid negative trials; top-candidate distribution `{'cal-xss-005-west-ref': 3, 'cal-xss-006-quill-ref': 3}`

## Limitations

- This selects a primary and fallback only for the constrained candidate-ranking task on this hardware.
- The calibration scenarios are development scenarios, not final held-out thesis evaluation.
- Token counts from llama.cpp are limited to generated-token observations; billing cost is not applicable for local models.
