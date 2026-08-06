# Local Model Calibration Bake-Off Tables v1.3

Table status: measured calibration data only; not final held-out evaluation.

## Model Eligibility And Ranking Metrics

| Model | Eligible | Valid outputs | MRR | Top-1 accuracy | Top-k recall | Ranking stability | Median latency ms |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `True` | `18/18` | `0.6190476190476191` | `0.5` | `0.75` | `1.0` | `59630.5` |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `True` | `18/18` | `0.5` | `0.25` | `0.75` | `1.0` | `66435.0` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `False` | `15/18` | `0.7777777777777778` | `0.6666666666666666` | `1.0` | `1.0` | `77663.0` |
| `gemma3_4b_it_gguf_q4_k_m` | `True` | `18/18` | `0.5416666666666666` | `0.25` | `1.0` | `1.0` | `32024.5` |

## Selection

- Primary: `qwen2_5_7b_instruct_gguf_q4_k_m`
- Fallback: `gemma3_4b_it_gguf_q4_k_m`
