# XSS v1.3 Ablation Thesis Tables

## Ranking Arms

| Arm | Rows | Valid rows | Provider failed | Top-1 | Top-k recall | MRR | Verified runs | Negative FP runs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 24 | 24 | 0 | 0.250 | 0.688 | 0.439 | 11 | 0 |
| `proprietary_gpt` | 120 | 0 | 120 | n/a | n/a | n/a | 0 | 0 |
| `local_qwen` | 120 | 120 | 0 | 0.312 | 0.688 | 0.496 | 55 | 0 |

## Provider Measurements

| Model | Artifacts | Provider failures | Latency mean ms | Input tokens | Output tokens | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M` | 120 | 0 | 111983.88333333333 | not_available | not_available | not_available |
| `gpt-5.6-luna` | 120 | 120 | not_available | not_available | not_available | not_available |
