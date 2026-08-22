# Thesis Tables: OWASP XSS v1.4 Confirmatory Evaluation

## Ranking Effectiveness

| Arm | Positive valid rows | Top-1 | Top-4 | MRR |
| --- | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 236 | 0.2034 | 0.7881 | 0.4573 |
| `proprietary_gpt` | 1179 | 0.2332 | 0.7812 | 0.4732 |
| `local_qwen` | 1175 | 0.2468 | 0.8298 | 0.4926 |

## Reliability

| Arm | Scheduled rows | Valid outputs | Malformed outputs | Provider/runtime failures | Contract-validity rate |
| --- | ---: | ---: | ---: | ---: | ---: |
| `deterministic_structural` | 266 | 266 | 0 | 0 | 1.0000 |
| `proprietary_gpt` | 1330 | 1329 | 0 | 1 | 0.9992 |
| `local_qwen` | 1330 | 1325 | 5 | 0 | 0.9962 |
