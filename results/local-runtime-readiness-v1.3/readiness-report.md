# Local Runtime Structured-Output Readiness v1.3

Status: non-scored readiness validation. This is not the measured 72-call calibration bake-off, not model selection, and not final v1.3 evaluation.

The earlier 32-token smoke outputs are treated as truncated configuration-validation outputs, not as model-quality failures.

## Frozen Common Settings

- Runtime: `llama.cpp-b9637-win-cpu-x64-llama-completion`
- Output mechanism: `llama.cpp --json-schema-file`
- JSON schema version: `local-ranking-readiness-json-schema-v1.3`
- Context size: `4096` tokens
- Maximum output: `768` tokens
- Timeout: `300` seconds
- Temperature: `0.0`
- Top-p: `1.0`
- Seed: `42`
- Maximum rationale length: `96` characters

## Readiness Results

| Model | Status | JSON parsed | All IDs once | Not truncated | Latency ms | Validation errors |
| --- | --- | --- | --- | --- | ---: | --- |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `not_ready` | `False` | `False` | `False` | `128360` | `malformed JSON response: Extra data` |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `not_ready` | `False` | `False` | `False` | `149873` | `malformed JSON response: Extra data` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `not_ready` | `False` | `False` | `False` | `136664` | `malformed JSON response: Extra data` |
| `gemma3_4b_it_gguf_q4_k_m` | `not_ready` | `False` | `False` | `False` | `60228` | `malformed JSON response: Extra data` |

All four raw outputs contain complete-looking JSON followed by the runtime
literal `[end of text]`. The strict parser therefore rejected each response as
extra data. This is recorded as a common runtime/output-boundary readiness
issue, not as model-ranking quality.

## Package Validation

- Package structurally valid: `True`
- Measured bake-off ready: `False`
- Global configuration revision required: `True`
