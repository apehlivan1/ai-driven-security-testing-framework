# Local Runtime Provisioning Smoke Report v1.3

Status: non-scored local runtime smoke validation. This is not the measured 72-call bake-off and not final v1.3 evaluation.

- Runtime: `llama.cpp-b9637-win-cpu-x64-llama-completion`
- Backend: `cpu`
- Validation valid: `True`
- Smoke requests: `4`
- Final 24-scenario XSS v1.3 benchmark used: `false`
- Vulnerability tests executed: `false`
- Final local model selected: `false`

## Smoke Outcomes

| Model | Status | Valid JSON contract | Provider failed | Latency ms | Validation errors |
| --- | --- | --- | --- | ---: | --- |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `invalid_or_failed` | `False` | `False` | `34594` | `malformed JSON response: Expecting property name enclosed in double quotes` |
| `gemma3_4b_it_gguf_q4_k_m` | `invalid_or_failed` | `False` | `False` | `27059` | `malformed JSON response: Expecting value` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `invalid_or_failed` | `False` | `False` | `48225` | `malformed JSON response: Invalid control character at` |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `invalid_or_failed` | `False` | `False` | `38476` | `malformed JSON response: Invalid control character at` |
