# Local Runtime Output-Boundary Audit v1.3

Status: non-scored transport audit and corrected readiness validation. This is not the measured calibration bake-off and not model selection.

## Root Cause

The previous readiness package showed schema-constrained JSON on stdout followed by a fixed literal `[end of text]` suffix. Timing and system logs were on stderr. Because the application parser received stdout as model content, it correctly rejected the response as extra data.

The suffix is treated as a llama.cpp runtime/EOS presentation marker outside the generated JSON boundary because it appeared after an otherwise complete JSON object for all four models while `--special` was not enabled. The adapter now separates only this exact trailing marker after verifying that the preceding text is valid JSON. Raw stdout and stderr remain preserved.

## Selected Common Transport

- Interface: `llama-completion stdout/stderr with versioned output-boundary parser`
- Parser rule: `llama-completion-transport-parser-v1.3`
- JSON schema: `local-ranking-readiness-json-schema-v1.3`
- Special tokens: `disabled; --special is not sent and llama.cpp default is false`
- Prompt display: `disabled with --no-display-prompt`
- Conversation mode: `single-turn conversation mode via --single-turn`

## Interface Comparison

| Interface | Selected | Reason |
| --- | --- | --- |
| `llama-completion` | `True` | minimal adapter, direct ModelClient compatibility, raw stdout/stderr retained |
| `llama-server` | `False` | available but not chosen for this correction because it introduces server lifecycle and HTTP transport before needed |
| `clean llama-completion with no-perf/log-disable` | `False` | less useful because timing metadata is required and the EOS marker still needs a content-boundary rule |

## Corrected Readiness Results

| Model | Status | Valid JSON | All IDs once | Stop | Token limit | Latency ms |
| --- | --- | --- | --- | --- | --- | ---: |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `ready` | `True` | `True` | `eos_runtime_marker` | `False` | `73596` |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `ready` | `True` | `True` | `eos_runtime_marker` | `False` | `114538` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `ready` | `True` | `True` | `eos_runtime_marker` | `False` | `118670` |
| `gemma3_4b_it_gguf_q4_k_m` | `ready` | `True` | `True` | `eos_runtime_marker` | `False` | `49780` |

## Package Validation

- Package valid: `True`
- Ready models: `4` of `4`
- Measured bake-off ready: `True`
