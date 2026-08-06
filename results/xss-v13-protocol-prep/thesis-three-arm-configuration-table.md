# Thesis Table Template: v1.3 XSS Ablation Arms

Status: configuration table only. No experimental results are included.

| Arm | Authority | Trials/scenario | Provider/model | Key frozen settings |
| --- | --- | ---: | --- | --- |
| `deterministic_structural` | deterministic structural ranking | `1` | deterministic-structural-v1 | no provider cost; no model output |
| `proprietary_gpt` | bounded hosted LLM ranking | `5` | openai / gpt-5.6-luna | temperature omitted; JSON schema output; candidate IDs only |
| `local_qwen` | bounded local open-weights ranking | `5` | local-llama.cpp / Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M | llama-completion; JSON schema; temp 0.0; seed 42 |
