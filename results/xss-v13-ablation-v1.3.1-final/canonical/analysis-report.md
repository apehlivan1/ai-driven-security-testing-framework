# XSS v1.3.1 Ablation Analysis Report

This report summarizes the final corrected v1.3.1 XSS ablation run. The study evaluates a bounded LLM role: models may only rank existing structured candidate IDs. Discovery, safety, execution, evidence collection and verification remain deterministic.

## Protocol Context

`evaluation-protocol-v1.3.1` is a recovery amendment to `evaluation-protocol-v1.3`. The amendment added provider-connectivity readiness and verifier completion timestamp retention. It did not change scenarios, snapshots, models, prompts, trial counts, budgets, scoring rules or verifier criteria.

## Main Results

Valid ranking rows produced these metrics:

| Arm | Valid rows | Top-1 | Top-k recall | MRR |
| --- | ---: | ---: | ---: | ---: |
| deterministic_structural | 24 | 0.2500 | 0.6875 | 0.3854 |
| proprietary_gpt | 116 | 0.2179 | 0.7179 | 0.4060 |
| local_qwen | 120 | 0.3125 | 0.6875 | 0.4427 |

The negative-scenario false-positive rate was `0.0` for all three arms. The verifier confirmed no findings in the eight negative scenarios.

## Reliability

The proprietary GPT arm attempted 120 calls. All reached the OpenAI provider and 116 returned schema-valid rankings. Four responses were contract-invalid because they contained duplicate, unknown or omitted candidate IDs. These are retained as malformed model-output observations and excluded from valid ranking-performance aggregates.

The local Qwen arm produced 120 valid local rankings with no runtime failures, malformed outputs or token-limit events. The Gemma contingency was not activated.

## Efficiency

The run retained `verification_completed_at` for every verifier result. The package can therefore report `time_to_first_verified_finding_ms = 8858`. Candidate count to first verification remains `not_available` because the retained global measurement summary does not expose enough per-run ordering data for that field.

## Limitations

The 24-scenario XSS benchmark is a controlled thesis benchmark, not evidence of general superiority across arbitrary web applications. GPT cost is unavailable because no numeric USD cost artifact was retained. Qwen token usage is unavailable in normalized provider fields, although runtime timing and generated-token counts are retained in local artifacts.
