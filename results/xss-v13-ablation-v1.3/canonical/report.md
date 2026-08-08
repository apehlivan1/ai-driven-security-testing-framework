# XSS v1.3 Ablation Analysis Report

Scope: frozen local v1.3 reflected-XSS benchmark only. Descriptive results only; no general model-superiority claim is made.

## Execution Integrity
- Protocol tag: `evaluation-protocol-v1.3`
- Source run: `results/xss-v13-ablation-v1.3/xss-v13-ablation-20260807T081244Z`
- Ranking rows: `264` (deterministic 24, proprietary GPT 120, local Qwen 120)
- Ground truth used phase: `post_run_scoring_only`
- Gemma contingency activated: `false`

## Key Results

- `deterministic_structural`: valid ranking rows `24/24`, provider failures `0`, verified-finding runs `11`, negative false-positive runs `0`.
- `proprietary_gpt`: valid ranking rows `0/120`, provider failures `120`, verified-finding runs `0`, negative false-positive runs `0`.
- `local_qwen`: valid ranking rows `120/120`, provider failures `0`, verified-finding runs `55`, negative false-positive runs `0`.

The proprietary GPT arm did not produce valid ranking outputs in this run because every provider call failed with a local socket-permission error. Those rows are retained as provider-failure artifacts and excluded from valid GPT ranking-performance aggregates.

Token usage and cost are `not_available` for GPT because no provider call completed, and `not_available`/`not_applicable` for local Qwen because the local runtime artifacts do not provide billable token or cost data.

Time-to-first-verified-finding fields are `not_available` in the current artifacts because finding records do not retain verifier completion timestamps in the format required by `metrics-definition-v1.3`.

## Limitations

- Results apply only to the frozen 24-scenario local reflected-XSS benchmark and the recorded environment.
- Repeated LLM trials are model trials, not independent benchmark cases.
- The GPT arm is an infrastructure-failure result, not evidence of GPT ranking quality.
- The package does not include ZAP, IDOR, or SQLi results.
