# OWASP SQLi v1.5 Protocol Freeze Report

Status: frozen pre-execution package. No final SQLi cases, GPT calls, Qwen calls or scored rankings were executed.

## Final Corpus

- Original SQLi cases: `504`
- READINESS_ONLY cases: `20`
- FINAL_CONFIRMATORY_ELIGIBLE cases: `200`
- Final eligible vulnerable: `105`
- Final eligible non-vulnerable: `95`
- Excluded evaluation role: `284`

## Ranking Design

- Pack size: `5`
- Candidate-test budget: `k=4`
- Positive scenarios: `105`
- Negative-only scenarios: `19`
- Total scenarios: `124`
- Ranking denominators: `{'deterministic_structural': 124, 'proprietary_gpt': 620, 'local_qwen': 620, 'total_ranking_rows': 1364}`

## Direct Execution Layer

- Direct execution denominator: `200`
- Expected HTTP requests if authorized: `1200`
- Inconclusive outcomes remain valid observations and remain in the denominator.

## Validation

- Valid: `True`
- Errors: `0`
- Warnings: `0`
