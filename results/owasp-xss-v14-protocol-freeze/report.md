# OWASP XSS v1.4 Protocol Freeze Package

Status: pre-execution protocol package. No final OWASP case execution, browser verification, GPT call or Qwen call was performed.

## Corpus

- Original OWASP XSS cases: `455`
- Compatible after deterministic adapters: `408`
- READINESS_ONLY: `20`
- FINAL_CONFIRMATORY_ELIGIBLE: `388`
- Final eligible vulnerable: `236`
- Final eligible non-vulnerable: `152`
- Excluded: `47`

## Core Ranking Scenarios

- Pack size: `5`
- Candidate-test budget k: `4`
- Positive scenarios: `236`
- Negative-only scenarios: `30`
- Total core scenarios: `266`
- Negative reuse distribution in positive scenarios: `{7: 32, 6: 120}`
- Focal vulnerable candidate position distribution: `{'1': 44, '2': 44, '3': 62, '4': 51, '5': 35}`
- Unused negatives after complete negative-only packs: `['ox14-c000056', 'ox14-c000102']`

## Trial Denominators

- Deterministic structural rows: `266`
- Proprietary GPT rows: `1330`
- Local Qwen rows: `1330`
- Total ranking rows: `2926`

## Validation

- Valid: `True`
- Errors: `0`
- Warnings: `0`
- Final confirmatory cases executed: `False`
- GPT calls executed: `False`
- Qwen calls executed: `False`
