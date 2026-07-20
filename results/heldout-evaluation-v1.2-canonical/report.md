# Canonical Held-Out Evaluation Results Package v1.2

This package preserves the thesis-use held-out evaluation artifacts for `evaluation-protocol-v1.2`.
It was built from completed artifacts only; no framework, OpenAI, target, or ZAP experiment was rerun during packaging.

## Provenance

- Protocol: `evaluation-protocol-v1.2`
- Git tag at packaging time: `evaluation-protocol-v1.2`
- Git commit: `7c2466121a888b4edf359d3166c45c687a06d765`
- Corrected v1.2 affected rerun: `.adstf-runs/heldout-evaluation-v1.2-affected-20260720T093154Z`
- Reused unaffected v1.1 run: `.adstf-runs/heldout-evaluation-20260720T064510Z`

## Included Results

- Unaffected v1.1 XSS deterministic framework results.
- Unaffected v1.1 XSS LLM ranking trials.
- Unaffected v1.1 SQLi framework results.
- Corrected v1.2 IDOR framework rerun.
- Corrected v1.2 ZAP passive rerun using `zap-heldout-passive-mapping-v1`.
- Corrected v1.2 ZAP active rerun using `zap-heldout-active-mapping-v1`.
- Corrected mixed-provenance v1.2 aggregate summary.

## Excluded Superseded Results

- v1.1 IDOR scoring affected by cross-case evidence contamination.
- v1.1 ZAP passive and active normalized scoring using development mappings.
- Any v1.1 aggregate totals containing those defective results.

## Canonical Metrics

| Evaluation | Scope | Cases | TP | FP | FN | TN |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Framework | XSS + SQLi + IDOR | 7 | 4 | 0 | 0 | 3 |
| Framework common scope | XSS + SQLi | 5 | 3 | 0 | 0 | 2 |
| ZAP passive | XSS + SQLi only | 5 | 0 | 0 | 3 | 2 |
| ZAP active | XSS + SQLi only | 5 | 1 | 0 | 2 | 2 |

IDOR is reported separately as framework-supported and ZAP-unsupported. ZAP IDOR cases `heldout-idor::hi-001` and `heldout-idor::hi-002` are excluded from ZAP scoring.

## LLM Ranking

LLM ranking is separate from verifier-confirmed findings. The LLM selected ordered candidate IDs only; the deterministic verifier still decided finding status.

- Provider: `openai`
- Model: `gpt-5.6-luna`
- Prompt version: `llm-candidate-ranking-v1`
- Configured trials: 5
- Calls: 15 valid / 0 invalid / 0 failed / 0 fallback
- Top-1 accuracy: 1.0
- Top-k recall: 1.0
- MRR: 1.0
- Tokens: 10294 total (6390 input, 3904 output)
- Latency: 95756 ms total, 6383.73 ms mean
- Estimated cost: not available from provider metadata

## Package Layout

- `manifest.json`: machine-readable package manifest.
- `checksums.sha256`: SHA-256 checksums for package files, excluding the checksum file itself.
- `ledgers/`: included and excluded result ledgers.
- `tables/`: normalized CSV/JSON tables for thesis analysis.
- `artifacts/raw/`: copied raw source artifacts; these are preserved separately from generated package summaries.
- `validation-report.json`: offline validation result for package completeness and consistency.

## Limitations

This package contains descriptive evaluation artifacts only. It does not add inferential statistics, prompt optimization, new experiments, new scanner mappings, or thesis-level conclusions.
