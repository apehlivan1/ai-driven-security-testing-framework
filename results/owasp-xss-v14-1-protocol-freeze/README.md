# v1.4.1 OWASP XSS Context-Enrichment Ablation Protocol Freeze

Status: frozen pre-execution package. No HTTP benchmark request, GPT call, Qwen call, local inference, browser verification, scored ranking row or ground-truth scoring was performed while creating this package.

This package freezes the v1.4.1 explanatory context-enrichment ablation derived from the frozen v1.4 OWASP XSS external-validation corpus and the corrected benign context observation package.

## Denominators

- Scenarios: `266` (`236` positive, `30` negative-only)
- Candidate references: `1330`
- Unique candidates: `388`
- Candidate-test budget: `k = 4`
- Deterministic rows: `532`
- GPT rows: `2660`
- Qwen rows: `2660`
- Total ranking rows: `5852`

## Model-Facing Inputs

- Minimal snapshots: `model-facing/minimal-candidate-snapshots/`
- Enriched snapshots: `model-facing/enriched-candidate-snapshots/`

Both snapshot sets preserve scenario IDs, candidate IDs and candidate ordering from v1.4. The minimal representation removes case-derived path and parameter-name fields. The enriched representation adds only corrected benign context features derived from the fixed inert marker `ADSTF_CTX_V141/SAFE`.
