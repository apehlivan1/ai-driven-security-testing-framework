# Held-Out Evaluation v1.2 Affected Rerun Report

- Protocol: `evaluation-protocol-v1.2`
- Run directory: `C:\Users\SELUAPNS\source\repos\ai-driven-security-testing-framework\.adstf-runs\heldout-evaluation-v1.2-affected-20260720T093154Z`
- Checkout tag: `evaluation-protocol-v1.2`
- Reused v1.1 XSS/SQLi artifacts: `true`
- Reran unaffected XSS/SQLi: `False`
- Ground truth loaded after affected execution: `True`

## Framework

- Combined TP/FP/FN/TN: `4/0/0/3`
- XSS TP/FP/FN/TN: `2/0/0/1`
- SQLi TP/FP/FN/TN: `1/0/0/1`
- IDOR TP/FP/FN/TN: `1/0/0/1`

## ZAP Baselines

- Passive evaluated cases: `5`
- Passive case IDs: `heldout-xss::hx-001, heldout-xss::hx-002, heldout-xss::hx-003, heldout-sqli::hs-001, heldout-sqli::hs-002`
- Passive unsupported case IDs: `heldout-idor::hi-001, heldout-idor::hi-002`
- Passive raw/matched/unmatched alerts: `38/0/38`
- Passive TP/FP/FN/TN: `0/0/3/2`
- Active evaluated cases: `5`
- Active case IDs: `heldout-xss::hx-001, heldout-xss::hx-002, heldout-xss::hx-003, heldout-sqli::hs-001, heldout-sqli::hs-002`
- Active unsupported case IDs: `heldout-idor::hi-001, heldout-idor::hi-002`
- Active raw/matched/unmatched alerts: `14/1/13`
- Active TP/FP/FN/TN: `1/0/2/2`

## Compliance

- IDOR evidence sets isolated: `True`
- Secrets found in new v1.2 artifacts: `False`
- Scanner alerts remain separate from verifier-confirmed framework findings.
- XSS and SQLi results retain v1.1 provenance and were not rerun.
