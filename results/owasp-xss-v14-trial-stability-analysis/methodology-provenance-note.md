# Methodology and Provenance

- Scope: original frozen OWASP XSS v1.4 evaluation only.
- Source rows: canonical v1.4 scored rows and retained v1.4 raw ranking-row artifacts.
- Ground truth use: limited to post-run identification of positive scenarios and vulnerable-candidate ranks already represented in canonical scored rows.
- Stability denominator: complete-ranking stability uses valid complete rankings only; invalid/provider-failed/malformed rows remain in reliability denominators and are reported as incomplete scenario evidence.
- Pairwise unit: trial pairs are summarized within scenario; they are not treated as independent inferential observations.
- Independent experimental unit: scenario, not individual repeated trial.
- Source integrity: `verified_source_integrity` against `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/checksums.sha256` and `results/owasp-xss-v14-confirmatory-final/canonical/checksums.sha256`.
- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero deterministic ranking calls, zero verifier calls.
