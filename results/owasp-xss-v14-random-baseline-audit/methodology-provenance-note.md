# Methodology and Provenance

- Scope: original frozen OWASP XSS v1.4 evaluation only.
- Excluded: v1.4.1 enriched deterministic rules and all later context-enrichment results.
- Sources: v1.4 protocol package, v1.4 canonical package, and retained v1.4 deterministic raw ranking artifacts.
- Ground truth use: limited to post-run structural verification of positive/negative scenario composition and final vulnerable ranks.
- Random reference: analytical, not an empirical rerun.
- Deterministic raw ranking provenance: 266 retained deterministic row artifacts are checked against `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/checksums.sha256` and linked to canonical scored rows through `results/owasp-xss-v14-confirmatory-final/canonical/normalized/scored-rows.json`.
- Deterministic raw source-integrity verdict: `verified_source_integrity`.
- Inference: no new hypothesis test was performed because the random-reference comparison was not frozen in the original v1.4 statistical plan.
- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero deterministic ranking calls, zero verifier calls.
