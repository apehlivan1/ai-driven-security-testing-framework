# Methodology and Provenance Note

This package is a derived evidence synthesis for Professor Comment 4. It reads existing frozen/canonical packages and readiness artifacts only.

Ground truth is used only where the source package already defines post-run scoring or readiness validation. The v1.4 OWASP XSS negative-only ranking scenarios are not reinterpreted as binary vulnerability-classification evidence.

Source packages checked:
- `results/owasp-xss-v14-confirmatory-final/canonical`: ranking-only evidence; checksum valid = `True`
- `results/owasp-xss-v14-random-baseline-audit`: derived candidate-construction and random-baseline audit; checksum valid = `True`
- `results/owasp-xss-v14-trial-stability-analysis`: derived ranking-only repeated-trial stability evidence; checksum valid = `True`
- `results/owasp-xss-v14-readiness`: runtime verifier evidence, readiness-only; checksum valid = `True`
- `results/xss-v13-ablation-v1.3.1-final/canonical`: runtime verifier and post-run ground-truth classification evidence; checksum valid = `True`
- `results/owasp-sqli-v15-1-confirmatory-final/canonical`: ranking-only evidence, runtime verifier evidence and post-run ground-truth classification evidence; checksum valid = `True`

For `results/xss-v13-ablation-v1.3.1-final/canonical`, the checksum-valid
statement applies to the evidence-bearing normalized/control artifacts used in
this Comment 4 analysis. The retained legacy package has two full-package
checksum mismatches in presentation-only artifacts:
`results/xss-v13-ablation-v1.3.1-final/canonical/analysis-report.md` and
`results/xss-v13-ablation-v1.3.1-final/canonical/figures/ranking-metrics-valid-only.pdf`.
Those presentation artifacts were not used to derive the Comment 4 numerical
findings, and the limitation is retained explicitly as provenance context.

No new experimental execution was performed: model calls, HTTP requests, browser tests, discovery, ranking calls and verifier calls are all zero.
