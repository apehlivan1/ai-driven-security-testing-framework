# Methodology and Provenance Note

This derived package reads frozen/canonical evidence only. It does not execute experiments, model calls, HTTP/browser requests, discovery, verifier logic, or scoring runs.

The authoritative bespoke held-out package was resolved from the v1.3.1 protocol and canonical manifest, not filename recency. The six calibration/development scenarios and local-model bake-off packages are not used as held-out results.

Source validation status:
- `bespoke_v13_1_canonical`: required checksum validation `True`
- `bespoke_v13_protocol_prep`: required checksum validation `True`
- `bespoke_v13_structural_validation`: required checksum validation `True`
- `owasp_xss_v14_canonical`: required checksum validation `True`
- `local_runtime_provisioning`: required checksum validation `True`
- `local_runtime_output_boundary`: required checksum validation `True`

For the bespoke v1.3.1 package, the numerical evidence-bearing files used here validate. A legacy full-package mismatch in presentation artifacts is recorded in the evidence inventory and is not used to derive numerical findings.

Validation status: `True`
