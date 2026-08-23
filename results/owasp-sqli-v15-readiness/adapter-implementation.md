# OWASP SQLi v1.5 Adapter Implementation

Status: READINESS_ONLY support. The adapters construct deterministic requests from pinned OWASP crawler metadata. They do not modify OWASP Benchmark source, choose payloads dynamically, expose ground truth to rankers, or change SQLi verifier criteria.

- `form`: submits one form parameter using `application/x-www-form-urlencoded`.
- `multi_form`: submits all original form parameters and mutates only the audited target input.
- `multi_query`: preserves all original query parameters and mutates only the audited target input.
- `header`: sets the audited request header deterministically.
- `cookie`: sets the audited cookie deterministically.

Transport compatibility remains separate from SQL/verifier compatibility. Runtime readiness still requires stable baseline behavior and reproducible true/false response differences for verification.
