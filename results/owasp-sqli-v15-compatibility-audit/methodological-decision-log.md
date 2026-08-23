# SQLi v1.5 Methodological Decision Log

- Preserve the existing non-destructive boolean-SQLi verifier philosophy.
- Do not classify write/state-changing SQL operations as direct or adapter-supported original cases.
- Treat stored procedures as incompatible unless a later protocol explicitly audits and proves read-only semantics.
- Separate deterministic transport compatibility from SQL/verifier compatibility.
- Keep OWASP ground truth only in offline audit and future post-run scoring data.
- Exclude BenchmarkTest IDs, Java paths, SQL operation names, payloads and labels from ranker-facing candidates.
- Keep SQLi candidate ranking and direct verifier validation as separate study layers with separate denominators.

Recommended pack size: `5`.
Recommended candidate-test budget: `k=4`.
