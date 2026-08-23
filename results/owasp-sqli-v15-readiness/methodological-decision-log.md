# OWASP SQLi v1.5 Readiness Decision Log

- READINESS_ONLY cases are selected before runtime execution using seed `owasp-sqli-v15-readiness-selection-v1`.
- READINESS_ONLY cases are permanently excluded from later final confirmatory denominators.
- SQLi payload values are deterministic framework-owned probes derived from the existing boolean-SQLi verifier philosophy.
- The LLM authority boundary remains unchanged: future rankers may order sanitized candidate IDs only.
- Ground truth is used only after readiness execution to summarize readiness behavior.
- Manual-review cases are revisited by offline static inspection only and remain unresolved when static evidence does not establish a sufficient boolean response oracle.
