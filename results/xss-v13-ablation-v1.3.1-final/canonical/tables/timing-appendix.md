# Timing Appendix: XSS v1.3.1

Derived only from retained v1.3.1 timestamps. Repeated LLM trials are model trials, not independent scenarios.

| Arm | Valid rows | Verified trials | Median ms | Mean ms | Median requests | Mean requests | Median candidates | Cost per finding |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Deterministic structural | 24 | 11 | 1140 | 1004.818 | 6 | 5.091 | 3 | not_applicable |
| Proprietary GPT | 116 | 56 | 354.5 | 511.268 | 4.0 | 4.714 | 2.0 | not_available |
| Local Qwen | 120 | 55 | 323 | 345.618 | 4 | 4.182 | 2 | not_available |

Negative scenarios and trials with no verifier-confirmed finding use `not_applicable` for time and request-to-first-finding fields.
For LLM arms, model/provider latency is reported separately in provider metrics and is not silently folded into this timestamp-derived table.
Cost per finding remains `not_available` for model arms because no frozen numeric USD pricing basis exists.
