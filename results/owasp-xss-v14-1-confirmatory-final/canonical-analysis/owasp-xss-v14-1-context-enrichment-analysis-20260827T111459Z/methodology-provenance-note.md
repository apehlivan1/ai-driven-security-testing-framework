# v1.4.1 Methodology and Provenance Note

- Frozen protocol tag: `evaluation-protocol-v1.4.1-ready`
- Frozen protocol commit: `08e72f32c9de7e0fb80f3ccfd64c85b6fe99ddb3`
- Protocol package: `results/owasp-xss-v14-1-protocol-freeze`
- Ground truth was loaded only after pre-scoring integrity validation.
- Repeated LLM trials are nested under scenario and arm and are not treated as independent benchmark scenarios.
- Invalid or malformed model outputs are retained in reliability denominators and excluded from valid ranking-performance aggregates.
- Negative-only scenarios are excluded from vulnerable-candidate rank, Top-1, Top-2, Top-4 and MRR denominators.
- Cost per finding is not available because no frozen numeric pricing basis exists.
- The deterministic resume-index incident is recorded as operational provenance only; no completed sequence was rerun.
- No new GPT, Qwen, HTTP, browser, discovery, deterministic-ranking or scoring execution calls were made by this post-run analysis.
