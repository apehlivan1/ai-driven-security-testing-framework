# Methodology and Provenance

- Scope: original frozen OWASP XSS v1.4 ranking-only evaluation.
- Plan: `docs/evaluation-v1.4-postrun-statistical-plan.md` and `results/owasp-xss-v14-statistical-plan/analysis-plan.json`.
- Frozen plan commit: `a3785c710e5865edb4ae289bb2906b07afa52406`.
- Source data: v1.4 canonical scored rows and Comment 2 scenario-level mean reciprocal-rank data.
- Independent unit: positive scenario.
- Repeated trials: GPT and Qwen trials are averaged within scenario before inferential comparison.
- Missing Qwen scenario: retained as a reliability outcome and not imputed.
- Primary test: paired two-sided Wilcoxon signed-rank, Qwen minus deterministic structural scenario-level MRR, unadjusted.
- Exploratory tests: paired scenario-level Wilcoxon with Holm correction across exactly 11 tests.
- SciPy version: `1.15.3`.
- Wilcoxon parameters: `{"alternative": "two-sided", "method": "auto", "zero_method": "pratt"}`.
- Bootstrap: `20000` paired scenario resamples, seed `20260827`.
- Source checksums valid: `True`.
- Denominators valid: `True`.
- Experimental activity: zero model calls, zero HTTP calls, zero browser calls, zero discovery calls, zero verifier calls, zero scored calls.
