# v1.4.1 Context-Enrichment Feasibility Report

Status: design and feasibility only. No benchmark execution, model call, local-model inference, vulnerability verification or experimental scoring was performed.

## Summary

The current repository can support a v1.4.1 context-enrichment ablation as a separate explanatory follow-up to the frozen v1.4 OWASP XSS evaluation. The proposed study should preserve the v1.4 scenario IDs, candidate IDs, pack size, candidate ordering, budget and ground-truth separation while adding a second ranker-facing representation that includes deterministic benign-observation context.

## Key Finding

The most important design correction is that v1.4.1 should not forward the existing sanitized `action_path` and `parameter_name` fields unchanged, because they contain numeric case-derived tokens. They should be replaced by abstract carrier and shape categories in any enriched ranker-facing snapshot.

## Feasibility Verdict

READY WITH METHODOLOGICAL CAVEATS

## Required Before Implementation

- Freeze a versioned enriched candidate schema.
- Implement fixture-tested benign marker reflection parsing.
- Add ranker-facing leakage checks for enriched snapshots.
- Freeze deterministic-enriched ranking rules before any scored run.
- Keep minimal and enriched GPT/Qwen arms in one contemporaneous protocol if the goal is a clean paired ablation.

## Scale

- Scenarios: 266.
- Candidate references: 1,330.
- Unique candidates requiring at most one benign enrichment request each: 388.
- Projected full six-arm ranking rows: 5,852.

## Scope Boundaries

This package does not modify v1.4, v1.5.1, source code, prompts, protocols or benchmark artifacts. It contains only feasibility/design evidence for a possible future v1.4.1 protocol.
