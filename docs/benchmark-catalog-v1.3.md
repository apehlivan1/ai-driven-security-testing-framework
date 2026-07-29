# Benchmark Catalog v1.3

Status: scenario design and structural-validation catalog only. This document does not contain experimental results and does not modify frozen v1.2 evidence.

The v1.3 reflected-XSS benchmark contains 24 independent scenarios: 16 vulnerable scenarios and 8 negative/control scenarios. It is intended for a future deterministic-versus-LLM candidate-ranking ablation study.

Semantic ground truth is stored separately in `examples/benchmarks/xss-v13-ground-truth.json` and must be loaded only during post-run evaluation. Discovery, ranking, execution and verification components should use the manifest and target configuration, not the semantic ground-truth file.

| Scenario | Outcome class | Candidates | Seeds | Structural purpose | Structural challenge |
| --- | --- | ---: | ---: | --- | --- |
| `x13-001` | `vulnerable` | 4 | 3 | Basic positive control with multiple candidates. | one safe reflected distractor |
| `x13-002` | `vulnerable` | 5 | 3 | Tests whether ranking over-prefers forms over an existing query parameter. | forms look more promising than the query parameter |
| `x13-003` | `vulnerable` | 6 | 3 | Multi-seed prioritization where the first seed contains safe reflections. | first seed contains only safe reflections |
| `x13-004` | `vulnerable` | 6 | 3 | Required-field decoy with a vulnerable optional text field. | required decoy looks dominant |
| `x13-005` | `vulnerable` | 7 | 3 | Input-type variation using a textarea candidate. | several text input distractors |
| `x13-006` | `vulnerable` | 8 | 3 | High candidate-count case with a query parameter on a neutral detail page. | many editable form distractors |
| `x13-007` | `vulnerable` | 5 | 3 | Checks a structurally favoured search input with a query-parameter distractor. | safe reflected query parameter distractor |
| `x13-008` | `vulnerable` | 6 | 3 | Neutral naming under ambiguity. | parameter names do not reveal intent |
| `x13-009` | `vulnerable` | 4 | 3 | Escaped-reflection distractor where the actionable form is on the second page. | first page has only escaped reflections |
| `x13-010` | `vulnerable` | 7 | 3 | Discovery includes non-reflecting inputs before the vulnerable candidate. | non-reflection decoys |
| `x13-011` | `vulnerable` | 6 | 3 | Evidence robustness with a stable-baseline query parameter. | response shape similar to safe cases |
| `x13-012` | `vulnerable` | 8 | 4 | Adversarial structural case where simple ranking signals are misleading. | simple structural ranking likely misleading |
| `x13-013` | `vulnerable` | 5 | 3 | Parameter-level distinction inside a multi-input form. | companion field is escaped |
| `x13-014` | `vulnerable` | 6 | 3 | Seed order puts safe pages before the vulnerable candidate. | safe page appears first |
| `x13-015` | `vulnerable` | 7 | 3 | Route-neutral positive case. | route name is neutral |
| `x13-016` | `vulnerable` | 5 | 3 | Ranker-adversarial positive where a safe candidate has stronger generic features. | safe candidate has stronger generic features |
| `x13-017` | `negative` | 4 | 2 | Escaped negative control. | all reflections escaped |
| `x13-018` | `negative` | 5 | 3 | Non-reflection negative control. | submitted values are not reflected |
| `x13-019` | `negative` | 6 | 3 | Multi-seed negative with several safe reflections. | multiple safe reflections across seed pages |
| `x13-020` | `negative` | 7 | 3 | High candidate-count negative where all candidates are non-executing. | many candidates, all non-executing |
| `x13-021` | `negative` | 6 | 3 | Decoy-rich negative with required fields and query parameters. | required fields and query parameters are decoys |
| `x13-022` | `negative` | 6 | 3 | Reflection-is-not-execution control. | literal-like payload text remains escaped or inert |
| `x13-023` | `negative` | 8 | 3 | Adversarial negative where structurally strong candidates are safe. | structurally strong candidates are all safe |
| `x13-024` | `negative` | 4 | 2 | Simple negative sanity case. | stable pages with no executable sink |

## Notes

- Route and parameter names are neutral and must not encode expected outcomes.
- Scenario IDs identify benchmark cases only; they do not identify the vulnerable candidate.
- Negative scenarios contain discoverable candidates but no candidate should verify.
- This catalog describes structure, not post-run scoring results.
