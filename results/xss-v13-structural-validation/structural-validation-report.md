# XSS v1.3 Structural Validation Report

Report status: structural validation only. No ranking, browser vulnerability testing, ZAP scanning, LLM execution, or final scoring was performed.

- Valid: `True`
- Scenarios: `24`
- Vulnerable scenarios: `16`
- Negative scenarios: `8`
- Candidate count range: `4` to `8`
- Candidate-count distribution: `{'4': 4, '5': 5, '6': 8, '7': 4, '8': 3}`
- Ground-truth semantics loaded: `False`

## Scenario Matrix

| Scenario | Outcome class | Candidates | Seeds | Structural challenge |
| --- | --- | ---: | ---: | --- |
| `x13-001` | `vulnerable` | 4 | 3 | one safe reflected distractor |
| `x13-002` | `vulnerable` | 5 | 3 | forms look more promising than the query parameter |
| `x13-003` | `vulnerable` | 6 | 3 | first seed contains only safe reflections |
| `x13-004` | `vulnerable` | 6 | 3 | required decoy looks dominant |
| `x13-005` | `vulnerable` | 7 | 3 | several text input distractors |
| `x13-006` | `vulnerable` | 8 | 3 | many editable form distractors |
| `x13-007` | `vulnerable` | 5 | 3 | safe reflected query parameter distractor |
| `x13-008` | `vulnerable` | 6 | 3 | parameter names do not reveal intent |
| `x13-009` | `vulnerable` | 4 | 3 | first page has only escaped reflections |
| `x13-010` | `vulnerable` | 7 | 3 | non-reflection decoys |
| `x13-011` | `vulnerable` | 6 | 3 | response shape similar to safe cases |
| `x13-012` | `vulnerable` | 8 | 4 | simple structural ranking likely misleading |
| `x13-013` | `vulnerable` | 5 | 3 | companion field is escaped |
| `x13-014` | `vulnerable` | 6 | 3 | safe page appears first |
| `x13-015` | `vulnerable` | 7 | 3 | route name is neutral |
| `x13-016` | `vulnerable` | 5 | 3 | safe candidate has stronger generic features |
| `x13-017` | `negative` | 4 | 2 | all reflections escaped |
| `x13-018` | `negative` | 5 | 3 | submitted values are not reflected |
| `x13-019` | `negative` | 6 | 3 | multiple safe reflections across seed pages |
| `x13-020` | `negative` | 7 | 3 | many candidates, all non-executing |
| `x13-021` | `negative` | 6 | 3 | required fields and query parameters are decoys |
| `x13-022` | `negative` | 6 | 3 | literal-like payload text remains escaped or inert |
| `x13-023` | `negative` | 8 | 3 | structurally strong candidates are all safe |
| `x13-024` | `negative` | 4 | 2 | stable pages with no executable sink |
