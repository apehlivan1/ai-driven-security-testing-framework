# Thesis-Ready Descriptive Tables

## Framework Results by Vulnerability Category

| Category | Cases | TP | FP | FN | TN | Accuracy | Precision | Recall | Specificity | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Framework Reflected XSS | 3 | 2 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework Read-only IDOR | 2 | 1 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework Boolean-based SQLi | 2 | 1 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework overall | 7 | 4 | 0 | 0 | 3 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

## Common-Scope Framework vs ZAP Comparison

| Evaluation | Cases | TP | FP | FN | TN | Accuracy | Precision | Recall | Specificity | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Framework common scope | 5 | 3 | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| ZAP passive | 5 | 0 | 0 | 3 | 2 | 0.4 | not_applicable | 0.0 | 1.0 | not_applicable |
| ZAP active | 5 | 1 | 0 | 2 | 2 | 0.6 | 1.0 | 0.3333 | 1.0 | 0.5 |

## XSS Candidate Ranking

| Ranking Source | Unit | Runs/Trials | Top-1 | Top-k | MRR | Verified Findings | No-Vuln FP |
| --- | --- | --- | --- | --- | --- | --- | --- |
| deterministic-structural-v1 | independent held-out XSS case | 3 | 0.0 | 1.0 | 0.5 | 2 | 0 |
| llm-candidate-ranking-v1 | LLM trial over held-out XSS case | 15 | 1.0 | 1.0 | 1.0 | 10 | 0 |

## LLM Usage and Latency

| Provider | Model | Calls | Valid | Invalid | Failed | Fallback | Tokens | Mean Latency ms | Cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openai | gpt-5.6-luna | 15 | 15 | 0 | 0 | 0 | 10294 | 6383.73 | not_available |

## ZAP IDOR Treatment

| Baseline | Unsupported Cases | Treatment |
| --- | --- | --- |
| ZAP passive | heldout-idor::hi-001, heldout-idor::hi-002 | Unsupported and excluded from ZAP scoring |
| ZAP active | heldout-idor::hi-001, heldout-idor::hi-002 | Unsupported and excluded from ZAP scoring |

Note: These are descriptive tables for a small held-out set. They do not establish statistical significance or general superiority.
