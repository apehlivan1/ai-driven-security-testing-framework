# Final Descriptive Analysis for Held-Out Evaluation v1.2

This analysis uses only `results/heldout-evaluation-v1.2-canonical`. It does not rerun experiments, modify raw artifacts, alter framework behavior, or introduce post-hoc scanner/prompt changes.

## Source and Traceability

- Canonical package: `results/heldout-evaluation-v1.2-canonical`
- Canonical manifest SHA-256: `8374d318fe31a44a56377dfc9885ad773431e1038475f8e5308706fa160a08e0`
- Protocol: `evaluation-protocol-v1.2`
- Git tag: `evaluation-protocol-v1.2`
- Git commit: `7c2466121a888b4edf359d3166c45c687a06d765`
- Canonical package validation: `True`

Every table in this directory is derived from the canonical manifest, normalized canonical tables, or copied canonical raw summaries.

## Main Descriptive Results

| Evaluation | Scope | Cases | TP | FP | FN | TN | Accuracy | Precision | Recall | Specificity | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Framework overall | xss+sqli+idor | 7 | 4 | 0 | 0 | 3 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework common scope | xss+sqli | 5 | 3 | 0 | 0 | 2 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| ZAP passive | xss+sqli | 5 | 0 | 0 | 3 | 2 | 0.4 | not_applicable | 0.0 | 1.0 | not_applicable |
| ZAP active | xss+sqli | 5 | 1 | 0 | 2 | 2 | 0.6 | 1.0 | 0.3333 | 1.0 | 0.5 |

The framework evaluated all seven held-out cases across reflected XSS, read-only IDOR, and boolean-based SQL injection. ZAP passive and ZAP active were evaluated only on the five XSS and SQLi cases because IDOR requires two-user authorization reasoning that these baselines did not support in this protocol.

## Framework by Category

| Category | Cases | TP | FP | FN | TN | Accuracy | Precision | Recall | Specificity | F1 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Framework Reflected XSS | 3 | 2 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework Read-only IDOR | 2 | 1 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |
| Framework Boolean-based SQLi | 2 | 1 | 0 | 0 | 1 | 1.0 | 1.0 | 1.0 | 1.0 | 1.0 |

## XSS Ranking

| Ranking Source | Unit | Runs/Trials | Top-1 | Top-k | MRR | Verified Findings |
| --- | --- | --- | --- | --- | --- | --- |
| deterministic-structural-v1 | independent held-out XSS case | 3 | 0.0 | 1.0 | 0.5 | 2 |
| llm-candidate-ranking-v1 | LLM trial over held-out XSS case | 15 | 1.0 | 1.0 | 1.0 | 10 |

The deterministic ranking row uses three independent held-out XSS cases. The LLM row uses fifteen repeated ranking trials across those same three cases. These repeated LLM trials measure ranking stability and behavior under the frozen prompt/model configuration; they are not fifteen independent benchmark cases.

## LLM Usage, Latency, and Cost

| Provider | Model | Prompt | Calls | Valid | Invalid | Failed | Fallback | Total Tokens | Mean Latency ms | Cost |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| openai | gpt-5.6-luna | llm-candidate-ranking-v1 | 15 | 15 | 0 | 0 | 0 | 10294 | 6383.73 | not_available |

Cost is marked `not_available` because the canonical provider metadata did not include a computed cost.

## Runtime and Failures

| Component | Runtime ms | Requested | Executed | Failed | Blocked | Provider/Scanner Failures |
| --- | --- | --- | --- | --- | --- | --- |
| framework_xss_reused_v1.1 | not_available_in_canonical_summary | 101 | 101 | 0 | 0 | not_applicable |
| framework_sqli_reused_v1.1 | not_available_in_canonical_summary | 19 | 19 | 0 | 0 | not_applicable |
| framework_idor_corrected_v1.2 | part_of_affected_v1.2_run_not_individually_reported | not_available_in_canonical_summary | not_available_in_canonical_summary | not_available_in_canonical_summary | not_available_in_canonical_summary | 0 |
| zap_passive_corrected_v1.2 | 143183 | not_applicable | not_applicable | not_applicable | not_applicable | 0 |
| zap_active_corrected_v1.2 | 139569 | not_applicable | not_applicable | not_applicable | not_applicable | 0 |
| llm_ranking_reused_v1.1 | 95756 | not_applicable | not_applicable | not_applicable | not_applicable | 0 |

Runtime is only reported where the canonical artifacts contain enough timing information. Framework XSS and SQLi reused v1.1 summaries contain action counts but not explicit per-component runtime.

## Descriptive Interpretation

- On the seven-case held-out framework scope, the framework produced 4 TP, 0 FP, 0 FN, and 3 TN.
- On the five-case common XSS+SQLi scope, the framework produced 3 TP, 0 FP, 0 FN, and 2 TN.
- ZAP passive produced no mapped XSS/SQLi vulnerability alerts on the common scope, resulting in 0 TP, 0 FP, 3 FN, and 2 TN.
- ZAP active produced one mapped SQLi alert and no mapped XSS alerts, resulting in 1 TP, 0 FP, 2 FN, and 2 TN.
- IDOR is treated separately: the framework supports it in this evaluation, while both ZAP baselines are marked unsupported and excluded from ZAP scoring.
- LLM ranking improved candidate ordering in the held-out XSS ranking task under the frozen prompt/model setup, but that result is based on repeated trials over only three XSS cases.

## Limitations

The held-out sample is intentionally small. These results are suitable for descriptive thesis tables and methodological discussion, but they should not be presented as statistically significant or as proof of general superiority over ZAP. The ZAP comparison is restricted to the shared XSS and SQLi scope. Scanner alerts remain distinct from verifier-confirmed framework findings.
