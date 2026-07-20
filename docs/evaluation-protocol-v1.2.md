# Evaluation Protocol v1.2

## Status

This document supersedes `evaluation-protocol-v1.1` before any thesis interpretation of held-out results. Version `v1.1` is preserved as a historical superseded protocol because its held-out execution exposed two pre-interpretation defects.

The corrected implementation must be frozen by an annotated Git tag named `evaluation-protocol-v1.2` after this document and related references are committed. This document intentionally does not contain a self-referential final commit hash.

## v1.1 Defects Corrected

1. Held-out IDOR evidence wiring was incorrect in the temporary evaluation assembly. The vulnerable `hi-001` finding included rejecting secure-control evidence from `hi-002`, causing the verifier to reject `hi-001` even though cross-user read evidence was present.
2. ZAP passive and active normalization used development mapping rules. As a result, ZAP scored six development cases instead of the five ZAP-supported held-out cases.

These corrections do not change prompts, model identifier, model settings, payloads, verifier criteria, benchmark cases, target behavior, budgets, ZAP scan policies, metric definitions, or failure-handling rules.

## Protocol-Critical Hashes

The following SHA-256 values identify protocol-critical files for `evaluation-protocol-v1.2`. The protocol document itself is not included to avoid self-reference.

| Artifact | SHA-256 |
| --- | --- |
| `examples/benchmarks/heldout-manifest-v1.json` | `81981053a3bcb7f806746c2515172ab28d4598804085edf7e7da0e4b76faf080` |
| `examples/benchmarks/heldout-ground-truth-v1.json` | `393bdd0b3646fe28aa8527dc3d6ef4afa287155af7ea7ce0b2e8456475e45878` |
| `examples/targets/heldout-xss-local.json` | `0c7901443aa10ccc35da38bf3f65e723d973c75bc8de20cf494340bb1f54f803` |
| `examples/targets/heldout-idor-local.json` | `e9b01625e30523f44be18a6e9342978ce9afb44dcf16e20ca11fdcbbf8610c92` |
| `examples/targets/heldout-sqli-local.json` | `69a078d876644c8e4432cdaf85c04d0c008b05e4ede030c687fab865b22fe13b` |
| `src/adstf/verification.py` | `4a108365c9fab4c1cb2f7af36d1e47d46f8d6109153cc803d4a450f8525b3cb7` |
| `src/adstf/discovery.py` | `e360edc3d440bc65ddc199e6fa9b5a8afb80ed5a60d40139a3f218c06cd54305` |
| `src/adstf/llm_ranking.py` | `7f39e73faf024eec0c7bf03e995e63572ad4ccc9c8f895f44bd6ae9a1de89e25` |
| `src/adstf/openai_ranking_wrapper.py` | `78db929df3ab691cbaa36fdae5a799c68e3dc8f6850b8e1edc0fe4b9f7a3f0df` |
| `src/adstf/zap_baseline.py` | `df4a9364e1769865436b6269a42f868255f720246d6e58af6af4e0888fa67c5b` |
| `src/adstf/mvp_benchmark.py` | `1ea300dd75de250d6e082c6722ea87cd158b612c47b56a7a7216587e2382a8ed` |
| `src/adstf/heldout_benchmark_server.py` | `7f634bc3fb780e6ab83116262193fd90036c8e87160913334875e0838f1dd893` |
| `src/adstf/heldout_evaluation.py` | `40f301478d51e2e770c8a701fbe2d5cd6dabf482838aeae5bf13c04eb0e3872a` |
| `src/adstf/heldout_validation.py` | `ffa1077b2ebb7cde37991d3c65e94c1a443e2cd2736d305da84d6447de6a9180` |
| `tests/test_heldout_evaluation.py` | `a9a46e5baafa0dc174551b59b469d669689bc989b030db8e2493a58e5a305cf8` |

## Held-Out Benchmark Set

The held-out benchmark set remains unchanged from `v1.1`.

| Case ID | Target | Category | Scored For Framework | Scored For ZAP |
| --- | --- | --- | --- | --- |
| `hx-001` | `heldout-xss` | reflected XSS | yes | yes |
| `hx-002` | `heldout-xss` | reflected XSS | yes | yes |
| `hx-003` | `heldout-xss` | reflected XSS | yes | yes |
| `hi-001` | `heldout-idor` | read-only IDOR | yes | no |
| `hi-002` | `heldout-idor` | read-only IDOR | yes | no |
| `hs-001` | `heldout-sqli` | boolean SQL injection | yes | yes |
| `hs-002` | `heldout-sqli` | boolean SQL injection | yes | yes |

Ground truth remains stored only in `examples/benchmarks/heldout-ground-truth-v1.json` and may be loaded only by post-run evaluation after action execution, verifier decisions, scanner runs, and LLM ranking trials have completed.

## Corrected IDOR Evidence Rule

Held-out IDOR findings must be verified using evidence scoped to the same held-out case.

- `hi-001` supporting evidence may include only its own sessions, ownership evidence, own-read evidence, cross-user-read evidence, and comparison/control evidence labeled `hi-001`.
- `hi-002` secure-control rejecting evidence must remain attached only to `hi-002`.
- Rejecting evidence from one case must never be included in another case's finding support set.
- Offline tests must prove that cross-case rejecting evidence is detected before verifier results are interpreted.

Verifier criteria remain unchanged. If a held-out IDOR finding lacks required same-case evidence, it must be inconclusive or rejected according to the frozen verifier lifecycle, not repaired by borrowing another case's evidence.

## Corrected Held-Out ZAP Mapping

Held-out ZAP normalization must use held-out mapping profiles only:

- Passive mapping version: `zap-heldout-passive-mapping-v1`
- Active mapping version: `zap-heldout-active-mapping-v1`
- Evaluated case IDs, exactly:
  - `heldout-xss::hx-001`
  - `heldout-xss::hx-002`
  - `heldout-xss::hx-003`
  - `heldout-sqli::hs-001`
  - `heldout-sqli::hs-002`
- Unsupported case IDs, exactly:
  - `heldout-idor::hi-001`
  - `heldout-idor::hi-002`

The ZAP-supported denominator is therefore five held-out cases: three XSS cases and two SQLi cases. IDOR remains unsupported and excluded from ZAP TP/FP/FN/TN calculations.

## Frozen Settings

The following settings remain unchanged from `evaluation-protocol-v1.1`:

- Reflected-input deterministic ranking: `deterministic-structural-v1`
- XSS candidate test budget: `6`
- LLM prompt version: `llm-candidate-ranking-v1`
- LLM model: `OPENAI_RANKING_MODEL=gpt-5.6-luna`
- Temperature request parameter: omitted; provider/model default used
- `OPENAI_SEND_TEMPERATURE`: must be unset, empty, `0`, `false`, or `no`
- LLM trial count: `5` trials per held-out XSS case
- SQLi baseline repetitions: `3`
- SQLi boolean true/false repetitions: `3`
- ZAP image: `zaproxy/zap-stable:2.16.1`
- ZAP image digest: `zaproxy/zap-stable@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`
- ZAP active policy: `zap-active-policy-v1`
- ZAP active rules: `40012` and `40018`
- ZAP passive and active budgets
- Payload behavior, verifier criteria, metric definitions, and failure-handling rules

## Rerun Requirements

After `evaluation-protocol-v1.2` is committed and tagged, the following must be rerun before thesis interpretation:

- Held-out structural validation
- Held-out framework IDOR execution and post-run scoring
- ZAP passive normalization/scoring with `zap-heldout-passive-mapping-v1`
- ZAP active normalization/scoring with `zap-heldout-active-mapping-v1`
- Aggregate summary/report generation

The v1.1 XSS LLM trials and SQLi framework execution were not affected by these two defects, but a complete all-v1.2 evaluation rerun may still be preferable for a single clean artifact set.

## Structural Validation

Structural validation for `evaluation-protocol-v1.2` was rerun after the correction:

- Run: `.adstf-runs/heldout-structural-validation-20260720T083205Z`
- Harness validation: passed
- Held-out ZAP supported scope: `heldout-xss::hx-001`, `heldout-xss::hx-002`, `heldout-xss::hx-003`, `heldout-sqli::hs-001`, `heldout-sqli::hs-002`
- Held-out ZAP unsupported scope: `heldout-idor::hi-001`, `heldout-idor::hi-002`
- Health checks: passed
- Reset checks: passed
- Manifest schema checks: passed
- Ground truth semantic loading: `false`
- Vulnerability testing: not performed

## Defect Procedure

After held-out evaluation begins under `v1.2`, prompts, policies, mappings, verifier rules, payload behavior, candidate schema, benchmark cases, budgets, and metric definitions are frozen. Any genuine integration defect requires a new protocol version, updated hashes, and complete reruns of affected experiments.
