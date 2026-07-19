# Evaluation Protocol v1.1

## Status

This document supersedes `evaluation-protocol-v1` before any held-out vulnerability testing was executed. Version `v1` is preserved as a historical superseded protocol.

The corrected implementation must be frozen by an annotated Git tag named `evaluation-protocol-v1.1` after this document and related references are committed. This document intentionally does not contain a self-referential final commit hash.

## Pre-Evaluation Corrections

Two pre-evaluation protocol defects were identified in `evaluation-protocol-v1`:

1. `evaluation-protocol-v1` recorded LLM temperature as `0.0`, but `src/adstf/openai_ranking_wrapper.py` omits the `temperature` request parameter unless `OPENAI_SEND_TEMPERATURE` is explicitly enabled. Prior real-provider smoke testing used the omission behavior because the selected model rejected an explicit temperature parameter.
2. `evaluation-protocol-v1` referenced Git commit `e5c347c0fbf87591422756a953d5f61c37c9134f`, which did not yet contain the protocol document, held-out target configs, held-out manifest, held-out ground truth, held-out server, validation code, or README references.

These corrections do not change prompts, model identifier, trial counts, benchmark cases, budgets, metrics, mappings, ZAP policies, verifier rules, payload behavior, target behavior, or scanner behavior.

The correction base commit is `79e66ad7725d9988badd748df08889fc2ab41bb9`, which contains `evaluation-protocol-v1` and the held-out protocol/benchmark assets. The final immutable identifier for this corrected protocol is the future annotated Git tag `evaluation-protocol-v1.1`.

## Purpose

This document freezes the experimental protocol for moving from development validation to held-out thesis evaluation. The held-out benchmark cases must not be used to tune prompts, mappings, policies, verifier rules, payloads, budgets, discovery behavior, scanner settings, or target behavior.

## Protocol-Critical Hashes

The following SHA-256 values identify protocol-critical files for `evaluation-protocol-v1.1`. The protocol document itself is not included in this table to avoid self-reference.

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
| `src/adstf/zap_baseline.py` | `67390438c4b374d4d9c2d3a0cdc7cf819972365574c16559eea90699341794d0` |
| `src/adstf/mvp_benchmark.py` | `1ea300dd75de250d6e082c6722ea87cd158b612c47b56a7a7216587e2382a8ed` |
| `src/adstf/heldout_benchmark_server.py` | `7f634bc3fb780e6ab83116262193fd90036c8e87160913334875e0838f1dd893` |
| `src/adstf/heldout_validation.py` | `9ff6b7095139d752b2e5be2debbed3bd357e9e8920831dd28aeb25d6dda25cb9` |

## Held-Out Benchmark Set

The held-out benchmark set is local-only, disposable, and separate from the development benchmarks. Evaluation units are benchmark cases, not individual HTTP requests.

| Case ID | Target | Category | Scored For Framework | Scored For ZAP |
| --- | --- | --- | --- | --- |
| `hx-001` | `heldout-xss` | reflected XSS | yes | yes |
| `hx-002` | `heldout-xss` | reflected XSS | yes | yes |
| `hx-003` | `heldout-xss` | reflected XSS | yes | yes |
| `hi-001` | `heldout-idor` | read-only IDOR | yes | no |
| `hi-002` | `heldout-idor` | read-only IDOR | yes | no |
| `hs-001` | `heldout-sqli` | boolean SQL injection | yes | yes |
| `hs-002` | `heldout-sqli` | boolean SQL injection | yes | yes |

IDOR is unsupported for ZAP passive and active baselines because these scans do not establish two isolated authenticated user sessions or prove cross-user read authorization behavior. IDOR cases must be reported as unsupported for ZAP and excluded from ZAP TP/FP/FN/TN calculations.

Ground truth is stored only in `examples/benchmarks/heldout-ground-truth-v1.json`. It may be loaded only by post-run evaluation code after all action execution, verification, scanner runs, and LLM ranking trials have completed.

## Common Scope

All methods must operate only on local held-out targets:

- Framework local URLs: `127.0.0.1:4391`, `127.0.0.1:4392`, `127.0.0.1:4393`
- ZAP Docker-facing URLs: `host.docker.internal:4391`, `host.docker.internal:4393`
- Allowed scheme: `http`

The framework may evaluate XSS, IDOR, and SQLi. ZAP baselines may evaluate only XSS and SQLi. Any alert outside the allowed host/port set must be recorded as out of scope and excluded from scoring.

## Frozen Framework Settings

- Reflected-input deterministic ranking: `deterministic-structural-v1`
- XSS candidate test budget: `6` candidates per held-out XSS case
- XSS browser timeout: `10` seconds per browser observation unless a lower-level executor default fails earlier
- IDOR sessions: exactly two isolated benchmark users per IDOR case
- SQLi baseline repetitions: `3`
- SQLi boolean true/false repetitions: `3`
- Framework maximum actions: `24` per held-out target config
- Verifier rules: frozen by `src/adstf/verification.py` hash above
- Findings must be decided only by verifier lifecycle outcomes: `verified`, `rejected`, or `inconclusive`

Inconclusive framework cases count as not verified for TP/FP/FN/TN classification, while still being separately reported as inconclusive.

## Frozen LLM Ranking Settings

The LLM component is evaluated only for XSS candidate ranking. It may rank existing discovered candidate IDs and provide rationales. It must not execute actions, generate payloads, control the browser, verify findings, access scanner output, or access ground truth.

- Prompt version: `llm-candidate-ranking-v1`
- Model provider boundary: command-client wrapper
- Provider: OpenAI wrapper via `python -m adstf.openai_ranking_wrapper`
- Model environment variable: `OPENAI_RANKING_MODEL=gpt-5.6-luna`
- Temperature request parameter: omitted
- Temperature behavior: provider/model default used
- `OPENAI_SEND_TEMPERATURE`: must be unset, empty, `0`, `false`, or `no`
- Maximum output tokens: `1200`
- Timeout: `OPENAI_TIMEOUT_SECONDS=60`
- Trial count: `5` trials per held-out XSS case
- Invalid, malformed, duplicate, omitted, unknown-ID, timed-out, and provider-failed trials must be retained but excluded from valid LLM performance aggregates
- Deterministic fallback may be used only for safe continuation and must not improve reported LLM metrics

Ranking metrics must be computed for deterministic ranking and valid LLM trials using the same candidate sets, test budgets, payload behavior, browser execution path, and verifier lifecycle.

## Frozen ZAP Baselines

ZAP baselines are scanner baselines, not verifier-confirmed framework findings.

Shared ZAP identity:

- Image: `zaproxy/zap-stable:2.16.1`
- Image digest: `zaproxy/zap-stable@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`
- Report format: OWASP ZAP JSON
- Raw reports and normalized alerts must be retained
- Unmatched alerts must be retained separately

Passive baseline:

- Baseline identity: `zap_passive`
- Mapping version: `zap-passive-mapping-v1`
- Traffic source: ZAP spider-generated traffic only
- Runtime budget: `1` minute per target
- Active scan: disabled
- Authentication: disabled

Active baseline:

- Baseline identity: `zap_active`
- Policy version: `zap-active-policy-v1`
- Mapping version: `zap-active-mapping-v1`
- Automation Framework plan: retained per target
- Enabled active rule IDs: `40012` reflected XSS and `40018` SQL injection
- Default threshold: `Off`
- Enabled-rule threshold: `Medium`
- Strength: `Low`
- Spider max duration: `1` minute
- Active scan max duration: `2` minutes
- Active rule max duration: `1` minute
- Authentication: disabled

ZAP must not proxy framework-crafted XSS or SQLi verifier traffic. ZAP uses only its own spider and active-scan traffic.

## Metrics

Case-level classification:

- TP: expected vulnerable and verified/alerted
- FP: expected secure and verified/alerted
- FN: expected vulnerable and not verified/alerted
- TN: expected secure and not verified/alerted

Framework metrics:

- TP, FP, FN, TN
- verified, rejected, inconclusive counts
- actions executed, blocked, failed, and skipped
- candidates tested before first verified finding
- time to first verified finding
- run duration
- request count where available

Scanner metrics:

- TP, FP, FN, TN over supported XSS and SQLi cases only
- unsupported case count
- raw alert count
- matched alert count
- unmatched alert count
- scan duration
- target scope validation result

Ranking metrics:

- top-1 accuracy for cases with vulnerable candidates
- top-k recall using frozen candidate test budget
- mean reciprocal rank
- vulnerable-candidate rank distribution
- selected-candidate distribution
- valid, invalid, failed, and fallback trial counts

Resource metrics:

- runtime per case and per baseline
- HTTP request count when recorded
- browser observation count when recorded
- token usage from provider metadata when available
- estimated LLM cost using the frozen model pricing basis recorded by the run artifact
- provider latency

No-vulnerability XSS cases must not force ranking metrics that do not apply. Such fields should be `null` or marked not applicable.

## Failure Handling

Framework action failures must be retained in artifacts. A case is inconclusive when required evidence cannot be collected, safety boundaries prevent confirmation, session isolation fails, or the verifier cannot satisfy category evidence requirements.

LLM provider failures, malformed output, unknown IDs, duplicate IDs, omitted candidates, and timeouts are invalid or failed trials. They are reported separately and excluded from valid LLM performance aggregates.

ZAP command failures must retain command, stdout, stderr, timing, image digest, target URL, and plan/report path. A failed ZAP target run is excluded from scanner performance aggregates and reported as failed, unless a complete JSON report was produced and scope validation passes.

## Defect Procedure

After held-out evaluation begins, prompts, policies, mappings, verifier rules, payload behavior, candidate schema, benchmark cases, budgets, and metric definitions are frozen.

A change is allowed only for a genuine integration defect, such as:

- The target cannot start or reset due to a non-security bug.
- An artifact cannot be parsed because of a schema mismatch.
- A Docker/ZAP command cannot run due to a documented Automation Framework compatibility issue.
- A provider API rejects a documented request parameter and the correction aligns the protocol with already implemented provider-wrapper behavior.
- A reporting path drops data that was already produced.

Any such change requires:

1. Stop the affected experiment.
2. Document the defect, affected artifacts, and reason the change is not result tuning.
3. Increment the relevant protocol, policy, mapping, prompt, or benchmark version.
4. Recompute hashes for all affected files.
5. Rerun all affected experiments from scratch under the new version.
6. Keep both old and new artifacts for auditability.

Changes are not allowed merely because a method performs poorly, misses a vulnerability, produces false positives, or because a prompt, mapping, or policy could be improved after seeing held-out results.

## Structural Validation

Structural validation for `evaluation-protocol-v1.1` was rerun after this correction:

- Run: `.adstf-runs/heldout-structural-validation-20260719T223330Z`
- Targets: `heldout-xss`, `heldout-idor`, `heldout-sqli`
- Health checks: passed
- Reset checks: passed
- Manifest schema checks: passed
- Ground truth file existence: confirmed
- Ground truth semantic loading: `false`
- Vulnerability testing: not performed

Structural validation may start held-out targets and check only health, reset, manifest schema, scope, and artifact schema behavior. It must not execute vulnerability tests, inspect held-out outcomes, load semantic ground truth, run final evaluation, or tune behavior.
