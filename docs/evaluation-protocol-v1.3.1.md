# Evaluation Protocol v1.3.1

Status: **frozen recovery amendment**.

This document is a recovery amendment to the frozen
`evaluation-protocol-v1.3`. It does not replace or edit the frozen v1.3
protocol, annotated tag, candidate snapshots, or completed v1.3 result package.
Those artifacts remain historical evidence of the first frozen execution
attempt.

This amendment is frozen by the annotated Git tag
`evaluation-protocol-v1.3.1`. Later methodological changes require a separately
versioned amendment and must not modify this frozen protocol in place.

## Provenance

Base protocol:

- protocol: `docs/evaluation-protocol-v1.3.md`;
- annotated tag: `evaluation-protocol-v1.3`;
- tag object: `f97df8ea7646971265b9b7f0e25853cd8f562dd0`;
- tagged commit: `2b12229a5c62665bcbf3c4618db8515aa2ea1e9f`;
- initial v1.3 execution branch head observed during amendment preparation:
  `e078aec806c290509da25f7073a507cd5940e434`.

Historical v1.3 result package:

- canonical package: `results/xss-v13-ablation-v1.3/canonical/`;
- raw run: `results/xss-v13-ablation-v1.3/xss-v13-ablation-20260807T081244Z/`;
- status: retained as historical evidence;
- GPT observations: retained as provider-call infrastructure failures, not GPT
  ranking-performance observations.

v1.3.1 live provider-connectivity readiness evidence:

- artifact:
  `results/xss-v13-1-provider-connectivity-readiness-live/provider-connectivity-readiness.json`;
- model identifier: `gpt-5.6-luna`;
- provider: `openai`;
- prompt version: `llm-candidate-ranking-v1`;
- temperature parameter: omitted, provider default used;
- live provider call executed: `true`;
- provider failed: `false`;
- valid: `true`;
- held-out scenario used: `false`;
- scored observation created: `false`;
- usage metadata present: `true`;
- latency recorded: `true`.

This readiness evidence confirms that the frozen proprietary provider boundary
is reachable from a normal local PowerShell environment. It supports treating
the v1.3 `[WinError 10013]` failures as execution-environment infrastructure
failures rather than GPT model-performance evidence.

## Defects Motivating v1.3.1

Two defects were identified after the frozen v1.3 execution.

First, all 120 `proprietary_gpt` calls failed before a provider response was
received. The retained artifacts show:

- model identifier resolved as `gpt-5.6-luna`;
- API key presence was confirmed without recording the secret;
- no raw provider response was received;
- no provider response id was retained;
- no token usage or cost metadata was retained;
- all failures had the same local socket-permission error:
  `[WinError 10013] An attempt was made to access a socket in a way forbidden
  by its access permissions`.

This failure is infrastructure evidence only. It must not be interpreted as GPT
model-quality evidence.

Second, the already-defined `time_to_first_verified_finding` metric could not
be calculated from the v1.3 run because verification completion timestamps were
not retained in finding records. The metric definition already allowed
`FindingRecord.report_fields.verification_completed_at`, but the implementation
did not persist that field.

## Unchanged Scientific Design

The amendment does not change:

- the 24 scenarios;
- frozen candidate snapshots;
- candidate metadata;
- three experimental arms;
- selected models;
- ranking prompt or parser;
- decoding or model settings;
- trial counts;
- candidate-test budget;
- top-k definition;
- executor behavior;
- verifier decision criteria;
- payload strategy;
- ground-truth separation;
- ranking metric definitions;
- detection metric definitions.

No v1.3.1 implementation or analysis may tune behavior based on the observed
v1.3 deterministic or Qwen results.

## Provider Connectivity Readiness

Before any scored `proprietary_gpt` schedule begins, v1.3.1 requires a
non-scored provider-connectivity readiness check.

The readiness check:

- uses the same restricted candidate-ranking contract;
- uses the frozen `gpt-5.6-luna` model identifier;
- omits the temperature parameter;
- uses a synthetic readiness candidate set that is not part of the 24 held-out
  scenarios;
- does not load ground truth;
- does not execute browser verification;
- does not create a scored observation;
- records raw response presence, parsed output validity, provider failure,
  response metadata, usage and latency when available.

If the readiness check fails because the provider cannot be reached, the scored
experiment must not start. The failure must be recorded as an infrastructure
readiness failure.

## Verification Timestamp Instrumentation

v1.3.1 retains verifier completion timestamps without changing verifier
decisions.

Timestamp semantics:

- field retained in `VerifierResult`: `completed_at`;
- field copied into `FindingRecord.report_fields` when a verifier result is
  applied: `verification_completed_at`;
- clock source: timezone-aware UTC wall-clock timestamp captured immediately
  when the deterministic verifier constructs its result;
- unit and format: ISO 8601 string with UTC offset;
- metric source: existing `docs/metrics-definition-v1.3.md`
  `FindingRecord.report_fields.verification_completed_at` rule.

The metric must not be reconstructed from file modification times, directory
ordering, JSON file names, or inferred event order.

Instrumentation-critical implementation hashes at draft preparation time:

| Artifact | SHA-256 |
| --- | --- |
| `src/adstf/contracts.py` | `b5e71a384e72576dc3adff94000fb3d07e35b4096c5cc45285674ef07246321b` |
| `src/adstf/verification.py` | `4499fc7289a6a65aba84c80ed80747df83e902b2b35827a65d42cfb3589b254d` |
| `src/adstf/lifecycle.py` | `c47d336f795c913564c91190e207dd1051491d96d754db4315869b720324099f` |
| `src/adstf/xss_v13_ablation_harness.py` | `6686753ab8ef1fe3522d75853925b3d75b7ac6e4e0416076aa3d8900e47c728d` |

These hashes were verified before the v1.3.1 freeze. Any future implementation
change affecting these files requires a separately versioned amendment.

## Recovery Scope

The original GPT infrastructure failure affected the `proprietary_gpt` arm.
However, the timestamp-retention defect affects all arms because
time-to-first-verifier-confirmed-finding is required for deterministic,
proprietary GPT and local Qwen comparisons.

Therefore, if the thesis requires a complete common-run comparison including
the existing time-to-first metric for all arms, the academically clean recovery
is:

```text
complete three-arm v1.3.1 rerun
```

The original v1.3 failed GPT observations must remain preserved and cited as
superseded infrastructure-failure evidence. They must not be deleted or
silently replaced.

v1.3.1 chooses the complete three-arm rerun. The final corrected study must run
`deterministic_structural`, `proprietary_gpt` and `local_qwen` under the same
corrected instrumentation and common execution environment.

The expected frozen denominators are:

| Arm | Ranking rows |
| --- | ---: |
| `deterministic_structural` | 24 |
| `proprietary_gpt` | 120 |
| `local_qwen` | 120 |
| Total | 264 |

## Failure Handling

v1.3.1 keeps the v1.3 failure-handling rules:

- malformed outputs are retained;
- provider failures are retained;
- timeouts are retained;
- failed or invalid model trials are excluded from valid ranking-performance
  aggregates;
- no silent retries are allowed;
- no deterministic ranking may be counted as a valid LLM result;
- Gemma must not silently replace failed Qwen trials.

The provider-connectivity readiness check is pre-execution infrastructure
validation, not a scored retry.

## Ground Truth

Ground truth remains inaccessible during readiness checks, ranking, execution,
evidence collection and deterministic verification. It may be loaded only after
the scored experiment has completed for post-run scoring.

## Readiness Package

The amendment-readiness package is:

`results/xss-v13-1-amendment-readiness/`

It must contain:

- manifest;
- provider-connectivity readiness schema/result;
- timestamp metric dry-validation fixture;
- validation report;
- human-readable report;
- checksums.

The package must clearly state whether live provider connectivity was executed.
For offline amendment validation, fake-provider readiness is sufficient to test
the reporting and validation mechanism but not sufficient to authorize scored
execution.

## Freeze Rule

This protocol is frozen. Freezing v1.3.1 required:

1. all offline tests passing;
2. amendment-readiness validation passing;
3. live non-scored proprietary-provider connectivity readiness passing;
4. updated hashes where necessary;
5. commit;
6. clean working tree;
7. annotated tag `evaluation-protocol-v1.3.1`.

After freezing, any further change to scenarios, snapshots, prompts, parser,
model identifiers, settings, budgets, verifier criteria, metrics or recovery
scope requires another protocol revision.
