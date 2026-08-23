# Experiment History

This document records the major evaluation protocol milestones so later thesis
writing can distinguish historical evidence from corrected final evidence.

## v1.2 Held-Out MVP Evaluation

`evaluation-protocol-v1.2` is the frozen held-out MVP evaluation for the initial
framework scope: reflected XSS, read-only IDOR and non-destructive
boolean-based SQL injection. Its canonical result package is:

`results/heldout-evaluation-v1.2-canonical/`

The v1.2 results remain frozen historical evidence. They should not be modified
by v1.3 work.

## v1.3 XSS Ablation Protocol

`evaluation-protocol-v1.3` froze the expanded reflected-XSS ablation study. It
defined:

- 24 frozen XSS scenarios
- one ground-truth-free candidate snapshot per scenario
- three arms: `deterministic_structural`, `proprietary_gpt` and `local_qwen`
- candidate-test budget 4
- identical snapshots and candidate metadata for all arms
- fixed prompt, parser, model/runtime settings and trial counts
- post-run ground-truth scoring only

The initial v1.3 execution produced valid deterministic and local Qwen results,
but all 120 proprietary GPT calls failed before reaching the provider because
of a local socket-permission infrastructure error. Those failed GPT observations
are preserved as historical infrastructure-failure evidence. They are not GPT
model-quality evidence.

## v1.3.1 Recovery Amendment

`evaluation-protocol-v1.3.1` is a recovery amendment to v1.3. It documents the
v1.3 infrastructure failure and adds only:

- proprietary-provider connectivity readiness before scored execution
- verifier completion timestamp retention for time-to-first-verified-finding
- execution-environment handling required to avoid the v1.3 socket-permission
  failure

It does not change scenarios, snapshots, models, prompts, parsers, decoding
settings, trial counts, budgets, top-k definition, verifier criteria,
ground-truth separation or scoring rules.

A manual non-scored provider readiness check confirmed that `gpt-5.6-luna` was
reachable from a normal local PowerShell environment. The readiness check did
not use a held-out scenario and did not create a scored observation.

## Final v1.3.1 XSS Ablation Run

The final corrected run is:

`results/xss-v13-ablation-v1.3.1-final/xss-v13-ablation-20260808T103409Z`

The canonical package is:

`results/xss-v13-ablation-v1.3.1-final/canonical/`

The final run produced the frozen denominators:

| Arm | Rows |
| --- | ---: |
| `deterministic_structural` | 24 |
| `proprietary_gpt` | 120 |
| `local_qwen` | 120 |
| Total | 264 |

The GPT arm had 116 schema-valid rankings and 4 schema-invalid rankings. The
schema-invalid responses are retained as malformed-output observations, not
provider failures. The Qwen arm had 120 valid rankings. Gemma was not
activated.

The v1.3.1 canonical package is the preferred evidence source for the final XSS
ablation discussion. The earlier v1.3 run should be cited only when explaining
the infrastructure recovery history.

## v1.5 OWASP SQLi Protocol And Interrupted Execution

`evaluation-protocol-v1.5` froze the OWASP Benchmark SQL injection external
validation design. It defined 200 final eligible OWASP SQLi cases, 124 ranking
scenarios, 124 deterministic ranking rows, 620 GPT ranking rows, 620 Qwen
ranking rows and a separate 200-case direct SQLi execution layer.

The first v1.5 scored execution attempt was manually interrupted. It completed
the deterministic arm, recorded 620 local GPT provider failures with
`WinError 10013`, and produced four valid Qwen observations before
interruption. The direct SQLi execution layer did not start. This run is
preserved only as failed/aborted execution evidence and must not be resumed or
used as final SQLi thesis evidence.

## v1.5.1 SQLi Recovery Amendment

`evaluation-protocol-v1.5.1` is a narrow recovery amendment to v1.5. It
corrects only the missing real non-scored GPT provider-connectivity preflight
and the reflected-input wording inherited by the SQLi ranking prompt. The
amended prompt version is `llm-sqli-candidate-ranking-v1`.

The v1.5.1 recovery path preserves the v1.5 corpus, snapshots, scenario packs,
decoy assignment, model identifiers, decoding settings, trial counts,
candidate-test budget, SQLi probes, adapters, verifier criteria, metrics and
scoring rules. The corrected final SQLi study must be a complete fresh v1.5.1
run in a separate result namespace, not a resume of the interrupted v1.5 run.
