# v1.4.1 Resumable Runner Readiness

This document records the non-scored execution-readiness layer for the frozen
`evaluation-protocol-v1.4.1` context-enrichment ablation. It does not modify the
protocol, candidate snapshots, schedule, model settings, prompts, parser,
budgets, metric definitions or scoring rules.

The readiness layer exists because the frozen v1.4.1 schedule contains 5852
ranking rows: 532 deterministic rows, 2660 GPT rows and 2660 Qwen rows. Prior
local Qwen runs showed that long single-session execution is operationally
fragile. The runner therefore writes one terminal artifact per scheduled row,
records an append-only journal entry with the artifact checksum and derives
resume state from persisted artifacts rather than from Codex process state.

## Resume Policy

The runner resumes from the lowest frozen sequence whose terminal artifact is
absent. Existing terminal artifacts are never regenerated silently. Valid,
malformed, provider-failed, runtime-failed and timed-out rows are all terminal
observations for resume purposes.

Before each resumed batch, the runner validates:

- the frozen schedule identity and denominators;
- protocol package checksums;
- snapshot checksums;
- absence of duplicate sequence IDs;
- absence of unscheduled result artifacts;
- consistency between artifacts and the append-only journal;
- absence of temporary or incomplete artifact files.

Any corrupt, incomplete, duplicate, unscheduled or checksum-inconsistent
artifact stops execution for manual audit.

## Batch Guidance

The readiness package records planning-only Qwen duration estimates using an
assumed 55 seconds per Qwen call. Conservative examples are:

- 32 calls for roughly 30 minutes;
- 65 calls for roughly 1 hour;
- 130 calls for roughly 2 hours;
- 500 to 650 calls for an overnight batch.

These are execution-planning estimates, not experimental results.

## Readiness Package

The generated readiness package is:

`results/owasp-xss-v14-1-resumable-runner-readiness/`

It contains the immutable derived execution schedule, schedule checksum,
resume-validation report, fake interruption evidence, batch guidance and
checksum validation. The package is non-experimental: it uses fake runner
fixtures only and records zero GPT calls, zero Qwen calls, zero HTTP requests
and zero scored rows.
