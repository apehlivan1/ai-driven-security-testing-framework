# Metrics Definition v1.3

Status: planning and instrumentation support only. This document defines the
measurement fields for future v1.3 experiments. It does not change
evaluation-protocol-v1.2, the v1.2 canonical package, or the v1.2 descriptive
analysis.

## Undefined Values

All v1.3 machine-readable reports must use explicit undefined values:

- `not_available`: the metric is meaningful, but the stored artifacts do not
  contain enough data to derive it.
- `not_applicable`: the metric has no meaningful denominator or does not apply
  to the arm, run, or case.

Missing cost, timestamp, request, or provider fields must not be encoded as
zero unless zero is directly derived from artifacts.

## Artifact Sources

Metrics must be derived from stored artifacts only:

- action request records
- action result records
- evidence records
- verifier result records
- finding records
- model-provider ranking artifacts
- normalized ZAP summaries, when available
- normalized case-level result tables

Manual aggregate values may be copied into a report only as provenance, not as
the source for v1.3 measurements.

## Action Counts

Unit: action records.

- `requested`: count of stored action request records.
- `approved`: count of stored action result records whose status is not
  `blocked`.
- `blocked`: count of action result records with status `blocked`.
- `executed`: count of action result records with status `executed`.
- `failed`: count of action result records with status `failed`.
- `skipped`: count of action result records with status `skipped`.
- `result_record_count`: count of stored action result records.

Formula:

```text
approved = result_record_count - blocked
```

This counts approval as "not blocked by safety policy and represented as a
result record"; it does not imply the action succeeded.

## Request Counts

Unit: HTTP requests or browser navigations.

For HTTP requests:

1. Prefer `normalized_observations.http_request_count`.
2. If absent, prefer `normalized_observations.request_count`.
3. If both are absent and the action result is `executed`, infer one HTTP
   request for action types:
   - `replay_request`
   - `mutate_parameter`
   - `authenticate_test_user`
   - `submit_form`
4. Otherwise count zero.

For browser navigations:

1. Prefer `normalized_observations.browser_navigation_count`.
2. If absent and the action result is `executed`, infer one browser navigation
   for action types:
   - `navigate`
   - `observe_browser`
   - `submit_form`
3. Otherwise count zero.

The summary must include `inferred_count_fields`, the number of request or
navigation counts inferred from action type rather than directly recorded in
`normalized_observations`.

## Candidate Tests

Unit: unique candidate IDs tested before a verifier-confirmed finding.

A candidate test is counted when an action request or action result has a
`candidate_id` in one of:

- `scope_context.candidate_id`
- `parameters.candidate_id`
- `normalized_observations.candidate_id`
- `attributes.candidate_id`

For candidate-ranking experiments, `candidates_tested_before_first_verification`
is the number of unique candidate IDs attached to eligible action/result
records completed at or before the first verified finding timestamp.

If the run has no verified finding, the value is `not_applicable`.
If the run has a verified finding but no candidate IDs are recorded in a
candidate-based arm, the value is `not_available`.
For non-candidate modules, the value is `not_applicable`.

## Verifier Decisions

Unit: verifier result records.

Counts:

- `verified`
- `rejected`
- `inconclusive`
- `total`

Formula:

```text
total = verified + rejected + inconclusive
```

Verifier result records are the preferred source. If no verifier result records
are available, finding states may be used as a fallback only for historical
artifact analysis and must be documented.

## First Verified Finding

The first verified finding timestamp is the earliest verified finding timestamp
recorded in `FindingRecord.report_fields` under one of:

- `verified_at`
- `verification_completed_at`
- `first_verified_at`

Time to first verified finding:

```text
time_to_first_verified_finding_ms =
  first_verified_finding_timestamp - earliest_run_activity_timestamp
```

The earliest run activity timestamp is the earliest available timestamp among:

- action result `started_at`
- evidence record `created_at`
- model-provider artifact `timestamp`

If a run has no verified finding:

- timestamp: `not_applicable`
- time to first verified finding: `not_applicable`
- requests to first verified finding: `not_applicable`
- candidates tested before first verification: `not_applicable`

If a run has a verified finding but no verified timestamp is stored, these
fields are `not_available`.

## Provider Metrics

Provider metrics apply only to LLM ranking arms. Deterministic arms must use
`not_applicable` for provider latency, token and cost fields.

Trial count:

```text
trial_count = count(model-provider ranking artifacts)
```

Valid trial count:

```text
valid_trial_count =
  count(trials with no validation_errors and provider_failed != true)
```

Malformed output:

```text
malformed_output_count =
  count(trials whose validation_errors include "malformed")

malformed_output_rate =
  malformed_output_count / trial_count
```

Timeout:

```text
timeout_count =
  count(provider_failed trials whose validation_errors or metadata identify a timeout)

timeout_rate =
  timeout_count / trial_count
```

Provider failure:

```text
provider_failure_count =
  count(provider_failed trials not counted as timeout)

provider_failure_rate =
  provider_failure_count / trial_count
```

Latency:

- unit: milliseconds
- source: `latency_ms` in each model-provider artifact
- summary: count, min, max, mean and total
- if no latency is recorded: `not_available`

Tokens:

- input tokens: prefer `usage.input_tokens`, otherwise `usage.prompt_tokens`
- output tokens: prefer `usage.output_tokens`, otherwise
  `usage.completion_tokens`
- total tokens: prefer `usage.total_tokens`; if absent and input/output are
  present, compute input + output
- if no token field is present: `not_available`

Cost:

- accepted cost fields: `estimated_cost_usd`, `total_cost_usd`, `amount_usd`,
  or `usd`
- cost availability is `available` if at least one ranking artifact contains a
  numeric USD cost value
- if no numeric provider cost is present: `not_available`

Cost per ranking trial:

```text
cost_per_ranking_trial_usd = total_provider_cost_usd / trial_count
```

Cost per verified finding:

```text
cost_per_verified_finding_usd =
  total_provider_cost_usd / verifier_confirmed_finding_count
```

If no finding is verified, cost per verified finding is `not_applicable`.
If findings are verified but cost is unavailable, it is `not_available`.

## Ranking Trial Accounting

Repeated LLM trials are not independent benchmark cases.

Required fields:

- `model_trial_count`: number of ranking artifacts.
- `independent_model_scenario_count`: number of unique scenario IDs.

Case-level detection metrics must use benchmark cases as the denominator, not
LLM trial count.

## Classification Metrics

Case-level classifications are read from normalized result rows:

- `TP`
- `FP`
- `FN`
- `TN`

v1.3 measurement instrumentation must reproduce these counts exactly and must
not reinterpret verifier decisions, scanner alerts, or ground truth.

Derived descriptive metrics may be calculated only when denominators are valid:

```text
accuracy = (TP + TN) / (TP + FP + FN + TN)
precision = TP / (TP + FP)
recall = TP / (TP + FN)
specificity = TN / (TN + FP)
F1 = 2 * precision * recall / (precision + recall)
detection_rate = TP / expected_vulnerable_case_count
```

Undefined denominator handling:

- denominator is zero: `not_applicable`
- source data missing: `not_available`

## ZAP Request Counts

ZAP request counts are used only when ZAP artifacts expose them directly.

Preferred sources:

1. normalized ZAP scan settings or command metadata containing request counts
2. ZAP report metadata with explicit request totals
3. ZAP command logs if parsed by a documented parser

If no reliable request count is present, ZAP request metrics must be
`not_available`. ZAP alerts must remain separate from verifier-confirmed
framework findings.

## Output Contract

Each future v1.3 experiment should be able to produce:

1. raw evidence
2. normalized JSON/CSV results
3. a human-readable report
4. thesis-ready tables and figures with traceable source data

Every generated result package must include a provenance manifest and SHA-256
checksums for all included artifacts.
