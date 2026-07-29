# Thesis Evidence Index

Status: living index for thesis evidence. evaluation-protocol-v1.2 artifacts
remain frozen historical evidence. v1.3 outputs are planned report structures
and must not overwrite v1.2 results.

## Frozen v1.2 Evidence

Canonical held-out package:

- Path: `results/heldout-evaluation-v1.2-canonical/`
- Protocol tag: `evaluation-protocol-v1.2`
- Purpose: canonical held-out results assembled from valid v1.1 and corrected
  v1.2 artifacts.
- Key files:
  - `manifest.json`
  - `checksums.sha256`
  - `validation-report.json`
  - `report.md`
  - `tables/framework-cases.csv`
  - `tables/zap-cases.csv`
  - `tables/common-scope-comparison.csv`
  - `tables/llm-ranking-trials.csv`
  - `tables/xss-ranking-metrics.csv`
  - `tables/summary-metrics.json`

Descriptive analysis:

- Path: `results/heldout-evaluation-v1.2-analysis/`
- Purpose: thesis-ready descriptive summaries based only on the canonical v1.2
  package.
- Key files:
  - `analysis-data.json`
  - `analysis-report.md`
  - `thesis-tables.md`
  - `checksums.sha256`
  - `validation-report.json`

These files should be cited as historical v1.2 evidence. They should not be
edited by v1.3 instrumentation or future experiments.

## Planned v1.3 Evidence

The v1.3 study is separate from v1.2. Its purpose is to strengthen measurement
quality, XSS ranking ablation, and reproducibility without changing the
authority boundary of the framework.

Implemented structural benchmark assets:

- Manifest: `examples/benchmarks/xss-v13-manifest.json`
- Semantic ground truth: `examples/benchmarks/xss-v13-ground-truth.json`
- Target configuration: `examples/targets/xss-v13-local.json`
- Catalog: `docs/benchmark-catalog-v1.3.md`
- Structural validation package: `results/xss-v13-structural-validation/`

The v1.3 XSS structural validation package contains scenario design and
structural-validation evidence only. It does not contain ranking results,
browser vulnerability-test results, ZAP results, LLM outputs, final scoring, or
thesis conclusions.

Local model feasibility and bake-off design:

- Design document: `docs/local-model-selection-v1.3.md`
- Selection manifest: `results/local-model-selection-v1.3/local-model-selection-manifest.json`
- Shortlist comparison table: `results/local-model-selection-v1.3/model-runtime-comparison.csv`
- Risk assessment: `results/local-model-selection-v1.3/reproducibility-risk-assessment.md`
- Checksums: `results/local-model-selection-v1.3/checksums.sha256`

These files contain measured machine facts, a model shortlist, and pre-defined
bake-off rules only. They do not contain model downloads, model outputs,
ranking trials, benchmark scores, final local-model selection, or v1.3 protocol
freeze decisions.

Local model fake bake-off harness package:

- Path: `results/local-model-bakeoff-v1.3/`
- Manifest: `results/local-model-bakeoff-v1.3/manifest.json`
- Fake trial rows: `results/local-model-bakeoff-v1.3/trial-results.csv`
- Model summaries: `results/local-model-bakeoff-v1.3/model-summary.csv`
- Selection-decision placeholder: `results/local-model-bakeoff-v1.3/selection-decision.json`
- Validation report: `results/local-model-bakeoff-v1.3/validation-report.json`
- Figure placeholders and source data:
  `results/local-model-bakeoff-v1.3/figures/`

This package is fake/non-experimental harness-validation data only. It exercises
the reporting structure, metric derivation, invalid-output accounting and
selection logic, but it does not run local models and does not select the final
primary or fallback model.

Local runtime provisioning and non-scored smoke package:

- Path: `results/local-runtime-provisioning-v1.3/`
- Manifest: `results/local-runtime-provisioning-v1.3/manifest.json`
- Runtime metadata: `results/local-runtime-provisioning-v1.3/runtime-metadata.json`
- Hardware report: `results/local-runtime-provisioning-v1.3/hardware-report.json`
- Model metadata: `results/local-runtime-provisioning-v1.3/model-metadata/`
- Raw smoke outputs: `results/local-runtime-provisioning-v1.3/raw-smoke-outputs/`
- Normalized smoke results:
  `results/local-runtime-provisioning-v1.3/normalized/smoke-results.csv`
- Download and licence ledger:
  `results/local-runtime-provisioning-v1.3/download-and-licence-ledger.csv`
- Checksums: `results/local-runtime-provisioning-v1.3/checksums.sha256`

This package records the provisioned llama.cpp CPU runtime and the four
shortlisted GGUF artifacts. It is a local-runtime feasibility smoke only: it is
not the measured 72-call calibration bake-off, does not use the final
24-scenario XSS v1.3 benchmark, does not execute vulnerability tests, and does
not select a local primary or fallback model. The smoke confirmed local model
loading and raw output capture, but the 32-token smoke cap produced malformed
JSON for all four models. Those malformed smoke responses are reproducibility
evidence, not performance results.

During provisioning, an initial `llama-cli.exe` invocation was found to enter
interactive conversation behavior. The final package uses
`llama-completion.exe`; only the final package should be cited as v1.3 local
runtime provisioning evidence.

Local structured-output readiness package:

- Path: `results/local-runtime-readiness-v1.3/`
- Manifest: `results/local-runtime-readiness-v1.3/manifest.json`
- Frozen settings:
  `results/local-runtime-readiness-v1.3/execution-settings.json`
- JSON schema:
  `results/local-runtime-readiness-v1.3/local-ranking-readiness-schema-v1.3.json`
- Runtime metadata: `results/local-runtime-readiness-v1.3/runtime-metadata.json`
- Hardware report: `results/local-runtime-readiness-v1.3/hardware-report.json`
- Raw readiness outputs: `results/local-runtime-readiness-v1.3/raw/`
- Normalized readiness results:
  `results/local-runtime-readiness-v1.3/normalized/readiness-results.csv`
- Validation report:
  `results/local-runtime-readiness-v1.3/validation-report.json`
- Checksums: `results/local-runtime-readiness-v1.3/checksums.sha256`

This package is a non-scored pre-bake-off readiness validation only. It uses
one synthetic eight-candidate input that is separate from both the six
calibration scenarios and the final 24-scenario XSS v1.3 benchmark. It does not
run vulnerability tests, does not use final held-out scenarios, does not run the
72-call calibration bake-off, and does not select a model.

The readiness run found a shared output-boundary issue: all four models loaded
and generated complete-looking JSON, but `llama-completion.exe` appended
`[end of text]` after the JSON object. The strict parser rejected this as extra
data for all four models. This should be cited as runtime/configuration
readiness evidence, not as model-quality or ranking-performance evidence. The
measured bake-off is not ready until a single global output-boundary correction
is defined, versioned and rerun for all four shortlisted models.

Local runtime output-boundary audit and corrected readiness package:

- Path: `results/local-runtime-output-boundary-v1.3/`
- Manifest: `results/local-runtime-output-boundary-v1.3/manifest.json`
- Transport settings:
  `results/local-runtime-output-boundary-v1.3/transport-settings.json`
- JSON schema:
  `results/local-runtime-output-boundary-v1.3/local-ranking-readiness-schema-v1.3.json`
- Exact commands:
  `results/local-runtime-output-boundary-v1.3/exact-commands/`
- Raw stdout/stderr and normalized content:
  `results/local-runtime-output-boundary-v1.3/raw/`
- Normalized readiness results:
  `results/local-runtime-output-boundary-v1.3/normalized/readiness-results.csv`
- Validation report:
  `results/local-runtime-output-boundary-v1.3/validation-report.json`
- Audit report:
  `results/local-runtime-output-boundary-v1.3/output-boundary-audit.md`
- Runtime-interface table:
  `results/local-runtime-output-boundary-v1.3/thesis-runtime-interface-table.md`
- Checksums:
  `results/local-runtime-output-boundary-v1.3/checksums.sha256`

This package corrects the shared readiness issue without changing the prompt,
schema, candidate input, model shortlist or per-model settings. The selected
common transport is `llama-completion` with stdout/stderr separation and a
versioned parser rule that separates only the exact trailing `[end of text]`
runtime marker after an otherwise valid JSON object. Raw stdout and stderr are
still retained. All four shortlisted models completed the synthetic
eight-candidate readiness contract after this correction.

The output-boundary package is readiness evidence only. It is not the 72-call
measured calibration bake-off, does not use the final 24-scenario XSS v1.3
benchmark, does not execute vulnerability tests, and does not select a final
local model.

Planned v1.3 result package layout:

```text
results/<study-id>/
  manifest.json
  checksums.sha256
  report.md
  normalized/
    summary.json
    case-results.csv
    ranking-trials.csv
    action-measurements.csv
  tables/
    thesis-tables.md
    thesis-tables.tex
  figures/
    <figure-id>.png
    <figure-id>.pdf
    <figure-id>.json
    <figure-id>.csv
  raw/
    <run-id>/
```

## Traceability Rules

- Every number in a thesis table must be traceable to a normalized JSON or CSV
  result.
- Every normalized result must be traceable to raw run artifacts.
- Every raw artifact included in a result package must have a SHA-256 checksum.
- Model-provider artifacts must retain model identifier, provider metadata,
  prompt version, request settings, timestamp, raw response, parsed ranking,
  validation errors, latency, token usage and cost data when available.
- Credentials, session values, API keys, local secrets and unrelated workspace
  data must never appear in evidence packages.

## Evidence Categories

- Discovery evidence: discovered candidates, seed pages, candidate schema,
  deterministic ranking scores and rationales.
- Ranking evidence: deterministic ranking output, proprietary LLM ranking
  output, local model ranking output, raw responses and validation status.
- Execution evidence: action requests, safety outcomes, action results, HTTP
  response metadata, browser observations, screenshots and HTML snapshots where
  applicable.
- Verification evidence: verifier input evidence refs, criteria checked,
  satisfied and missing criteria, outcome, limitations and finding state.
- Scanner evidence: raw ZAP reports, normalized alerts, mapping versions,
  unmatched alerts, scan policies and scope validation.
- Ground-truth evidence: held separately and loaded only for post-run scoring.

## Current Gaps For v1.3

- Historical v1.2 artifacts do not always expose enough data to derive every
  timing and request metric.
- ZAP request counts are only available when ZAP reports or command metadata
  expose them reliably.
- Provider cost remains `not_available` unless a provider artifact contains a
  numeric USD cost field or a defensible external cost source is recorded before
  the experiment.
