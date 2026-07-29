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
