# AI-Driven Security Testing Framework

Thesis title: **Design and Evaluation of an AI-Driven Framework for Automated Web Application Security Testing**

This repository is the planning workspace for a master's thesis project focused on designing and evaluating an AI-driven framework for authorized, controlled, black-box security testing of laboratory web applications.

Current status: **minimal Python implementation scaffold with a local DVWA HTTP smoke test, deterministic reflected-XSS vertical slice, limited multi-seed reflected-input discovery, and a small local reflected-input development benchmark**. The repository contains core contracts, file-based run artifacts, deterministic safety and verification lifecycle behavior, a mock dry run, a minimal HTTP executor, Playwright-based reflected-XSS integrations, and unit tests.

## Safety Scope

This project is intended only for ethical, authorized security research in controlled laboratory environments. It must not be used against systems without explicit permission.

## Documentation

- [Architecture overview](docs/architecture-overview.md)
- [MVP scope and verification](docs/mvp-scope-and-verification.md)
- [Action and evidence contract](docs/action-and-evidence-contract.md)
- [Open architectural decisions](docs/open-decisions.md)

## Scaffold Decisions

- Python is used for the initial scaffold because it is well suited for security automation, research workflows, and later LLM/tool integrations.
- The scaffold uses the Python standard library plus Playwright for the first browser-observed vulnerability verification.
- Run artifacts are stored as structured files so early experiments remain easy to inspect and reproduce.
- Vulnerability modules are statically registered placeholders; there is no plugin system yet.
- The mock dry run uses mock actions only.
- The DVWA smoke command performs one local in-scope HTTP request and one blocked out-of-scope request. It does not produce vulnerability findings.
- The reflected-XSS integration logs into local DVWA, uses a safe JavaScript marker assignment, verifies actual browser execution, runs a benign control case, and records artifacts through the existing verifier lifecycle.
- The reflected-XSS integration observes configured authenticated seed pages and discovers simple GET-form and query-parameter reflected-input candidates before building test and control actions.
- Reflected-input candidates are ranked by target-independent structural features such as scope, source type, text-like editable inputs, required-input count, parameter count, and deterministic URL/parameter tie-breaking. The prioritizer does not use benchmark-revealing route labels such as `xss` or `reflect`.
- Candidate scores, ranking rationale, and selected/non-selected status are recorded as evidence for auditability.
- A state-free local reflected-input development benchmark provides fixed reproducible scenarios with neutral GET-form and query-parameter candidates, with ground truth stored separately for post-run evaluation only.
- The deterministic reflected-input ranker is versioned as `deterministic-structural-v1`; the benchmark scenarios are meant to evaluate this frozen ruleset, not tune it.
- Browser observations use a reusable browser executor that checks scope before navigation and validates the final page URL after navigation.
- Reflected-XSS-specific verification criteria live with the XSS module definition rather than inside the generic verifier.
- The scaffold performs no crawling, LLM calls, scanner integration, database storage, ground-truth evaluation, IDOR testing, SQL injection testing, or plugin loading.
- The scaffold performs no crawling, LLM calls, scanner integration, database storage, IDOR testing, SQL injection testing, or plugin loading.

## Setup

Use Python 3.11 or newer.

On PowerShell:

```powershell
$env:PYTHONPATH = "src"
python -m pip install -e .
python -m playwright install chromium
```

## Run Tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests
```

## Run The Dry Run

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dry_run
```

The dry run writes local artifacts under `.adstf-runs/`, which is ignored by Git.

## Run The DVWA HTTP Smoke Test

The live smoke test expects the official DVWA project to be running locally on `127.0.0.1:4280`. The target config pins the expected benchmark source reference to DVWA release `2.5` for reproducibility:

- Target config: [examples/targets/dvwa-local.json](examples/targets/dvwa-local.json)
- Official project: https://github.com/digininja/DVWA
- Pinned release: https://github.com/digininja/DVWA/releases/tag/2.5
- Pinned commit: `a96943dc1f52f390ee5df72144660636c4b7dd06`

One way to start the target locally is to clone the official DVWA release and run its Docker Compose setup. Docker Desktop or Docker Engine must be running. For the most reproducible local setup, use a local build from that pinned checkout rather than relying on a rolling container tag.

```powershell
git clone --branch 2.5 --depth 1 https://github.com/digininja/DVWA.git
cd DVWA
@"
services:
  dvwa:
    pull_policy: build
"@ | Set-Content compose.override.yml
docker compose up -d
```

Then, from this repository:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dvwa_smoke
```

The smoke test:

- loads the DVWA target configuration
- approves and executes one in-scope request to `/login.php`
- blocks and records one out-of-scope request
- prevents redirects from bypassing the target allowlist
- records normalized HTTP metadata as evidence
- writes a complete auditable run directory
- produces no vulnerability finding

If DVWA redirects to `setup.php` after login, initialize the local database from `http://127.0.0.1:4280/setup.php` by clicking **Create / Reset Database**. This is target preparation for the local benchmark, not part of the framework's testing lifecycle.

## Run The DVWA Reflected-XSS Integration

After DVWA is running locally and its database is initialized:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dvwa_xss_reflected
```

The reflected-XSS integration:

- loads the pinned DVWA target configuration
- observes the configured reflected-XSS seed pages
- records discovered simple GET reflected-input candidates from all configured seed pages as evidence
- ranks discovered candidates with a deterministic target-independent prioritizer
- confirms the target is reachable
- logs into DVWA using the configured benchmark test account
- sets DVWA's benchmark security level to `low` for this controlled local run
- builds reflected-XSS and control URLs from the selected discovered candidate
- submits a safe reflected-XSS marker payload
- observes actual JavaScript execution in Chromium
- runs a benign non-executing control case
- stores screenshots and HTML artifacts for reproduction
- sends the finding through the existing verifier lifecycle
- exits successfully only when the verifier returns `verified`

## Run The Local Development Benchmark

This development benchmark is intentionally small and neutral. It is useful for exercising reflected-input discovery, deterministic ranking, candidate testing order, and post-run metrics before introducing an LLM baseline. It is not the final held-out thesis evaluation benchmark.

Start the local state-free benchmark server:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_server --host 127.0.0.1 --port 4291
```

Reset is reproducible because the benchmark has no persistent state. Restarting the server is sufficient; the `/reset` endpoint is also available for scripted checks:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_xss
```

The development benchmark integration:

- loads [examples/targets/reflected-dev-local.json](examples/targets/reflected-dev-local.json)
- runs fixed named scenarios on the same local server
- observes each scenario's configured seed pages
- discovers multiple simple GET-form and query-parameter candidates
- ranks candidates without using route or parameter names that reveal vulnerability status
- records every candidate score, rationale, and selected/non-selected state as evidence
- tests candidates in ranked order until a finding is verified or the scenario budget is exhausted
- includes scenarios where the vulnerable candidate is structurally favored, not structurally favored, exposed through a query parameter, and absent
- stores screenshots, HTML artifacts, findings, verifier results, and a report
- writes post-run benchmark evaluation to `artifacts/benchmark-evaluation.json`
- writes scenario execution details to `artifacts/scenario-run-summary.json`

Ground truth for this development benchmark is stored in [examples/benchmarks/reflected-dev-ground-truth.json](examples/benchmarks/reflected-dev-ground-truth.json). It is intended only for post-run evaluation and must not be used by discovery, ranking, verification, or reporting logic.

The benchmark evaluation records:

- top-1 accuracy over scenarios with a vulnerable candidate
- top-k recall using each scenario's fixed test budget
- mean reciprocal rank
- candidates tested before verification
- verified finding count
- no-vulnerability scenario behavior

Current fixed development scenarios:

- `case-a`: baseline scenario where the vulnerable candidate is structurally favored and ranked first.
- `case-b`: vulnerable candidate is present but not structurally favored; deterministic ranking reaches it after higher-ranked non-vulnerable candidates.
- `case-c`: no vulnerable candidate; the framework should exhaust the candidate set without a verified finding.
- `case-d`: vulnerable candidate is exposed as a query parameter and ranked behind simple GET-form candidates.

Latest validated scenario run produced:

- scenario count: `4`
- top-1 accuracy over vulnerable scenarios: `0.3333333333333333`
- top-k recall over vulnerable scenarios: `1.0`
- mean reciprocal rank: `0.5277777777777778`
- no-vulnerability false-positive count: `0`
