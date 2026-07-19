# AI-Driven Security Testing Framework

Thesis title: **Design and Evaluation of an AI-Driven Framework for Automated Web Application Security Testing**

This repository is the planning workspace for a master's thesis project focused on designing and evaluating an AI-driven framework for authorized, controlled, black-box security testing of laboratory web applications.

Current status: **minimal Python implementation scaffold with a local DVWA HTTP smoke test, deterministic reflected-XSS vertical slice, limited multi-seed reflected-input discovery, a small local reflected-input development benchmark, a bounded LLM candidate-ranking baseline boundary, a deterministic read-only IDOR vertical slice, and a deterministic non-destructive boolean-SQLi vertical slice**. The repository contains core contracts, file-based run artifacts, deterministic safety and verification lifecycle behavior, a mock dry run, a minimal HTTP executor, Playwright-based reflected-XSS integrations, provider-neutral candidate ranking, isolated benchmark-user session support, SQLi response-differential verification, and unit tests.

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
- The bounded LLM ranking path may only rank already discovered candidate IDs and provide rationales. It cannot execute actions, generate payloads, control the browser, verify findings, or access ground truth.
- The read-only IDOR path uses two isolated benchmark-user sessions referenced by redacted `session_ref` values. Session credentials and tokens stay in memory and are not persisted in action requests, target artifacts, reports, or evidence.
- The boolean-SQLi path uses repeated baseline, boolean-true, and boolean-false HTTP requests. Verification requires stable baseline behavior and reproducible true/false differences; server errors and reflected payload text alone are not sufficient evidence.
- Browser observations use a reusable browser executor that checks scope before navigation and validates the final page URL after navigation.
- Reflected-XSS-specific verification criteria live with the XSS module definition rather than inside the generic verifier.
- The scaffold performs no crawling, scanner integration, framework database storage, tool-calling agents, or plugin loading.

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

Reset is reproducible because the benchmark has no persistent state. Restarting the server is sufficient; the `/reset` endpoint is also available for scripted checks.

Run the deterministic baseline:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_xss
```

Run the deterministic baseline plus one bounded provider-neutral LLM-ranking trial using the fake model client:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_xss --ranking-mode both --llm-client fake --fake-llm-strategy as_listed --trials 1
```

Run one real OpenAI provider smoke trial through the command-client boundary:

```powershell
$env:PYTHONPATH = "src"
$env:OPENAI_API_KEY = "<set outside repository>"
$env:OPENAI_RANKING_MODEL = "gpt-5.6-luna"
python -m adstf.dev_benchmark_xss --ranking-mode both --llm-client command --trials 1 --llm-command python -m adstf.openai_ranking_wrapper
```

Run a five-trial development characterization with the same bounded ranking boundary:

```powershell
$env:PYTHONPATH = "src"
$env:OPENAI_API_KEY = "<set outside repository>"
$env:OPENAI_RANKING_MODEL = "gpt-5.6-luna"
python -m adstf.dev_benchmark_xss --ranking-mode both --llm-client command --trials 5 --llm-command python -m adstf.openai_ranking_wrapper
```

Provider credentials must be supplied only through environment variables. The wrapper reads `OPENAI_API_KEY` and does not write it to prompts, responses, metrics, or artifacts. Optional environment variables are `OPENAI_RANKING_MODEL`, `OPENAI_TIMEOUT_SECONDS`, and `OPENAI_BASE_URL`.

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
- when LLM ranking is enabled, writes prompt/response artifacts under `artifacts/llm/`
- separates discovered candidates, tested vulnerability hypotheses, verifier-confirmed findings, and post-run ground-truth matches in the benchmark report and evaluation summary
- records aggregate repeated-trial metrics while preserving per-trial and per-scenario evaluation details

Ground truth for this development benchmark is stored in [examples/benchmarks/reflected-dev-ground-truth.json](examples/benchmarks/reflected-dev-ground-truth.json). It is intended only for post-run evaluation and must not be used by discovery, ranking, verification, or reporting logic.

The benchmark evaluation records:

- top-1 accuracy over scenarios with a vulnerable candidate
- top-k recall using each scenario's fixed test budget
- mean reciprocal rank
- vulnerable-candidate rank distribution
- selected-candidate distribution
- candidates tested before verification
- verified finding count
- no-vulnerability scenario behavior
- valid, invalid, failed, and fallback model-call/trial counts
- token usage, latency, and estimated cost when available
- ranking source and trial number
- model identifier, prompt version, validation errors, and provider failures for LLM ranking runs

The LLM ranking artifact records:

- model identifier
- prompt version
- model settings
- structured candidate input
- prompt
- raw response
- parsed ranking
- validation errors
- token or cost data when available
- timestamp
- trial number

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

Latest validated bounded ranking comparison used the fake provider-neutral model client for plumbing validation, not a real LLM provider. It produced:

- deterministic baseline top-1 accuracy: `0.3333333333333333`
- deterministic baseline mean reciprocal rank: `0.5277777777777778`
- fake LLM trial top-1 accuracy: `0.3333333333333333`
- fake LLM trial mean reciprocal rank: `0.5833333333333334`
- fake LLM validation error count: `0`

The OpenAI command wrapper is available as `python -m adstf.openai_ranking_wrapper`. It uses the command-client boundary, reads credentials from environment variables only, requests structured JSON output, and returns model/provider metadata, latency, raw response, token usage when returned by the provider, and cost as `null` when unavailable. A real-provider smoke run requires `OPENAI_API_KEY` to be set in the shell before running the command.

## Run The Local Read-Only IDOR Development Benchmark

This development benchmark is intentionally small and state-free. It demonstrates two isolated benchmark-user sessions, explicit user-owned resources, a vulnerable read-only cross-user request, and a secure rejected control case. It is not the final held-out thesis evaluation benchmark.

Start the local benchmark server on the IDOR target port:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_server --host 127.0.0.1 --port 4292
```

Run the deterministic IDOR vertical slice:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_idor
```

The IDOR integration:

- loads [examples/targets/idor-dev-local.json](examples/targets/idor-dev-local.json)
- authenticates two configured benchmark users into separate in-memory sessions
- records redacted `session_context` evidence for user A and user B
- records explicit `resource_ownership` evidence for benchmark resources
- confirms successful read access by each user to their own resource
- replays a read-only cross-user request for an intentionally vulnerable case
- replays a read-only cross-user request for a secure control case
- records HTTP exchanges and comparison evidence
- verifies or rejects findings through the existing verifier lifecycle
- writes post-run evaluation to `artifacts/idor-benchmark-evaluation.json`

Ground truth for this development benchmark is stored in [examples/benchmarks/idor-dev-ground-truth.json](examples/benchmarks/idor-dev-ground-truth.json). It is intended only for post-run evaluation and must not be used by authentication, execution, comparison, verification, or reporting logic.

## Run The Local Boolean-SQLi Development Benchmark

This development benchmark is intentionally small and state-free from the framework's perspective. The benchmark target uses an in-memory SQLite database internally to provide one genuinely vulnerable boolean-SQLi case and one parameterized secure control case. The framework itself does not use database storage.

Start the local benchmark server on the SQLi target port:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_server --host 127.0.0.1 --port 4293
```

Run the deterministic boolean-SQLi vertical slice:

```powershell
$env:PYTHONPATH = "src"
python -m adstf.dev_benchmark_sqli
```

The SQLi integration:

- loads [examples/targets/sqli-dev-local.json](examples/targets/sqli-dev-local.json)
- sends repeated baseline requests
- sends repeated bounded boolean-true and boolean-false requests
- records HTTP exchanges and normalized response fingerprints
- records comparison evidence for baseline stability and true/false reproducibility
- verifies or rejects findings through the existing verifier lifecycle
- writes post-run evaluation to `artifacts/sqli-benchmark-evaluation.json`

The SQLi integration does not extract data, bypass authentication, use stacked queries, use destructive payloads, or perform error-based or timing-based SQL injection checks.

Ground truth for this development benchmark is stored in [examples/benchmarks/sqli-dev-ground-truth.json](examples/benchmarks/sqli-dev-ground-truth.json). It is intended only for post-run evaluation and must not be used by execution, comparison, verification, or reporting logic.
