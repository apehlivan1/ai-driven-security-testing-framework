# AI-Driven Security Testing Framework

Thesis title: **Design and Evaluation of an AI-Driven Framework for Automated Web Application Security Testing**

This repository is the planning workspace for a master's thesis project focused on designing and evaluating an AI-driven framework for authorized, controlled, black-box security testing of laboratory web applications.

Current status: **minimal Python implementation scaffold with a local DVWA HTTP smoke test and deterministic reflected-XSS vertical slice**. The repository contains core contracts, file-based run artifacts, deterministic safety and verification lifecycle behavior, a mock dry run, a minimal HTTP executor, a Playwright-based reflected-XSS integration, and unit tests.

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
- The reflected-XSS integration observes a configured authenticated seed page and discovers simple GET reflected-input candidates before building test and control actions.
- Browser observations use a reusable browser executor that checks scope before navigation and validates the final page URL after navigation.
- Reflected-XSS-specific verification criteria live with the XSS module definition rather than inside the generic verifier.
- The scaffold performs no crawling, LLM calls, scanner integration, database storage, ground-truth evaluation, IDOR testing, SQL injection testing, or plugin loading.

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
- observes the configured reflected-XSS seed page
- records discovered simple GET reflected-input candidates as evidence
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
