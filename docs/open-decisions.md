# Open Architectural Decisions

This document captures decisions that should be made before implementation begins. The goal is to avoid accidental architecture choices hidden inside early code.

## Testing Scope and Extensibility

### Decision: Vulnerability Module Contract

The framework must support adding new vulnerability-specific testing and verification modules without redesigning its core orchestration, evidence, and reporting mechanisms.

The minimum first-implementation contract is defined in [Action and Evidence Contract v0.1](action-and-evidence-contract.md). The remaining decision is how much of that contract should be represented as formal types during the first scaffold.

Options:

- Define a minimal module contract covering hypothesis types, category-specific testing strategies, validators, allowed actions, evidence requirements, evidence schema, verification rules, and report fields.
- Start with informal module conventions and formalize them after the MVP.
- Define only action and verification interfaces first, then add reporting extensions later.

Recommended direction:

- Define a small explicit module contract before implementation.
- Keep the orchestrator, evidence store, verifier, and report generator module-aware but not module-specific.
- Require heuristic or LLM-assisted module decisions to be explicit, auditable, and evidence-backed.
- Avoid dynamic plugin loading until at least one vertical slice works end to end.

### Decision: Exact MVP Validation Coverage

The first MVP uses XSS, broken access control / IDOR, and SQL injection as representative categories for validating the architecture. These categories do not define the final thesis scope. Each MVP module still needs precise boundaries.

Options:

- Start with reflected XSS only, then add stored and DOM-based XSS later.
- Start with read-only IDOR cases, then add modification workflows later.
- Start with error-based and boolean-style SQL injection checks, then add timing-based checks later.

Recommended direction:

- Prefer the smallest verifiable subset for each category first.
- Avoid destructive tests in the MVP.
- Treat the first three categories as example modules that exercise different parts of the architecture.

Future vulnerability coverage may include authentication and session-management weaknesses, path traversal, server-side request forgery, command injection, sensitive information exposure, and security misconfiguration.

### Decision: Black-Box Assumptions

The thesis describes black-box testing, but benchmark applications may expose source code or ground truth.

Options:

- Strict black-box testing for the agent, with source and ground truth used only during evaluation.
- Gray-box testing as a later extension.

Recommended direction:

- Keep the MVP strictly black-box.
- Isolate source code and ground truth from the agent.

## Target and Benchmark Strategy

### Decision: Benchmark Applications

The project needs a small, controlled set of lab targets.

Options:

- Use intentionally vulnerable training applications.
- Add one custom benchmark application with known vulnerabilities.
- Use several targets to improve external validity.

Recommended direction:

- Start with one simple benchmark for MVP development.
- Add at least one more realistic benchmark before final evaluation.

### Decision: Ground Truth Format

Evaluation requires expected vulnerability labels.

Options:

- Store ground truth as structured files.
- Store ground truth in a database.
- Derive ground truth from benchmark documentation where possible.

Recommended direction:

- Use a structured, reviewable ground-truth format first.
- Keep it separate from runtime evidence.

## Autonomy Level

### Decision: Human-in-the-Loop Versus Fully Autonomous Runs

The thesis can evaluate different levels of automation.

Options:

- Human approval for every test action.
- Human approval only for higher-risk actions.
- Fully autonomous execution inside a strict lab scope.

Recommended direction:

- Begin with auditable autonomous execution inside a narrow allowlist.
- Keep optional human approval as a configuration mode if time allows.

### Decision: Agent Structure

The system may use a single reasoning loop or multiple specialized reasoning roles.

Options:

- Single LLM reasoning component.
- Separate planning, analysis, verification-assistance, and reporting roles.
- Hybrid approach where deterministic orchestration owns state and LLM calls are task-specific.

Recommended direction:

- Do not commit to a multi-agent design yet.
- First define the state model, action interface, and verification rules.

## Tool and Execution Boundaries

### Decision: Approved Action Set

The framework needs a clear list of actions the LLM can request.

The initial action envelope and first action types are defined in [Action and Evidence Contract v0.1](action-and-evidence-contract.md).

Options:

- Browser navigation and form submission.
- HTTP request replay and parameter mutation.
- Passive scanner invocation.
- Active vulnerability checks exposed by enabled modules.

Recommended direction:

- Define typed actions before choosing implementation libraries.
- Make every action validate scope before execution.
- Require vulnerability modules to declare the action types they need.

### Decision: Payload Policy

Payload design affects both safety and evaluation validity.

Options:

- Use a fixed payload library.
- Let the LLM generate payload candidates.
- Use fixed payloads first, then allow LLM-generated variants under validation.

Recommended direction:

- Use bounded, reviewable payload sets for the MVP.
- Treat LLM-generated payloads as a later research extension.
- Keep payload sets attached to vulnerability modules rather than the core framework.

### Decision: Authentication Handling

Broken access control testing requires at least two roles or users.

Options:

- Preconfigured test accounts.
- Researcher-provided login flows.
- Recorded authenticated sessions.

Recommended direction:

- Use preconfigured benchmark accounts first.
- Keep session handling explicit in the target configuration.

## Verification and Evidence

### Decision: Verifier Ownership

The Finding Verifier should own the evidence-sufficiency decision. The Test Orchestrator should only detect when a hypothesis is ready to be checked, invoke the verifier, record the result, and continue the workflow.

Recommended direction:

- Keep verification sufficiency rules inside the Finding Verifier and vulnerability modules.
- Keep workflow routing and state transitions inside the Test Orchestrator.
- Treat this verifier boundary as a potential scientific contribution because it reduces reliance on LLM judgment alone.

### Decision: Verification Criteria by Vulnerability Module

Each vulnerability module needs objective confirmation rules.

The first verifier result shape and finding lifecycle are defined in [Action and Evidence Contract v0.1](action-and-evidence-contract.md).

Options:

- Define strict per-module evidence requirements before any result can be marked verified.
- Allow confidence-based findings in the final report.

Recommended direction:

- Require strict criteria for verified findings.
- Allow suspected and inconclusive findings, but exclude them from true-positive metrics unless separately analyzed.
- Do not allow a module to produce verified findings until its verification criteria are defined.

### Decision: Evidence Retention

The framework must store enough information for reproducibility without collecting unnecessary sensitive data.

Options:

- Store full HTTP requests and responses.
- Store summarized evidence plus selected raw artifacts.
- Redact secrets and session tokens.

Recommended direction:

- Store reproducibility-critical evidence.
- Redact or isolate secrets.
- Make evidence retention policy explicit before implementation.

## LLM Usage

### Decision: Model Provider and Deployment

The system can use local models, hosted models, or both.

Options:

- Hosted model provider.
- Local model.
- Provider-agnostic interface.

Recommended direction:

- Keep the architecture provider-agnostic.
- Choose concrete providers only after defining required capabilities, cost limits, privacy constraints, and evaluation repeatability needs.

### Decision: Prompting and State Strategy

The LLM needs enough context to reason without receiving unbounded logs.

Options:

- Full conversation history.
- Structured state summaries.
- Retrieval from evidence and knowledge stores.

Recommended direction:

- Prefer structured state summaries with links to evidence records.
- Avoid relying on long raw chat history as the source of truth.

## Data Storage

### Decision: Evidence Store Technology

The architecture needs persistent storage, but the technology is not yet selected.

Options:

- File-based structured artifacts.
- Embedded database.
- Server database.

Recommended direction:

- Decide based on query needs, reproducibility, and expected experiment volume.
- Avoid choosing a database before the evidence schema is clear.

### Decision: Output Formats

Reports should support both thesis evaluation and human review.

Options:

- Human-readable report.
- Machine-readable findings.
- Standard security-report interchange format.

Recommended direction:

- Produce both human-readable and machine-readable outputs.
- Define the finding schema before implementation.
- Allow module-specific report sections through structured extensions, not custom report pipelines.

## Evaluation Methodology

### Decision: Baselines

The thesis needs fair comparison against traditional approaches.

Options:

- Passive scanner baseline.
- Active scanner baseline.
- Manual benchmark ground truth comparison.

Recommended direction:

- Use at least one traditional automated scanner baseline.
- Keep run budgets and target states comparable.

### Decision: Metrics

The evaluation must define success before implementation.

Options:

- Precision, recall, F1 score.
- Time to first verified finding.
- Coverage of routes, forms, parameters, and roles.
- Report quality assessed by rubric.
- Cost per verified finding.

Recommended direction:

- Use quantitative metrics for discovery accuracy.
- Use a separate rubric for report quality.

### Decision: Repeated Trials

LLM-driven systems may produce variable results.

Options:

- Single deterministic run.
- Multiple runs with fixed settings.
- Multiple runs across model configurations.

Recommended direction:

- Plan for repeated trials.
- Record all run settings needed for reproducibility.

## Repository Documentation Plan

Suggested small documentation structure:

- `README.md`: project summary, status, safety disclaimer, and links to planning documents.
- `docs/architecture-overview.md`: system architecture, workflow, components, safety boundaries, and evaluation shape.
- `docs/open-decisions.md`: unresolved choices that must be settled before implementation.
- `docs/evaluation-plan.md`: future document describing benchmarks, metrics, baselines, and experimental protocol.
- `docs/thesis-notes.md`: future document for research questions, assumptions, and literature notes.

The last two documents should be added later, after the core architecture decisions are reviewed.
