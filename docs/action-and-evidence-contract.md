# Action and Evidence Contract v0.1

## Purpose

This document defines the minimum implementation-facing contract needed before project scaffolding begins. It is intentionally technology-neutral and avoids designing a heavy plugin framework before the first vertical slice exists.

The contract covers:

- Action requests and action results
- Evidence records and findings
- Verifier outcomes and lifecycle
- The smallest useful vulnerability-module contract

The first implementation should treat these as internal data contracts. They do not need to become a public plugin API yet.

## Required for First Implementation

The first scaffolding milestone should include these contracts as code-level concepts, even if their storage and execution are initially simple:

- A common action request shape.
- A common action result shape.
- A common evidence record shape.
- A common finding shape.
- A verifier result shape.
- A small vulnerability-module contract for the three MVP modules.
- A lifecycle that prevents LLM-generated hypotheses from becoming verified findings without verifier approval.

## Deferred Until Later

The first implementation should not yet include:

- A dynamic plugin loader.
- Remote module installation.
- A public extension marketplace.
- Multiple database backends.
- A multi-agent architecture.
- Complex report export formats.
- Fully generic support for every vulnerability class.

These can be revisited after at least one vertical slice works end to end.

## Core Principles

- The LLM may propose hypotheses and actions, but it does not execute actions directly.
- The Scope and Safety Boundary must approve an action before execution.
- The Approved Test Executor records action results but does not decide vulnerability truth.
- The Finding Verifier owns the evidence-sufficiency decision.
- Every heuristic or LLM-assisted decision must be explicit, auditable, and linked to evidence.
- Ground truth remains benchmark-only and must not be available to the LLM, executor, or verifier during normal test execution.

## Action Request

An action request is a bounded operation proposed by the framework and submitted for safety validation before execution.

Required fields:

- `action_id`: unique identifier for the requested action.
- `run_id`: test run identifier.
- `requested_by`: component that requested the action, such as explorer, LLM reasoning layer, verifier, or module strategy.
- `module_id`: vulnerability module associated with the action, if any.
- `action_type`: controlled action type.
- `target_ref`: reference to a discovered page, endpoint, form, request, parameter, session, or resource.
- `scope_context`: target scope information needed for safety checks.
- `parameters`: action-specific inputs.
- `preconditions`: conditions that must hold before execution.
- `safety_class`: expected risk level within the lab.
- `rationale`: short explanation for why the action is being requested.
- `expected_evidence`: evidence types the action is expected to produce.

The `rationale` may come from the LLM, a deterministic strategy, or the verifier. It is useful for auditability but must not bypass safety checks.

### Initial Action Types

The first implementation only needs a small controlled set:

- `navigate`: open an allowed URL or discovered route.
- `submit_form`: submit values to a discovered form.
- `replay_request`: replay a captured request without unsafe side effects.
- `mutate_parameter`: replay a request while changing one parameter.
- `authenticate_test_user`: establish a session for a configured benchmark user.
- `observe_browser`: capture rendered page, DOM, browser event, or execution marker evidence.
- `compare_observations`: compare two or more collected observations.

These action types are enough for the reflected XSS, read-only IDOR, and boolean-based SQL injection vertical slice.

### Action Request Validation

Before execution, each action request must be checked for:

- Allowed host, port, and scheme.
- Allowed HTTP method for the current safety mode.
- Allowed session or test user.
- Allowed payload family.
- Request-rate and run-budget limits.
- Required preconditions.
- Absence of explicitly blocked behavior, such as destructive database operations or out-of-scope callbacks.

If validation fails, the action must not execute. The blocked action should still be recorded as audit evidence.

## Action Result

An action result records what happened after an action request was validated.

Required fields:

- `action_id`: identifier of the original action request.
- `run_id`: test run identifier.
- `status`: `executed`, `blocked`, `failed`, or `skipped`.
- `started_at` and `completed_at`: timestamps or equivalent ordering markers.
- `executor`: component that handled execution.
- `normalized_observations`: structured summary of what was observed.
- `evidence_refs`: evidence records produced by the action.
- `safety_notes`: scope decisions, blocked reasons, or policy warnings.
- `error`: failure details, if applicable.

Action results should preserve enough information to explain the test run without requiring raw logs to be reread by the LLM.

## Evidence Record

An evidence record is an immutable observation or artifact produced during exploration, testing, verification, or reporting.

Required fields:

- `evidence_id`: unique identifier.
- `run_id`: test run identifier.
- `source`: component that created the evidence.
- `evidence_type`: controlled evidence type.
- `target_ref`: affected page, endpoint, parameter, session, resource, or finding.
- `created_at`: timestamp or equivalent ordering marker.
- `summary`: concise human-readable description.
- `data_ref`: pointer to stored raw or structured artifact, if retained separately.
- `redaction_status`: whether sensitive values were absent, redacted, isolated, or retained for reproduction.
- `related_action_ids`: actions that produced or used this evidence.

Initial evidence types:

- `http_exchange`: request and response metadata with retained or redacted details.
- `browser_observation`: rendered page, DOM marker, console event, or execution signal.
- `comparison_result`: normalized comparison between two or more observations.
- `session_context`: test-user or role context, with secrets redacted or isolated.
- `resource_ownership`: evidence that a resource belongs to a specific benchmark user or role.
- `verification_note`: verifier rationale, criteria result, or missing evidence note.
- `blocked_action`: action that was rejected by safety policy.

Raw artifacts may be stored separately from the evidence record. The record should point to them rather than embedding large responses everywhere.

## Finding Record

A finding record represents a vulnerability hypothesis and its verification state.

Required fields:

- `finding_id`: unique identifier.
- `run_id`: test run identifier.
- `module_id`: vulnerability module responsible for the finding.
- `title`: short descriptive title.
- `category`: vulnerability category, such as reflected XSS, read-only IDOR, or boolean-based SQL injection.
- `affected_target`: endpoint, page, parameter, role, resource, or workflow.
- `state`: current lifecycle state.
- `hypothesis`: concise claim being tested.
- `created_by`: LLM reasoning layer, module strategy, deterministic tool, or researcher.
- `supporting_evidence_refs`: evidence supporting the hypothesis.
- `verification_result_ref`: verifier result, once verification has been attempted.
- `report_fields`: module-specific reporting fields that can be rendered by the common report generator.

Optional first-implementation fields:

- `severity`: preliminary severity, if a simple severity model is defined.
- `confidence`: useful for prioritization, but must not determine verified status.
- `deduplication_key`: stable key for merging repeated findings.

## Finding Lifecycle

The first implementation should use a small lifecycle:

- `suspected`: a hypothesis exists but has not been independently verified.
- `verification_requested`: the orchestrator has submitted the hypothesis to the verifier.
- `verified`: the verifier determined that required evidence and control cases are sufficient.
- `rejected`: the verifier determined that evidence contradicts the hypothesis or confirms safe behavior.
- `inconclusive`: the verifier could not reach a decision because evidence is missing, unstable, unsafe to collect, or blocked by scope.

Allowed transitions:

- `suspected` to `verification_requested`
- `verification_requested` to `verified`
- `verification_requested` to `rejected`
- `verification_requested` to `inconclusive`
- `inconclusive` to `verification_requested`, if new evidence becomes available

The first implementation should not need complex lifecycle branches such as accepted risk, duplicate, waived, remediated, or reopened. Those are deferred.

## Verifier Result

A verifier result is the Finding Verifier's decision about a suspected finding.

Required fields:

- `verification_result_id`: unique identifier.
- `finding_id`: finding being verified.
- `module_id`: module whose verification rules were applied.
- `outcome`: `verified`, `rejected`, or `inconclusive`.
- `criteria_checked`: list of required criteria evaluated.
- `criteria_satisfied`: criteria that were satisfied.
- `criteria_missing`: criteria that were missing or could not be evaluated.
- `control_cases`: control cases used and their outcomes.
- `evidence_refs`: evidence records used in the decision.
- `reproduction_status`: whether the behavior was reproduced during verification.
- `rationale`: concise verifier explanation.
- `limitations`: scope limits, instability, or ambiguity affecting the decision.

The verifier may request additional actions through the orchestrator when evidence is insufficient, but the orchestrator still owns workflow routing and safety validation.

## Smallest Useful Vulnerability-Module Contract

A vulnerability module is a small internal unit that describes how one vulnerability category should be tested and verified. For the first implementation, it does not need dynamic loading or a plugin system.

Required module responsibilities:

- Declare `module_id`, display name, and category.
- Declare supported hypothesis types.
- Declare required target features, such as reflected input, user-owned resources, or replayable parameters.
- Provide a testing strategy that can produce bounded action requests.
- Declare allowed action types.
- Declare payload families or test markers, if needed.
- Declare evidence requirements for verification.
- Provide validator logic or criteria used by the Finding Verifier.
- Provide report fields that fit into the common finding report.

Required module boundary:

- The module may propose actions, evidence requirements, and validation criteria.
- The module must not bypass the Scope and Safety Boundary.
- The module must not directly execute actions.
- The module must not access benchmark ground truth during normal testing.
- The module must not create a verified finding without the Finding Verifier lifecycle.

## MVP Module Requirements

### Reflected XSS Module

Required for first implementation:

- Identify candidate reflected inputs.
- Request bounded marker submission.
- Request browser observation.
- Require evidence of reflection plus browser-observable execution or deterministic equivalent.
- Require at least one safe control case.

Deferred:

- Stored XSS.
- DOM-based XSS.
- Blind XSS and out-of-band callbacks.

### Read-Only IDOR Module

Required for first implementation:

- Use two configured test users.
- Identify user-owned resources.
- Request read-only cross-user access checks.
- Require positive ownership control and negative access-control comparison.
- Preserve session separation evidence with secrets redacted or isolated.

Deferred:

- Write, delete, or privilege-changing access-control tests.
- Complex role hierarchies.
- Access-control testing without clearly owned benchmark resources.

### Boolean-Based SQL Injection Module

Required for first implementation:

- Identify replayable parameters.
- Request baseline, boolean-true, and boolean-false requests.
- Require repeated differential evidence.
- Require baseline stability and false-condition control.
- Avoid destructive, data-extracting, or timing-primary tests.

Deferred:

- Data extraction.
- Union-based exploitation.
- Time-based SQL injection as primary proof.
- Database-specific exploitation.

## Scaffolding Readiness Checklist

The repository is ready for scaffolding when the first implementation can create these concepts without choosing a final framework stack:

- Target configuration object.
- Action request and result objects.
- Evidence and finding objects.
- Verifier result object.
- Minimal run state machine.
- Static registration of the three MVP modules.
- Safety validation boundary for allowed actions.
- Placeholder report generation from finding records.

## Decisions That Still Block Scaffolding

Only these decisions genuinely block the first scaffolding milestone:

- The first implementation language and basic project layout.
- The first benchmark target, because it determines initial target configuration and test-user assumptions.
- The initial storage approach at the level of file-based artifacts versus an embedded local store.

The following can be deferred until after scaffolding:

- Specific LLM provider or local model.
- Final database technology.
- Final agent framework.
- Dynamic module loading.
- Full benchmark suite.
- Full report export format.
- Final severity scoring model.
