# MVP Scope and Verification

## Purpose

This document defines the proposed first vertical slice for the framework. The MVP uses three representative vulnerability categories to validate the architecture:

- Reflected XSS
- Read-only broken access control / IDOR using two isolated test users
- Non-destructive boolean-based SQL injection

These categories are not the final thesis vulnerability scope. They are selected because they exercise different framework capabilities: browser-observable client-side behavior, role/session comparison, and request/response differential testing. The core framework should support adding more categories later through category-specific testing strategies, validators, and evidence requirements.

The MVP should validate the architectural loop:

1. Discover attack surface.
2. Generate a bounded hypothesis.
3. Execute approved test actions.
4. Collect structured evidence.
5. Apply independent verification.
6. Produce traceable findings and reports.

## Shared Verification Principles

For all MVP categories:

- The LLM may propose hypotheses or next actions, but it must not mark a finding as verified.
- The Test Orchestrator may trigger verification and process the verifier's result, but it must not decide whether evidence is sufficient.
- The Finding Verifier owns the evidence-sufficiency decision.
- Deterministic checks should be used wherever possible.
- Heuristic or LLM-assisted decisions must remain explicit, auditable, and evidence-backed.
- A finding without a required control case should be `inconclusive`, not `verified`.
- All actions must stay inside the configured laboratory scope.

Possible verification outcomes:

- `verified`: required evidence and control case are present and support the finding.
- `rejected`: verification contradicts the hypothesis or shows expected safe behavior.
- `inconclusive`: evidence is missing, unstable, ambiguous, blocked by scope limits, or affected by application errors.

## Reflected XSS

### In Scope

- Reflected XSS in query parameters, form fields, or request parameters discovered during black-box exploration.
- Non-persistent payloads that execute only in the controlled test browser context.
- Tests that demonstrate script execution, DOM insertion, or browser-observable execution markers in a controlled lab target.

### Out of Scope

- Stored XSS.
- DOM-based XSS that requires complex client-side source analysis.
- Blind XSS or out-of-band callback testing.
- Payloads intended to steal credentials, session tokens, or sensitive data.
- Tests against production systems or third-party domains.

### Required Preconditions

- The target URL and allowed hosts are configured.
- The target page, parameter, or form input has been discovered.
- The test browser context is isolated from personal accounts and real credentials.
- The payload set is bounded and approved for laboratory testing.
- The page can be reloaded or revisited to reproduce the behavior.

### Allowed Framework Actions

- Navigate to discovered pages.
- Submit reflected-input candidates through forms or query parameters.
- Replay captured requests with one parameter changed at a time.
- Insert bounded XSS test markers.
- Observe rendered page output and browser execution signals.
- Capture request, response, DOM state, console events if available, and screenshots if useful.

### Minimum Evidence for Confirmation

- The affected URL, parameter, or form field.
- The exact non-sensitive payload or marker used.
- The request that triggered the behavior.
- The response or rendered DOM showing reflection or injection context.
- A browser-observable execution signal or equivalent deterministic validation.
- A timestamped reproduction attempt inside the authorized scope.

### Required Control Case

At least one control case is required:

- The same request with a harmless marker that is reflected but not executed.
- The same endpoint with encoded or neutralized input showing no execution.
- A comparison showing that execution only occurs when the test payload is used.

### Rejection or Inconclusive Reasons

Reject the hypothesis when:

- The payload is safely encoded or escaped.
- The marker appears only as inert text.
- Execution cannot be reproduced.
- The behavior occurs outside the tested parameter or is unrelated to submitted input.

Mark the result inconclusive when:

- The page changes unpredictably between runs.
- Browser instrumentation cannot observe execution reliably.
- Scope limits prevent the needed confirmation step.
- Authentication or session state prevents reproduction.

### Required Retained Artifacts

- Target page and input identifier.
- Triggering request and relevant response excerpt.
- Payload or marker identifier.
- Rendered DOM evidence or execution signal.
- Control-case request and result.
- Verification status and verifier rationale.

## Read-Only Broken Access Control / IDOR

### In Scope

- Read-only access-control failures where one test user can view another test user's resource.
- Direct object reference manipulation involving IDs, slugs, resource paths, or similar identifiers.
- Comparisons using two isolated benchmark users with separate data.

### Out of Scope

- Destructive modification, deletion, or creation of another user's resources.
- Privilege escalation beyond the configured benchmark roles.
- Attacks against real accounts or production data.
- Social, physical, or credential-theft scenarios.
- Access-control issues requiring source-code inspection.

### Required Preconditions

- Two isolated test users are available.
- Each user has at least one distinguishable resource.
- Sessions for both users can be established and kept separate.
- The target resource type and access path have been discovered.
- The benchmark data can be reset or restored if needed.

### Allowed Framework Actions

- Authenticate as each configured test user.
- Discover resources visible to each user.
- Record resource identifiers for both users.
- Replay read-only requests across user sessions.
- Compare status codes, response bodies, redirects, and visible page content.
- Request verifier checks for suspected cross-user access.

### Minimum Evidence for Confirmation

- The two test users or roles involved, identified by safe labels.
- The resource identifier owned by user A.
- A request made as user B for user A's resource.
- Evidence that user B received user A's protected resource or protected data.
- A comparison showing that the resource is legitimately accessible to user A.
- A comparison showing that user B should not have access under the benchmark assumptions.

### Required Control Case

Both controls are required:

- Positive control: user A can access user A's own resource.
- Negative control: user B attempts to access a resource or identifier that should be unavailable, or user B's allowed resources are shown to be distinct from user A's resource.

### Rejection or Inconclusive Reasons

Reject the hypothesis when:

- The resource is intentionally public.
- User B receives an authorization failure, redirect, or sanitized response.
- The supposedly foreign resource actually belongs to user B.
- The identifier does not reference a real protected resource.

Mark the result inconclusive when:

- User ownership cannot be established.
- Sessions are mixed or contaminated.
- The application returns unstable or cached responses.
- Benchmark assumptions do not define expected access behavior.
- Required user accounts or resources are unavailable.

### Required Retained Artifacts

- Safe labels for both test users and roles.
- Session identifiers or token references, redacted where needed.
- Resource ownership evidence.
- Positive-control request and result.
- Cross-user request and result.
- Negative-control request and result.
- Verifier rationale for access-control classification.

## Non-Destructive Boolean-Based SQL Injection

### In Scope

- Boolean-based SQL injection checks on discovered parameters.
- Non-destructive payloads that compare logically true and logically false conditions.
- Response-difference analysis using status code, response length, content markers, error behavior, or timing only when used as supporting context rather than the main MVP proof.

### Out of Scope

- Data extraction.
- Authentication bypass attempts against real accounts.
- Stacked queries.
- Destructive database operations.
- Time-based SQL injection as the primary MVP confirmation method.
- Union-based exploitation beyond simple non-destructive detection.
- Database fingerprinting beyond what is needed to verify the hypothesis.

### Required Preconditions

- A parameterized endpoint or form input has been discovered.
- A stable baseline response can be collected.
- The same request can be replayed with controlled parameter changes.
- The payload set is bounded, non-destructive, and approved.
- The target state can tolerate repeated read-only requests.

### Allowed Framework Actions

- Replay baseline requests.
- Mutate one parameter at a time.
- Submit paired boolean-true and boolean-false payloads.
- Repeat tests to check response stability.
- Compare response status, length, selected content markers, and normalized body differences.
- Request verifier classification based on repeated differential evidence.

### Minimum Evidence for Confirmation

- The affected endpoint and parameter.
- A baseline request and response.
- A boolean-true test request and response.
- A boolean-false test request and response.
- A repeated comparison showing a consistent difference between true and false conditions.
- Evidence that the difference is not explained by random content, session changes, or generic input validation.

### Required Control Case

At least two controls are required:

- Baseline control: the original request behaves consistently across repeated runs.
- Negative control: the boolean-false condition produces a consistently different result from the boolean-true condition.

An additional neutral-input control is preferred when available.

### Rejection or Inconclusive Reasons

Reject the hypothesis when:

- True and false payloads produce equivalent normalized responses.
- Differences are caused by generic validation, encoding, or application errors unrelated to SQL behavior.
- The result cannot be reproduced across repeated attempts.
- The target blocks the payload before it reaches query logic.

Mark the result inconclusive when:

- Responses are unstable or highly dynamic.
- Scope or safety limits prevent repeated testing.
- The endpoint has side effects that make repetition unsafe.
- The signal is too weak to distinguish from noise.
- Authentication or session state changes affect the response.

### Required Retained Artifacts

- Endpoint and parameter identifier.
- Baseline request and normalized response summary.
- Boolean-true request and normalized response summary.
- Boolean-false request and normalized response summary.
- Repetition count and consistency observations.
- Difference metrics or selected content markers.
- Verifier rationale and final classification.

## Remaining Decisions Before Project Scaffolding

Before implementation scaffolding begins, the following decisions should be settled:

- The exact vulnerability module contract: testing strategy, validators, evidence schema, allowed actions, and report extensions.
- The first benchmark target or targets for the MVP.
- The ground-truth format and rules for keeping it isolated from the testing agent.
- The target configuration format, including host allowlists, credentials, roles, and run limits.
- The finding schema and required evidence fields.
- The verification state machine and allowed transitions between `suspected`, `verified`, `rejected`, and `inconclusive`.
- The evidence retention and redaction policy.
- The initial bounded payload sets for the three MVP modules.
- The minimum run metrics needed for thesis evaluation.
- The approval model for actions that may be higher risk even in a lab.
- The reset strategy for benchmark applications between repeated trials.
