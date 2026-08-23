# SQLi and IDOR/BOLA Evaluation Expansion Feasibility Plan

This document records a feasibility and methodology audit for extending the evaluation beyond the completed reflected-XSS studies. It treats the completed v1.2, v1.3.1 and v1.4 evidence as historical results and does not alter those protocols, artifacts, prompts, model settings, verifier criteria or benchmark cases.

The goal of the proposed expansion is not to add new vulnerability categories. It is to assess whether the existing bounded-ranking contribution can be evaluated more broadly for the two already supported representative vulnerability families: non-destructive boolean-based SQL injection and read-only IDOR/BOLA.

## Current Repository State

The framework currently contains deterministic support for three representative vulnerability families:

- reflected XSS, with the most mature candidate discovery, ranking and evaluation infrastructure;
- read-only IDOR, with two isolated benchmark-user sessions and deterministic verifier logic;
- non-destructive boolean-based SQL injection, with deterministic true/false request comparison and verifier logic.

The strongest ranking-evaluation infrastructure currently exists for reflected XSS. The v1.3.1 XSS ablation study evaluates deterministic structural ranking, a hosted proprietary GPT ranking provider and the selected local Qwen model over frozen candidate snapshots. The v1.4 OWASP XSS confirmatory work extends that external-validation direction for XSS.

The SQLi and IDOR implementations are functionally narrower. They validate the common lifecycle concepts of target configuration, action creation, safety checks, execution, evidence retention, deterministic verification and post-run ground-truth scoring, but they do not yet provide the same independent multi-candidate ranking study design used for XSS.

## Current SQL Injection Capability

The current SQLi slice is deterministic and deliberately bounded. It uses configured benchmark cases rather than automatic SQLi discovery. A SQLi case defines a request path, parameter, baseline value, boolean-true value, boolean-false value and expected behavior. The runner issues repeated baseline, true and false requests through the existing safety, action-result, evidence and verifier lifecycle.

The verifier requires stable baseline behavior and reproducible true/false response differences. A server error, payload reflection or response-length difference alone is not sufficient as proof. This is methodologically important because it keeps the current thesis scope non-destructive and avoids using error-based, timing-based, stacked-query or data-extraction behavior.

Existing evidence is small but internally coherent:

- development benchmark: one intentionally vulnerable SQLi case and one secure control;
- held-out v1.2 evaluation: `hs-001` as a verified true positive and `hs-002` as a rejected true negative;
- normalized v1.2 category result: 2 SQLi cases, TP 1 / FP 0 / FN 0 / TN 1.

The main gaps are:

- no SQLi candidate discovery or multi-candidate ranking path;
- no SQLi-specific candidate schema for deterministic/GPT/Qwen ranking;
- no external SQLi benchmark compatibility layer;
- no large SQLi negative/adversarial corpus;
- no direct evidence yet that OWASP Benchmark Java SQLi cases produce observable behavior compatible with the current boolean-comparison verifier.

## OWASP Benchmark Java SQLi Feasibility

A local OWASP Benchmark Java source tree is present under `.external/owasp-benchmark-java`. The available files indicate OWASP Benchmark version 1.2. Git metadata could not be safely read because the repository is flagged by Git as having dubious ownership in this environment, so the audit relied on repository files rather than changing Git configuration.

Static case inventory from `expectedresults-1.2.csv`:

| Item | Count |
| --- | ---: |
| Total labelled benchmark cases | 2740 |
| SQL injection cases | 504 |
| SQLi vulnerable cases | 272 |
| SQLi non-vulnerable cases | 232 |
| SQLi CWE value | 89 |

Static input-carrier inventory from the benchmark crawler XML for the 504 SQLi cases:

| Case shape | Cases |
| --- | ---: |
| cookie | 48 |
| header | 93 |
| form parameter | 97 |
| two form parameters | 57 |
| three form parameters | 46 |
| four form parameters | 50 |
| three query parameters | 113 |

The XML occurrence counts are larger than case counts for multi-parameter cases: cookie 48, form parameter 549, query parameter 339 and header 93.

A first static source screen suggests that OWASP SQLi cases are not all equivalent to the current non-destructive boolean-based path:

| Static pattern | Vulnerable | Non-vulnerable | Total |
| --- | ---: | ---: | ---: |
| SELECT-like query screen | 199 | 178 | 377 |
| INSERT pattern | 42 | 28 | 70 |
| UPDATE pattern | 62 | 47 | 109 |
| stored procedure call pattern | 31 | 26 | 57 |
| executeUpdate pattern | 42 | 28 | 70 |
| result printed to response | 135 | 127 | 262 |
| first-pass read-like screen |  |  | 338 |
| first-pass not read-like screen |  |  | 166 |

These numbers are only a compatibility screen. They do not prove exploitability, verifier compatibility or safe execution. In particular, cases involving `INSERT`, `UPDATE`, `executeUpdate` or stored procedures should not be treated as direct fits for the current read-only boolean-verification design without a separate methodological decision.

Representative files reinforce this issue:

- one early SQLi case uses a stored procedure call and header input;
- another uses an `INSERT` statement, which conflicts with the current non-destructive read-only philosophy;
- a closer case uses a form parameter in a SELECT-like query, but still requires response-stability validation before it can be treated as verifier-compatible.

### SQLi Compatibility Assessment

OWASP Benchmark Java is promising for SQLi external validation, but it should not be used wholesale as a scored corpus without a compatibility audit. The benchmark contains a large labelled SQLi set and substantial non-vulnerable coverage, which is valuable for false-positive and true-negative observations. However, direct use is complicated by input carriers, request methods, multi-parameter cases, write-like SQL behavior, stored procedures and the need for stable response differences.

Recommended compatibility categories:

- `DIRECT`: original case can be executed locally with the framework while preserving original ground truth, non-destructive behavior and verifier compatibility.
- `ADAPTER-SUPPORTED`: original case and ground truth are preserved, but an adapter is required for transport details such as form parameters, headers, cookies or session-independent request construction.
- `DERIVED/ADAPTED`: a methodologically documented derivative is needed because the original case cannot be used directly under the thesis safety and verification constraints.
- `EXCLUDED`: case is incompatible with the thesis constraints or cannot be evaluated without altering the intended safety model.

The next SQLi milestone should establish these categories before any ranking or vulnerability testing is run.

### v1.5 Static Audit Result

The v1.5 OWASP Benchmark SQLi compatibility audit was completed as a non-scored static audit. It produced reproducible artifacts under `results/owasp-sqli-v15-compatibility-audit/` and did not execute SQLi requests, call GPT, call Qwen, or generate scored rankings.

The pinned OWASP Benchmark Java SQLi population remains:

| Item | Count |
| --- | ---: |
| Total SQLi cases | 504 |
| Vulnerable SQLi cases | 272 |
| Non-vulnerable SQLi cases | 232 |

The conservative compatibility classification is:

| Class | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `DIRECT` | 0 | 0 | 0 |
| `ADAPTER_SUPPORTED` | 220 | 115 | 105 |
| `DERIVED_ADAPTED` | 0 | 0 | 0 |
| `EXCLUDED` | 127 | 73 | 54 |
| `MANUAL_REVIEW` | 157 | 84 | 73 |

The audit intentionally reports no `DIRECT` cases because every statically eligible original OWASP SQLi case requires at least deterministic transport adapter support, such as multi-parameter query handling, form-parameter submission, header handling, or cookie handling. This does not mean the corpus is unusable; it means the original cases should not be treated as directly executable by the current single-parameter SQLi development runner.

The audit identifies 220 original OWASP SQLi cases as potentially usable for a later direct external validation layer after deterministic adapters are implemented and runtime readiness confirms stable boolean behavior. These 220 cases are also the current candidate pool for a later SQLi candidate-ranking layer. The 127 excluded cases are excluded because their static behavior conflicts with the non-destructive verifier philosophy: 70 are write/state-changing `INSERT`-style cases and 57 use stored-procedure behavior that cannot be assumed read-only from static evidence. The remaining 157 read-like cases require manual review because the static audit did not identify a sufficient response oracle for boolean true/false comparison.

### v1.5 READINESS_ONLY Result

The v1.5 deterministic adapter and READINESS_ONLY validation milestone was completed as a non-scored readiness exercise. It selected 20 cases before runtime execution using seed `owasp-sqli-v15-readiness-selection-v1`: two vulnerable and two non-vulnerable examples for each of `form`, `multi_form`, `multi_query`, `header`, and `cookie`. These 20 cases are permanently marked `READINESS_ONLY` for v1.5 and are excluded from later final confirmatory denominators.

The implemented deterministic adapters are:

- form parameter adapter;
- multi-form parameter adapter;
- multi-query parameter adapter;
- header adapter;
- cookie adapter.

The readiness run executed only the selected READINESS_ONLY cases. It did not execute final-confirmatory cases, did not call GPT, did not call Qwen, and did not generate scored ranking results. Runtime request construction, evidence collection and verifier decisions did not use OWASP ground truth; expected labels were attached only in the post-execution readiness report.

Readiness status: `PASS`.

Reconciled v1.5 corpus after readiness:

| Evaluation role | Total | Vulnerable | Non-vulnerable |
| --- | ---: | ---: | ---: |
| `READINESS_ONLY` | 20 | 10 | 10 |
| `FINAL_CONFIRMATORY_ELIGIBLE` | 200 | 105 | 95 |
| `EXCLUDED` | 284 | 157 | 127 |

The unresolved `MANUAL_REVIEW` count remains 157 after additional offline/static review. These cases remain unresolved because static source evidence shows writer output but not a sufficient deterministic boolean response oracle. No runtime probing was used to reclassify them.

Preliminary final SQLi ranking design after removing READINESS_ONLY cases:

| Item | Count |
| --- | ---: |
| Pack size | 5 |
| Candidate-test budget `k` | 4 |
| Positive scenarios | 105 |
| Negative-only scenarios | 19 |
| Total core ranking scenarios | 124 |
| Deterministic rows | 124 |
| GPT rows at five trials | 620 |
| Qwen rows at five trials | 620 |
| Total projected ranking rows | 1364 |

## Recommended SQLi Expansion Design

The SQLi expansion should be versioned separately, for example as `evaluation-protocol-v1.5` or `sqli-owasp-v1.5`, and should be explicitly distinct from the frozen XSS protocols.

The recommended design is:

1. Start with a static OWASP Benchmark SQLi compatibility audit.
2. Preserve original OWASP Benchmark ground truth wherever cases are directly or adapter-supported compatible.
3. Keep execution non-destructive and read-only for the direct framework verifier path.
4. Separate external benchmark compatibility from LLM ranking.
5. Construct sanitized SQLi candidate snapshots only after compatibility is classified.
6. Compare deterministic structural ranking, hosted GPT ranking and local Qwen ranking only over identical structured candidate inputs.
7. Keep the LLM restricted to ordering existing candidate IDs with bounded rationales.
8. Keep payload/test construction, action execution, evidence collection, verifier decisions and ground-truth scoring deterministic and outside the LLM.

The candidate schema must be category-specific or vulnerability-neutral rather than reusing the reflected-XSS schema unchanged. Safe model-facing metadata may include opaque candidate ID, input carrier, method category, parameter-count category, whether an adapter is required, and other structural features. It must not include ground-truth labels, original expected results, source code, SQL statements, credentials, session tokens, payloads or details that trivially reveal the answer.

The SQLi verifier should not be relaxed merely to fit more OWASP cases. If an OWASP case cannot produce stable baseline behavior and reproducible true/false differences under the existing non-destructive verification philosophy, it should be classified as unsupported or adapter/derived rather than forcing a positive result.

## Current IDOR/BOLA Capability

The current IDOR slice uses two isolated benchmark-user sessions. Authentication is represented as auditable action/evidence, while session secrets are redacted or represented through stable references and hashes. Runtime evidence includes session context, ownership evidence, own-resource reads, cross-user reads and response comparisons.

The verifier requires session separation, ownership evidence, own-resource access behavior and read-only cross-user access evidence. Runtime outcomes are assigned by the deterministic verifier and remain separate from post-run ground-truth classification.

Existing evidence is small but methodologically useful:

- development benchmark: one vulnerable cross-user read case and one secure control;
- held-out v1.2 corrected evaluation: `hi-001` as a verified true positive and `hi-002` as a rejected true negative;
- normalized v1.2 category result: 2 IDOR cases, TP 1 / FP 0 / FN 0 / TN 1;
- v1.2. correction explicitly fixed evidence separation so secure-control rejection evidence cannot affect the vulnerable case.

The main gaps are:

- no IDOR/BOLA candidate discovery or ranking path;
- no expanded multi-user, multi-resource candidate corpus;
- no external IDOR/BOLA benchmark integrated in the repository;
- no category-specific candidate schema that can represent object-access hypotheses without exposing session secrets or ground-truth ownership;
- no evidence yet that an external API benchmark such as crAPI can be used safely and reproducibly under the thesis constraints.

## IDOR/BOLA Benchmark Options

### Option A: Controlled Expanded Local IDOR/BOLA Benchmark

This is the best immediate option after SQLi. It would expand the existing local IDOR concept into a larger controlled benchmark with several users, resources, endpoint shapes, secure controls, vulnerable object-access cases, decoys and negative cases.

Advantages:

- strong control over ground truth and reset behavior;
- supports read-only execution and safe local testing;
- preserves the existing two-session verifier philosophy;
- allows candidate snapshots to be constructed without exposing secrets;
- produces meaningful true-negative and false-positive observations.

Limitations:

- lower external validity than an independently maintained benchmark;
- risk of overfitting if scenario design is too close to the existing held-out IDOR cases.

### Option B: crAPI or Similar External BOLA/API Benchmark

An external API benchmark such as crAPI could improve external validity and make the IDOR/BOLA evaluation more realistic. However, the repository does not currently contain an inspected or integrated crAPI target. This option has higher setup and methodology risk because authentication, state reset, object ownership, API workflows and non-destructive scope must be audited before it can be used for scoring.

Advantages:

- stronger external-validity argument;
- more realistic API/BOLA workflows;
- useful as a later confirmatory feasibility study.

Limitations:

- acquisition and reproducibility are unresolved;
- ground-truth mapping may require manual audit;
- session and object identifiers must be shielded from LLM inputs;
- execution may require multi-step API state setup;
- higher risk of drifting away from the central ranking contribution.

### Option C: Hybrid External-App Candidate Ranking Study

A hybrid design could use deterministic observation of an external API benchmark to create sanitized object-access candidate snapshots, while keeping execution and verification deterministic. This may become attractive after a controlled IDOR/BOLA benchmark is implemented, but it should not be the first IDOR expansion.

## Recommended IDOR/BOLA Expansion Design

The recommended IDOR/BOLA expansion should follow SQLi, not precede it. It should begin with a controlled local benchmark expansion rather than jumping directly to crAPI.

The IDOR/BOLA candidate object should represent a sanitized object-access hypothesis, for example an opaque endpoint/resource/requesting-user relation. The model-facing candidate must not include session tokens, credentials, raw ownership labels, ground truth, source code or anything that reveals which cross-user request is vulnerable. The LLM should only rank existing sanitized candidate IDs.

The deterministic components should continue to own:

- user/session setup;
- object ownership establishment;
- own-resource control reads;
- cross-user read construction;
- safety checks;
- HTTP execution;
- evidence retention;
- verifier classification.

The IDOR/BOLA verifier should remain read-only. It should not be expanded into privilege escalation, write/delete operations or business-logic exploitation in this phase.

## Reusable Components from v1.4 and Existing XSS Work

The following components and methodological patterns can be reused:

- frozen candidate snapshots;
- opaque candidate IDs;
- separated semantic ground truth;
- deterministic structural baseline;
- hosted GPT and local Qwen ranking arms;
- restricted model-output parser and validation;
- invalid/malformed/provider-failed ranking records;
- fixed candidate-test budgets;
- frozen trial schedules;
- provenance manifests and checksums;
- canonical raw and normalized result packaging;
- denominator validation;
- evidence index updates;
- separation between runtime verifier states and post-run TP/FP/FN/TN classification.

The following should not be reused mechanically:

- the reflected-XSS candidate schema;
- XSS-specific prompt wording;
- XSS-specific discovery assumptions;
- XSS-specific browser execution expectations;
- XSS-specific verifier evidence requirements.

For SQLi and IDOR/BOLA, the same authority boundary should be preserved, but the candidate schema and deterministic test construction must be category-specific.

## Versioning and Study Naming

Recommended naming:

- `evaluation-protocol-v1.5`: OWASP Benchmark SQLi compatibility audit and, if later approved, SQLi ranking/execution evaluation.
- `evaluation-protocol-v1.6`: expanded controlled IDOR/BOLA benchmark and ranking evaluation.
- optional later `evaluation-protocol-v1.7`: external API/BOLA feasibility or confirmatory validation, for example crAPI, only after v1.6 is stable.

These should remain separate from the already frozen XSS v1.3.1 and v1.4 evidence.

## Recommended Implementation Sequence

### Milestone 1: SQLi OWASP Compatibility Audit and Protocol Design

This should be the immediate next implementation milestone. It should not run scored experiments.

It should establish:

- exact OWASP Benchmark Java provenance and version identifiers available locally;
- labelled SQLi case inventory;
- input-carrier and request-shape inventory;
- static compatibility classification into `DIRECT`, `ADAPTER-SUPPORTED`, `DERIVED/ADAPTED` and `EXCLUDED`;
- read-like versus write/update/procedure classification;
- safe candidate metadata schema for SQLi ranking;
- adapter requirements for query parameters, form parameters, headers and cookies;
- whether direct verifier-compatible SQLi execution is feasible for a meaningful number of cases;
- dry-validation that model-facing candidate snapshots contain no labels or ground truth.

Success criteria:

- all 504 labelled OWASP SQLi cases are classified or explicitly marked for manual review;
- classification rules are versioned before any scoring;
- no SQLi attack execution is performed;
- no LLM/provider/local-model calls are performed;
- a recommended SQLi protocol path is produced.

### Milestone 2: SQLi Protocol Preparation and Dry Validation

If Milestone 1 confirms enough compatible cases, prepare frozen SQLi candidate snapshots and dry-validate deterministic/GPT/Qwen ranking schedules without scored calls.

### Milestone 3: SQLi Scored Ranking and Execution Evaluation

Only after protocol freeze, execute the SQLi study under the preserved authority boundary.

### Milestone 4: Controlled IDOR/BOLA Benchmark Expansion Design

Design an expanded internal IDOR/BOLA benchmark with multiple users, resources, endpoint shapes, negative cases and adversarial decoys.

### Milestone 5: Controlled IDOR/BOLA Protocol Preparation, Execution and Canonicalization

Freeze candidate snapshots, run deterministic/GPT/Qwen ranking comparisons and deterministic read-only verification.

### Optional Milestone 6: External BOLA Feasibility

Assess crAPI or another local external API benchmark only after the controlled IDOR/BOLA expansion is complete.

## Complexity and Research Risk

SQLi expansion has medium-to-high methodological complexity because OWASP Benchmark cases differ substantially in transport, query type and observable behavior. The major risk is overclaiming compatibility or forcing a non-destructive verifier onto cases that were not designed for boolean response comparison.

IDOR/BOLA expansion has medium methodological complexity if kept controlled and local. It becomes high complexity if an external API benchmark is introduced immediately.

Neither expansion should alter the LLM authority model. The LLM can remain a bounded ranking component if candidate schemas are designed carefully and if payloads, sessions, credentials, execution, evidence and verification remain deterministic.

## Chapter 4 Impact

If completed, SQLi and IDOR/BOLA expansion would strengthen Chapter 4 by showing whether the ranking architecture generalizes beyond reflected XSS. It would also address the current limitation that SQLi and IDOR are supported only through small deterministic validation sets.

However, the expanded studies must be reported separately from v1.2, v1.3.1 and v1.4. They should not overwrite prior conclusions. The thesis should distinguish:

- XSS as the mature ranking-ablation and confirmatory external-validation family;
- SQLi as a promising external benchmark expansion if compatibility is defensible;
- IDOR/BOLA as a controlled read-only expansion with potential later external validation.

## Final Verdicts

| Family | Verdict | Reason |
| --- | --- | --- |
| SQL injection | READY AFTER SPECIFIED PREREQUISITES | OWASP Benchmark Java provides a large labelled SQLi corpus, but compatibility with the current non-destructive boolean verifier must be audited before scoring. |
| IDOR/BOLA | READY AFTER SPECIFIED PREREQUISITES | The current read-only IDOR lifecycle is sound but too small; expansion first requires a controlled benchmark and sanitized object-access candidate schema. |

## Exact Recommended Next Milestone

Proceed with a narrow `v1.5 OWASP Benchmark SQLi compatibility audit and protocol-design preparation` milestone.

The milestone should inspect and classify the existing local OWASP Benchmark Java SQLi cases, define the SQLi candidate-ranking schema and adapter requirements, and produce dry-validation artifacts only. It should not run SQLi attacks, call GPT or Qwen, freeze a scored protocol, change verifier logic or alter any XSS evidence.

## v1.5 Implementation Status

The SQLi compatibility audit and deterministic readiness phase are complete.
The audit identified 504 SQLi-labelled OWASP Benchmark cases and the readiness
phase reserved 20 READINESS_ONLY cases outside the final corpus. The readiness
run passed as an infrastructure/readiness check while preserving 14
inconclusive readiness outcomes as a methodological observation.

The frozen pre-execution protocol is now documented in
`docs/evaluation-protocol-v1.5.md`. Its protocol-freeze package is
`results/owasp-sqli-v15-protocol-freeze/`. The package contains 200
FINAL_CONFIRMATORY_ELIGIBLE cases, 124 ranking scenarios, 1364 scheduled
ranking rows and a separate 200-case direct-execution schedule. Package
validation records zero final SQLi executions, zero scored ranking rows, zero
GPT calls and zero Qwen calls.

The next milestone, if authorized, is final v1.5 confirmatory execution under
the frozen protocol. It should not reinterpret readiness as proof that all 200
final cases are verifier-confirmable, and inconclusive final outcomes must
remain in the direct-execution denominator.

### v1.5 Confirmatory Harness Readiness Result

The missing v1.5 confirmatory execution and canonicalization harness has been
implemented as infrastructure only. The dry-validation package is
`results/owasp-sqli-v15-confirmatory-harness-readiness/`. It reproduces the
frozen denominators, validates resume/duplicate-artifact handling, validates
ground-truth separation, and records zero final SQLi runtime executions, zero
GPT calls, zero Qwen calls and zero scored observations.

The repository is ready for live v1.5 preflight once the external local OWASP
Benchmark target is running and `OPENAI_RANKING_MODEL` is set to the frozen
`gpt-5.6-luna` value. The dry-validation report currently records Qwen
runtime/model hashes as valid and records the GPT model environment variable as
missing.
