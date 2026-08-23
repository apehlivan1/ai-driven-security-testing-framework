# Evaluation Protocol v1.5.1

Status: **recovery amendment prepared for manual commit and freeze**.

Protocol identifier: `evaluation-protocol-v1.5.1`.

This document is a narrow recovery amendment to `evaluation-protocol-v1.5`.
It preserves the v1.5 protocol and protocol-freeze package as historical
pre-execution evidence, and it prepares a corrected, complete fresh v1.5.1 run.
It does not authorize a scored execution by itself and it must be committed and
frozen before a final v1.5.1 scored run is performed.

The v1.5 protocol-freeze package remains authoritative for the unchanged
corpus, candidate snapshots, scenario packs, candidate order, decoy assignment,
model identifiers, decoding settings, trial counts, candidate-test budget,
SQLi probes, deterministic adapters, verifier criteria, scoring rules,
retry/failure policy and statistical methodology:

- protocol document: `docs/evaluation-protocol-v1.5.md`;
- protocol package: `results/owasp-sqli-v15-protocol-freeze/`.

## Recovery Motivation

The interrupted v1.5 scored execution is preserved as failed/aborted execution
evidence only. It must not be resumed, modified, deleted, overwritten, repaired
or used as the final thesis result. The interrupted run is located at
`results/owasp-sqli-v15-confirmatory-final/owasp-sqli-v15-confirmatory-20260823T122428Z/`.

Two implementation/execution defects were identified during the interrupted
v1.5 execution.

First, the v1.5 live preflight validated GPT configuration and environment
presence but did not perform an actual non-scored OpenAI provider-connectivity
request. As a result, all 620 GPT scored rows failed locally with
`WinError 10013` before a provider response was obtained. This failure is
classified as an execution-environment/provider-connectivity failure, not as
GPT model-performance evidence.

Second, the frozen shared prompt version `llm-candidate-ranking-v1` began with
XSS-specific wording: `You rank reflected-input candidates...`. The v1.5 study
is a SQL injection ranking study. Although the surrounding v1.5 candidate
snapshots and protocol text were SQLi-specific, this prompt wording created a
construct-validity defect because both GPT and Qwen were asked to rank SQLi
candidates through a prompt phrase inherited from the reflected-XSS study.

## Narrow Corrections

v1.5.1 changes only:

1. pre-execution proprietary-provider connectivity validation;
2. the SQLi ranking prompt wording and prompt version used by both GPT and
   Qwen;
3. execution-output separation so the corrected future run writes to a distinct
   v1.5.1 result namespace.

v1.5.1 does not change:

- the 200 final eligible OWASP SQLi cases;
- the 124 ranking scenarios;
- the frozen candidate snapshots;
- candidate ordering or decoy assignment;
- the three ranking arms;
- model selection;
- model identifiers;
- decoding/model settings;
- trial counts;
- candidate-test budget `k = 4`;
- `top_k = min(candidate_test_budget, candidate_count)`;
- SQLi probes;
- deterministic transport adapters;
- verifier decision criteria;
- runtime scoring rules;
- ground-truth separation;
- metric definitions;
- retry/failure policy.

## Corrected Prompt Version

The corrected SQLi prompt version is `llm-sqli-candidate-ranking-v1`.

Exact prompt template:

```text
You rank structured SQL injection candidate records for authorized local security-testing evaluation.
You may only choose from the supplied candidate_id values. Do not create payloads, do not construct HTTP requests, do not request execution, do not verify findings, and do not use ground truth.
Return strict JSON in this exact shape: {"ranking":[{"candidate_id":"...","rationale":"brief reason"}]}.
Include every candidate exactly once.
Candidates:
<JSON-serialized candidate_input, sorted by key and indented>
```

This prompt preserves the bounded authority model. The model may only rank
supplied candidate IDs and provide bounded rationales. It may not generate SQL
payloads, construct HTTP requests, execute actions, verify findings, inspect
ground truth or alter the candidate set.

GPT and Qwen must receive the same corrected prompt semantics and the same
frozen sanitized SQLi candidate snapshots. The old `llm-candidate-ranking-v1`
prompt remains historical evidence for v1.5 but must not be used for the final
v1.5.1 SQLi scored execution.

## Provider-Connectivity Readiness

Before any future scored v1.5.1 execution begins, preflight must perform a real
non-scored GPT provider-connectivity request using:

- provider: OpenAI;
- model identifier: `gpt-5.6-luna`;
- prompt version: `llm-sqli-candidate-ranking-v1`;
- temperature parameter: omitted;
- provider default temperature: used;
- `OPENAI_SEND_TEMPERATURE`: unset or false.

The connectivity request must use only a synthetic non-final candidate record
with candidate ID `synthetic-connectivity-candidate`. It must not use any final
SQLi candidate snapshot, any `FINAL_CONFIRMATORY_ELIGIBLE` OWASP case, any
original BenchmarkTest identifier, any SQLi ground truth or any execution
specification. It must not create a scored ranking observation. The API key
must be read only from the process environment and must not be printed or
persisted.

If provider connectivity is unavailable, preflight must fail before scored
execution starts.

## Future Execution Rule

The corrected study must be a complete fresh v1.5.1 run. It must not resume the
interrupted v1.5 run and must not reuse the four existing Qwen observations or
the 620 failed GPT observations as final scored data.

The projected v1.5.1 ranking denominators remain:

| Arm | Rows |
| --- | ---: |
| deterministic_structural | 124 deterministic rows |
| proprietary_gpt | 620 GPT rows |
| local_qwen | 620 Qwen rows |
| total | 1364 ranking rows |

The separate direct deterministic SQLi execution layer remains:

| Unit | Count |
| --- | ---: |
| final eligible OWASP SQLi cases | 200 direct cases |
| expected HTTP requests | 1200 |

The future v1.5.1 execution output root is
`results/owasp-sqli-v15-1-confirmatory-final/`. This distinct namespace is
required so the historical aborted v1.5 evidence remains untouched.

## Dry Validation

The amendment-preparation milestone performs dry validation only. It must not
execute deterministic scored rows, GPT scored rows, Qwen scored rows, final SQLi
cases or the 200-case direct SQLi layer. It may validate the future execution
plan with fixtures and existing readiness-only artifacts, and it may validate
that the non-scored provider-connectivity mechanism can be exercised through a
fake provider without creating scored observations.

The dry-validation package for this amendment is
`results/owasp-sqli-v15-1-amendment-readiness/`.

## Versioning

After this amendment is reviewed, committed and frozen, later methodological
changes require a separately versioned protocol amendment. The final v1.5.1
scored execution may begin only after the repository is clean, protocol hashes
and package checksums validate, the real non-scored GPT connectivity preflight
passes, Qwen runtime/model hashes validate and the local OWASP Benchmark target
is reachable.
