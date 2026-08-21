# OWASP XSS v1.4 Compatibility Readiness Report

Status: non-scored readiness validation. No GPT, Qwen or final ranking experiment was executed.

## Pass Criteria Defined Before Runtime

- `PASS`: all selected READINESS_ONLY cases execute the intended request shape in scope, produce evidence, receive a defined verifier outcome, preserve ground-truth isolation, avoid model-facing identity leakage, cover every supported input source, and match readiness ground truth.
- `PARTIAL_PASS`: structural readiness criteria pass, but one or more readiness ground-truth outcomes do not match the runtime verifier result.
- `FAIL`: target health, transport shape, scope, evidence, verifier definition, role separation or leakage validation fails.

## Benchmark Provenance

- Official remote: `https://github.com/OWASP-Benchmark/BenchmarkJava`
- Declared version: `1.2`
- Pinned revision: `ba2e3f9a29fa3bde6a5c073d679393c9b94f025f`
- Expected-results SHA-256: `f0311c850dea7f15125113f7cfdbd7ad612d7f5951c7331584f6981b6ae2d630`

## Selection

- Seed: `owasp-xss-v14-readiness-selection-v1`
- Selected cases: `20`
- Distribution by expected result: `{'vulnerable': 10, 'non_vulnerable': 10}`
- Distribution by input source: `{'header': 4, 'parameter_name_enumeration': 4, 'parameter': 4, 'parameter_map': 4, 'query_string': 4}`

## Runtime Target

- Base URL: `https://127.0.0.1:8443/benchmark`
- Startup command: `runBenchmark.bat` or `mvn initialize; mvn clean package cargo:run -Pdeploy` from `.external/owasp-benchmark-java`.
- Java target recorded by the benchmark POM: `8`; local Maven reports the active Java runtime during startup.
- Health reachable: `True`
- Health status: `200`
- Health error: `None`

## Safety Configuration

- Allowed schemes: `['https']`
- Allowed hosts: `['127.0.0.1']`
- Allowed ports: `[8443]`
- Enabled module: `xss.reflected`

## Adapter Summary

- Direct parameter, parameter-map and query-string cases use deterministic query construction.
- Header cases use deterministic per-action browser headers; rankers never choose header names or values.
- Parameter-name enumeration cases place the marker/control in the request parameter name and the original case marker value in the parameter value.
- Cookie support was not implemented because the authoritative audit found no required cookie transport for XSS.
- A single deterministic inert-suffix marker payload is used so terminal-character mutations in READINESS_ONLY cases do not break the script boundary.
- No LLM-generated payloads, model-selected payloads or multi-payload suite were introduced during this readiness milestone.

## Per-Case Runtime Results

| Opaque ID | Original case | Source | Expected | Payload action | Control action | Verifier | Match |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ox14-c000028` | `BenchmarkTest00280` | `header` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000080` | `BenchmarkTest00543` | `parameter_name_enumeration` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000166` | `BenchmarkTest01053` | `header` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000176` | `BenchmarkTest01175` | `header` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000180` | `BenchmarkTest01179` | `header` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000187` | `BenchmarkTest01254` | `parameter` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000206` | `BenchmarkTest01338` | `parameter_map` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000213` | `BenchmarkTest01345` | `parameter_map` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000240` | `BenchmarkTest01508` | `parameter` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000257` | `BenchmarkTest01591` | `parameter` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000276` | `BenchmarkTest01667` | `query_string` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000279` | `BenchmarkTest01670` | `query_string` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000280` | `BenchmarkTest01671` | `query_string` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000325` | `BenchmarkTest02127` | `parameter` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000338` | `BenchmarkTest02223` | `parameter_map` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000345` | `BenchmarkTest02230` | `parameter_map` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000360` | `BenchmarkTest02316` | `parameter_name_enumeration` | `vulnerable` | `executed` | `executed` | `verified` | `True` |
| `ox14-c000364` | `BenchmarkTest02320` | `parameter_name_enumeration` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000375` | `BenchmarkTest02331` | `parameter_name_enumeration` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |
| `ox14-c000436` | `BenchmarkTest02609` | `query_string` | `non_vulnerable` | `executed` | `executed` | `inconclusive` | `True` |

## Reconciled Corpus

- Original total XSS cases: `455`
- Original compatible after adapters: `408`
- READINESS_ONLY count: `20`
- FINAL_CONFIRMATORY_ELIGIBLE count: `388`
- FINAL_CONFIRMATORY_ELIGIBLE vulnerable count: `236`
- FINAL_CONFIRMATORY_ELIGIBLE negative count: `152`
- Remaining excluded count: `47`

## Preliminary Final Ranking Scale From FINAL_CONFIRMATORY_ELIGIBLE Only

| Pack size | Positive scenarios | Negative scenarios | Mean decoy reuse | Max decoy reuse | Unique cases represented | Candidate tests/arm |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 5 | 236 | 30 | 6.2105263157894735 | 7 | 388 | 1064 |

## Integrity Statements

- READINESS_ONLY cases were selected before runtime execution.
- FINAL_CONFIRMATORY_ELIGIBLE cases were not executed.
- Benchmark ground truth was not included in model-facing candidates, execution specifications, executor inputs or verifier inputs.
- Ground truth appears only in internal provenance and post-run readiness reporting.
- No GPT or Qwen calls occurred.

## Validation

- Valid: `True`
- Errors: `0`
- Warnings: `0`
- Readiness status: `PASS`
