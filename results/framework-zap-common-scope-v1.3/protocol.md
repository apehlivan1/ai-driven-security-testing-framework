# Framework versus ZAP Common-Scope Protocol v1.3

Status: frozen before runtime execution.

This supporting evaluation compares the deterministic framework, OWASP ZAP passive scanning, and OWASP ZAP active scanning on the same independently selected OWASP Benchmark Java cases.

## Case Design

- Total independent cases: `50`.
- Reflected-XSS cases: `25` (`15` vulnerable, `10` non-vulnerable).
- Boolean SQL-injection cases: `25` (`15` vulnerable, `10` non-vulnerable).
- Overall composition: `30` vulnerable and `20` non-vulnerable cases.
- Common-scope eligibility is restricted to query-parameter-shaped cases that can be exercised by both the framework runtime path and the evaluated ZAP configurations without per-case credentials, headers, cookies, or manual state.

## Deterministic Selection

Selection uses SHA-256 over `framework-zap-common-scope-v1.3-selection-v1|category|expected_result|candidate_id|original_case_id` within each stratum. The first required cases per stratum are selected before runtime execution. Ground truth is used only to create the frozen positive/negative strata and is stored separately for post-run scoring.

## Execution and Mapping

- Framework XSS cases use the existing deterministic browser observation and verifier path.
- Framework SQLi cases use the existing non-destructive boolean SQL-injection direct execution and verifier path.
- ZAP passive uses the evaluated `zap-baseline.py` workflow.
- ZAP active uses the evaluated active policy with rules `40012` and `40018` at the already used low-strength bounded configuration.
- Scanner alerts are mapped to a case only when the alert name matches the vulnerability family and the alert URL path and parameter match the frozen selected case target.
- Failures are preserved as observations. No silent retries or case substitution are permitted.

## Pilot Rule

The first five selected cases are executed as a pilot using the complete framework, ZAP passive, and ZAP active workflow. The selected 50-case list is not changed based on pilot outcomes. If the projected total runtime is below approximately three hours, execution may continue automatically with the remaining cases; otherwise execution stops after the pilot.

## Selected Case IDs

| Case key | Category | Candidate ID | Original OWASP ID |
| --- | --- | --- | --- |
| `xss::ox14-c000330` | `reflected_xss` | `ox14-c000330` | `BenchmarkTest02132` |
| `xss::ox14-c000419` | `reflected_xss` | `ox14-c000419` | `BenchmarkTest02586` |
| `xss::ox14-c000382` | `reflected_xss` | `ox14-c000382` | `BenchmarkTest02399` |
| `xss::ox14-c000116` | `reflected_xss` | `ox14-c000116` | `BenchmarkTest00721` |
| `xss::ox14-c000431` | `reflected_xss` | `ox14-c000431` | `BenchmarkTest02598` |
| `xss::ox14-c000200` | `reflected_xss` | `ox14-c000200` | `BenchmarkTest01267` |
| `xss::ox14-c000394` | `reflected_xss` | `ox14-c000394` | `BenchmarkTest02480` |
| `xss::ox14-c000403` | `reflected_xss` | `ox14-c000403` | `BenchmarkTest02489` |
| `xss::ox14-c000104` | `reflected_xss` | `ox14-c000104` | `BenchmarkTest00651` |
| `xss::ox14-c000400` | `reflected_xss` | `ox14-c000400` | `BenchmarkTest02486` |
| `xss::ox14-c000062` | `reflected_xss` | `ox14-c000062` | `BenchmarkTest00395` |
| `xss::ox14-c000421` | `reflected_xss` | `ox14-c000421` | `BenchmarkTest02588` |
| `xss::ox14-c000253` | `reflected_xss` | `ox14-c000253` | `BenchmarkTest01587` |
| `xss::ox14-c000124` | `reflected_xss` | `ox14-c000124` | `BenchmarkTest00729` |
| `xss::ox14-c000386` | `reflected_xss` | `ox14-c000386` | `BenchmarkTest02403` |
| `xss::ox14-c000352` | `reflected_xss` | `ox14-c000352` | `BenchmarkTest02237` |
| `xss::ox14-c000399` | `reflected_xss` | `ox14-c000399` | `BenchmarkTest02485` |
| `xss::ox14-c000273` | `reflected_xss` | `ox14-c000273` | `BenchmarkTest01664` |
| `xss::ox14-c000398` | `reflected_xss` | `ox14-c000398` | `BenchmarkTest02484` |
| `xss::ox14-c000384` | `reflected_xss` | `ox14-c000384` | `BenchmarkTest02401` |
| `xss::ox14-c000219` | `reflected_xss` | `ox14-c000219` | `BenchmarkTest01351` |
| `xss::ox14-c000065` | `reflected_xss` | `ox14-c000065` | `BenchmarkTest00469` |
| `xss::ox14-c000351` | `reflected_xss` | `ox14-c000351` | `BenchmarkTest02236` |
| `xss::ox14-c000377` | `reflected_xss` | `ox14-c000377` | `BenchmarkTest02394` |
| `xss::ox14-c000261` | `reflected_xss` | `ox14-c000261` | `BenchmarkTest01595` |
| `sqli::os15-c000302` | `boolean_sqli` | `os15-c000302` | `BenchmarkTest01726` |
| `sqli::os15-c000477` | `boolean_sqli` | `os15-c000477` | `BenchmarkTest02644` |
| `sqli::os15-c000142` | `boolean_sqli` | `os15-c000142` | `BenchmarkTest00845` |
| `sqli::os15-c000304` | `boolean_sqli` | `os15-c000304` | `BenchmarkTest01728` |
| `sqli::os15-c000005` | `boolean_sqli` | `os15-c000005` | `BenchmarkTest00026` |
| `sqli::os15-c000146` | `boolean_sqli` | `os15-c000146` | `BenchmarkTest00849` |
| `sqli::os15-c000443` | `boolean_sqli` | `os15-c000443` | `BenchmarkTest02532` |
| `sqli::os15-c000292` | `boolean_sqli` | `os15-c000292` | `BenchmarkTest01716` |
| `sqli::os15-c000145` | `boolean_sqli` | `os15-c000145` | `BenchmarkTest00848` |
| `sqli::os15-c000453` | `boolean_sqli` | `os15-c000453` | `BenchmarkTest02542` |
| `sqli::os15-c000468` | `boolean_sqli` | `os15-c000468` | `BenchmarkTest02635` |
| `sqli::os15-c000482` | `boolean_sqli` | `os15-c000482` | `BenchmarkTest02649` |
| `sqli::os15-c000480` | `boolean_sqli` | `os15-c000480` | `BenchmarkTest02647` |
| `sqli::os15-c000483` | `boolean_sqli` | `os15-c000483` | `BenchmarkTest02650` |
| `sqli::os15-c000478` | `boolean_sqli` | `os15-c000478` | `BenchmarkTest02645` |
| `sqli::os15-c000152` | `boolean_sqli` | `os15-c000152` | `BenchmarkTest00927` |
| `sqli::os15-c000469` | `boolean_sqli` | `os15-c000469` | `BenchmarkTest02636` |
| `sqli::os15-c000305` | `boolean_sqli` | `os15-c000305` | `BenchmarkTest01729` |
| `sqli::os15-c000087` | `boolean_sqli` | `os15-c000087` | `BenchmarkTest00517` |
| `sqli::os15-c000485` | `boolean_sqli` | `os15-c000485` | `BenchmarkTest02652` |
| `sqli::os15-c000308` | `boolean_sqli` | `os15-c000308` | `BenchmarkTest01732` |
| `sqli::os15-c000216` | `boolean_sqli` | `os15-c000216` | `BenchmarkTest01303` |
| `sqli::os15-c000373` | `boolean_sqli` | `os15-c000373` | `BenchmarkTest02173` |
| `sqli::os15-c000464` | `boolean_sqli` | `os15-c000464` | `BenchmarkTest02631` |
| `sqli::os15-c000501` | `boolean_sqli` | `os15-c000501` | `BenchmarkTest02737` |
