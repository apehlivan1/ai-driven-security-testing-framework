# Security Testing Report: Held-Out Boolean Query Benchmark

## Findings

### Boolean SQL injection hypothesis for held-out case hs-001

- State: `verified`
- Category: `boolean_sqli`
- Affected target: `http://127.0.0.1:4393/catalog/item?ref=`
- Hypothesis: The ref parameter may alter database query logic through boolean conditions.

### Boolean SQL injection hypothesis for held-out case hs-002

- State: `rejected`
- Category: `boolean_sqli`
- Affected target: `http://127.0.0.1:4393/catalog/card?ref=`
- Hypothesis: The ref parameter may alter database query logic through boolean conditions.

