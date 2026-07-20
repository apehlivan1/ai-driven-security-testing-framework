# Security Testing Report: Held-Out Read-Only Access Benchmark

## Findings

### Read-only IDOR hypothesis for held-out case hi-001

- State: `verified`
- Category: `read_only_idor`
- Affected target: `http://127.0.0.1:4392/portal/file?doc=r-218`
- Hypothesis: A second isolated user may read a resource owned by the first user through a read-only request.

### Read-only IDOR hypothesis for held-out case hi-002

- State: `rejected`
- Category: `read_only_idor`
- Affected target: `http://127.0.0.1:4392/portal/item?doc=r-427`
- Hypothesis: A second isolated user may read a resource owned by the first user through a read-only request.

