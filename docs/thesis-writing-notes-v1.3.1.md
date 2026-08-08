# Thesis Writing Notes v1.3.1

These notes translate the final v1.3.1 XSS ablation package into thesis-writing
guidance. They are descriptive notes only and do not replace the canonical
artifacts.

## Suggested Framing

The main contribution should be presented as an architecture and evaluation
boundary, not as an unconstrained autonomous hacking agent. The framework
separates candidate discovery, bounded ranking, deterministic safety,
deterministic execution, evidence retention, verifier decisions and post-run
ground-truth scoring.

The LLM contribution is intentionally narrow: it ranks already discovered
candidate IDs. It cannot generate payloads, execute actions, call tools, inspect
ground truth, or verify its own findings. This makes its behavior auditable and
allows comparison against a deterministic structural baseline.

## How To Describe v1.3.1

Use `evaluation-protocol-v1.3.1` as the final corrected XSS ablation protocol.
Mention that it is a recovery amendment to v1.3. The amendment only added:

- pre-execution proprietary-provider connectivity validation
- verifier completion timestamp retention for the already-defined
  time-to-first-verified-finding metric
- execution-environment handling required after the v1.3 socket-permission
  failure

State clearly that v1.3.1 did not change the scenarios, candidate snapshots,
models, prompt, parser, decoding settings, trial counts, budgets, top-k
definition, verifier logic, or scoring rules.

## Results Language

Safe wording:

- "On the frozen 24-scenario XSS ablation benchmark..."
- "Under the restricted candidate-ranking contract..."
- "The local Qwen arm achieved the highest MRR in this benchmark..."
- "The GPT arm achieved the highest top-k recall among valid ranking rows..."
- "All three arms produced zero verifier-confirmed findings in negative
  scenarios."

Avoid:

- "The framework is better than ZAP in general."
- "Qwen is better than GPT."
- "The LLM can autonomously hack websites."
- "The results prove general vulnerability-detection superiority."

## Numbers To Cite

Ranking metrics over valid ranking rows:

| Arm | Valid rows | Top-1 | Top-k recall | MRR |
| --- | ---: | ---: | ---: | ---: |
| Deterministic structural | 24 | 0.2500 | 0.6875 | 0.3854 |
| Proprietary GPT | 116 | 0.2179 | 0.7179 | 0.4060 |
| Local Qwen | 120 | 0.3125 | 0.6875 | 0.4427 |

Reliability:

- GPT: 120 attempted, 116 valid, 4 schema-invalid, 0 provider failures.
- Qwen: 120 attempted, 120 valid, 0 malformed/runtime failures.
- Deterministic: 24 rows, all valid.
- No retries were used.
- Gemma contingency was not activated.

Efficiency:

- Time to first verifier-confirmed finding: 8858 ms.
- Requests to first verifier-confirmed finding: 3.
- Candidates tested before first verifier-confirmed finding: 1.
- Valid-row median time to first verifier-confirmed finding:
  deterministic structural 1140 ms, proprietary GPT 354.5 ms, local Qwen
  323 ms.
- Valid-row median requests to first verifier-confirmed finding:
  deterministic structural 6, proprietary GPT 4.0, local Qwen 4.
- Total GPT tokens: 157042.
- GPT cost: `not_available`.

When discussing timing, state that the comparative timing table is derived from
retained v1.3.1 timestamps. Provider/model latency is reported separately in
provider metrics, and cost-per-finding remains `not_available` because no
frozen numeric USD pricing basis exists.

## Where Each Claim Comes From

- Main canonical package:
  `results/xss-v13-ablation-v1.3.1-final/canonical/`
- Human-readable analysis:
  `results/xss-v13-ablation-v1.3.1-final/canonical/analysis-report.md`
- Thesis tables:
  `results/xss-v13-ablation-v1.3.1-final/canonical/tables/`
- Normalized metrics:
  `results/xss-v13-ablation-v1.3.1-final/canonical/normalized/`
- Validation:
  `results/xss-v13-ablation-v1.3.1-final/canonical/validation-report.json`
- Checksums:
  `results/xss-v13-ablation-v1.3.1-final/canonical/checksums.sha256`

## Suggested Thesis Structure

Methodology section:

- explain the framework authority boundary
- define benchmark cases and candidate snapshots
- describe the three ranking arms
- describe verifier-only finding confirmation
- describe ground-truth separation
- describe failure handling and invalid model outputs

Results section:

- start with denominator validation
- present valid ranking metrics
- present malformed/provider/runtime failure accounting
- present negative-scenario behavior
- present time/request/token measurements
- then discuss limitations

Limitations section:

- benchmark is controlled and XSS-specific
- repeated LLM trials are not independent applications
- cost is unavailable where no numeric cost artifact exists
- local Qwen measurements are tied to the recorded CPU/runtime environment
- the study evaluates ranking, not unconstrained autonomous exploitation
