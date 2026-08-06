# XSS v1.3 Protocol Preparation Dry Validation

Status: dry validation only. No scored ranking trials, browser vulnerability verification, deterministic evaluation, local-model trials, proprietary-model trials or ZAP runs were executed.

- Validation valid: `True`
- Scenario snapshots: `24`
- Arms: `deterministic_structural, proprietary_gpt, local_qwen`
- Shared candidate inputs across arms: `True`
- Ground-truth semantics loaded: `False`
- Candidate snapshots contain ground truth: `False`
- Budget values: `[4]`
- Top-k definition: `top_k = min(test_budget, discovered_candidate_count)`

## Arm Summary

| Arm | Trials per scenario | Main settings |
| --- | ---: | --- |
| `deterministic_structural` | `1` | deterministic-structural-v1 |
| `proprietary_gpt` | `5` | gpt-5.6-luna; temperature parameter omitted; max output 1200 |
| `local_qwen` | `5` | Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M; temp 0.0; max output 768; timeout 300s |

## Freeze Blockers

- `evaluation-protocol-v1.3` is still a draft.
- The generated package must be reviewed and committed.
- The repository must be clean before an annotated protocol tag is created.

## Warnings

- ready for protocol commit/tag only after generated files are committed and the working tree is clean
