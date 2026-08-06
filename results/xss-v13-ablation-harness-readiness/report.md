# XSS v1.3 Ablation Harness Readiness

Status: dry-run harness validation only. No scored calls, provider calls, local-model inference, browser vulnerability verification, ZAP, IDOR or SQLi were executed.

- Validation valid: `True`
- Scheduled ranking rows: `264`
- Candidate snapshots: `24`
- Ground truth loaded: `False`
- Proprietary API calls executed: `False`
- Local model calls executed: `False`
- Browser vulnerability verification executed: `False`

## Arm Denominators

| Arm | Scheduled ranking rows | Trials/scenario | Max candidate tests |
| --- | ---: | ---: | ---: |
| `deterministic_structural` | `24` | `1` | `96` |
| `proprietary_gpt` | `120` | `5` | `480` |
| `local_qwen` | `120` | `5` | `480` |
