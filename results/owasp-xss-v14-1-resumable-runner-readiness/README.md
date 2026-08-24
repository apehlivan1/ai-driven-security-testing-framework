# v1.4.1 Resumable Runner Readiness

Status: non-scored execution-readiness package. No GPT call, Qwen call, HTTP benchmark request or scored ranking row was executed.

- Protocol tag: `evaluation-protocol-v1.4.1-ready`
- Protocol commit: `08e72f32c9de7e0fb80f3ccfd64c85b6fe99ddb3`
- Total frozen rows: `5852`
- Deterministic rows: `532`
- GPT rows: `2660`
- Qwen rows: `2660`
- Schedule checksum: `c567fcc0faa616969c02334dcb7ce861873d9fde36eb9bb21ed0077e5d114cac`

## Batch Command Examples

These examples are documentation only. Execute them only after explicit scored-execution authorization.

```powershell
$env:OPENAI_RANKING_MODEL = "gpt-5.6-luna"
python -m adstf.owasp_xss_v14_1_resumable_runner --mode execute --max-scheduled-calls 65 --execute-scored-ranking
```

## Qwen Batch Planning

- 30 minute planning batch: `32` calls
- 1 hour planning batch: `65` calls
- 2 hour planning batch: `130` calls
- Overnight conservative batch: `500` calls
- Overnight upper batch: `650` calls
