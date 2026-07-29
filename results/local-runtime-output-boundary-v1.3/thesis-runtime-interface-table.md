# Runtime Interface Table v1.3

Table status: output-boundary audit only; not model ranking performance.

| Interface | Selected | Content boundary | Metadata boundary | Reason |
| --- | --- | --- | --- | --- |
| `llama-completion` | `True` | stdout normalized content after exact trailing runtime marker separation | stderr plus transport metadata | minimal adapter, direct ModelClient compatibility, raw stdout/stderr retained |
| `llama-server` | `False` | documented response content field | server JSON response fields | available but not chosen for this correction because it introduces server lifecycle and HTTP transport before needed |
| `clean llama-completion with no-perf/log-disable` | `False` | stdout | reduced stderr | less useful because timing metadata is required and the EOS marker still needs a content-boundary rule |
