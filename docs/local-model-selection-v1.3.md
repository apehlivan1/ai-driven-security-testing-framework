# Local Open-Weights Model Feasibility and Bake-Off Design v1.3

Status: feasibility, shortlist, runtime provisioning, readiness validation and
measured calibration bake-off completed. The selected primary local model for
the constrained v1.3 candidate-ranking task is
`qwen2_5_7b_instruct_gguf_q4_k_m`. The selected contingency model is
`gemma3_4b_it_gguf_q4_k_m`. `evaluation-protocol-v1.3` is not frozen.

The selection was made only after all shortlisted candidates were tested under
identical measured conditions on development/calibration scenarios that are not
part of the final 24-scenario v1.3 XSS benchmark. All four model results remain
preserved for thesis reporting.

## Authority Boundary

The local model receives only the same structured candidate metadata as the
proprietary model under `llm-candidate-ranking-v1`.

Allowed output:

- an ordered list of existing candidate IDs;
- brief rationales for those existing candidate IDs.

Forbidden inputs:

- raw HTML;
- source code;
- browser state;
- screenshots;
- credentials;
- API keys;
- session values;
- semantic ground truth;
- unrelated workspace content.

Forbidden authority:

- payload generation;
- action execution;
- browser or HTTP control;
- verification;
- finding confirmation.

The deterministic verifier remains the only component allowed to confirm,
reject, or mark findings inconclusive.

## Measured Machine Facts

Measured on this workstation during this milestone:

| Property | Measured value | Notes |
| --- | --- | --- |
| Operating system | Windows 10, version `10.0.19045` | Python/platform and .NET system info |
| Architecture | `AMD64` | Python/platform |
| CPU | 11th Gen Intel Core i7-1165G7 @ 2.80GHz | Windows registry |
| Usable logical processors | 8 | `os.cpu_count()` and environment |
| Physical core count | not directly measured | CIM access was denied; operational planning should use 8 logical processors |
| Total RAM | 16,895,107,072 bytes, about 15.7 GiB | .NET `ComputerInfo` |
| Available RAM at inspection | 3,470,745,600 bytes, about 3.2 GiB | Snapshot only; not a fixed machine limit |
| GPU | Intel Iris Xe Graphics | Registry display driver data |
| Dedicated VRAM | `not_available` | Integrated GPU; adapter memory not exposed |
| Confirmed acceleration APIs | CPU; no CUDA detected | `nvidia-smi` and `nvcc` absent |
| Potential acceleration APIs | DirectX driver present; Vulkan/SYCL not verified | Must be measured if used |
| Free disk on repo drive | about 291.2 GB decimal, 271.2 GiB | Python `shutil.disk_usage` |
| Python | 3.14.0 | Current process |
| pip | 25.2 | Current Python |
| Playwright | 1.61.0 | Installed |
| Docker CLI | 29.0.1 | Docker daemon was not reachable |
| Docker Compose | 2.40.3-desktop.1 | CLI present |

Installed local inference runtime inspection:

| Runtime | Available now | Evidence |
| --- | --- | --- |
| Ollama | no | `where.exe ollama` not found |
| llama.cpp CLI/server | no | `where.exe llama-cli llama-server` not found |
| LM Studio CLI | no | `where.exe lmstudio` not found |
| Transformers | no | Python import check failed |
| vLLM | no | Python import check failed |
| llama-cpp-python | no | Python import check failed |
| Docker Model Runner | partial | Docker CLI plugin listed, but Docker daemon was unavailable |

## Practical Constraints

- The machine should be treated as CPU-first for the local-model study.
- A quantized GGUF model is the lowest-risk format for this environment.
- Python-native GPU/ML stacks are not a good first choice because Python 3.14
  and missing `torch`/`transformers`/`vLLM` increase setup risk.
- Current free RAM is low for 7B models, but total RAM is sufficient if other
  applications are closed before a measured smoke test.
- The planned local arm requires at least 120 ranking calls for the v1.3 XSS
  study: 24 scenarios x 5 trials.
- The bake-off must measure actual latency and output validity before choosing
  the final primary and fallback model.

## Shortlisted Candidate Models

The shortlist intentionally spans more than one model family. All entries are
estimates until measured in the bake-off.

| Candidate | Family | Runtime | Quantization | Expected memory | Expected latency | JSON reliability estimate | License/reproducibility notes | Shortlist reason |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M` | Qwen | llama.cpp | Q4_K_M | 4.68 GB weights; plan 7-9 GB RAM | 20-60 seconds/call | strong | Apache 2.0 model card; official GGUF repo available | Strong structured-data and JSON-oriented instruction-following candidate |
| `bartowski/Phi-3.5-mini-instruct-GGUF:Q4_K_M` or equivalent Phi GGUF | Phi | llama.cpp | Q4_K_M | 2.39 GB weights; plan 4-6 GB RAM | 8-25 seconds/call | medium | Microsoft base model is MIT; community quant provenance and hash required | Best low-memory fallback candidate |
| `mistralai/Mistral-7B-Instruct-v0.3` GGUF Q4_K_M | Mistral | llama.cpp | Q4_K_M | 7B Q4 class; plan 7-9 GB RAM | 20-60 seconds/call | medium | Apache 2.0 model card; exact GGUF source must be pinned | Strong open Apache-licensed alternative family |
| `tensorblock/gemma-3-4b-it-GGUF:Q4_K_M` or equivalent Gemma 3 4B GGUF | Gemma | llama.cpp | Q4_K_M | 2.49 GB weights; plan 4-6 GB RAM | 8-30 seconds/call | medium | Gemma license; access/license terms must be recorded | Smaller non-Qwen, non-Phi candidate with practical memory profile |

Not shortlisted for the first bake-off:

- Llama 3.1 8B Instruct: runnable, but gated access and Llama-specific license
  terms add friction for the first local academic baseline.
- Ollama-managed tags: easy to use, but less transparent than direct GGUF file
  hashing unless blob digests are carefully recorded.
- Transformers/vLLM: not currently installed and likely to create avoidable
  Python/runtime setup complexity on this machine.

## Calibration Bake-Off Design

The bake-off must run before final local-model selection and before freezing
`evaluation-protocol-v1.3`.

Calibration set:

- Use development/calibration reflected-input scenarios only.
- Do not use the final 24-scenario v1.3 held-out XSS benchmark.
- Recommended minimum: 6 calibration scenarios.
- Include 4 vulnerable and 2 negative scenarios.
- Include 4-8 discovered candidates per scenario.
- Include at least:
  - one structurally favoured vulnerable candidate;
  - one structurally unfavoured vulnerable candidate;
  - one negative case with strong-looking safe candidates;
  - one multi-seed case;
  - one query-parameter case;
  - one required-field/form-structure decoy case.

Identical conditions for every shortlisted model:

- same candidate input schema;
- same `llm-candidate-ranking-v1` prompt;
- same candidate ordering in the request;
- same context size;
- same maximum output tokens;
- same decoding settings;
- same timeout;
- same parser and validation rules;
- same deterministic fallback policy for safe continuation;
- same hardware state recording;
- same trial count.

Recommended bake-off trial count:

- 3 trials per calibration scenario per shortlisted model.

For 4 shortlisted models and 6 calibration scenarios:

```text
4 models x 6 scenarios x 3 trials = 72 ranking calls
```

This is large enough to measure validity, latency, and stability without
spending the full 120-call final-study budget before model selection.

## Pre-Registered Selection Metrics

The final local primary and fallback should be selected using these metrics,
calculated on calibration data only:

1. Valid-output rate.
2. Malformed-output rate.
3. Unknown/duplicate/omitted candidate-ID rate.
4. Timeout/failure rate.
5. Top-1 accuracy on vulnerable calibration scenarios.
6. Top-k recall using the frozen calibration test budget.
7. Mean reciprocal rank on vulnerable calibration scenarios.
8. No-vulnerability false-positive selection behavior.
9. Ranking stability across repeated trials.
10. Median and p90 latency per ranking call.
11. Estimated total runtime for 120 final v1.3 calls.
12. Peak memory/RAM feasibility observed during smoke execution, if measurable.
13. License and reproducibility metadata completeness.

The bake-off report must preserve results for every tested model, even though
only the selected primary and fallback remain in the final v1.3 evaluation
configuration.

## Tie-Breaking Rules

Apply these rules in order, before looking at final held-out results:

1. Exclude any model with valid-output rate below 90%.
2. Exclude any model with timeout/failure rate above 10%.
3. Exclude any model that cannot complete the calibration bake-off without
   memory pressure severe enough to invalidate timing.
4. Among remaining models, prefer higher mean reciprocal rank.
5. If MRR differs by less than 0.05, prefer higher valid-output rate.
6. If still tied, prefer lower median latency.
7. If still tied, prefer more complete reproducibility metadata and simpler
   license terms.
8. If still tied, prefer the smaller model because the final study requires 120
   local ranking calls.

Fallback model selection:

- choose the highest-ranked model that is materially smaller or faster than the
  primary, unless it failed validity thresholds.

## Metadata Required During Bake-Off

For every tested model:

- model repository;
- model revision/commit;
- exact filename(s);
- file size(s);
- SHA-256 hash for every model artifact;
- quantization;
- base model;
- license;
- llama.cpp release tag;
- llama.cpp binary SHA-256;
- backend used: CPU, Vulkan, SYCL, OpenVINO, or other;
- thread count;
- context size;
- maximum output tokens;
- temperature;
- top_p;
- seed;
- prompt version;
- full prompt text;
- raw response;
- parsed ranking;
- validation errors;
- latency;
- timeout/failure status;
- hardware snapshot;
- execution timestamp.

## Implemented Harness Support

The repository now includes a reusable fake-only bake-off harness:

- module: `src/adstf/local_model_bakeoff.py`;
- fake package: `results/local-model-bakeoff-v1.3/`;
- calibration set version: `local-model-calibration-xss-v1.3`;
- selection rule version: `local-model-selection-rules-v1.3`;
- trial design: 4 shortlisted models x 6 calibration scenarios x 3 trials =
  72 ranking calls;
- final held-out XSS v1.3 scenarios used: no;
- live model execution: no;
- final local model selection: no.

The harness uses the existing `llm-candidate-ranking-v1` prompt and parser.
The fake package deliberately includes valid and invalid fake responses so that
malformed JSON, duplicate IDs, unknown IDs, omitted IDs, timeouts, and provider
failures are represented in the validation path. These fake outputs are
non-experimental test data and must not be interpreted as model performance.

The live bake-off must reuse the same scenario definitions, trial counts,
selection gates, tie-breaking order, parser behavior, and authority boundary.
Only the fake model client should be replaced with a measured local runtime
client after model artifacts and runtime binaries are installed and hashed.

## Local Runtime Provisioning Smoke

The repository now includes a local llama.cpp-compatible runtime adapter and a
non-scored provisioning smoke package:

- adapter module: `src/adstf/local_runtime.py`;
- smoke command module: `src/adstf/local_runtime_smoke.py`;
- provisioning package: `results/local-runtime-provisioning-v1.3/`;
- runtime: llama.cpp release `b9637`, Windows CPU x64 build;
- executable used for smoke: `llama-completion.exe`;
- backend used: CPU;
- smoke output cap: 32 tokens;
- smoke timeout: 120 seconds per model;
- prompt: unchanged `llm-candidate-ranking-v1`;
- candidate data: three synthetic local-smoke candidates, not part of the
  six calibration scenarios and not part of the final 24-scenario XSS v1.3
  benchmark;
- scoring status: non-scored, no final model selection.

All four shortlisted GGUF artifacts were downloaded, hashed and recorded:

| Candidate | Repository | Revision | Artifact status |
| --- | --- | --- | --- |
| Qwen2.5 7B Instruct Q4_K_M | `Qwen/Qwen2.5-7B-Instruct-GGUF` | `bb5d59e06d9551d752d08b292a50eb208b07ab1f` | downloaded and hashed |
| Phi-3.5 Mini Instruct Q4_K_M | `bartowski/Phi-3.5-mini-instruct-GGUF` | `6d70da17e749a471ccb62ade694486011a75cda3` | downloaded and hashed |
| Mistral 7B Instruct v0.3 Q4_K_M | `bartowski/Mistral-7B-Instruct-v0.3-GGUF` | `61fd4167fff3ab01ee1cfe0da183fa27a944db48` | downloaded and hashed |
| Gemma 3 4B IT Q4_K_M | `ggml-org/gemma-3-4b-it-GGUF` | `d0976223747697cb51e056d85c532013931fe52e` | downloaded and hashed |

The smoke run confirmed that the local runtime could load each model, return
raw output, and exercise the existing parser and validation path. The outputs
were malformed for all four models because the smoke cap was intentionally
small. This must not be interpreted as model performance. The measured bake-off
still needs a separate execution with the pre-registered calibration scenarios,
the final bake-off output limit, and the frozen model-selection rules.

An initial attempt using `llama-cli.exe` was preserved separately as an
invocation-defect artifact because that executable entered interactive
conversation behavior. The corrected adapter uses `llama-completion.exe`.

## Structured-Output Readiness

The repository now includes a separate non-scored structured-output readiness
package:

- readiness module: `src/adstf/local_runtime_readiness.py`;
- readiness package: `results/local-runtime-readiness-v1.3/`;
- runtime: llama.cpp release `b9637`, Windows CPU x64 build;
- executable: `llama-completion.exe`;
- constrained output mechanism: `--json-schema-file`;
- schema version: `local-ranking-readiness-json-schema-v1.3`;
- context size: 4096 tokens;
- maximum output: 768 tokens;
- timeout: 300 seconds per model;
- decoding settings: temperature 0.0, top-p 1.0, seed 42;
- prompt: unchanged `llm-candidate-ranking-v1`;
- candidate input: one synthetic maximum-shape readiness request with eight
  candidates, not part of the six calibration scenarios and not part of the
  final 24-scenario XSS v1.3 benchmark;
- scoring status: non-scored, no final model selection.

The 768-token limit was chosen from the worst permitted response shape: one
JSON object containing eight ranking entries, every existing candidate ID once,
and bounded rationales up to 96 characters. This leaves margin above the
expected JSON length while remaining small enough for CPU feasibility checks.

Readiness outcome:

| Candidate | Readiness status | Main validation result |
| --- | --- | --- |
| Qwen2.5 7B Instruct Q4_K_M | not ready | strict parser rejected extra data after JSON |
| Phi-3.5 Mini Instruct Q4_K_M | not ready | strict parser rejected extra data after JSON |
| Mistral 7B Instruct v0.3 Q4_K_M | not ready | strict parser rejected extra data after JSON |
| Gemma 3 4B IT Q4_K_M | not ready | strict parser rejected extra data after JSON |

All four models loaded and produced complete-looking JSON, but the runtime
stdout appended a literal `[end of text]` marker after the JSON object. The
existing parser correctly treated this as `malformed JSON response: Extra data`.
This is a shared runtime/configuration compatibility issue, not a measured
model-quality result.

The measured 72-call bake-off is therefore not ready to execute under the
current common configuration. The next correction should be global and applied
identically to all four models, for example by selecting a llama.cpp one-shot
output mode or documented runtime argument that does not append the end marker,
or by formally separating documented runtime terminators from model-generated
content in the adapter. Any such correction must be versioned before rerunning
readiness for all four models. Individual model-specific tuning remains
forbidden.

## Output-Boundary Correction

The repository now includes a narrow output-boundary audit and corrected
readiness package:

- module: `src/adstf/local_runtime_output_boundary.py`;
- package: `results/local-runtime-output-boundary-v1.3/`;
- transport settings version: `llama-completion-transport-boundary-v1.3`;
- parser rule version: `llama-completion-transport-parser-v1.3`;
- selected common interface: `llama-completion` stdout/stderr transport with a
  versioned output-boundary parser;
- schema: unchanged `local-ranking-readiness-json-schema-v1.3`;
- prompt: unchanged `llm-candidate-ranking-v1`;
- candidate input: unchanged synthetic eight-candidate readiness input;
- final 24-scenario XSS v1.3 benchmark used: no;
- calibration bake-off executed: no;
- vulnerability testing executed: no;
- final model selected: no.

Root cause:

- generated JSON was written to stdout;
- timing and system metadata were written to stderr;
- the fixed literal `[end of text]` appeared on stdout after an otherwise
  complete JSON object for all four models;
- `--special` was not enabled, and prompt display was disabled;
- the application parser correctly rejected the unseparated stdout as extra
  data.

Correction:

- retain raw stdout and stderr unchanged;
- treat `[end of text]` as a llama.cpp runtime/EOS presentation marker only
  when it is the exact trailing suffix after an otherwise valid JSON object;
- store normalized model content separately from raw process output;
- leave genuine extra model-generated text invalid;
- leave marker-like text inside JSON rationales untouched;
- apply the same transport rule to all four models.

`llama-server.exe` is available in the provisioned release and its executable
hash is recorded in the output-boundary package. It was not selected for this
correction because the corrected `llama-completion` interface gives a clear
content/metadata boundary while avoiding a new HTTP server lifecycle before the
measured bake-off.

Corrected readiness result:

| Candidate | Readiness status | Stop condition | Token limit reached |
| --- | --- | --- | --- |
| Qwen2.5 7B Instruct Q4_K_M | ready | EOS runtime marker separated | false |
| Phi-3.5 Mini Instruct Q4_K_M | ready | EOS runtime marker separated | false |
| Mistral 7B Instruct v0.3 Q4_K_M | ready | EOS runtime marker separated | false |
| Gemma 3 4B IT Q4_K_M | ready | EOS runtime marker separated | false |

The measured 72-call calibration bake-off is now technically ready to execute,
subject to preserving the same prompt, schema, candidates, generation settings,
parser rule and model shortlist.

## Sources Used

- Qwen2.5 7B Instruct GGUF model card:
  <https://huggingface.co/Qwen/Qwen2.5-7B-Instruct-GGUF>
- Qwen2.5 7B Instruct model card:
  <https://huggingface.co/Qwen/Qwen2.5-7B-Instruct>
- llama.cpp README and backend documentation:
  <https://github.com/ggml-org/llama.cpp>
- llama.cpp releases:
  <https://github.com/ggml-org/llama.cpp/releases>
- Phi-3.5 Mini Instruct model card:
  <https://huggingface.co/microsoft/Phi-3.5-mini-instruct>
- Phi-3.5 Mini GGUF quantization page:
  <https://huggingface.co/bartowski/Phi-3.5-mini-instruct-GGUF>
- Mistral 7B Instruct v0.3 model card:
  <https://huggingface.co/mistralai/Mistral-7B-Instruct-v0.3>
- Gemma 3 4B GGUF page:
  <https://huggingface.co/tensorblock/gemma-3-4b-it-GGUF>

## Next Narrow Task

Prepare the executable v1.3 XSS ablation protocol for freezing. The preparation
must create ground-truth-free candidate snapshots for the final 24 scenarios,
prove that deterministic, proprietary GPT and local Qwen arms consume identical
candidate inputs, record the Qwen/Gemma fallback rule, and stop before any
scored final experiment is run.
