# Local Model Reproducibility Risk Assessment v1.3

Status: shortlist and bake-off design only. No model was downloaded, no model
was selected, and no ranking trial was run.

## Main Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Runtime not installed | Bake-off cannot run yet | Add a separate setup milestone for llama.cpp only |
| Docker daemon unavailable | Docker Model Runner is not currently usable | Prefer standalone llama.cpp binary for first bake-off |
| Low available RAM snapshot | 7B candidates may fail or swap if many apps are open | Close applications before measured bake-off; include smaller Phi/Gemma candidates |
| CPU-only latency | The bake-off and final 120 calls may take substantial time | Measure latency in calibration bake-off before final model selection |
| Integrated GPU VRAM unknown | GPU acceleration cannot be assumed | Treat CPU as baseline; record any Vulkan/SYCL use only if measured |
| Model repository updates | Re-running later may use different files | Record repository revision and SHA-256 of exact GGUF files |
| llama.cpp release churn | Outputs and performance can vary by build | Pin release tag and binary hash before bake-off |
| Near-determinism rather than full determinism | Small output variation may remain | Record seed, decoding settings, threads, backend and binary version |
| JSON grammar limitations | Valid JSON may still contain wrong candidate IDs | Keep existing parser validation and invalid-output accounting |
| Community GGUF provenance | Some shortlist quantizations are community-provided | Record quant repo, revision, file hash and base model license |
| Selection overfitting | Choosing after seeing held-out v1.3 results would bias evaluation | Select only from calibration scenarios outside the final 24-scenario held-out XSS benchmark |

## Readiness Judgment

The machine is suitable for a measured local-model bake-off if the study uses
quantized GGUF models through a CPU-friendly llama.cpp runtime. It is not yet
appropriate to select a final local primary/fallback model from estimates alone.

The next milestone should implement the bake-off harness and metadata schema
using fake responses only. Model download and live bake-off execution should
remain separate explicitly authorized milestones.
