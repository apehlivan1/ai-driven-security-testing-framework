# Reproducibility and Resource Limitations

- The provisioning smoke uses the Windows CPU build of llama.cpp and therefore measures CPU-first feasibility.
- The smoke request is intentionally non-scored and does not select a primary or fallback model.
- The smoke uses a 32-token output cap to test local load, raw output capture and parser execution on CPU; malformed JSON is expected unless the model completes the strict JSON object inside that cap.
- Token counts are `not_available` because the llama.cpp CLI adapter does not expose token usage in a normalized provider envelope.
- Cost is `not_available` for local models because no external provider billing applies.
- Peak process memory is not yet measured by the minimal CLI adapter; the measured bake-off should record operating-system memory snapshots before and after each call.
- A malformed smoke response is a recorded interoperability fact, not grounds for removing a shortlisted model unless the model cannot load or execute.
