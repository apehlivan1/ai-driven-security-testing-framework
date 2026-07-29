# Local Model Bake-Off v1.3 Harness Report

Report status: non-experimental fake model data. This package validates the bake-off harness, metrics, reporting layout and selection logic only.

- Models in shortlist: `4`
- Calibration scenarios: `6`
- Trials per model per scenario: `3`
- Total fake trial rows: `72`
- Final model selected: `False`
- Final held-out XSS v1.3 benchmark used: `false`

## Selection Rules

- Gate: `valid_output_rate >= 0.9`
- Gate: `timeout_provider_failure_rate <= 0.1`
- Gate: `memory_feasible == True`
- Gate: `completed_required_calibration_scenarios == required_calibration_scenarios`

Tie-breaking order:
- `higher_mean_reciprocal_rank`
- `higher_top_1_accuracy`
- `higher_top_k_recall`
- `higher_ranking_stability`
- `lower_malformed_output_rate`
- `lower_median_latency_ms`
- `lower_estimated_peak_memory_gb`
- `higher_metadata_completeness_score`
- `lexicographic_model_candidate_id`

## Model Summaries

| Model | Eligible | Valid rate | Timeout/failure rate | MRR | Median latency ms |
| --- | --- | ---: | ---: | ---: | ---: |
| `qwen2_5_7b_instruct_gguf_q4_k_m` | `True` | `1.0` | `0.0` | `0.625` | `480.0` |
| `phi3_5_mini_instruct_gguf_q4_k_m` | `True` | `1.0` | `0.0` | `0.3125` | `240.0` |
| `mistral_7b_instruct_v0_3_gguf_q4_k_m` | `False` | `0.8888888888888888` | `0.0` | `0.5909090909090909` | `520.0` |
| `gemma3_4b_it_gguf_q4_k_m` | `False` | `0.8333333333333334` | `0.05555555555555555` | `0.7` | `300` |
