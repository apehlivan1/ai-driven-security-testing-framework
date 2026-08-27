# Thesis-Ready Wording for Professor Comment 6

## Results

The v1.4.1 context-enrichment ablation shows a substantial representation effect. Scenario-level MRR increased from 0.4681 to 0.7768 for the deterministic family, from 0.4337 to 0.7619 for GPT, and from 0.4808 to 0.6314 for Qwen. The corresponding MRR deltas are +0.3087, +0.3282 and +0.1506. These values should be read as effects of adding deterministic benign context fields to the candidate representation, not as direct evidence that the language models independently discovered new vulnerability reasoning.

## Discussion

The enriched representation improved both model-backed and deterministic prioritization. This is methodologically important because the same enriched fields were made available to the deterministic enriched comparator. GPT enriched was not statistically distinguishable from deterministic enriched on the primary paired MRR comparison, while Qwen enriched was lower than deterministic enriched. The strongest supported interpretation is therefore that the additional reflection-derived context is highly informative, whereas incremental model-specific benefit beyond deterministic use of that context remains limited in this frozen benchmark.

## Limitation / Threat to Validity

Several enriched variables, especially reflection detection and marker-preservation categories, are strong susceptibility proxies for reflected XSS even though they are not ground-truth labels. The v1.4.1 analysis therefore does not isolate independent LLM reasoning from non-proxy contextual information. A restricted-context sensitivity analysis excluding the strongest direct reflection and preservation proxy variables would be needed for that narrower claim, but it is not required to report the existing v1.4.1 result as a representation/enrichment ablation.