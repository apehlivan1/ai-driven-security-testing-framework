# Evaluation Synthesis for Thesis Writing

Status: thesis-writing synthesis derived from already validated frozen/canonical
evaluation artifacts and Professor Comment 1-6 closure evidence.

This document is not a new experiment. It does not rerun ranking, model calls,
HTTP/browser requests, verifier calls, scoring, bootstrap procedures,
permutation tests or exploratory analyses. It is a writing bridge from the
completed evidence packages to the final thesis chapters.

Primary evidence sources:

- `docs/thesis-evidence-index.md`
- `results/owasp-xss-v14-random-baseline-audit/`
- `results/owasp-xss-v14-trial-stability-analysis/`
- `results/owasp-xss-v14-scenario-statistical-analysis/`
- `results/professor-comment-4-negative-sqli-analysis/`
- `results/professor-comment-5-bespoke-contamination-analysis/`
- `results/professor-comment-6-context-enrichment-analysis/`
- frozen/canonical XSS, SQLi and v1.4.1 result packages referenced by those
  closures

## Supported Research and Evaluation Questions

The completed evaluation supports the following thesis questions:

1. Does bounded model-backed ranking improve candidate prioritization relative
   to deterministic structural ranking under a fixed candidate-test budget?
2. Does any observed ranking effect generalize across datasets, model families,
   representation conditions and vulnerability categories?
3. How should repeated LLM trials be interpreted when trial outputs are nested
   within the same benchmark scenario?
4. How does deterministic benign context enrichment change ranking
   performance, and does the change represent model-specific reasoning or a
   representation effect?
5. What do the completed evaluations show about reliability, reproducibility,
   negative/control behavior and verifier-backed classification?

These questions are narrower than a claim about autonomous penetration testing.
They are about candidate prioritization under a bounded authority contract:
models may rank already supplied candidate IDs, while execution, safety,
evidence collection, ground-truth access and final vulnerability verification
remain outside the model component.

## Evaluation Components

The evaluation consists of four main evidence layers.

The bespoke XSS v1.3.1 evaluation is a 24-scenario held-out local benchmark
with 16 positive and 8 negative/control scenarios. It compares deterministic
structural ranking, hosted GPT ranking and local Qwen ranking over frozen
ground-truth-free candidate snapshots. It is the lower-contamination-risk XSS
evidence source because the scenarios were locally constructed, frozen before
final scored execution and excluded from model-selection/calibration runs.

The OWASP XSS v1.4 evaluation is the larger public external-validation ranking
study. It uses 236 positive ranking scenarios and 30 negative-only ranking
scenarios, each with five candidates and candidate-test budget `k = 4`.
Because OWASP Benchmark is public, possible model training-data exposure cannot
be ruled out; this is a contamination-risk caveat, not evidence of actual
contamination.

The OWASP XSS v1.4.1 context-enrichment ablation uses the same v1.4 scenario
packs, candidate IDs, candidate ordering and budget, but compares minimal
candidate representations with enriched representations containing
deterministically collected benign reflection context. It includes six arms:
deterministic minimal, deterministic enriched, GPT minimal, GPT enriched, Qwen
minimal and Qwen enriched.

The OWASP SQLi v1.5.1 evaluation provides a separate SQL-injection ranking and
direct verifier/classification layer. It supports comparison of ranking
behavior across vulnerability categories and demonstrates deterministic
runtime verification/classification for non-destructive boolean-based SQLi
under the frozen protocol.

Across all ranking evaluations, the scenario is the independent experimental
unit. Repeated GPT and Qwen trials are nested measurements used to characterize
model variability and reliability; they do not create additional independent
benchmark scenarios. Ranking evidence remains distinct from runtime
verification and post-run classification evidence.

## Original OWASP XSS v1.4 Ranking Evidence

In the original public OWASP XSS v1.4 positive scenarios, each scenario has
five candidates and exactly one vulnerable candidate. The analytic random
reference is therefore Top-1 `0.2000`, Top-2 `0.4000`, Top-4 `0.8000` and MRR
`0.4567`.

| Arm | Top-1 | Top-2 | Top-4 | MRR | Interpretation |
| --- | ---: | ---: | ---: | ---: | --- |
| Random reference | 0.2000 | 0.4000 | 0.8000 | 0.4567 | Analytic reference |
| Deterministic structural | 0.2034 | 0.4153 | 0.7881 | 0.4573 | Essentially at random reference |
| GPT | 0.2332 | 0.4105 | 0.7812 | 0.4732 | Descriptive trend above deterministic on MRR |
| Qwen | 0.2468 | 0.4468 | 0.8298 | 0.4926 | Strongest descriptive MRR among original v1.4 arms |

The OWASP v1.4 benchmark contains 236 positive scenarios in total. Qwen
contributes valid ranking-performance values for 235/236 positive scenarios;
the excluded scenario remains represented in reliability reporting through its
five malformed terminal outputs.

The deterministic discrimination audit shows that the original deterministic
ranker is not a pure random or tie-only ranker, but its structural
discrimination is weakly aligned with vulnerability on this homogeneous OWASP
candidate class. There were `30/266` all-five-tied scenarios, `153/266` with
two distinct pre-tiebreak scores and `83/266` with three distinct pre-tiebreak
scores. Among the 236 positive scenarios, the vulnerable candidate was
strictly highest before tiebreaking in `0/236`, tied for highest in `151/236`,
strictly lowest in `27/236`, and had no distractor sharing its score in only
`40/236` scenarios.

The Comment 3 scenario-level inferential analysis is the main statistical
qualification for the original v1.4 XSS descriptive table. The primary
comparison is Qwen minus deterministic structural ranking on scenario-level
mean reciprocal rank:

| Comparison | Paired n | Mean difference | 95% CI | Wilcoxon p | Rank-biserial |
| --- | ---: | ---: | ---: | ---: | ---: |
| Qwen - deterministic MRR | 235 | +0.0355 | [-0.0207, +0.0922] | 0.659123 | +0.0348 |

This result does not statistically support a claim that Qwen outperformed the
deterministic baseline on the frozen OWASP XSS v1.4 scenario class. The v1.4
result should therefore be written as a descriptive model-backed trend, not as
statistical superiority.

## Repeated-Trial Stability

Repeated model trials are useful, but they are not independent benchmark
scenarios. GPT showed material variability in exact complete rankings despite
substantial ordinal agreement across trials. For positive scenarios, GPT had
mean Spearman `0.7393` and mean Kendall tau `0.7326`; exact complete rankings
differed in `156/236` positive scenarios.

Qwen showed a different profile. All valid repeated rankings were identical
within scenario. In the original v1.4 positive set, `235` positive scenarios
had five valid identical Qwen rankings, while one positive scenario had five
malformed terminal outputs and no valid Qwen ranking. This supports a
reliability/stability statement, but not an increase in independent sample
size.

## Bespoke Held-Out XSS v1.3.1 Evidence

The bespoke v1.3.1 XSS benchmark contains 24 scenarios: 16 positive and 8
negative/control scenarios. Candidate counts range from 4 to 8 with
distribution `{4: 4, 5: 5, 6: 8, 7: 4, 8: 3}`. Among the positive scenarios,
the candidate-count distribution is `{4: 2, 5: 4, 6: 5, 7: 3, 8: 2}` and each
positive scenario has exactly one vulnerable candidate.

Because candidate counts vary, the random reference is scenario-specific. For
the 16 positive bespoke scenarios, the analytic random reference is Top-1
`0.1757`, Top-2 `0.3515`, Top-4 `0.7030` and budget-censored MRR `0.3661`.
The reported MRR values below use the canonical budget-censored v1.3.1
semantics: reciprocal-rank credit is assigned only when the vulnerable
candidate appears within `top_k`.

| Arm | Top-1 | Top-2 | Top-4 | Budget-censored MRR | MRR minus random |
| --- | ---: | ---: | ---: | ---: | ---: |
| Deterministic structural | 0.2500 | 0.3125 | 0.6875 | 0.3854 | +0.0193 |
| GPT | 0.2250 | 0.4500 | 0.7219 | 0.4107 | +0.0445 |
| Qwen | 0.3125 | 0.3750 | 0.6875 | 0.4427 | +0.0766 |

Top-4 requires special care because scenarios with exactly four candidates
have random Top-4 `1.0000` by definition when `k = 4`. On the positive subset
with more than four candidates, random Top-4 is `0.6605`; observed Top-4 was
`0.6429` for deterministic structural ranking, `0.6821` for GPT and `0.6429`
for Qwen.

The bespoke results provide lower-contamination-risk supporting evidence that
model-backed ranking can contain useful prioritization signal. They also
qualify the thesis claim: effects are model-, metric- and dataset-dependent,
and the 24-scenario bespoke benchmark is too small for broad generalization.
Raw MRR and observed-minus-random MRR values across original OWASP v1.4 and
bespoke v1.3.1 remain informative within their own protocol definitions, but
they should not be interpreted as perfectly harmonized cross-dataset effect
sizes because v1.4 uses full-order reciprocal-rank semantics whereas v1.3.1
uses budget-censored MRR.

## Negative and Control Evidence

The original OWASP XSS v1.4 evaluation includes 30 negative-only ranking
scenarios. These are ranking-only packs: the ranker must return an ordering and
does not make a vulnerability/no-vulnerability decision or abstention. For
that reason, specificity and false-positive rate are not meaningful for the
OWASP XSS v1.4 negative-only ranking packs.

The OWASP XSS v1.4 candidate construction contains 152 unique non-vulnerable
candidates. These contribute 944 distractor placements in positive scenarios
and 150 placements in negative-only scenarios, for 1094 total non-vulnerable
placements. All 152 non-vulnerable candidates are used at least once.

Verifier-backed XSS control evidence is available from the v1.3.1 eight
negative/control scenarios. The deterministic arm contributes one retained
outcome per scenario, while GPT and Qwen contribute repeated trial-level
outcomes. No verifier-confirmed false positive occurred in any retained
outcome. The point estimate for specificity is therefore `1.0000` and FPR is
`0.0000`, but repeated trial rows must not be interpreted as additional
independent negative scenarios beyond the eight controls.

## SQLi v1.5.1 Evidence

The SQLi v1.5.1 evaluation does not reproduce the descriptive model-backed
ranking advantage seen in XSS. Ranking metrics over the frozen SQLi ranking
task are:

| Arm | Top-1 | Top-4 | MRR |
| --- | ---: | ---: | ---: |
| Deterministic structural | 0.1905 | 0.8667 | 0.4552 |
| GPT | 0.1897 | 0.7874 | 0.4447 |
| Qwen | 0.1442 | 0.7981 | 0.4274 |

The direct deterministic SQLi verifier/classification layer produced:

| Metric | Value |
| --- | ---: |
| TP | 84 |
| FP | 0 |
| FN | 21 |
| TN | 95 |
| Recall | 0.8000 |
| Specificity | 1.0000 |
| Precision | 1.0000 |
| Accuracy | 0.8950 |
| F1 | 0.8889 |
| Balanced accuracy | 0.9000 |

Runtime verifier states remain separate from post-run classification. The
direct SQLi layer produced 84 verified and 116 inconclusive runtime outcomes;
after post-run ground truth was applied, these mapped to TP 84, FP 0, FN 21
and TN 95 under the frozen scoring rules.

## Context-Enrichment v1.4.1 Evidence

The context-enrichment ablation compares minimal abstract candidate
representations against enriched representations that add deterministic benign
reflection observations. The six-arm positive-scenario results are:

| Arm | Top-1 | Top-2 | Top-4 | MRR |
| --- | ---: | ---: | ---: | ---: |
| det_minimal | 0.2119 | 0.4364 | 0.7797 | 0.4681 |
| det_enriched | 0.6356 | 0.8136 | 0.9576 | 0.7768 |
| gpt_minimal | 0.1814 | 0.3517 | 0.7525 | 0.4337 |
| gpt_enriched | 0.6042 | 0.8076 | 0.9771 | 0.7619 |
| qwen_minimal | 0.2308 | 0.4145 | 0.8590 | 0.4808 |
| qwen_enriched | 0.4110 | 0.6610 | 0.9237 | 0.6314 |

Within-family MRR deltas are:

| Family | Minimal MRR | Enriched MRR | Delta |
| --- | ---: | ---: | ---: |
| Deterministic | 0.4681 | 0.7768 | +0.3087 |
| GPT | 0.4337 | 0.7619 | +0.3282 |
| Qwen | 0.4808 | 0.6314 | +0.1506 |

The frozen primary paired MRR comparisons are:

| Comparison | Delta MRR | 95% CI | Holm p | Interpretation |
| --- | ---: | ---: | ---: | --- |
| GPT enriched vs GPT minimal | +0.3282 | [0.2834, 0.3739] | 0.0004 | Enrichment improves GPT |
| Qwen enriched vs Qwen minimal | +0.1531 | [0.1010, 0.2049] | 0.0004 | Enrichment improves Qwen |
| GPT enriched vs deterministic enriched | -0.0149 | [-0.0480, 0.0181] | 0.3825 | Not statistically distinguishable |
| Qwen enriched vs deterministic enriched | -0.1454 | [-0.1941, -0.0991] | 0.0004 | Qwen enriched lower |

This is the key proxy-risk interpretation. Enrichment substantially improves
ranking performance, but the improvement is not unique to LLMs. Deterministic
enrichment improves almost as much as GPT enrichment and more than Qwen
enrichment. GPT enriched is not statistically distinguishable from
deterministic enriched on primary MRR, while Qwen enriched is significantly
lower. Because enriched fields such as `reflection_detected`,
`reflection_count_category` and especially `marker_preservation_category` can
act as strong reflected-XSS susceptibility proxies, enrichment must not be
presented as evidence of independent LLM reasoning. It is strongest as
evidence that safe deterministic context can strongly improve prioritization.

## Reliability and Reproducibility

The hosted GPT arm is identified in the frozen artifacts as `gpt-5.6-luna`,
with prompt version `llm-candidate-ranking-v1` for XSS v1.3.1/v1.4/v1.4.1 and
the corrected SQLi prompt version in v1.5.1. GPT cost remains `not_available`
where no frozen numeric pricing basis exists, even when token usage is
recorded.

The local Qwen arm uses `Qwen/Qwen2.5-7B-Instruct-GGUF:Q4_K_M`, repository
revision `bb5d59e06d9551d752d08b292a50eb208b07ab1f`, local `llama.cpp`
`llama-completion.exe`, CPU backend, seed `42`, temperature `0.0`, top-p
`1.0`, context size `4096`, maximum output `768`, timeout `300` seconds and 8
threads. Local execution gives greater artifact and runtime control than a
hosted provider, but its observed latency is hardware-specific and must not be
treated as an inherent property of all local inference.

Failure and malformed outputs are retained as terminal observations rather
than silently retried or repaired. In v1.4, GPT had 1329/1330 contract-valid
rows and Qwen had 1325/1330 contract-valid rows. In v1.4.1, GPT enriched had
12 contract-invalid rows, Qwen minimal had 10 contract-invalid rows, and the
other four arms had no contract-invalid rows. In v1.5.1 SQLi, GPT had 617/620
valid rows with 3 provider-failed rows, and Qwen had 615/620 valid rows with 5
malformed rows. These reliability results should be reported separately from
ranking quality.

The evaluation history relies on protocol freezes, deterministic schedules,
provenance manifests and checksums. Some statistical planning was post-run
closure work rather than prospective preregistration; this should be reported
as a limitation even where the plan was frozen before the derived inferential
analysis was executed.

## Evidence-Backed Synthesis Claims

| Claim | Evidence | Strength | Allowed wording | Wording to avoid |
| --- | --- | --- | --- | --- |
| Bounded model-backed ranking can provide useful prioritization signal in some settings. | OWASP XSS v1.4 descriptive Qwen/GPT MRR above deterministic; bespoke v1.3.1 model-backed MRR above deterministic; Comment 5. | Supported with scope limitation | Model-backed ranking showed useful descriptive signal in evaluated XSS settings. | LLM ranking is generally superior. |
| The original deterministic v1.4 baseline is essentially at the analytic random reference. | Comment 1 random baseline: deterministic MRR 0.4573 vs random 0.4567. | Strongly supported for original OWASP XSS v1.4 | The original deterministic baseline was essentially at random on this OWASP candidate class. | The deterministic ranker is purely random. |
| Qwen has the strongest descriptive MRR among original v1.4 arms, but not statistical superiority. | Comment 2/3: Qwen MRR 0.4926; primary Qwen-deterministic delta +0.0355, CI crosses zero, p 0.659123. | Strongly supported | Qwen had the highest descriptive MRR, but the primary scenario-level comparison was not statistically supported. | Qwen significantly outperformed deterministic ranking. |
| Repeated LLM trials characterize variability rather than increasing scenario count. | Comment 2 stability audit; Comment 3 scenario-level unit. | Strongly supported | Trial rows are nested within scenarios and describe model variability/reliability. | Five trials make five independent benchmark cases. |
| SQLi does not reproduce the XSS descriptive model-backed advantage. | Comment 4 SQLi ranking metrics. | Supported with scope limitation | In the frozen SQLi ranking task, deterministic ranking had higher descriptive MRR than GPT and Qwen. | LLMs are worse for SQLi in general. |
| Context enrichment produces a strong representation effect. | Comment 6 v1.4.1 deltas for deterministic, GPT and Qwen. | Strongly supported | Deterministic benign context substantially improved ranking. | Enrichment proves LLM reasoning. |
| Deterministic baselines can become highly competitive when strong deterministic context signals are available. | Comment 6: deterministic enriched MRR 0.7768; GPT enriched not distinguishable; Qwen enriched lower. | Strongly supported for v1.4.1 | Strong deterministic context made the deterministic comparator highly competitive. | Deterministic ranking is always preferable. |
| Final vulnerability decisions remain deterministic/verifier-controlled. | Protocols and architecture; Comment 4 SQLi direct classification; v1.3.1 verifier-backed controls. | Strongly supported architecturally | Runtime verification and post-run classification are outside the LLM ranking authority. | The LLM verifies vulnerabilities. |
| Public OWASP evidence has possible training-data exposure risk. | Comment 5 contamination-risk analysis. | Supported as caveat | Possible exposure cannot be ruled out; this is not evidence of actual contamination. | The models were contaminated by OWASP. |
| Bespoke v1.3.1 provides lower-contamination-risk supporting evidence. | Comment 5 provenance and held-out design. | Supported with limitation | Bespoke scenarios are substantially lower contamination risk than public OWASP. | Bespoke contamination risk is mathematically zero. |

## Thesis Tables and Figures

Recommended main-body tables:

1. Evaluation overview table: dataset, vulnerability class, scenario count,
   arms, trial structure, evidence type.
2. Original OWASP XSS v1.4 ranking table with analytic random reference.
3. Comment 3 primary scenario-level inference table.
4. Bespoke v1.3.1 observed-versus-random summary.
5. SQLi v1.5.1 ranking and direct classification summary.
6. v1.4.1 minimal-versus-enriched MRR decomposition and primary comparisons.

Recommended main-body figures:

1. Architecture/authority-boundary figure from Chapter 3.
2. A compact evaluation-evidence map showing public OWASP XSS, bespoke XSS,
   context enrichment and SQLi.
3. Optional bar plot of MRR by arm and dataset, with explicit caution that the
   datasets have different random references, denominators and MRR semantics.

Recommended appendix tables:

- Full Comment 1 pre-tiebreak discrimination and candidate reuse tables.
- Full Comment 2 trial-stability tables.
- Full Comment 3 exploratory comparisons.
- Full Comment 4 negative/control details.
- Full Comment 5 scenario-specific random references.
- Full Comment 6 enriched-feature/proxy-risk inventory and reliability table.

## Chapter Mapping

Methodology:

- Use protocol freezes, frozen candidate snapshots, ground-truth separation,
  deterministic schedules, nested-trial handling and no-silent-retry semantics.
- Explain that post-run statistical closure analysis was derived after the
  original v1.4 run and should be framed transparently.

Implementation / Framework Architecture:

- Use the bounded authority model: deterministic discovery/control,
  restricted candidate ranking, deterministic safety/execution/evidence and
  deterministic verification/classification.
- Emphasize that model outputs are rankings of supplied candidate IDs, not
  payload generation or vulnerability verification.

Evaluation Setup:

- Present bespoke XSS v1.3.1, OWASP XSS v1.4, context enrichment v1.4.1 and
  SQLi v1.5.1 as separate evidence layers with distinct denominators and
  interpretation boundaries.

Results:

- Lead with descriptive ranking metrics and random references where relevant.
- Keep reliability, negative/control behavior and direct verifier/classification
  metrics separate from ranking metrics.

Discussion:

- Synthesize that model-backed ranking can be useful, but effects vary by
  model, representation, dataset and vulnerability category.
- Explain the context-enrichment result as a representation/proxy-risk finding,
  not proof of independent LLM reasoning.

Threats to Validity:

- Include public OWASP training-data exposure risk, small bespoke sample size,
  repeated-trial correlation, one missing Qwen positive scenario in v1.4,
  CPU-only local latency, proxy-risk in v1.4.1, ranking-only versus
  classification semantics, benchmark representativeness, limited vulnerability
  categories and post-run statistical planning.

Conclusion:

- State that the thesis supports bounded model-backed prioritization as an
  optional decision-support component under deterministic control, not as an
  autonomous security-testing authority.

## Supervisor Comment Closure Status

| Comment | Closure package | Status |
| --- | --- | --- |
| 1. Random baseline and deterministic discrimination | `results/owasp-xss-v14-random-baseline-audit/` | DONE |
| 2. Repeated-trial stability | `results/owasp-xss-v14-trial-stability-analysis/` | DONE |
| 3. Scenario-level inference | `results/owasp-xss-v14-scenario-statistical-analysis/` | DONE |
| 4. Negative/control evidence and SQLi | `results/professor-comment-4-negative-sqli-analysis/` | DONE |
| 5. OWASP contamination caveat and bespoke XSS | `results/professor-comment-5-bespoke-contamination-analysis/` | DONE |
| 6. Context enrichment and proxy-risk | `results/professor-comment-6-context-enrichment-analysis/` | DONE |

## Remaining Evidence Gaps

No new experiment is methodologically required for the current thesis claims if
the claims remain bounded to the completed evidence. The thesis should avoid
claiming general LLM superiority, autonomous penetration-testing capability,
statistical superiority for original v1.4 Qwen over deterministic ranking, or
independent LLM reasoning from enriched context.

A future restricted-context sensitivity analysis would be required only for the
narrower claim that LLMs independently reason better from non-proxy contextual
information. A future broader external-validation study would be required only
for stronger generalization across applications and vulnerability classes.
Those are useful future-work directions, not blockers for the current thesis
if the conclusions stay evidence-scoped.

## Recommended Thesis Writing Order

1. Finish Chapter 4 Results using the main-body tables above.
2. Write Chapter 4 Discussion immediately after Results, because many claims
   depend on the limitations and proxy-risk interpretation.
3. Write Chapter 4 Threats to Validity using the closure-package limitations.
4. Revisit Chapter 3 only to ensure the architecture text matches the final
   bounded-authority conclusions.
5. Write Chapter 5 Conclusion after the Results and Discussion language has
   stabilized.
