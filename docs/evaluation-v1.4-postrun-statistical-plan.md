# OWASP XSS v1.4 Post-Run Statistical Analysis Plan

Status: frozen post-run statistical analysis plan for Professor Comment 3.

This plan is frozen after the descriptive OWASP XSS v1.4 results, the
Professor Comment 1 random-baseline audit, and the Professor Comment 2
repeated-trial stability audit, but before the Professor Comment 3 inferential
tests are executed.

This is not a prospective preregistration and must not be represented as one.
It is a post-run analysis plan created to prevent additional methodological
choices from being made after inferential model-comparison results are
calculated.

This plan does not modify the original frozen v1.4 protocol, canonical v1.4
results, or later v1.4.1 artifacts.

## Scope

The scope is the original frozen OWASP Benchmark XSS v1.4 ranking evaluation:

- total scenarios: `266`;
- positive scenarios: `236`;
- negative-only scenarios: `30`;
- deterministic structural arm: one ranking per scenario;
- proprietary GPT arm: five repeated trials per scenario;
- local Qwen arm: five repeated trials per scenario.

The v1.4 evaluation is ranking-only. It must not be interpreted as
verifier-confirmed vulnerability-finding evidence.

## Input Artifacts

The analysis must use only the retained original v1.4 and derived Comment 2
scenario-level artifacts:

- protocol: `docs/evaluation-protocol-v1.4.md`;
- protocol package: `results/owasp-xss-v14-protocol-freeze/`;
- metric specification:
  `results/owasp-xss-v14-protocol-freeze/metric-scoring-specification.json`;
- canonical scored rows:
  `results/owasp-xss-v14-confirmatory-final/canonical/normalized/scored-rows.json`;
- canonical ranking aggregates:
  `results/owasp-xss-v14-confirmatory-final/canonical/normalized/ranking-aggregates.json`;
- canonical reliability aggregates:
  `results/owasp-xss-v14-confirmatory-final/canonical/normalized/reliability-aggregates.json`;
- canonical checksum file:
  `results/owasp-xss-v14-confirmatory-final/canonical/checksums.sha256`;
- source raw-run checksum file:
  `results/owasp-xss-v14-confirmatory-final/owasp-xss-v14-confirmatory-20260821T235804Z/checksums.sha256`;
- Comment 2 scenario-level stability data:
  `results/owasp-xss-v14-trial-stability-analysis/scenario-level-stability.csv`;
- Comment 2 scenario-level mean reciprocal-rank data:
  `results/owasp-xss-v14-trial-stability-analysis/scenario-mean-rr.csv`;
- Comment 2 source-integrity report:
  `results/owasp-xss-v14-trial-stability-analysis/source-integrity-report.json`.

The future statistical analysis must fail closed if required inputs are
missing, source checksums fail, or scenario denominators do not match this
plan.

## Experimental Unit and Repeated Trials

The independent experimental unit is the positive scenario.

The original positive-scenario population is `236`. GPT and Qwen trial rows are
repeated measurements nested within scenario and arm. Trial rows must never be
treated as independent observations.

For LLM ranking performance, valid repeated trials must be aggregated within
scenario before inferential comparison. Scenarios must not be weighted by the
number of valid repeated trials.

## Primary Metric

The primary metric is scenario-level mean reciprocal rank.

For deterministic ranking, each positive scenario has one reciprocal-rank
value. For GPT and Qwen, the scenario-level value is the mean reciprocal rank
over the valid frozen trials belonging to that scenario.

This intentionally differs slightly from trial-row-weighted aggregate MRR when
validity counts differ across scenarios. For GPT, the original
trial-row-weighted MRR is `0.4732`, while the Comment 2 mean of per-scenario
mean RR is `0.4733`, because one positive GPT scenario has only four valid
trials.

## Primary Comparison and Hypothesis

There is one primary comparison:

`local_qwen` versus `deterministic_structural`

Rationale: Qwen is the preselected local open-weights model-backed ranking arm
and the reproducible local comparator for the thesis architecture. This
primary comparison is selected because of Qwen's experimental role and the
reproducibility objective, not because of its observed descriptive effect size.

Primary substantive hypothesis:

Model-backed ranking using the preselected local Qwen arm changes
scenario-level ranking effectiveness relative to the original deterministic
structural baseline, with the substantive research expectation that Qwen
prioritizes vulnerable candidates more effectively.

The inferential test is two-sided. If the primary result is not statistically
supported, thesis wording must remain limited to a consistent descriptive trend
or equivalent wording, rather than claiming Qwen superiority. If it is
supported, wording must still be limited to the frozen OWASP XSS v1.4 scenario
class.

## Primary Paired Denominator

The Qwen-versus-deterministic primary analysis uses the `235` positive
scenarios with valid Qwen scenario-level mean RR.

The omitted Qwen paired scenario has five malformed terminal Qwen outputs and
no valid Qwen ranking. It must not be imputed, repaired, retried, or silently
excluded from reliability reporting.

Deterministic rows are available for all `236` positive scenarios. The primary
paired denominator is nevertheless `235`, because paired analysis requires both
Qwen and deterministic scenario-level reciprocal-rank values.

## Primary Inferential Test

The primary inferential test is:

- paired;
- scenario-level;
- two-sided Wilcoxon signed-rank test;
- alpha `0.05`;
- paired n reported explicitly;
- zero differences and ties documented explicitly;
- Pratt zero handling used where supported by the selected statistical
  implementation.

The intended implementation is Python with SciPy's `scipy.stats.wilcoxon`,
using:

- `alternative="two-sided"`;
- `zero_method="pratt"`;
- `method="auto"` or the closest documented SciPy equivalent available in the
  repository environment.

If exact Wilcoxon calculation is not available because of ties or zero
differences, the analysis must use the library's documented asymptotic
implementation and record that fact. It must not silently substitute another
test.

## Primary Effect Estimate

The primary effect estimate is:

`mean(Qwen scenario-level RR - deterministic scenario RR)`

The future analysis must also report:

- mean paired difference;
- median paired difference;
- 95% paired bootstrap confidence interval for the mean paired difference;
- Wilcoxon statistic and raw p-value;
- matched-pairs rank-biserial correlation.

The matched-pairs rank-biserial correlation should be calculated from signed
ranks for paired differences using the same zero-handling convention documented
for the Wilcoxon implementation. The exact formula used must be recorded in
the output package.

## Bootstrap Confidence Interval

The bootstrap procedure is:

- resampling unit: paired positive scenario;
- resamples: `20000`;
- random seed: `20260827`;
- confidence interval: percentile 95% CI for the mean paired difference.

The bootstrap must resample paired scenarios, not trial rows.

## Secondary and Exploratory Comparisons

The following MRR comparisons are non-primary:

- `local_qwen` versus `proprietary_gpt`;
- `proprietary_gpt` versus `deterministic_structural`.

They use the same scenario-level paired Wilcoxon methodology and paired
bootstrap effect estimates. They are secondary/exploratory comparisons, not
additional primary hypotheses.

Pairing denominators are:

- GPT versus deterministic: `236` positive scenarios;
- Qwen versus GPT: `235` positive scenarios with valid Qwen and GPT
  scenario-level mean RR.

## Exploratory Threshold Outcomes

Top-1, Top-2, and Top-4 are exploratory ranking outcomes.

For GPT and Qwen, each positive scenario value is the proportion of valid
repeated trials in which the vulnerable candidate meets the threshold. For the
deterministic arm, each positive scenario value is binary `0` or `1`.

If inferential tests are performed for these exploratory metrics, they must use
paired scenario-level values only. Individual trial threshold outcomes must not
be treated as independent observations.

Unless a more appropriate paired procedure is explicitly justified before
execution, exploratory threshold comparisons use the same paired
scenario-level Wilcoxon procedure and paired bootstrap effect estimates as the
MRR comparisons.

## Multiplicity Correction

There is exactly one unadjusted primary hypothesis test:

`local_qwen` versus `deterministic_structural` on scenario-level mean RR.

Multiplicity correction must not be used to alter or reclassify the primary
test.

All other inferential model comparisons belong to one exploratory family:

- two additional MRR comparisons;
- three model-pair comparisons for Top-1;
- three model-pair comparisons for Top-2;
- three model-pair comparisons for Top-4.

Expected exploratory family size: `11` tests.

Holm correction must be applied across the full exploratory family of `11` raw
p-values. Future output must report both raw and Holm-adjusted p-values for
the exploratory family.

## Missing, Invalid, and Failure Handling

Frozen v1.4 failure handling applies.

Invalid structured outputs, malformed outputs, provider failures, runtime
failures and timeouts remain visible in reliability reporting. They are
excluded from valid ranking-performance values and must not be silently
repaired, retried, imputed, or replaced.

Known structure from the completed Comment 2 stability audit:

- GPT provides scenario-level mean RR for all `236` positive scenarios,
  although one scenario is based on four valid trials;
- Qwen provides valid scenario-level mean RR for `235/236` positive scenarios;
- one Qwen positive scenario has five malformed terminal outputs and no valid
  ranking.

The future analysis must report these denominators explicitly and must not
silently change denominators between tables.

## Random Reference

Professor Comment 1 established the analytic random-ranking reference for the
original v1.4 scenario structure. The random reference may be shown
descriptively beside the statistical model comparison, but no unplanned
random-baseline inferential hypothesis test is part of Professor Comment 3.

## Validation Rules

The future statistical analysis must fail closed unless all of the following
conditions hold:

- canonical v1.4 and raw-run checksums validate;
- Comment 2 stability package checksums validate;
- exactly `236` positive scenarios and `30` negative-only scenarios are
  present;
- deterministic scenario-level RR exists for all `236` positive scenarios;
- GPT scenario-level mean RR exists for all `236` positive scenarios;
- Qwen scenario-level mean RR exists for exactly `235` positive scenarios;
- the missing Qwen scenario is represented as five malformed terminal outputs;
- primary Qwen-versus-deterministic paired n is exactly `235`;
- GPT-versus-deterministic paired n is exactly `236`;
- Qwen-versus-GPT paired n is exactly `235`;
- repeated LLM trials are aggregated within scenario before comparison;
- no trial rows are treated as independent observations;
- invalid/failure terminal rows remain represented in reliability outputs;
- no new experimental/model/HTTP/browser/discovery/verifier/scored calls are
  performed by the statistical analysis.

## Expected Future Outputs

The future Professor Comment 3 analysis package should include:

- machine-readable statistical input table at scenario level;
- paired-comparison results for the primary MRR comparison;
- exploratory MRR and Top-1/Top-2/Top-4 comparison table;
- bootstrap confidence interval data and seed/procedure metadata;
- Wilcoxon implementation metadata;
- reliability and denominator note;
- random-reference descriptive context;
- thesis-ready Markdown and LaTeX tables;
- validation report;
- checksums;
- concise human-readable analysis report.

## Interpretation Rules

Statistical significance is not equivalent to practical importance. Effect
estimates and confidence intervals must accompany p-values.

Failure to reject the null must not be described as proof that arms are
equivalent.

Descriptive Top-k or MRR differences alone must not be called statistically
supported superiority.

Qwen's five repeated trials do not create `n = 1175`. GPT's repeated-trial
variability does not create `n = 1179`. The primary analysis remains paired at
scenario level.

No broad claim of general LLM superiority, general Qwen superiority, or general
scanner/framework superiority may be drawn from this plan or its future
analysis.
