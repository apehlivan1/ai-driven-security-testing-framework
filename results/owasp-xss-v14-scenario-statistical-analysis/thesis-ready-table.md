# Thesis-Ready Tables: v1.4 Scenario-Level Inference

## Primary MRR Comparison

| Comparison | n | Arm A mean | Arm B mean | Mean diff | Median diff | 95% bootstrap CI | W | raw p | rank-biserial |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen - Deterministic MRR | 235 | 0.4926 | 0.4571 | +0.0355 | +0.0000 | [-0.0207, +0.0922] | 12665.5000 | 0.659123 | +0.0348 |


## Exploratory Comparisons

| Comparison | n | Arm A mean | Arm B mean | Mean diff | Median diff | 95% bootstrap CI | W | raw p | rank-biserial | Holm p | Holm < 0.05 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen - GPT MRR | 235 | 0.4926 | 0.4742 | +0.0183 | +0.0000 | [-0.0292, +0.0660] | 13082.0000 | 0.851072 | +0.0147 | 1 | False |
| GPT - Deterministic MRR | 236 | 0.4733 | 0.4573 | +0.0160 | +0.0000 | [-0.0323, +0.0638] | 12717.5000 | 0.547765 | +0.0471 | 1 | False |
| GPT - Deterministic TOP1 | 236 | 0.2333 | 0.2034 | +0.0299 | +0.0000 | [-0.0396, +0.0975] | 7969.5000 | 0.100787 | +0.1635 | 1 | False |
| Qwen - Deterministic TOP1 | 235 | 0.2468 | 0.2043 | +0.0426 | +0.0000 | [-0.0340, +0.1191] | 7620.0000 | 0.291841 | +0.1111 | 1 | False |
| Qwen - GPT TOP1 | 235 | 0.2468 | 0.2343 | +0.0126 | +0.0000 | [-0.0523, +0.0774] | 9038.5000 | 0.856999 | -0.0183 | 1 | False |
| GPT - Deterministic TOP2 | 236 | 0.4108 | 0.4153 | -0.0044 | +0.0000 | [-0.0831, +0.0733] | 11756.0000 | 0.8951 | -0.0113 | 1 | False |
| Qwen - Deterministic TOP2 | 235 | 0.4468 | 0.4128 | +0.0340 | +0.0000 | [-0.0553, +0.1234] | 9585.0000 | 0.457614 | +0.0690 | 1 | False |
| Qwen - GPT TOP2 | 235 | 0.4468 | 0.4126 | +0.0343 | +0.0000 | [-0.0413, +0.1113] | 10894.0000 | 0.435673 | +0.0673 | 1 | False |
| GPT - Deterministic TOP4 | 236 | 0.7814 | 0.7881 | -0.0068 | +0.0000 | [-0.0508, +0.0381] | 4904.0000 | 0.388346 | -0.1188 | 1 | False |
| Qwen - Deterministic TOP4 | 235 | 0.8298 | 0.7872 | +0.0426 | +0.0000 | [-0.0298, +0.1149] | 6352.0000 | 0.245042 | +0.1351 | 1 | False |
| Qwen - GPT TOP4 | 235 | 0.8298 | 0.7813 | +0.0485 | +0.0000 | [-0.0136, +0.1115] | 5710.0000 | 0.0202887 | +0.2625 | 0.223176 | False |


Holm correction was applied to exactly 11 exploratory tests. The primary Qwen-vs-deterministic MRR test is reported unadjusted according to the frozen plan.
