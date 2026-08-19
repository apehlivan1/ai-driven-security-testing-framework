# Section 2.2 Literature Matrix: LLM-Assisted Security Testing

Source set: all PDF files currently stored in `thesis/literature/section-2.2/`.

Scope note: this matrix analyzes only the supplied PDFs. It does not use external bibliographic lookup, final thesis results, or unsupplied literature. Page references refer to the page markers/extracted page order of the supplied PDFs. When a paper cites another work for an important point, the claim is treated as a secondary citation unless the analyzed paper itself provides the evidence.

Status key for LLM authority:

- YES: the paper explicitly gives the LLM this responsibility.
- PARTIAL: the paper gives the LLM some influence over the responsibility, but not complete or direct authority.
- NO: the paper explicitly keeps this responsibility outside the LLM component.
- NOT REPORTED: the supplied paper does not provide enough information to classify the responsibility.
- N/A: the responsibility is outside the paper's technical scope.

Theme key:

- A. LLM-assisted penetration testing and offensive security
- B. Web-application security testing with LLMs
- C. LLM agents with tool/browser/terminal authority
- D. LLM-assisted attack-surface discovery, crawling, or task execution
- E. Candidate, task, or test prioritization
- F. Payload generation or exploit construction
- G. Evidence interpretation and vulnerability verification
- H. Benchmarking and evaluation methodology for LLM security systems
- I. Reliability, nondeterminism, cost, and reproducibility
- J. Safety, isolation, and authority boundaries

## Paper Matrix

### 1. Deng et al. - PentestGPT

- Citation key suggestion: `deng2024pentestgpt`
- Full title: PENTESTGPT: Evaluating and Harnessing Large Language Models for Automated Penetration Testing
- Authors: Gelei Deng, Yi Liu, Victor Mayoral-Vilches, Peng Liu, Yuekang Li, Yuan Xu, Tianwei Zhang, Yang Liu, Martin Pinzger, Stefan Rass
- Year: 2024
- Venue: 33rd USENIX Security Symposium
- DOI: not explicitly present in the supplied paper
- Type of study: benchmark construction, exploratory LLM evaluation, and proposed LLM-assisted penetration-testing system
- Classification: CORE
- Themes: A, C, F, G, H, I

Research problem addressed:

The paper investigates whether large language models can perform or assist with penetration-testing tasks. It frames penetration testing as difficult to automate because it requires expert reasoning, tool use, interpretation of results, and multi-step state management.

Methodology:

The authors construct a benchmark from HackTheBox and VulnHub targets and decompose penetration-testing tasks into subtasks. They evaluate GPT-3.5, GPT-4, and Bard through an interactive loop where LLM outputs are executed in a controlled environment and results are fed back to the LLM. They then introduce PentestGPT, with reasoning, generation, and parsing modules, to manage context and task decomposition.

Tools/scanners/benchmarks evaluated:

HackTheBox, VulnHub, official walkthroughs/certified penetration-tester baselines, and LLMs including GPT-3.5, GPT-4, and Bard. The system discusses use of penetration-testing tools through LLM-generated commands and instructions.

Vulnerability classes relevant to this thesis:

The benchmark is broad and includes vulnerabilities mapped to OWASP Top 10 and CWE categories. For this thesis, it is relevant mainly as a broad LLM-assisted penetration-testing precedent rather than as a focused XSS/IDOR/SQLi candidate-ranking study.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | PARTIAL | LLMs are evaluated on penetration-testing subtasks, including enumeration and identifying injection points; task decomposition is described in Sections 3-4, pp. 4-7. |
| Candidate or task prioritization | PARTIAL | The reasoning module maintains a penetration-testing task tree and steers subsequent actions, but the paper does not isolate ranking of already discovered structured candidates as a separate contract; overview and Figure 2, pp. 8-10. |
| Payload/test generation | YES | The generation module translates subtasks into concrete commands or GUI-operation descriptions; Section 5.4, p. 10. |
| Execution of tools/actions | PARTIAL | In the evaluation, human experts execute LLM directives while strictly following the LLM's instructions; testing strategy, pp. 5-6. PentestGPT itself still depends on a user/testing environment loop. |
| Evidence interpretation | YES | The parsing module condenses tool outputs, source code, and HTTP pages for use by the LLM; overview and system design, pp. 3, 8-10. |
| Vulnerability verification / finding decision | PARTIAL | The paper has LLM-side verification of task-tree updates and evaluation against completed subtasks, but final correctness is assessed against benchmark/walkthrough outcomes; Figure 2 and Section 5, pp. 9-10. |
| Ground-truth access during testing | NOT REPORTED | The paper compares outputs to walkthroughs/baselines during evaluation, but the supplied text does not establish that ground truth is available to the LLM during testing; Sections 3-4, pp. 4-7. |

Degree of autonomy:

Semi-autonomous / human-in-the-loop. The LLM proposes penetration-testing actions and reasons over feedback; human experts execute the suggested operations during evaluation.

Models/runtime:

GPT-3.5, GPT-4, and Bard are evaluated. The paper discusses token-window limits and OpenAI API cost in the experiments (pp. 6-7, p. 14).

Experimental methodology:

The paper uses a decomposed penetration-testing benchmark, compares subtask completion against official walkthrough/certified-tester baselines, and reports cost for OpenAI API usage. It includes ablation-style comparisons for PentestGPT modules.

Main findings relevant to this thesis:

- LLMs can assist with specific penetration-testing subtasks such as tool use, output interpretation, and proposing next actions, while struggling with complete end-to-end testing; abstract and introduction, pp. 2-4.
- Context loss is identified as a major failure reason, motivating structured task-state management; failure analysis, p. 7.
- The paper demonstrates that LLM-assisted penetration testing needs evaluation at subtask level rather than only whole-target success/failure; benchmark design and evaluation, pp. 4-7.

Limitations acknowledged by the authors:

- The paper identifies loss of session context as the primary cause of many trial failures (Table 4 discussion, p. 7).
- The design is motivated by weaknesses in direct LLM use, including context limits and task-management difficulties (Sections 4-5, pp. 7-10).

Matrix interpretation:

This paper is highly relevant as background for LLM-assisted penetration testing, but it differs from this thesis because it gives the LLM broad planning, command-generation, and output-interpretation roles. It does not present a bounded architecture where the LLM only ranks already discovered candidates and deterministic components decide execution and verification.

Specific claims useful to cite:

- Claim stated by paper: penetration testing has resisted automation due to the expertise required from human professionals. Location: Abstract/Introduction, p. 2.
- Claim stated by paper: LLMs show strengths on penetration-testing subtasks but struggle with completing full penetration-testing processes. Location: Abstract/Introduction, pp. 2-3.
- Claim stated by paper: context loss is a major failure cause in LLM penetration-testing trials. Location: failure analysis, p. 7.
- Claim stated by paper: PentestGPT separates reasoning, generation, and parsing modules to manage penetration-testing context. Location: Figure 2 and Sections 5.3-5.5, pp. 9-10.

Notes for use:

Use as a core precedent for LLM-assisted penetration testing and for motivating why broad LLM authority creates context-management and evaluation challenges. Avoid citing it as evidence for the exact bounded candidate-ranking design of this thesis.

---

### 2. Fang et al. - LLM Agents can Autonomously Hack Websites

- Citation key suggestion: `fang2024llmagents`
- Full title: LLM Agents can Autonomously Hack Websites
- Authors: Richard Fang, Rohan Bindu, Akul Gupta, Qiusi Zhan, Dainel Kang
- Year: 2024
- Venue: not explicitly shown in the supplied PDF
- DOI: not explicitly present in the supplied paper
- Type of study: empirical evaluation of autonomous LLM agents on sandboxed web-hacking tasks
- Classification: CORE
- Themes: A, B, C, F, H, I, J

Research problem addressed:

The paper examines the offensive cybersecurity capabilities of LLM agents that can use tools, read documents, and operate autonomously against web applications.

Methodology:

The authors construct or curate sandboxed websites with different vulnerabilities, give agents browser/function-calling/document access, and evaluate whether the agents achieve defined goals within an execution budget. They compare models and agent components, including tool use and document access.

Tools/scanners/benchmarks evaluated:

LLM agents implemented with the OpenAI Assistants API and LangChain; browser-manipulation tools; document retrieval; a sandboxed website benchmark with multiple vulnerability types.

Vulnerability classes relevant to this thesis:

XSS and SQL injection appear directly in the benchmark. The paper also includes CSRF, authorization bypass, SSRF, file upload, and other web vulnerabilities.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | YES | The agent is asked to hack websites without being told the vulnerability beforehand; abstract and introduction, p. 1. |
| Candidate or task prioritization | YES | The agent plans and selects strategies during autonomous operation, but the paper does not isolate candidate ranking as a restricted output; agent setup and prompting, p. 3. |
| Payload/test generation | YES | The vulnerability list includes attacks requiring SQL injection, XSS, and complex multi-step payload/strategy construction; Table 1 area, p. 4. |
| Execution of tools/actions | YES | The agent can call functions to manipulate a web browser and retrieve results; agent capabilities, pp. 1 and 3. |
| Evidence interpretation | YES | The agent observes responses/history and uses them to continue the task; Figure 1 and agent setup, pp. 1 and 3. |
| Vulnerability verification / finding decision | PARTIAL | Success is evaluated by goal achievement within a time limit rather than by a separate deterministic verifier; metrics description, p. 3. |
| Ground-truth access during testing | NO / PARTIAL | The agent is not told the specific vulnerability, but it is given the goal "Hack this website"; abstract and setup, pp. 1 and 3. Ground-truth labels are used for evaluation, not reported as provided to the agent. |

Degree of autonomy:

High. The paper explicitly evaluates autonomous web-hacking agents with browser/tool access and no human feedback for tasks such as blind database-schema extraction.

Models/runtime:

The paper reports GPT-4 as the capable model and states that tested open-source models did not succeed in the same way (abstract/introduction, pp. 1-2). It uses OpenAI Assistants API and LangChain for tool execution (p. 3).

Experimental methodology:

Agents are evaluated on a set of sandboxed websites. Success is determined by achieving a task goal within a time budget. The paper reports pass@5-style success and cost analysis.

Main findings relevant to this thesis:

- Frontier LLM agents can autonomously exploit sandboxed web vulnerabilities under broad tool authority; abstract/introduction, p. 1.
- GPT-4 with documents, tool use, and the assistant API performs substantially better than less capable/open-source models in the reported setup; pp. 1, 4-5.
- The paper explicitly raises responsible-disclosure and safety concerns and confines experiments to sandboxed websites; impact statement, p. 9.

Limitations acknowledged by the authors:

- The paper reports remaining failures on harder tasks and identifies difficult vulnerability classes where GPT-4 still fails; results discussion, p. 4.
- Safety risks are acknowledged in the impact statement, including potential misuse if methods were applied to real websites; p. 9.

Matrix interpretation:

This paper is essential related work because it demonstrates the opposite end of the authority spectrum: an LLM agent with broad autonomy over exploration, execution, and exploitation. It helps motivate why this thesis investigates a narrower role for LLMs, but it is not substantially similar to the thesis framework because it does not keep execution and verification deterministic.

Specific claims useful to cite:

- Claim stated by paper: LLM agents can autonomously hack sandboxed websites without being told the vulnerability beforehand. Location: abstract/introduction, p. 1.
- Claim stated by paper: the agent is equipped with browser manipulation, document reading, function calling, and action history. Location: Figure 1 and setup discussion, pp. 1 and 3.
- Claim stated by paper: sandboxed evaluation was used to avoid impact on real-world systems. Location: impact statement, p. 9.
- Claim stated by paper: broad autonomous capability raises security and deployment questions. Location: abstract/introduction and impact statement, pp. 1 and 9.

Notes for use:

Use as a core contrast source. It supports the need to discuss LLM authority, safety, and autonomy, but it should not be cited as evidence for bounded ranking-only LLM design.

---

### 3. Isozaki et al. - Towards Automated Penetration Testing

- Citation key suggestion: `isozaki2025automated`
- Full title: Towards Automated Penetration Testing: Introducing LLM Benchmark, Analysis, and Improvements
- Authors: Isamu Isozaki, Manil Shrestha, Rick Console, Edward Kim
- Year: 2025
- Venue: Adjunct Proceedings of the 33rd ACM Conference on User Modeling, Adaptation and Personalization (UMAP Adjunct '25)
- DOI: `10.1145/3708319.3733804`
- Type of study: benchmark paper, LLM penetration-testing evaluation, and PentestGPT improvement/ablation study
- Classification: CORE
- Themes: A, C, H, I

Research problem addressed:

The paper argues that LLM-based penetration testing lacks comprehensive open end-to-end benchmarks and evaluates how current LLMs perform with PentestGPT-style assistance.

Methodology:

The authors introduce an open penetration-testing benchmark based on VulnHub boxes, evaluate GPT-4o and Llama 3.1-405B using a modified PentestGPT, and conduct ablations intended to improve tool performance.

Tools/scanners/benchmarks evaluated:

PentestGPT, GPT-4o, Llama 3.1-405B, VulnHub machines, and a benchmark released by the authors.

Vulnerability classes relevant to this thesis:

The benchmark is broader than web application testing and includes reconnaissance, exploitation, and privilege escalation categories. It is relevant to this thesis mainly for LLM security evaluation methodology and the role of human assistance.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | PARTIAL | The benchmark includes reconnaissance and enumeration tasks; benchmark task categories are described around Table 1, pp. 3-4. |
| Candidate or task prioritization | PARTIAL | PentestGPT-style task planning is evaluated, but ranking of existing structured web candidates is not isolated; introduction and ablation discussion, pp. 1-5. |
| Payload/test generation | YES | The evaluated tool provides commands and task guidance for penetration testing; prompt appendix shows generation-session prompts, pp. 15-16. |
| Execution of tools/actions | PARTIAL | The paper discusses minimal human assistance and human execution of LLM-suggested actions in the benchmarking process; pp. 1-2 and p. 10. |
| Evidence interpretation | YES | The tool consumes command results and updates penetration-testing state in the PentestGPT workflow; prompt/appendix and methodology, pp. 10, 15-16. |
| Vulnerability verification / finding decision | PARTIAL | Task success is evaluated through benchmark completion/outcomes, not by a separate deterministic verifier; evaluation sections, pp. 3-5, 10. |
| Ground-truth access during testing | NOT REPORTED | The benchmark has task outcomes, but the supplied text does not report ground truth being exposed to the LLM during execution. |

Degree of autonomy:

Semi-autonomous. The paper explicitly notes that the evaluated models fall short of end-to-end penetration testing even with minimal human assistance.

Models/runtime:

GPT-4o and Llama 3.1-405B. Modified PentestGPT implementation.

Experimental methodology:

Open benchmark, model comparison, ablations, and task-category analysis. The paper emphasizes end-to-end penetration testing and human assistance.

Main findings relevant to this thesis:

- The paper supports treating LLM security evaluation as benchmark-driven and highlights the absence of comprehensive open end-to-end penetration-testing benchmarks; abstract/introduction, pp. 1-2.
- It reports that evaluated LLMs still fall short of full end-to-end penetration testing even with some human assistance; abstract/introduction, p. 1.
- It discusses transparency and bias concerns in benchmark processes involving human operators; related work/introduction, p. 2.

Limitations acknowledged by the authors:

- The paper discusses that full auto-penetration testing may not be practical or desirable in all cases and that human involvement remains relevant; p. 2.
- It notes computation limitations preventing use of constrained generation in one ablation; p. 5.

Matrix interpretation:

This is a useful methodology and benchmark source, especially for distinguishing human-assisted, end-to-end penetration testing from the narrower LLM role in this thesis. It is not directly about bounded candidate ranking in black-box web application testing.

Specific claims useful to cite:

- Claim stated by paper: there is a need for open benchmarks for LLM-based penetration testing. Location: abstract/introduction, p. 1.
- Claim stated by paper: GPT-4o and Llama 3.1-405B fall short of end-to-end penetration testing even with minimal human assistance in the authors' benchmark. Location: abstract/introduction, p. 1.
- Claim stated by paper: human assistance introduces questions about transparency and bias in benchmarking. Location: p. 2.
- Claim stated by paper: the benchmark categorizes penetration-testing tasks into reconnaissance, general techniques, exploitation, and privilege escalation. Location: Table 1 area, pp. 3-4.

Notes for use:

Use to justify careful benchmark design, predeclared protocols, and limited claims. Do not use it as direct evidence for web-form candidate ranking.

---

### 4. Jaswal and Baghel - AWE

- Citation key suggestion: `jaswal2026awe`
- Full title: AWE: Adaptive Agents for Dynamic Web Penetration Testing
- Authors: Akshat Singh Jaswal, Ashish Baghel
- Year: 2026
- Venue: Workshop on LLM Assisted Security and Trust Exploration (LAST-X) 2026
- DOI: `10.14722/last-x.2026.23037`
- Type of study: proposed multi-agent autonomous web-penetration-testing framework with benchmark evaluation
- Classification: CORE
- Themes: A, B, C, D, F, G, H, I

Research problem addressed:

The paper argues that pattern-driven scanners lack adaptability and that unconstrained LLM-based penetration testers can be costly, unstable, and difficult to reproduce. It proposes an adaptive multi-agent framework for dynamic web penetration testing.

Methodology:

The authors design AWE as a memory-augmented multi-agent system with specialized vulnerability pipelines and evaluate it on XBOW and DVWA-style controlled tests. They compare against MAPTA and report success, cost, token, latency, and payload-attempt data.

Tools/scanners/benchmarks evaluated:

AWE, MAPTA, XBOW Validation Benchmarks, DVWA, and comparisons across Claude Sonnet 4, GPT-4o, and Gemini 2.0 Flash within the AWE orchestration layer.

Vulnerability classes relevant to this thesis:

XSS, blind SQL injection, SQL injection, SSRF, SSTI, XXE, and command injection appear in the reported evaluation. XSS and SQLi are directly relevant.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | PARTIAL | AWE includes endpoint discovery/reconnaissance as a foundation service; architecture discussion, p. 3. |
| Candidate or task prioritization | YES | The orchestration layer converts reconnaissance output into a prioritized execution plan and selects agents; architecture discussion, p. 4. |
| Payload/test generation | YES | The LLM is described as a flexible generator of candidate attack inputs, and AWE uses context-aware payload mutations/generation; pp. 1-2. |
| Execution of tools/actions | YES | Specialized agents execute targeted exploitation strategies under orchestration and budgets; pp. 3-4. |
| Evidence interpretation | YES | The system uses server responses, timing behavior, reflection positions, sanitization behavior, and memory to guide exploitation; pp. 1-4. |
| Vulnerability verification / finding decision | PARTIAL | The paper uses browser-backed verification and specialized pipelines; however, it does not present the thesis-style restriction where a separate deterministic verifier alone decides findings; pp. 1, 3-4. |
| Ground-truth access during testing | NOT REPORTED | Benchmarks contain hidden flags or controlled vulnerable cases, but the supplied text does not report ground truth being exposed to the LLM during execution; evaluation discussion, pp. 5-7. |

Degree of autonomy:

High. AWE is presented as an autonomous web penetration-testing framework with multi-agent orchestration and specialized agents.

Models/runtime:

Claude Sonnet 4, GPT-4o, and Gemini 2.0 Flash are reported in model-selection/evaluation sections. MAPTA is referenced as using GPT-5 in the paper's comparison.

Experimental methodology:

Evaluation on XBOW's 104-challenge benchmark and controlled DVWA experiments. The paper reports category-wise success, cost reduction, token use, speed, and payload-attempt distributions.

Main findings relevant to this thesis:

- The paper supports the argument that LLM security systems can benefit from structured architecture rather than unconstrained general-purpose reasoning; abstract and discussion, pp. 1, 8.
- It provides a related example of specialized pipelines combined with LLM orchestration for web vulnerabilities; system design, pp. 3-4.
- It reports reliability/efficiency trade-offs including tokens, cost, and time-bounded evaluation; pp. 1-2, 5-8.

Limitations acknowledged by the authors:

- AWE is limited for multi-step planning, chained vulnerabilities, and classes outside its specialized-agent design; failure modes and discussion, pp. 7-8.
- The paper acknowledges reliance on heuristic abstractions and model-dependent reasoning variability; discussion, p. 8.

Matrix interpretation:

AWE is relevant because it also restricts some general-purpose LLM behavior using structure, budgets, and specialized pipelines. It remains substantially different from this thesis because the LLM has broader authority over prioritization, payload/input generation, and autonomous exploitation.

Specific claims useful to cite:

- Claim stated by paper: pattern-driven scanners and unconstrained LLM-based penetration testers have different limitations, including cost, instability, and reproducibility concerns. Location: abstract/introduction, p. 1.
- Claim stated by paper: AWE uses specialized vulnerability-specific pipelines and memory-augmented orchestration. Location: abstract/system design, pp. 1, 3-4.
- Claim stated by paper: AWE's limitations include multi-step planning limits, heuristic abstraction assumptions, and model sensitivity. Location: discussion, p. 8.
- Claim stated by paper: time-bounded and cost-bounded evaluation are used to reflect operational constraints. Location: scope/background, p. 2.

Notes for use:

Use as a recent related-work contrast for structured LLM-based web penetration testing. Be careful not to treat its payload-generation architecture as equivalent to the thesis's ranking-only LLM boundary.

---

### 5. Liu et al. - ChatGPT and Vulnerability Management

- Citation key suggestion: `liu2024chatgptvulnerability`
- Full title: Exploring ChatGPT's Capabilities on Vulnerability Management
- Authors: Peiyu Liu, Junming Liu, Lirong Fu, Kangjie Lu, Yifan Xia, Xuhong Zhang, Wenzhi Chen, Haiqin Weng, Shouling Ji, Wenhai Wang
- Year: 2024
- Venue: 33rd USENIX Security Symposium
- DOI: not explicitly present in the supplied paper
- Type of study: large-scale empirical evaluation of ChatGPT on vulnerability-management tasks
- Classification: SUPPORTING
- Themes: A, H, I

Research problem addressed:

The paper asks whether ChatGPT can assist maintainers across vulnerability-management tasks such as summarization, security bug report identification, severity evaluation, repair assessment, and patch classification.

Methodology:

The authors evaluate ChatGPT on six vulnerability-management tasks using a large dataset, compare results to state-of-the-art task-specific approaches, and study prompt engineering effects. They use GPT-4-0314 for large-scale tests with temperature set to zero and top_p set to 1.0 to improve determinism.

Tools/scanners/benchmarks evaluated:

ChatGPT, task-specific SOTA baselines, and datasets for six vulnerability-management tasks. The study is not a web-application scanner or DAST benchmark.

Vulnerability classes relevant to this thesis:

The paper is broader than web application testing. It is relevant to vulnerability management and LLM reliability, not to XSS/IDOR/SQLi execution.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | N/A | The study evaluates vulnerability-management tasks, not web-app discovery; Figure 1 and Section 2.1, pp. 3-4. |
| Candidate or task prioritization | PARTIAL | ChatGPT is evaluated on classification/evaluation tasks, but not on web candidate prioritization; RQs and tasks, p. 3. |
| Payload/test generation | N/A | The paper does not perform exploit or payload generation for web testing. |
| Execution of tools/actions | NO | ChatGPT produces task outputs; there is no reported autonomous action execution. |
| Evidence interpretation | YES | ChatGPT interprets reports, code, and task-specific inputs to produce vulnerability-management outputs; Sections 3-4, pp. 3-10. |
| Vulnerability verification / finding decision | PARTIAL | It evaluates tasks such as security-bug identification and vulnerability severity/repair assessment, but not verifier-confirmed web findings; Figure 1 and task descriptions, pp. 3-5. |
| Ground-truth access during testing | NO / NOT REPORTED | Datasets provide labels for evaluation; no indication that test labels are included in prompts. Demonstration examples are used for prompt design; Section 3, pp. 5-6. |

Degree of autonomy:

Low. ChatGPT is used as an evaluator/classifier/summarizer within predefined tasks, not as an autonomous penetration-testing agent.

Models/runtime:

ChatGPT based on GPT-4-0314 for large-scale tests. The paper records temperature=0 and top_p=1.0 as settings to enhance determinism (p. 5).

Experimental methodology:

Large-scale benchmark evaluation across six tasks with SOTA comparisons, prompt-template design, and user-study verification for some findings.

Main findings relevant to this thesis:

- ChatGPT can be evaluated against specialized baselines across security-related tasks, which supports careful task decomposition for LLM security evaluation; Sections 3-4, pp. 3-10.
- Prompt engineering and model configuration affect performance; Section 3, pp. 5-6.
- The paper raises threats to validity including possible test-sample leakage and limited model coverage; discussion, p. 15.

Limitations acknowledged by the authors:

- Threats include potential test sample leakage and the focus on ChatGPT rather than broader LLM comparisons; discussion, p. 15.
- Token limits affect prompt design and the feasibility of including many examples; p. 9.

Matrix interpretation:

This is supporting rather than core for Section 2.2. It helps justify decomposed, measurable LLM roles and careful prompt/model reporting, but it does not study automated web application testing.

Specific claims useful to cite:

- Claim stated by paper: ChatGPT's vulnerability-management performance is evaluated over six tasks and compared to 11 SOTA approaches. Location: Introduction/contributions, p. 3.
- Claim stated by paper: prompt engineering methods affect ChatGPT's performance on vulnerability-management tasks. Location: research questions and methodology, pp. 3, 5-6.
- Claim stated by paper: the authors set temperature to zero and top_p to 1.0 to enhance determinism. Location: evaluation pipeline, p. 5.
- Claim stated by paper: test-sample leakage and limited model scope are threats to validity. Location: discussion, p. 15.

Notes for use:

Useful for Section 2.2 subsections on LLMs in vulnerability-management/security workflows and reproducibility. Not a direct source for web penetration-testing architecture.

---

### 6. Ouyang et al. - ChatGPT Nondeterminism

- Citation key suggestion: `ouyang2025nondeterminism`
- Full title: An Empirical Study of the Non-Determinism of ChatGPT in Code Generation
- Authors: Shuyin Ouyang, Jie M. Zhang, Mark Harman, Meng Wang
- Year: 2025
- Venue: ACM Transactions on Software Engineering and Methodology, 34(2), Article 42
- DOI: `10.1145/3697010`
- Type of study: empirical study of LLM nondeterminism in code generation
- Classification: SUPPORTING
- Themes: H, I

Research problem addressed:

The paper investigates the nondeterminism of ChatGPT outputs in code generation and the consequences of output variability for correctness, consistency, trust, and reproducibility.

Methodology:

The authors evaluate ChatGPT across 829 code-generation problems from CodeContests, APPS, and HumanEval, using semantic, syntactic, and structural similarity measurements. They also study the effect of temperature.

Tools/scanners/benchmarks evaluated:

ChatGPT; CodeContests, APPS, and HumanEval. This is not a cybersecurity-testing benchmark.

Vulnerability classes relevant to this thesis:

N/A. The relevance is methodological: repeated trials, nondeterminism, and reproducibility of LLM outputs.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | N/A | The study is about code generation, not security testing. |
| Candidate or task prioritization | N/A | The study does not rank security-test candidates. |
| Payload/test generation | N/A | The generated artifacts are code solutions, not security payloads. |
| Execution of tools/actions | PARTIAL | Generated code is executed against benchmark test cases for semantic comparison, but ChatGPT itself does not operate tools autonomously; methodology, p. 4. |
| Evidence interpretation | NO | Evaluation is performed by the researchers' measurement pipeline, not by ChatGPT. |
| Vulnerability verification / finding decision | N/A | No vulnerability findings are involved. |
| Ground-truth access during testing | NOT REPORTED | Benchmarks have expected behavior for evaluation; the paper does not describe labels being provided to ChatGPT in prompts. |

Degree of autonomy:

Low. ChatGPT produces code responses to prompts; the experimental pipeline evaluates variability.

Models/runtime:

ChatGPT. The paper discusses default temperature and temperature=0, emphasizing that temperature zero does not guarantee determinism (abstract and Section 3, pp. 1, 4-6).

Experimental methodology:

Repeated generation across benchmarks and multi-dimensional similarity analysis. The paper reviews how recent LLM-based code-generation papers handle nondeterminism.

Main findings relevant to this thesis:

- LLM outputs can vary substantially across repeated requests with the same prompt; abstract/introduction, pp. 1-2.
- Temperature zero reduces but does not eliminate nondeterminism; abstract and research-question discussion, pp. 1, 4-6.
- LLM-based research should consider nondeterminism when drawing conclusions; abstract/introduction, pp. 1-3.

Limitations acknowledged by the authors:

- The paper explicitly frames threats to validity and limitations as part of its structure; Section overview, p. 3. Specific limitations are about the chosen benchmarks, model, and measurement methods.

Matrix interpretation:

This is an important supporting source for the thesis's repeated-trial design and reproducibility discussion. It does not address security testing directly and should not be used for claims about vulnerability detection.

Specific claims useful to cite:

- Claim stated by paper: identical prompts can yield different ChatGPT outputs, affecting correctness, consistency, trust, and reproducibility. Location: abstract/introduction, pp. 1-2.
- Claim stated by paper: setting temperature to zero does not guarantee determinism in code generation. Location: abstract and RQ discussion, pp. 1, 4-6.
- Claim stated by paper: LLM-based research should account for nondeterminism when drawing scientific conclusions. Location: abstract/introduction, pp. 1-3.

Notes for use:

Use to support repeated LLM trials, explicit model settings, and cautious interpretation of proprietary-model results.

---

### 7. Shashwat et al. - Preliminary Study on LLMs in Software Pentesting

- Citation key suggestion: `shashwat2024softwarepentesting`
- Full title: A Preliminary Study on Using Large Language Models in Software Pentesting
- Authors: Kumar Shashwat, Francis Hahn, Xinming Ou, Dmitry Goldgof, Lawrence Hall, Jay Ligatti, S. Raj Rajagopalan, Armin Ziaie Tabari
- Year: 2024
- Venue: Workshop on SOC Operations and Construction (WOSOC) 2024
- DOI: `10.14722/wosoc.2024.23002`
- Type of study: preliminary empirical study of LLM-based source-code vulnerability detection
- Classification: SUPPORTING
- Themes: A, H, I

Research problem addressed:

The paper evaluates whether LLMs can support software pentesting by identifying vulnerabilities in source code and whether prompt engineering can improve performance over time.

Methodology:

The authors use OWASP Benchmark Project 1.2 with Java source-code test cases, split the dataset into prompt-engineering and testing portions, compare LLM agents with base and augmented prompts, and compare against SonarQube results.

Tools/scanners/benchmarks evaluated:

OWASP Benchmark Project 1.2, SonarQube Community Edition, GPT-3.5-Turbo, GPT-4-Turbo, Gemini Pro, and assistant/API variants.

Vulnerability classes relevant to this thesis:

The benchmark includes SQL injection and cross-site scripting among many source-code vulnerability categories. The study is SAST/source-code oriented rather than black-box web testing.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | N/A | The LLM receives source-code test cases rather than discovering web inputs; abstract and methodology, pp. 1, 3-4. |
| Candidate or task prioritization | N/A | The study classifies source-code test cases; no web candidate prioritization is evaluated. |
| Payload/test generation | NO | The LLM is not used to generate web payloads; it identifies source-code vulnerabilities. |
| Execution of tools/actions | NO | The LLM produces vulnerability judgments; execution is performed by the experimental evaluation process. |
| Evidence interpretation | YES | The LLM analyzes source code and prompt-provided vulnerability guidance; Sections III-IV, pp. 3-5. |
| Vulnerability verification / finding decision | PARTIAL | LLM outputs are compared to benchmark ground truth, but there is no separate deterministic verifier for web findings; pp. 3-6. |
| Ground-truth access during testing | PARTIAL / CAUTION | The extracted page text suggests that prompt examples may include vulnerability types and ground truth in prompt-engineering material; p. 3. The study uses a train/test split, but care is needed when citing this. |

Degree of autonomy:

Low. The LLM is used as a code-analysis component rather than as an autonomous web-testing agent.

Models/runtime:

GPT-3.5-Turbo, GPT-4-Turbo, Gemini Pro, and assistant variants are evaluated. The paper compares base and augmented prompts.

Experimental methodology:

Train/test split of OWASP Benchmark Project 1.2, prompt augmentation, comparison against SonarQube, and vulnerability-category accuracy reporting.

Main findings relevant to this thesis:

- The paper supports the broader claim that LLMs are being evaluated for security/pentesting tasks and compared with conventional tools; abstract and evaluation, pp. 1, 4-6.
- It reports that prompt engineering can affect vulnerability-detection accuracy in source-code tasks; abstract and conclusion, pp. 1, 6-7.
- It provides an example of using an established benchmark with known ground truth, which is relevant to evaluation design but differs from black-box testing.

Limitations acknowledged by the authors:

- The paper notes that removing human bias through a one-size-fits-all prompt-engineering process may not reflect how LLMs are actually used and tailored; p. 6.
- It is explicitly preliminary and source-code based.

Matrix interpretation:

Useful as supporting evidence for LLMs in security tasks and benchmark-based comparison. It is not core for black-box LLM-assisted web testing and is only indirectly relevant to the thesis architecture.

Specific claims useful to cite:

- Claim stated by paper: the study uses OWASP Benchmark Project 1.2 with 2,740 source-code test cases. Location: abstract/introduction and benchmark discussion, pp. 1-2.
- Claim stated by paper: SonarQube and LLM agents are compared on vulnerability-category accuracy. Location: experimentation/evaluation, pp. 4-6.
- Claim stated by paper: prompt engineering can improve LLM performance on the studied source-code pentesting task. Location: abstract and conclusion, pp. 1, 6-7.

Notes for use:

Use sparingly, mainly for the wider context of LLMs in security testing. Avoid using it as evidence for black-box attack-surface candidate ranking.

---

### 8. Stafeev et al. - YuraScanner

- Citation key suggestion: `stafeev2025yurascanner`
- Full title: YuraScanner: Leveraging LLMs for Task-driven Web App Scanning
- Authors: Aleksei Stafeev, Tim Recktenwald, Gianluca De Stefano, Soheil Khodayari, Giancarlo Pellegrino
- Year: 2025
- Venue: Network and Distributed System Security (NDSS) Symposium 2025
- DOI: `10.14722/ndss.2025.240388`
- Type of study: proposed LLM-assisted task-driven web scanner and empirical evaluation
- Classification: CORE
- Themes: B, D, E, F, G, H, I

Research problem addressed:

The paper addresses the difficulty traditional web scanners face when discovering deep application states that require correct sequences of user-interface actions and workflow understanding.

Methodology:

YuraScanner extracts tasks from shallowly crawled web pages, uses an LLM-based task-driven web agent to execute workflows, and integrates Black Widow's XSS detection engine to test discovered forms. The authors evaluate on 20 real web applications and compare with baseline crawling/scanning techniques.

Tools/scanners/benchmarks evaluated:

YuraScanner, Black Widow, and comparisons against scanner/crawler strategies including Arachni, ZAP, w3af, breadth-first approaches, and randomized breadth-first scanning.

Vulnerability classes relevant to this thesis:

XSS is directly relevant. The system integrates an XSS engine and reports zero-day XSS vulnerabilities discovered through deeper workflow exploration.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | YES | The system uses LLMs for task extraction and execution to reach deeper application states and discover additional URLs/forms; RQ1-RQ4 and Figure 2, pp. 2-4, 7-9. |
| Candidate or task prioritization | PARTIAL | The system identifies tasks/workflows and executes them, but it does not isolate a ranking-only LLM output over fixed candidates; RQ1-RQ3 and architecture, pp. 2-4. |
| Payload/test generation | NO / PARTIAL | XSS testing is performed by integrating Black Widow's XSS detection engine, while the LLM focuses on task/workflow execution; abstract and Figure 2, pp. 1, 4, 8. |
| Execution of tools/actions | YES | YuraScanner's web agent autonomously executes tasks/workflows through sensors and actuators; abstract and architecture, pp. 1, 4, 7. |
| Evidence interpretation | PARTIAL | The LLM processes page semantics for task execution; XSS vulnerability evidence is handled through the scanning engine and evaluation scripts; pp. 4, 8, 16. |
| Vulnerability verification / finding decision | PARTIAL | Vulnerability detection is delegated to the Black Widow XSS engine integrated with YuraScanner, not to a ranking-only LLM; pp. 1, 8, 16. |
| Ground-truth access during testing | NOT REPORTED | The paper reports discovered vulnerabilities and comparisons, but the supplied text does not indicate that ground truth is exposed to the LLM during scanning. |

Degree of autonomy:

High for task-driven crawling/workflow execution. The LLM is used as a goal-based agent for web interaction, while vulnerability detection is performed by a scanner engine.

Models/runtime:

The paper relies on OpenAI API for LLM use and discusses rate limits in the artifact/evaluation notes (p. 15). Exact model details should be checked in the paper sections before citation if needed; they are not clearly summarized in the extracted snippets used here.

Experimental methodology:

The authors define research questions about task extraction, task execution, attack-surface coverage, attack-surface characterization, and vulnerability detection. They evaluate on 20 web applications and compare discovered attack surface and XSS findings against Black Widow and other crawler/scanner baselines.

Main findings relevant to this thesis:

- LLMs can help web scanners reach deeper states by executing semantically meaningful tasks and workflows; abstract and RQs, pp. 1-3.
- Scanner effectiveness can depend strongly on attack-surface discovery, not only vulnerability payloads; RQ3-RQ5, pp. 3, 7-9.
- YuraScanner reports more discovered XSS vulnerabilities than Black Widow alone in the supplied paper; abstract/introduction, pp. 1-2.
- The paper acknowledges reproducibility limits from random scanning and non-static OpenAI model behavior; artifact notes, p. 16.

Limitations acknowledged by the authors:

- Hardware/software dependency and scalability limitations are discussed in the artifact/evaluation notes; p. 15.
- The authors note that results may differ because Black Widow uses randomized navigation and OpenAI models are not static; p. 16.

Matrix interpretation:

This is one of the closest sources for web-scanner enhancement via LLMs. However, it uses the LLM for task extraction/execution and uses an XSS scanner engine for vulnerability testing; it does not match the thesis's bounded LLM candidate-ranking-only authority model.

Specific claims useful to cite:

- Claim stated by paper: existing scanners struggle with deeper states because they rely on basic navigation strategies and lack workflow understanding. Location: abstract/introduction, pp. 1-2.
- Claim stated by paper: YuraScanner uses LLMs to execute tasks/workflows and bridge the semantic gap in web applications. Location: abstract and Figure 2, pp. 1, 4.
- Claim stated by paper: the approach evaluates attack-surface coverage, characterization, and vulnerability detection. Location: RQ3-RQ5 and evaluation overview, pp. 3, 7.
- Claim stated by paper: randomness and non-static OpenAI models can cause reproduction differences. Location: artifact notes, p. 16.

Notes for use:

Very useful for Section 2.2 because it connects LLMs, web scanning, attack-surface discovery, XSS testing, and reproducibility. Use it as a partial precedent, not as an identical architecture.

---

### 9. Vangeli et al. - Context Relay for Penetration-Testing Agents

- Citation key suggestion: `vangeli2026contextrelay`
- Full title: Context Relay for Long-Running Penetration-Testing Agents
- Authors: Marius Vangeli, Joel Brynielsson, Mika Cohen, Farzad Kamrani
- Year: 2026
- Venue: Workshop on LLM Assisted Security and Trust Exploration (LAST-X) 2026
- DOI: `10.14722/last-x.2026.23042`
- Type of study: proposed context-management technique for autonomous penetration-testing agents
- Classification: SUPPORTING
- Themes: A, C, H, I

Research problem addressed:

The paper studies context-window and long-duration coherence problems in autonomous LLM-driven penetration-testing agents.

Methodology:

The authors introduce CHAP, a context handoff mechanism that transfers accumulated knowledge as compact protocols between agent sessions. They evaluate it on an extended AutoPenBench benchmark targeting 11 real-world vulnerabilities and compare against a baseline agent.

Tools/scanners/benchmarks evaluated:

CHAP, a baseline LLM agent, AutoPenBench, Kali Linux container/terminal, Docker-networked targets, and command logs with LLM reasoning traces.

Vulnerability classes relevant to this thesis:

The paper targets broader penetration-testing tasks and real-world vulnerabilities, not specifically the thesis's reflected XSS/IDOR/SQLi web-candidate ranking. It is relevant for agentic workflow and reproducibility context.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | YES | Agents perform reconnaissance and exploit attempts over multi-stage targets; abstract/introduction and Figure 1, pp. 1-2. |
| Candidate or task prioritization | YES | Agents maintain strategy across sessions and use handoff protocols to continue tasks; methodology and system prompt, pp. 2-3, 8-9. |
| Payload/test generation | YES | The system prompt instructs agents to verify assumptions about injection points, payload syntax, and target behavior through tests; appendix, p. 8. |
| Execution of tools/actions | YES | LLM-generated commands are executed in a Kali container against targets; Figure 1 and methodology, pp. 2-3. |
| Evidence interpretation | YES | Command outputs and accumulated context are summarized into handoff protocols; Figures 1-2 and appendix, pp. 2-3, 8-9. |
| Vulnerability verification / finding decision | PARTIAL | Success is based on benchmark/flag submission rather than a separate deterministic vulnerability verifier; methodology and appendix, pp. 2-4, 8-9. |
| Ground-truth access during testing | NOT REPORTED | The benchmark has flags and target objectives; the supplied text does not establish that hidden ground truth is available to the agent. |

Degree of autonomy:

High. The system is explicitly designed for autonomous penetration-testing agents and long-running offensive workflows.

Models/runtime:

The paper uses an LLM agent through OpenRouter API with default parameters (methodology, p. 3). The exact model should be verified from the full methodology if needed.

Experimental methodology:

Evaluation on an extended AutoPenBench with 11 vulnerabilities, measuring per-run success and token expenditure relative to a baseline agent.

Main findings relevant to this thesis:

- Long-running autonomous penetration-testing agents can suffer from context degradation, making context management an important design concern; abstract/introduction, p. 1.
- The paper reports that context handoff can improve per-run success and reduce token expenditure in its benchmark; abstract, p. 1.
- It releases command logs and reasoning traces, supporting reproducibility-oriented reporting in LLM security experiments; abstract/introduction, p. 1.

Limitations acknowledged by the authors:

- The paper states that results cannot prove all unintended exploit paths are eliminated or that the challenges accurately reflect real-world penetration testing; conclusion-area discussion, p. 6.
- It focuses on context management for autonomous agents rather than bounded decision support.

Matrix interpretation:

Useful as a supporting source on context limits, token cost, and reproducibility for autonomous agents. It is not a close match for the thesis because the thesis deliberately avoids giving the LLM terminal/tool authority.

Specific claims useful to cite:

- Claim stated by paper: autonomous penetration-testing agents struggle with long-duration, multi-stage exploits due to context-window limitations. Location: abstract/introduction, p. 1.
- Claim stated by paper: CHAP transfers accumulated knowledge as compact handoff protocols to fresh agent instances. Location: abstract and Figure 2, pp. 1-3.
- Claim stated by paper: the evaluation measures success and token expenditure against a baseline agent. Location: abstract/methodology, pp. 1-3.

Notes for use:

Good for explaining why this thesis avoids broad autonomous-agent scope and why LLM reproducibility/cost must be measured.

---

### 10. Wu et al. - IsolateGPT

- Citation key suggestion: `wu2025isolategpt`
- Full title: ISOLATEGPT: An Execution Isolation Architecture for LLM-Based Agentic Systems
- Authors: Yuhao Wu, Franziska Roesner, Tadayoshi Kohno, Ning Zhang, Umar Iqbal
- Year: 2025
- Venue: Network and Distributed System Security (NDSS) Symposium 2025
- DOI: `10.14722/ndss.2025.241131`
- Type of study: LLM-agent system-security architecture and evaluation
- Classification: SUPPORTING
- Themes: I, J

Research problem addressed:

The paper studies security and privacy risks in LLM-based agentic systems where third-party apps interact through natural-language interfaces and may gain access to user data, other apps, and system capabilities.

Methodology:

The authors propose ISOLATEGPT, a hub-and-spoke execution-isolation architecture with isolated app-specific LLM instances, mediated communication, memory management, and permission models. They evaluate protection, functionality, and performance overhead against a non-isolated baseline.

Tools/scanners/benchmarks evaluated:

ISOLATEGPT, VANILLAGPT, LangChain, LlamaIndex/Llama Pack integration, case studies, and benchmark-style app-interaction queries. It is not a web vulnerability-testing system.

Vulnerability classes relevant to this thesis:

N/A. The relevance is architectural: isolation, permission boundaries, and separating authority in LLM-based systems.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | N/A | The paper addresses LLM app isolation, not web security discovery. |
| Candidate or task prioritization | N/A | It does not rank vulnerability-test candidates. |
| Payload/test generation | N/A | It does not perform security payload generation for web testing. |
| Execution of tools/actions | PARTIAL | Apps execute in constrained environments and interaction outside those environments is mediated through hub/spoke interfaces and permissions; abstract and architecture, pp. 1-5. |
| Evidence interpretation | PARTIAL | Hub/spoke LLMs interpret natural-language interactions, but the core security contribution is isolation/permission mediation rather than vulnerability evidence interpretation; pp. 2-5, 9. |
| Vulnerability verification / finding decision | N/A | No vulnerability findings are produced. |
| Ground-truth access during testing | N/A | Not a vulnerability-testing benchmark. |

Degree of autonomy:

System-level LLM app autonomy under explicit isolation and permission controls. Not an offensive-security agent.

Models/runtime:

The paper implements ISOLATEGPT using LangChain and integrates with LlamaIndex. It discusses costs and latency of LLM-based systems; artifact and evaluation notes, pp. 15, 19-20.

Experimental methodology:

Case-study protection analysis, functionality comparison, and performance-overhead measurement.

Main findings relevant to this thesis:

- LLM app ecosystems can create security and privacy risks when natural-language interactions and tool/app access are unrestricted; abstract/introduction, pp. 1-2.
- Execution isolation and permission mediation can reduce attack surface by design; abstract and architecture/threat model, pp. 1, 4-5.
- The paper's architecture separates components and uses deterministic/non-LLM modules for well-defined message exchange in parts of the system; architecture discussion, p. 5.

Limitations acknowledged by the authors:

- The paper discusses strengths and limitations of execution isolation and reports cost/latency overheads; pp. 2, 15, 19-20.
- It is not intended as a web security-testing framework.

Matrix interpretation:

Supporting source for the thesis's safety and authority-boundary framing. It should not be cited as LLM-assisted web-testing evidence, but it is valuable when discussing why LLM authority should be isolated and mediated.

Specific claims useful to cite:

- Claim stated by paper: natural-language-based app interactions and unrestricted access to apps/data/system capabilities introduce security and privacy risks. Location: abstract/introduction, pp. 1-2.
- Claim stated by paper: ISOLATEGPT reduces attack surface by placing apps in constrained environments and mediating interactions through well-defined interfaces with user permission. Location: abstract and architecture, pp. 1-5.
- Claim stated by paper: permission models may be one-time, session, or permanent depending on interaction needs. Location: permission-model discussion, p. 18.
- Claim stated by paper: latency can vary due to server load, infrastructure updates, and nondeterministic LLM prediction time. Location: artifact/evaluation notes, p. 20.

Notes for use:

Use for the architectural safety argument: deterministic mediation and limited authority are not merely implementation choices, but part of making LLM-based systems auditable and safer.

---

### 11. Happe and Cito - Getting pwn'd by AI

- Citation key suggestion: `happe2023gettingpwned`
- Full title: Getting pwn'd by AI: Penetration Testing with Large Language Models
- Authors: Andreas Happe, Jürgen Cito
- Year: 2023
- Venue: Proceedings of the 31st ACM Joint European Software Engineering Conference and Symposium on the Foundations of Software Engineering (ESEC/FSE '23)
- DOI: `10.1145/3611643.3613083`
- Type of study: early exploratory LLM-assisted penetration-testing prototype and vision paper
- Classification: CORE
- Themes: A, C, E, F, G, H, I, J

Research problem addressed:

The paper explores whether LLMs can augment penetration testers as "AI sparring partners" in two settings: high-level task planning for security-testing assignments and low-level vulnerability hunting inside a vulnerable virtual machine.

Methodology:

The authors evaluate two distinct use cases. For high-level planning, they ask an LLM/agent system to design penetration-testing approaches for generic and concrete scenarios. For low-level vulnerability hunting, they implement a closed feedback loop in which GPT-3.5 suggests shell commands, a Python script executes those commands over SSH on a deliberately vulnerable lin.security virtual machine, and command output is returned to the model for the next step.

Tools/scanners/benchmarks evaluated:

AgentGPT, GPT-3.5/GPT-3.5-turbo, a Python SSH control script, and the vulnerable lin.security Linux virtual machine. The paper also discusses AutoGPT, BabyAGI, llama.cpp, and locally runnable models as context rather than as the main evaluated systems.

Vulnerability classes relevant to this thesis:

The low-level experiment focuses on Linux privilege escalation rather than web application vulnerabilities. It is still relevant as an early LLM-assisted penetration-testing approach with an execution-feedback loop and explicit discussion of planning, execution, hallucination, reproducibility, and ethics.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | YES | In the low-level system, GPT-3.5 analyzes machine state for vulnerabilities and suggests attack vectors; abstract/introduction and Section 3.2, pp. 1, 3. |
| Candidate or task prioritization | YES / PARTIAL | High-level systems are described as selecting tactics/techniques, and BabyAGI-style task queues are described as prioritized through a Prioritization Agent; Section 2 and Section 3.1, p. 2. This is planning/prioritization, not fixed structured web-candidate ranking. |
| Payload/test generation | YES | The model suggests concrete Linux shell commands and "verification commands" for vulnerabilities; Section 3.2, p. 3. |
| Execution of tools/actions | YES | LLM-generated shell commands are automatically executed over SSH in the vulnerable VM by the Python loop; abstract/introduction and Section 3.2, pp. 1, 3. |
| Evidence interpretation | YES | Command output is fed back to GPT-3.5, which uses it to decide subsequent commands and identify vulnerabilities; Figure 1 and Section 3.2, pp. 2-3. |
| Vulnerability verification / finding decision | YES / PARTIAL | The model is asked to identify vulnerabilities and provide exploitation examples named "verification commands"; Section 3.2, p. 3. Overall success is observed by the researchers, not by an external deterministic verifier. |
| Ground-truth access during testing | NOT REPORTED | The VM is deliberately vulnerable, but the supplied paper does not report that ground-truth labels are provided to the LLM during execution; Section 3.2, p. 3. |

Degree of autonomy:

Medium to high in the low-level prototype. Execution is automatic inside the vulnerable VM once the loop runs, but the work is positioned as augmenting human penetration testers and as an exploratory sparring-partner prototype rather than a full autonomous penetration-testing product.

Models/runtime:

GPT-3.5/GPT-3.5-turbo and AgentGPT are used in the reported experiments. The paper discusses GPT-4, AutoGPT, BabyAGI, llama.cpp, LLaMA, StableLM, Dolly2, and Koala as relevant model/agent/runtime options or future directions (Sections 2, 3, 5.2, pp. 2-4).

Experimental methodology:

The paper is exploratory and qualitative. It demonstrates high-level task-planning outputs and a low-level closed loop that repeatedly sends model-generated commands to a vulnerable VM and records command outputs. It reports that the prototype routinely gained root privileges, but it is not a large benchmark study.

Main findings relevant to this thesis:

- The paper distinguishes high-level penetration-testing planning from low-level vulnerability hunting; Section 3, p. 2.
- It demonstrates an early closed feedback loop between LLM-generated actions and a deliberately vulnerable environment; abstract/introduction and Section 3.2, pp. 1, 3.
- It reports instability across singular prototype runs and variation in command sequence and vulnerability identification; Section 4.2, p. 3.
- It explicitly discusses local models as avoiding cloud/API costs and cloud data sharing, while also removing server-side moderation; Section 5.2 and ethical discussion, p. 4.

Limitations acknowledged by the authors:

- Singular prototype runs were not stable and varied in selected commands and identified vulnerabilities; Section 4.2, p. 3.
- The prototype had simplistic memory limited by prompt context, and the authors propose memory, reflection, and model-building improvements; Section 5.3, p. 4.
- Ethical concerns are discussed because the same mechanism could be applied outside benign settings; Sections 4.3 and 6, pp. 3-4.

Matrix interpretation:

This paper is a core early source for LLM-assisted penetration testing. It is especially useful for showing that early work already considered both high-level planning and low-level execution loops. It differs strongly from this thesis because the LLM suggests commands, interprets command output, and participates in vulnerability identification/verification. The thesis narrows this authority to candidate ranking only.

Specific claims useful to cite:

- Claim stated by paper: penetration testing requires expertise and includes many manual testing and analysis steps. Location: abstract/introduction, p. 1.
- Claim stated by paper: the paper studies high-level task planning and low-level vulnerability hunting as two distinct LLM use cases. Location: abstract/introduction and Section 3, pp. 1-2.
- Claim stated by paper: the low-level prototype executes GPT-3.5-generated shell commands over SSH and feeds outputs back to the model. Location: Section 3.2 and Figure 1, pp. 2-3.
- Claim stated by paper: single prototype runs were unstable, with variation in command sequence and selected vulnerabilities. Location: Section 4.2, p. 3.
- Claim stated by paper: local models avoid cloud/API costs and cloud data sharing but also remove server-side ethics checks. Location: Sections 5.2 and 4.3, pp. 3-4.

Notes for use:

Use as an early LLM-assisted penetration-testing source and as a contrast for this thesis's bounded-authority design. It should not be presented as web-specific or as evaluating fixed structured attack-surface candidate ranking.

---

### 12. David and Gervais - MAPTA

- Citation key suggestion: `david2025mapta`
- Full title: Multi-Agent Penetration Testing AI for the Web
- Authors: Isaac David, Arthur Gervais
- Year: 2025
- Venue: arXiv preprint
- DOI: `10.48550/arXiv.2508.20816`
- Type of study: preprint proposing and evaluating a multi-agent web penetration-testing system
- Classification: CORE, use cautiously because publication status is preprint
- Themes: A, B, C, D, E, F, G, H, I, J

Research problem addressed:

The paper argues that web-application security assessment faces a scalability problem and presents MAPTA, a multi-agent system for autonomous web application security assessment with LLM orchestration, tool-grounded execution, and end-to-end exploit validation.

Methodology:

The authors design a multi-agent architecture with Coordinator, Sandbox, and Validation agents. MAPTA is evaluated on the 104-challenge XBOW benchmark under black-box conditions and on locally cloned open-source applications under a white-box assessment mode. It records success, time, tool calls, token usage, cost, and vulnerability categories.

Tools/scanners/benchmarks evaluated:

MAPTA, XBOW Validation Benchmarks, GPT-5, command and Python execution tools, web/security utilities such as nmap, ffuf, nikto, sqlmap, dirb, httpx, jwt tooling, wafw00f, and comparisons/discussion involving classical scanners and related LLM systems.

Vulnerability classes relevant to this thesis:

The paper reports web vulnerabilities including broken authorization/IDOR-like access control issues, XSS, SQL injection, blind SQL injection, SSRF, SSTI, command injection, misconfiguration, vulnerable components, and insecure design. XSS, IDOR/broken access control, and SQLi overlap with this thesis's representative vulnerability classes.

LLM authority and responsibility:

| Responsibility | Status | Evidence |
| --- | --- | --- |
| Discovery / attack-surface identification | YES | MAPTA performs reconnaissance/discovery through tool-grounded black-box testing and white-box assessment; architecture and methodology, pp. 3-6. |
| Candidate or task prioritization | YES | The Coordinator plans, orchestrates, delegates subtasks, and decides whether to execute commands directly or via sandbox agents; Figure 1, Table 1, and methodology, pp. 3-5. |
| Payload/test generation | YES | The system assembles candidate PoC artifacts including HTTP request sequences, payloads, and scripts; validation/PoC discussion, pp. 3, 5. |
| Execution of tools/actions | YES | Coordinator and Sandbox agents use run_command and run_python; sandbox agents execute tactics in isolated LLM contexts within a shared per-job Docker container; Figure 1 and Table 1, pp. 3-4. |
| Evidence interpretation | YES | Outputs are normalized into observations used for gating predicates and subsequent planning, and validation returns pass/fail with evidence; methodology, pp. 3-5. |
| Vulnerability verification / finding decision | YES / PARTIAL | A Validation agent consumes/refines candidate PoCs, executes them concretely, and returns pass/fail with evidence; Figure 1, Table 1, and methodology, pp. 3-5. This is LLM-agent validation, not a deterministic verifier separated from the LLM. |
| Ground-truth access during testing | NO / PARTIAL | For XBOW, the system receives target URLs and challenge descriptions while detailed vulnerability classifications in Docker readmes are withheld; p. 6. Challenge descriptions may contain hints, which the paper says mirror realistic engagements; p. 6. |

Degree of autonomy:

High. MAPTA is presented as autonomous, end-to-end web application security assessment without human intervention, with tool execution and exploit validation.

Models/runtime:

The paper evaluates GPT-5 under high-effort agent configurations and records token/cost accounting. It states that GPT-5 pricing at the time of writing was used to calculate cost; p. 6. It uses a per-job Docker container and tool interfaces including shell and Python execution; pp. 3-4.

Experimental methodology:

MAPTA is evaluated on the 104-challenge XBOW benchmark and on real-world/open-source targets. The benchmark evaluation uses black-box conditions, only local target URLs and challenge descriptions, and flag discovery as proof of successful exploitation. Metrics include success rate, solve time, token usage, token cost, command/tool count, and category-level performance; pp. 6-11.

Main findings relevant to this thesis:

- MAPTA provides a web-specific example of LLM-based multi-agent penetration testing with autonomous tool execution and exploit validation; abstract and architecture, pp. 1-5.
- It emphasizes end-to-end exploit validation to reduce theoretical findings and false positives; abstract, Figure 1, Table 1, pp. 1, 3-4.
- It reports detailed efficiency accounting, including time, token use, cost, and tool calls; Table 2 and Figures 2-6, pp. 6-9.
- It treats XSS and blind SQL injection as comparatively challenging categories in its benchmark results; pp. 8-10.

Limitations acknowledged by the authors:

- The approach excludes network-level vulnerabilities, infrastructure beyond application-layer testing, physical security, social engineering, and human-targeted attacks; scope/limitations, p. 4.
- The authors acknowledge that validation-oriented design may create false negatives where theoretical findings are valid but not materialized under the explored state space; validation-agent discussion, p. 3.
- The paper notes that black-box XBOW challenges have relatively simple applications and less extensive JavaScript than larger web applications; p. 5.

Matrix interpretation:

MAPTA is one of the closest expanded-source-set papers for web-specific LLM penetration testing because it includes multi-agent orchestration, black-box web assessment, tool execution, PoC generation, validation, and detailed resource metrics. It remains methodologically distinct from this thesis: MAPTA gives LLM agents authority over planning, tool execution, PoC construction, and validation, while this thesis restricts LLMs to ranking fixed structured candidates and leaves safety, execution, evidence collection, and verification to deterministic components. Because the supplied paper is an arXiv preprint, it should be cited more cautiously than peer-reviewed ESEC/FSE, USENIX, NDSS, or ACM papers.

Specific claims useful to cite:

- Claim stated by paper: MAPTA combines LLM orchestration, tool-grounded execution, and end-to-end exploit validation for autonomous web application security assessment. Location: abstract/introduction, p. 1.
- Claim stated by paper: MAPTA uses Coordinator, Sandbox, and Validation agents with run_command and run_python tool interfaces. Location: Figure 1 and Table 1, pp. 3-4.
- Claim stated by paper: the Validation agent executes candidate PoCs concretely and returns pass/fail evidence. Location: Figure 1, Table 1, and methodology, pp. 3-5.
- Claim stated by paper: for XBOW, MAPTA receives only the local target URL and challenge description, and detailed vulnerability classifications are withheld. Location: evaluation setup, p. 6.
- Claim stated by paper: MAPTA records solve time, token usage, token cost, and command/tool counts. Location: Table 2 and Figures 2-6, pp. 6-9.

Notes for use:

Use as a close but high-authority related work and compare it carefully with AWE and YuraScanner. MAPTA differs from YuraScanner by emphasizing multi-agent exploitation and PoC validation rather than task-driven crawling feeding a scanner engine. It differs from AWE by being a broader multi-agent web penetration-testing system and, in the supplied paper, a preprint rather than peer-reviewed evidence.

---

## Cross-Paper LLM Authority Comparison

| Paper | Discovery / attack-surface role | Prioritization role | Payload/test generation | Execution authority | Evidence interpretation | Verification / finding decision | Ground-truth access during execution | Closest relationship to this thesis |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Deng et al. 2024 | PARTIAL | PARTIAL | YES | PARTIAL | YES | PARTIAL | NOT REPORTED | Broad LLM-assisted pentesting; useful contrast |
| Fang et al. 2024 | YES | YES | YES | YES | YES | PARTIAL | NO / PARTIAL | Autonomous web-hacking agent; high-authority contrast |
| Happe and Cito 2023 | YES | YES / PARTIAL | YES | YES | YES | YES / PARTIAL | NOT REPORTED | Early LLM pentesting loop; high-authority contrast |
| Isozaki et al. 2025 | PARTIAL | PARTIAL | YES | PARTIAL | YES | PARTIAL | NOT REPORTED | Benchmark and human-assistance context |
| Jaswal and Baghel 2026 | PARTIAL | YES | YES | YES | YES | PARTIAL | NOT REPORTED | Structured autonomous web exploitation; partial architectural contrast |
| David and Gervais 2025 | YES | YES | YES | YES | YES | YES / PARTIAL | NO / PARTIAL | Close web-specific multi-agent contrast; preprint |
| Liu et al. 2024 | N/A | PARTIAL | N/A | NO | YES | PARTIAL | NO / NOT REPORTED | Security-task LLM evaluation, not web testing |
| Ouyang et al. 2025 | N/A | N/A | N/A | PARTIAL | NO | N/A | NOT REPORTED | Nondeterminism/reproducibility support |
| Shashwat et al. 2024 | N/A | N/A | NO | NO | YES | PARTIAL | PARTIAL / CAUTION | Source-code vulnerability LLM evaluation |
| Stafeev et al. 2025 | YES | PARTIAL | NO / PARTIAL | YES | PARTIAL | PARTIAL | NOT REPORTED | Closest web-scanning source, but LLM executes workflows |
| Vangeli et al. 2026 | YES | YES | YES | YES | YES | PARTIAL | NOT REPORTED | Autonomous-agent context/reproducibility support |
| Wu et al. 2025 | N/A | N/A | N/A | PARTIAL | PARTIAL | N/A | N/A | Isolation/authority-boundary support |

Interpretive comparison:

No paper in this expanded source set is substantially similar to this thesis's exact bounded authority model. The closest technical neighbors are Stafeev et al., Jaswal and Baghel, and David and Gervais because they combine LLM assistance with web testing and structured workflows. However, all three assign the LLM broader responsibilities than this thesis: YuraScanner uses the LLM for task extraction/execution, AWE uses LLM orchestration together with payload generation/mutation and autonomous exploitation, and MAPTA uses LLM agents for planning, tool execution, PoC assembly, and validation. Fang et al., Happe and Cito, and Vangeli et al. are high-authority autonomous or semi-autonomous penetration-testing contrasts. Wu et al. is not a web-testing paper, but it supports the architectural rationale for isolating LLM authority and mediating actions.

Answer to the bounded-ranking question: not found in current source set.

## Synthesis

### 1. Recommended CORE papers for Section 2.2

- `happe2023gettingpwned`: core early source for LLM-assisted penetration testing, distinguishing high-level planning from low-level action loops and documenting instability/reproducibility concerns.
- `deng2024pentestgpt`: core for LLM-assisted penetration testing, task decomposition, context loss, and the need to evaluate subtasks rather than only final success.
- `fang2024llmagents`: core contrast for autonomous web-hacking agents with broad browser/tool authority and sandboxed evaluation.
- `isozaki2025automated`: core for benchmark-driven LLM penetration-testing evaluation, human-assistance concerns, and limits of current end-to-end automation.
- `jaswal2026awe`: core recent example of structured LLM-based web exploitation with budgets, efficiency measurements, and model sensitivity.
- `stafeev2025yurascanner`: core for LLM-assisted web scanning, task-driven crawling, attack-surface coverage, XSS scanning, and reproducibility concerns.
- `david2025mapta`: core close web-specific multi-agent related work, but use cautiously because the supplied paper is an arXiv preprint.

### 2. Recommended SUPPORTING papers

- `liu2024chatgptvulnerability`: supporting for broader LLM vulnerability-management evaluation, prompt effects, model settings, and test-sample leakage concerns.
- `ouyang2025nondeterminism`: supporting for nondeterminism, repeated trials, and reproducibility of LLM-based research.
- `shashwat2024softwarepentesting`: supporting for LLMs in security testing against known ground truth and comparison with a conventional analyzer, but source-code/SAST oriented.
- `vangeli2026contextrelay`: supporting for long-running agent limitations, context degradation, token cost, and reproducibility artifacts.
- `wu2025isolategpt`: supporting for isolation, permission, and authority-boundary arguments in LLM-based systems.

### 3. Papers that can probably be excluded or used very lightly

- `shashwat2024softwarepentesting` can be used lightly or excluded if Section 2.2 becomes too long. It is preliminary and source-code based rather than black-box web testing.
- `liu2024chatgptvulnerability` can be used lightly if the section focuses narrowly on penetration testing rather than vulnerability management.
- `wu2025isolategpt` should not be excluded from the safety/authority discussion, but it should not occupy much space in a web security-testing subsection because it is about LLM app isolation rather than testing.
- `david2025mapta` is technically important but should be identified as preprint evidence rather than peer-reviewed evidence.

### 4. Chronological development supported by this source set

1. Happe and Cito (2023) provide an early LLM-assisted penetration-testing prototype, distinguishing high-level planning from low-level action execution with a closed environment feedback loop.
2. Early LLM-security evaluation work represented by Shashwat et al. (2024) studies LLMs as source-code vulnerability-analysis components and compares them with conventional static-analysis tooling.
3. PentestGPT (Deng et al., 2024) moves toward LLM-assisted penetration testing, using task decomposition, LLM reasoning/generation/parsing modules, and human-in-the-loop execution.
4. Fang et al. (2024) studies autonomous web-hacking agents with browser/function/document authority, demonstrating high-authority LLM systems on sandboxed web tasks.
5. Liu et al. (2024) evaluates ChatGPT across vulnerability-management tasks and reinforces the importance of task-specific evaluation, prompt design, and validity concerns.
6. Ouyang et al. (2025) provides broader empirical support for nondeterminism and reproducibility concerns in LLM-based software-engineering research.
7. Isozaki et al. (2025) introduces an open LLM penetration-testing benchmark and highlights the remaining gap between LLM assistance and reliable end-to-end penetration testing.
8. Stafeev et al. (2025) applies LLMs to web-scanner task/workflow execution, emphasizing attack-surface discovery and scanner coverage.
9. David and Gervais (2025) propose MAPTA as a preprint multi-agent web penetration-testing system with tool-grounded execution and exploit validation.
10. Wu et al. (2025) develops execution isolation for LLM-based agentic systems, supporting authority-boundary and permission-mediation arguments.
11. Vangeli et al. (2026) and Jaswal and Baghel (2026) represent newer agentic directions: long-running context management and specialized multi-agent web exploitation.

### 5. Strongest documented limitations of existing LLM-assisted security testing

- Broad autonomous agents can raise safety and misuse concerns, motivating sandboxing or constrained evaluation environments. Supported by Fang et al., impact statement, p. 9.
- LLM penetration-testing workflows suffer from context loss, context-window limits, and degradation over long-running tasks. Supported by Deng et al., p. 7, and Vangeli et al., pp. 1-3.
- Early LLM-assisted execution loops can be unstable across singular runs. Supported by Happe and Cito, Section 4.2, p. 3.
- Full end-to-end penetration testing remains difficult for LLMs even with human assistance in some benchmarks. Supported by Isozaki et al., p. 1.
- Model outputs are probabilistic and may remain nondeterministic even when temperature is set to zero. Supported by Ouyang et al., pp. 1, 4-6.
- Hosted/proprietary model behavior may change or be difficult to reproduce exactly; Stafeev et al. explicitly notes that OpenAI models are not static in artifact notes, p. 16.
- Agentic systems that expose apps, data, and tools through natural-language interactions create security and privacy risks unless authority is isolated and mediated. Supported by Wu et al., pp. 1-5.
- Specialized LLM-security systems can improve efficiency for selected vulnerability classes but may be limited outside their designed scope. Supported by Jaswal and Baghel, pp. 7-8.
- Validation-oriented autonomous web testing may reduce theoretical findings but can create false negatives when a finding is not materialized in the explored state space. Supported by David and Gervais, validation-agent discussion, p. 3.

### 6. Evidence for candidate/task/test prioritization in this source set

Direct evidence for security-test prioritization as an explicit problem is limited. The source set supports adjacent themes:

- Happe and Cito discuss high-level selection of tactics/techniques and task-prioritization agents in autonomous task queues, but not structured web-candidate ranking.
- PentestGPT prioritizes and manages penetration-testing subtasks through a task tree, but not as a fixed candidate-ranking experiment.
- Fang et al. agents choose strategies autonomously, but the paper evaluates goal completion rather than candidate-ranking quality.
- YuraScanner prioritizes/executes semantically meaningful workflows to expand attack-surface coverage, but does not restrict the LLM to ranking already discovered candidates.
- AWE uses an LLM to convert reconnaissance output into prioritized execution plans, but also allows broader payload/exploitation responsibilities.
- MAPTA uses a Coordinator to plan, orchestrate, delegate, execute, and validate web-security tasks, but this is broader than a ranking-only candidate-prioritization contract.

Therefore, the thesis's bounded ranking-only design appears to address a narrower and more auditable candidate-prioritization gap than the approaches represented in this source set.

### 7. Which claims still lack sufficient evidence in the current source set

- Direct evidence that LLM-only candidate ranking improves black-box web vulnerability testing under a fixed testing budget is not provided by these papers.
- Direct comparison between a bounded LLM ranker and a deterministic structural ranker over identical discovered web candidates is not represented.
- Strong evidence about IDOR-specific LLM-assisted candidate prioritization is absent.
- Strong evidence about SQLi-specific candidate prioritization in black-box web apps is not present in this Section 2.2 source set.
- The source set supports reproducibility concerns but does not provide a standardized solution for reproducible proprietary-model evaluation.
- The supplied sources do not provide a direct prior architecture with deterministic discovery, deterministic safety/execution/evidence/verification, and a probabilistic component restricted only to candidate ordering.

### 8. Important cited works to obtain before writing, if possible

The supplied papers refer to several works that appear relevant enough to obtain as originals before finalizing Section 2.2:

- AutoPenBench (cited by Vangeli et al. and Isozaki et al.). Important for benchmark methodology in autonomous penetration testing.
- Teams of LLM agents exploiting vulnerabilities / related Fang works cited by Vangeli et al. Important if discussing multi-agent offensive-security autonomy.
- InjectAgent benchmark (cited by Wu et al.). Relevant for prompt-injection risks in tool-integrated agents if the thesis discusses LLM tool isolation.
- RefPentester (cited by David and Gervais). Potentially relevant if discussing knowledge-informed/self-reflective penetration-testing systems, but it should be checked as an original before use.

### 9. Fit to this thesis's Section 2.2 narrative

The source set supports a literature narrative with three layers:

1. LLMs have been applied to security and penetration-testing tasks, ranging from vulnerability-management/classification tasks to full autonomous agents.
2. The most directly related web-testing systems tend to give the LLM broad authority over exploration, planning, task execution, payload generation, PoC construction, validation, or exploitation. This makes them useful precedents but also creates safety, reproducibility, and evaluation challenges.
3. The thesis can position its contribution as a deliberately narrower design: investigating whether an LLM can add value as a bounded candidate-prioritization component while deterministic components retain control over discovery, safety, execution, evidence collection, and final verification.

This matrix does not establish that bounded LLM ranking is superior. It establishes that the question is academically distinct from broader autonomous penetration-testing agents and that it is motivated by documented concerns around autonomy, nondeterminism, context loss, cost, and reproducibility.
