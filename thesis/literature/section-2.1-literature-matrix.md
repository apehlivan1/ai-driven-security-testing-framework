# Section 2.1 Literature Matrix: Automated Web Application Security Testing and Existing Approaches

Source set: all PDF files currently stored in `thesis/literature/section-2.1/`.

Scope note: this matrix analyzes only the supplied PDFs. Page references refer to the page markers/extracted page order of the supplied PDFs. When a supplied paper discusses prior work, the claim is treated as a secondary citation unless the analyzed paper is itself the original source.

Theme key:

- A. Evolution of automated/black-box web security testing
- B. Web vulnerability scanners and DAST approaches
- C. Attack-surface discovery and crawling
- D. Vulnerability/test candidate selection
- E. Scanner effectiveness and false positives/false negatives
- F. Benchmark design and negative/non-vulnerable cases
- G. Scanner performance/efficiency
- H. Limitations of existing automated approaches
- I. OWASP ZAP or comparable scanner evidence

## Paper Matrix

### 1. Aydos et al. - Security testing of web applications: A systematic mapping of the literature

- Citation key suggestion: `aydos2022security`
- Full title: Security testing of web applications: A systematic mapping of the literature
- Authors: Murat Aydos, Cigdem Aldan, Evren Coskun, Alperen Soydan
- Year: 2022
- Venue: Journal of King Saud University - Computer and Information Sciences, 34, 6775-6792
- DOI: `10.1016/j.jksuci.2021.09.018`
- Type of study: systematic mapping study
- Classification: SUPPORTING
- Themes: A, B, E, H, I

Research problem addressed:

The paper maps research on web application security testing and categorizes the literature by contribution type, research type, tools, analysis technique, automation level, accuracy concerns, vulnerability types, and systems under test.

Methodology:

The authors performed a systematic mapping study. They searched selected academic databases, applied inclusion/exclusion criteria, and analyzed a final pool of 80 technical articles. The research questions and classification process are described in Sections 3 and 4, with the final paper pool and mapping categories summarized in Section 5.

Tools/scanners/benchmarks evaluated:

The paper does not conduct a new scanner experiment. It maps tools used in prior studies. It explicitly identifies tools including Burp Suite and OWASP ZAP among web application security testing tools (Section 5, pp. 10-12; Table 3).

Vulnerability classes relevant to this thesis:

The mapping includes web vulnerability categories such as XSS and SQL injection, and more broadly follows OWASP-oriented web security testing categories (Section 5, Table 5).

Main findings relevant to this thesis:

- The paper supports the general claim that web application security testing is an established research area with both manual and automated approaches (Introduction, pp. 1-3).
- It supports the claim that automated web application security testing tools commonly face false-positive and false-negative concerns (Introduction, p. 2; Section 5, pp. 10-12).
- It identifies Burp Suite and OWASP ZAP as among commonly used tools in the mapped literature (Section 5, pp. 10-12).
- It shows that DAST appears frequently in the mapped source set, while IAST was rare in the reviewed studies (Section 5, pp. 10-12).

Limitations acknowledged by the authors:

- The authors discuss threats to validity for the mapping process, including search strategy, database/source selection, inclusion/exclusion criteria, and data extraction (Section 5.2, pp. 17-18).
- The review is constrained by the selected databases, search terms, and classification procedure (Section 5.2, pp. 17-18).

Relevance to Section 2.1:

Useful as a broad background source showing how automated web application security testing research is categorized and how common DAST, scanner tools, and FP/FN concerns are in the literature. It is less useful for detailed empirical scanner effectiveness because it is a mapping study rather than a controlled scanner comparison.

Specific claims useful to cite:

- Claim stated by paper: Web application security testing may be conducted automatically or manually, and both black-box and white-box testing are common categories. Location: Introduction, pp. 1-2.
- Claim stated by paper: Automated web application security testing tools are known to be error-prone and may report false positives and false negatives. Location: Introduction, p. 2; Section 5, pp. 10-12.
- Claim stated by paper: Burp Suite and OWASP ZAP appear among popular web application security testing tools in the mapped studies. Location: Section 5, pp. 10-12.
- Claim stated by paper: Only a subset of reviewed studies explicitly mention or address false positives/false negatives. Location: Section 5, pp. 10-12.

Notes for use:

This paper is appropriate for framing the field and terminology, but empirical claims about scanner performance should preferably cite papers that directly evaluate scanners.

---

### 2. Brandi et al. - Sniping at web applications to discover input-handling vulnerabilities

- Citation key suggestion: `brandi2024sniping`
- Full title: Sniping at web applications to discover input-handling vulnerabilities
- Authors: Ciro Brandi, Gaetano Perrone, Simon Pietro Romano
- Year: 2024
- Venue: Journal of Computer Virology and Hacking Techniques, 20, 641-667
- DOI: `10.1007/s11416-024-00518-0`
- Type of study: proposed scanner/fuzzer and empirical comparison
- Classification: CORE
- Themes: B, C, D, E, G, H, I

Research problem addressed:

The paper addresses automated discovery of input-handling vulnerabilities in web applications. It focuses on fuzzing request parameters and on the challenge of deciding which observed behaviors should be considered vulnerability evidence.

Methodology:

The authors propose a modular rule-based fuzzing architecture. It uses a man-in-the-middle proxy to record interactions, a repeater to produce template-based requests, an analyzer to transform fuzzing outcomes into formal observations, and a Prolog knowledge base/oracle to map observations to possible vulnerabilities. The approach is evaluated on WAVSEP and compared with OWASP ZAP.

Tools/scanners/benchmarks evaluated:

- OWASP ZAP is used as a scanner comparison.
- WAVSEP is used as the benchmark platform.
- The proposed rule-based fuzzer is the main evaluated artifact.

Vulnerability classes relevant to this thesis:

SQL injection, cross-site scripting, and path traversal are central to the evaluated approach (Abstract and Sections 2, 6, and 7).

Main findings relevant to this thesis:

- The paper treats web application penetration testing as an opaque-box/semi-automatic process in which visible and hidden resources, core functions, and data entry points are identified before testing (Section 2, p. 2).
- It explicitly frames input points, including fields, URLs, and headers, as testing targets that need to be identified and prioritized (Section 7, pp. 22-23).
- It highlights the oracle problem: determining whether observed behavior is sufficient evidence of a vulnerability is difficult and requires structured analysis (Sections 3-5, pp. 5-13).
- It reports category-specific differences between a rule-based fuzzer and ZAP on WAVSEP (Section 6, especially Tables 6 and 7, pp. 15-17).
- It discusses the trade-off between increasing payload count and reducing efficiency, and notes that more payloads may affect false positives and request volume (Section 6.4 and Section 7, pp. 17-23).

Limitations acknowledged by the authors:

- The performance and detection capability of the rule-based approach depend on payload selection and rule/oracle quality (Section 6.4, pp. 17-19).
- The authors acknowledge intrinsic limitations of a rule-based approach and discuss possible improvements through semantic payload generation, knowledge-base extension, and profiling (Section 7, pp. 22-24).
- The paper notes the broader difficulty of evaluating such approaches without a sufficiently formalized benchmarking basis in related work (Section 3, pp. 5-7).

Relevance to Section 2.1:

Highly relevant because it links attack-surface/input-point identification, candidate prioritization, oracle/verifier design, scanner comparison, and efficiency trade-offs. It provides strong support for motivating candidate prioritization and deterministic oracle/verifier boundaries.

Specific claims useful to cite:

- Claim stated by paper: Opaque-box web application penetration testing includes footprinting, identification of resources/functions, and mapping data entry points before vulnerability testing. Location: Section 2, p. 2.
- Claim stated by paper: Vulnerability detection in a fuzzer requires an oracle, and oracle design is a recognized difficulty. Location: Sections 3-5, pp. 5-13.
- Claim stated by paper: Input points such as fields, URLs, and headers can be enumerated and prioritized for testing. Location: Section 7, pp. 22-23.
- Claim stated by paper: Increasing the number of payloads can increase the chance of discovering a vulnerability but reduces efficiency and may influence false positives. Location: Section 6.4 and Section 7, pp. 17-23.
- Claim stated by paper: OWASP ZAP is used as a comparison point for the proposed fuzzer. Location: Section 6, Tables 6 and 7, pp. 15-17.

Notes for use:

The paper is especially useful for the thesis narrative around candidate selection and evidence/oracle design. Detailed numerical comparisons with ZAP should be checked carefully in the original tables before use, because the relevant extracted text is dense and table-dependent.

---

### 3. Doupe et al. - Why Johnny Can't Pentest: An Analysis of Black-box Web Vulnerability Scanners

- Citation key suggestion: `doupe2010johnny`
- Full title: Why Johnny Can't Pentest: An Analysis of Black-box Web Vulnerability Scanners
- Authors: Adam Doupe, Marco Cova, Giovanni Vigna
- Year: 2010
- Venue: Conference paper; the supplied PDF front matter does not clearly expose the venue
- DOI: Not explicitly present in the supplied PDF
- Type of study: empirical scanner comparison and benchmark study
- Classification: CORE
- Themes: A, B, C, D, E, F, G, H

Research problem addressed:

The paper evaluates the effectiveness of black-box web vulnerability scanners and investigates why scanners miss vulnerabilities in realistic web applications.

Methodology:

The authors designed WackoPicko, a deliberately vulnerable web application with realistic functionality, crawling challenges, and representative vulnerabilities. They evaluated 11 black-box web vulnerability scanners in multiple configurations and measured vulnerability detection, crawling behavior, false positives, and runtime.

Tools/scanners/benchmarks evaluated:

- 11 black-box web vulnerability scanners, including both open-source and commercial tools.
- WackoPicko is introduced and used as the benchmark.
- WIVET is referenced/used for crawler evaluation context.

Vulnerability classes relevant to this thesis:

The WackoPicko benchmark includes XSS, SQL injection, code injection, broken access controls, session-related issues, forceful browsing, and logic flaws (Sections 3-4, pp. 3-7).

Main findings relevant to this thesis:

- The paper provides a clear scanner workflow: crawl the application, enumerate reachable pages and input vectors, generate crafted values, and analyze responses (Introduction, pp. 1-2).
- Crawling is presented as critical to vulnerability detection: a scanner cannot detect a vulnerability on a page or code path it never reaches (Sections 1, 3, and 7, pp. 1-4 and pp. 18-20).
- The authors found that scanners missed many vulnerabilities and that some vulnerability categories were not detected by any scanner in their experiment (Results and Conclusion, pp. 9-14 and pp. 20-21).
- The paper documents both false negatives and false positives, showing that scanner output requires interpretation and triage (Results, pp. 9-14).
- It highlights benchmark-design concerns, including the need for realistic crawling challenges and the limitations of educational vulnerable applications as scanner benchmarks (Benchmark design, pp. 4-7).

Limitations acknowledged by the authors:

- The authors note that a single benchmark application cannot be exhaustive, although it can provide useful insight into scanner strengths and weaknesses (Discussion, pp. 12-14).
- They acknowledge that scanner evaluation depends on benchmark design, vulnerability selection, scanner configuration, and interpretation of results (Discussion, pp. 12-14).
- The paper discusses broad unresolved scanner limitations including modern client-side code, state, infinite spaces, authentication, and application-specific logic flaws (Discussion/Conclusion, pp. 18-21).

Relevance to Section 2.1:

This is one of the strongest sources for Section 2.1. It directly supports the motivation for bounded testing budgets, attack-surface discovery, benchmark design with realistic challenges, scanner false negatives/false positives, and the distinction between crawling and vulnerability detection.

Specific claims useful to cite:

- Claim stated by paper: A typical black-box scanner first crawls a web application, then attacks discovered input points, and then analyzes responses. Location: Introduction, pp. 1-2.
- Claim stated by paper: Crawling is as critical as vulnerability detection for scanner effectiveness. Location: Abstract and Sections 1/3, pp. 1-4; Conclusion, pp. 20-21.
- Claim stated by paper: Scanners may fail because of crawling, input selection, or response-analysis limitations. Location: Introduction/Discussion, pp. 2 and pp. 12-14.
- Claim stated by paper: Many vulnerabilities in WackoPicko were missed, and some were not detected by any tested scanner. Location: Results and Conclusion, pp. 9-14 and pp. 20-21.
- Claim stated by paper: Existing benchmark applications can be unrealistic or educational, motivating a benchmark with realistic crawling challenges and both vulnerabilities and non-vulnerable behavior. Location: Benchmark design, pp. 4-7.
- Claim stated by paper: Runtime varied substantially across scanners. Location: Results, Figure 3, pp. 9-10.

Notes for use:

If the final thesis needs the exact venue, obtain bibliographic metadata from the publisher/ACM/DBLP rather than inferring it from secondary references.

---

### 4. Doupe et al. - Enemy of the State: A State-Aware Black-Box Web Vulnerability Scanner

- Citation key suggestion: `doupe2012enemy`
- Full title: Enemy of the State: A State-Aware Black-Box Web Vulnerability Scanner
- Authors: Adam Doupe, Ludovico Cavedon, Christopher Kruegel, Giovanni Vigna
- Year: 2012
- Venue: Conference paper; the supplied PDF front matter does not clearly expose the venue
- DOI: Not explicitly present in the supplied PDF
- Type of study: proposed state-aware scanner/crawler and empirical evaluation
- Classification: CORE
- Themes: A, B, C, D, E, G, H

Research problem addressed:

The paper addresses limitations of black-box scanners when testing stateful web applications. It focuses on the discoverability problem caused by scanners that ignore application state changes.

Methodology:

The authors propose a state-aware black-box scanner that infers an application state machine from external observations. The inferred model is used to guide crawling and fuzzing. The implementation combines a state-aware crawler with fuzzing plugins from an existing open-source scanner, and the evaluation compares coverage and vulnerability discovery against other crawlers/scanners.

Tools/scanners/benchmarks evaluated:

- The proposed state-aware scanner.
- wget, w3af, skipfish, and WackoPicko v2 are discussed in the evaluation.
- w3af fuzzing plugins are used in the proposed prototype so that differences can be attributed partly to crawling/state handling rather than a different fuzzing engine.

Vulnerability classes relevant to this thesis:

The paper evaluates web vulnerability discovery generally; relevant categories include the vulnerability classes available in the evaluated applications and fuzzing plugins, including input-driven classes such as XSS and SQL injection where reachable code paths matter.

Main findings relevant to this thesis:

- The paper strongly supports the claim that discoverability limits black-box testing: a scanner cannot detect vulnerabilities in code paths it never executes (Motivation and Evaluation, pp. 2 and 9).
- It shows that application state is a major obstacle for scanner coverage and vulnerability discovery (Abstract and Sections 2-4, pp. 1-8).
- It separates crawling/state exploration from fuzzing, which is relevant to this thesis's separation of discovery/ranking from execution and verification (Sections 3-5, pp. 3-9).
- The evaluation uses code coverage, true vulnerabilities, and false positives as metrics, supporting multi-dimensional evaluation rather than a single score (Evaluation, pp. 9-13).

Limitations acknowledged by the authors:

- The approach can be affected by state explosion and the large space of possible request values (Discussion/limitations, pp. 13-15).
- The authors note that concurrent access by other users could affect state inference, because observed state changes may not be attributable only to the scanner (Discussion/limitations, pp. 13-14).
- The approach did not fully solve all modern interaction patterns, and extensions such as better AJAX support are discussed as future work (Discussion/future work, pp. 13-15).

Relevance to Section 2.1:

Highly relevant for explaining why discovery and state handling are difficult in automated black-box testing, and why candidate selection under bounded budgets is not trivial. It is also useful for motivating controlled, auditable workflows where crawling and vulnerability testing are separated.

Specific claims useful to cite:

- Claim stated by paper: Black-box scanners suffer from a discoverability problem because they cannot test pages/code paths they never reach. Location: Motivation, p. 2; Evaluation discussion, p. 9.
- Claim stated by paper: State-changing behavior in web applications can cause scanners to miss parts of the application or miss vulnerabilities. Location: Abstract and Motivation, pp. 1-2.
- Claim stated by paper: State-aware crawling can improve code coverage and help discover vulnerabilities missed by other tools. Location: Evaluation, pp. 10-13.
- Claim stated by paper: False positives are serious because users must triage scanner output. Location: Evaluation methodology, p. 9.
- Claim stated by paper: A fuzzer's effectiveness is bounded by the code paths reached by the crawler. Location: Evaluation discussion, p. 9.

Notes for use:

This paper should be cited primarily for state/discovery limitations and not as direct evidence about OWASP ZAP unless ZAP is explicitly present in the evaluated tool list in the exact supplied paper passages.

---

### 5. Khalil - Why Johnny Still Can't Pentest: A Comparative Analysis of Open-source Black-box Web Vulnerability Scanners

- Citation key suggestion: `khalil2018johnny`
- Full title: Why Johnny Still Can't Pentest: A Comparative Analysis of Open-source Black-box Web Vulnerability Scanners
- Authors: Rana Fouad Khalil
- Year: 2018
- Venue: Master's thesis, University of Ottawa
- DOI: Not explicitly present in the supplied PDF
- Type of study: empirical scanner comparison; master's thesis
- Classification: SUPPORTING
- Themes: A, B, C, E, F, G, H, I

Research problem addressed:

The thesis evaluates open-source black-box web application vulnerability scanners, focusing on crawling coverage, vulnerability detection accuracy, scanning speed, reporting, usability, and comparison with a commercial scanner.

Methodology:

The author evaluates five open-source scanners and Burp Suite Professional against WIVET, WAVSEP, and WackoPicko. Scanners are tested in point-and-shoot/default and configured/trained modes. Metrics include crawling coverage, vulnerability detection accuracy, scanning speed, usability, reporting quality, and final scanner ranking.

Tools/scanners/benchmarks evaluated:

- Scanners: Arachni, ZAP, Skipfish, Wapiti, Vega, and Burp Suite Professional.
- Benchmarks: WIVET, WAVSEP, and WackoPicko.

Vulnerability classes relevant to this thesis:

The thesis covers scanner testing against multiple web vulnerability classes through WAVSEP and WackoPicko, including XSS and SQL injection. It also discusses authenticated-state and access-related scanner limitations relevant to IDOR/broken access control framing.

Main findings relevant to this thesis:

- The thesis supports that crawling coverage is critical to scanner vulnerability detection (Abstract, p. 2; Conclusion, p. 66).
- It reports that scanners had difficulty with dynamic JavaScript and Flash-generated content, causing vulnerabilities to be missed (Abstract, p. 2; Results/Discussion, pp. 55-61; Conclusion, p. 66).
- It shows that configured/trained scanner operation can improve detection for some scanners but adds runtime and human effort (Abstract, p. 2; Introduction, pp. 14-16; Conclusion, p. 66).
- It provides specific ZAP comparative evidence, including ZAP's inclusion as a evaluated open-source scanner and its final ranking relative to Burp Suite Pro in this study (Introduction, p. 16; Results, p. 59).
- It discusses difficulties maintaining authenticated state during scans (Discussion, pp. 60-61).

Limitations acknowledged by the author:

- The study is limited by the choice of scanners tested (Conclusion, pp. 66-67).
- The analysis could be more in-depth, especially because open-source scanner internals could be examined further (Conclusion, pp. 66-67).
- The author states it is not possible to test every vulnerability and web technology and suggests adding more test cases and crawling challenges in future work (Conclusion, pp. 66-67).
- Benchmark choice and scope limit generalization (Conclusion, pp. 66-67).

Relevance to Section 2.1:

Useful as supporting evidence because it updates the "Johnny" line of scanner evaluation with open-source tools, including ZAP. It should not be treated as the strongest academic source because it is a master's thesis rather than a peer-reviewed article, but it contains useful practical evaluation details and scanner-configuration observations.

Specific claims useful to cite:

- Claim stated by thesis: Proper crawling is critical to detecting vulnerabilities. Location: Abstract, p. 2; Conclusion, p. 66.
- Claim stated by thesis: Many evaluated scanners had difficulty crawling/parsing dynamic JavaScript and Flash, causing missed vulnerabilities. Location: Abstract, p. 2; Results/Discussion, pp. 55-61; Conclusion, p. 66.
- Claim stated by thesis: Configured/trained scans improved some scanners but increased runtime and human intervention. Location: Introduction, pp. 14-16; Conclusion, p. 66.
- Claim stated by thesis: ZAP was evaluated as an open-source scanner and ranked close to Burp Suite Pro in the study's scoring. Location: Introduction, p. 16; Results, p. 59.
- Claim stated by thesis: Scanners had difficulty recognizing and maintaining authenticated state. Location: Discussion, pp. 60-61.

Notes for use:

Use this source carefully as supporting evidence and prefer peer-reviewed sources for central claims when available. Several literature-review statements inside the thesis are secondary citations and should not be cited as original evidence unless the original source is obtained.

---

### 6. Koman and Janiszewski - SCAnME - scanner comparative analysis and metrics for evaluation

- Citation key suggestion: `koman2025scanme`
- Full title: SCAnME - scanner comparative analysis and metrics for evaluation
- Authors: Jakub Koman, Marek Janiszewski
- Year: 2025
- Venue: International Journal of Information Security, 24, Article 147
- DOI: `10.1007/s10207-025-01054-8`
- Type of study: empirical scanner comparison and evaluation-methodology proposal
- Classification: CORE
- Themes: B, C, E, F, G, H, I

Research problem addressed:

The paper proposes and demonstrates SCAnME, a methodology for comparative evaluation of DAST scanners across functionality, effectiveness, performance, reporting, and usability. It addresses the need for fair scanner evaluation across multiple criteria and realistic usage configurations.

Methodology:

The authors define an evaluation methodology with several pillars, then evaluate selected scanners against OWASP Juice Shop and OWASP VulnerableApp. They compare scanner functionality, effectiveness against OWASP Top 10 categories, performance/time, and report quality. The paper discusses basic and advanced scan configurations and records true/false positives and negatives where applicable.

Tools/scanners/benchmarks evaluated:

- Scanners: OWASP ZAP, Wapiti, w4af, and Codename SCNR.
- Benchmarks/applications: OWASP Juice Shop and OWASP VulnerableApp.

Vulnerability classes relevant to this thesis:

The paper uses OWASP Top 10 categories. It is directly relevant to injection vulnerabilities, XSS/SQLi scanner detection, and scanner limitations around broken access control and other categories.

Main findings relevant to this thesis:

- The paper describes DAST scanners as consisting broadly of crawler, fuzzer, and analyzer components (Background, p. 2).
- It argues that effectiveness evaluation should include both real vulnerabilities and false/non-exploitable cases so that false positives can be measured (Methodology, pp. 4-6).
- It recommends repeated scans because DAST scan results can be affected by scanner errors or target overload, supporting reliability measurement (Methodology, pp. 4-6).
- It reports that scanner performance differs by target, configuration, and vulnerability class; scanners detect only specific OWASP Top 10 categories well (Results/Conclusion, pp. 11-17).
- It provides direct OWASP ZAP baseline evidence, including ZAP's precision/report quality strengths and low true-positive counts in parts of the evaluation (Results, pp. 11-16).
- It emphasizes that simply running DAST tools is insufficient for a thorough penetration test (Conclusion, pp. 16-17).

Limitations acknowledged by the authors:

- Crawling coverage was omitted from the methodology and would require dedicated metrics and target support (Limitations/future work, p. 17).
- The use of OWASP-maintained target applications may introduce bias (Limitations/future work, p. 17).
- Finding suitable evaluation targets is challenging, and a dedicated target may be needed for the methodology (Limitations/future work, p. 17).
- The methodology can be extended with additional metrics (Limitations/future work, p. 17).

Relevance to Section 2.1:

Very relevant for modern scanner-baseline evaluation, fair comparison metrics, negative cases, repeated runs, and ZAP evidence. This is a strong source for explaining why this thesis keeps scanner alerts separate from verifier-confirmed findings and why comparisons must be restricted to supported common scope.

Specific claims useful to cite:

- Claim stated by paper: DAST scanners can be viewed as having crawler, fuzzer, and analyzer components. Location: Background, p. 2.
- Claim stated by paper: Scanner effectiveness evaluation should account for false positives and false negatives, including non-exploitable/false cases. Location: Methodology, pp. 4-6.
- Claim stated by paper: Repeated scanner executions may be needed because scans can be nondeterministic or affected by errors/target overload. Location: Methodology, pp. 4-6.
- Claim stated by paper: Tested DAST scanners detected only some OWASP Top 10 categories effectively and struggled with categories such as broken access control. Location: Results/Conclusion, pp. 11-17.
- Claim stated by paper: No single scanner was best across all criteria; scanner usefulness depends on target and evaluation dimension. Location: Conclusion, pp. 16-17.
- Claim stated by paper: DAST alone is insufficient for a thorough penetration test. Location: Conclusion, pp. 16-17.

Notes for use:

This is one of the best sources for the thesis's fair-baseline-comparison discussion, especially because it is recent, includes ZAP, and explicitly discusses methodology.

---

### 7. Stafeev and Pellegrino - SoK: State of the Krawlers - Evaluating the Effectiveness of Crawling Algorithms for Web Security Measurements

- Citation key suggestion: `stafeev2024krawlers`
- Full title: SoK: State of the Krawlers - Evaluating the Effectiveness of Crawling Algorithms for Web Security Measurements
- Authors: Aleksei Stafeev, Giancarlo Pellegrino
- Year: 2024
- Venue: Proceedings of the 33rd USENIX Security Symposium, August 14-16, 2024, Philadelphia, PA, USA
- DOI: Not explicitly present in the supplied PDF
- Type of study: systematization of crawling algorithms and empirical crawler-evaluation study
- Classification: CORE
- Themes: A, B, C, G, H, I

Research problem addressed:

The paper studies how web crawlers are used in security and web-measurement research, how crawling algorithms are described and implemented, and how different crawler configurations affect coverage. It addresses the limited comparative evidence about crawler effectiveness in web security measurements and the difficulty of transferring crawling results across studies with different parameters, testbeds, and metrics.

Methodology:

The authors systematized crawling use in 403 security, privacy, web, and measurement papers selected from 7,840 papers, and separately analyzed 27 software-engineering papers that proposed 35 crawling techniques. They decomposed crawling approaches into page-similarity and navigation building blocks, reimplemented or patched techniques in Arachnarium, and evaluated crawler configurations on two datasets: DS1 with nine real-size and two benchmark web applications, and DS2 with 2,000 popular websites sampled from the CrUX Top 10K. Evaluation metrics include code coverage, JavaScript source coverage, and link coverage. The design and metrics are described in Sections 2-4, Tables 1, 5, and 6, and Figure 1.

Tools/scanners/benchmarks evaluated:

- Arachnarium, the authors' crawler-evaluation framework.
- Building-block crawling algorithms, including page-similarity and navigation strategies such as URL equality, DOM/tree-edit-distance variants, BFS, DFS, randomized BFS, randomized state selection, and JAW.
- Security-testing tools used as compound crawler implementations: Arachni, Skipfish, Wapiti, and OWASP ZAP. The authors turned off vulnerability detection features for these tools to evaluate crawling coverage rather than vulnerability detection (Section 3.4.2, p. 9).
- DS1 includes WordPress, OwnCloud, PrestaShop, Joomla, Drupal, Vanilla, phpBB, SCARF, HotCRP, WackoPicko, and AddressBook; DS2 uses a CrUX-based sample of popular websites (Table 5, p. 8).

Vulnerability classes relevant to this thesis:

The paper does not evaluate vulnerability detection by class. Its relevance is to attack-surface discovery and crawling, which are prerequisites for later vulnerability testing. It explicitly connects code coverage to automated web testing and black-box application scanners that explore attack surface to collect endpoints for vulnerability detection (Section 3.3, pp. 7-8).

Main findings relevant to this thesis:

- The paper supports the claim that crawler effectiveness is an important but under-studied part of web security measurements (Abstract and Introduction, pp. 2-3).
- The survey found substantial underspecification in published crawling methodologies. For example, Table 1 reports missing or unspecified navigation strategies, page similarity, navigation depth, navigation limits, and page-load waiting time across the surveyed papers (Section 2.1, Table 1, p. 4).
- The authors report that 273 of the 403 surveyed measurement papers did not navigate beyond a single page, while 130 used website navigation (Section 2.1.2, p. 4).
- Arachnarium evaluates crawler behavior with code, JavaScript source, and link coverage metrics, directly connecting coverage measurement to automated web testing and black-box scanner attack-surface exploration (Section 3.3, pp. 7-8).
- The empirical evaluation found that no single crawler configuration ranked first across all absolute and global coverage metrics, and randomized BFS-based configurations were often among the best-performing configurations (Section 4.2 and Discussion, pp. 10-13).
- The paper reports that commonly used algorithms such as URL equality and BFS did not perform best on average; switching algorithms improved coverage in measured cases (Discussion, Insight #4, p. 13).
- The paper reports that algorithm choice matters less under very tight crawling budgets, while increasing navigation depth can substantially increase coverage (Discussion, Insights #6 and #9, pp. 13-14).
- In the compound-tool comparison with vulnerability detection disabled, security testing tools lagged behind crawler configurations in global coverage; Arachni was the best-performing tool and ZAP ranked last in code coverage among the evaluated tools (Discussion, Insight #13, p. 14). This is crawling evidence only, not vulnerability-detection evidence.

Limitations acknowledged by the authors:

- The authors discuss ethical and validity concerns for crawling live public websites, including accidental collection of personal information and excessive request volume; they describe mitigations such as public unauthenticated pages, concurrency limits, sequential browser actions, and domain-level scheduling (Section 5.2, pp. 14-15).
- External validity is limited because confirming generalizability would require expanding the standalone application dataset, which is hard to do at scale (Section 5.2, p. 15).
- The evaluation uses three coverage metrics, and the authors note that correlations among metrics may not hold for other metrics (Section 5.2, p. 15).
- Dynamic links and JavaScript may lead to overestimation of covered or missed surface because many resources are discovered by only one crawler run (Section 5.2, p. 15).
- The paper focuses on crawling algorithms used in empirical studies and does not evaluate UI-testing approaches that may explore deeper behaviors (Related Works, p. 15).

Relevance to Section 2.1:

Highly relevant for attack-surface discovery and crawling. It provides modern evidence that crawling methodology, parameter choices, coverage metrics, and reproducibility details materially affect what surface is discovered before testing. It is especially useful for motivating why this thesis treats candidate discovery output as an explicit, auditable input to later prioritization rather than assuming that the attack surface is automatically or completely known.

Specific claims useful to cite:

- Claim stated by paper: Web crawlers are widely used in web security measurements, but their performance and impact had been only limitedly studied. Location: Abstract, p. 2.
- Claim stated by paper: The authors analyzed 403 measurement papers and 27 crawler-technique papers, identified 35 crawling techniques, and evaluated them using Arachnarium. Location: Introduction/contributions, pp. 2-3.
- Claim stated by paper: Many papers underspecify crawling algorithms or parameters such as navigation strategy, page similarity, depth, limits, and page-load waiting time. Location: Section 2.1.2 and Table 1, p. 4; Discussion Insight #1, p. 13.
- Claim stated by paper: Code, JavaScript source, and link coverage are used as crawler performance metrics, with code coverage connected to automated web testing and black-box application scanning. Location: Section 3.3, pp. 7-8.
- Claim stated by paper: The authors evaluated 102 crawler configurations and reduced page-similarity algorithms through a preliminary experiment before the main experiments. Location: Section 4, pp. 9-10.
- Claim stated by paper: No single crawler configuration ranked first across both absolute and global coverage metrics. Location: Discussion Insight #5, p. 13.
- Claim stated by paper: Randomized BFS configurations were often among the top-performing configurations, while commonly used algorithms did not necessarily perform best. Location: Section 4.2, pp. 10-11; Discussion Insights #4-#6, pp. 13-14.
- Claim stated by paper: Increasing navigation beyond a single page can substantially increase coverage, while additional re-crawls can also increase coverage across metrics. Location: Section 4.4, Figure 4 and Table 10, pp. 12-13.
- Claim stated by paper: Security-testing tools evaluated as crawlers, including ZAP, were not on par with crawler configurations in global coverage when vulnerability detection was disabled. Location: Discussion Insight #13, p. 14.

Notes for use:

The separate USENIX Security 2024 artifact appendix also exists and can be used as reproducibility support. Substantive crawling claims should now cite the full paper rather than the appendix. When using the ZAP-related claim, state clearly that ZAP was evaluated as a crawler with vulnerability detection disabled, not as a vulnerability scanner.

---

### 8. Urbano et al. - Reinforced WAVSEP: a Benchmarking Platform for Web Application Vulnerability Scanners

- Citation key suggestion: `urbano2022reinforced`
- Full title: Reinforced WAVSEP: a Benchmarking Platform for Web Application Vulnerability Scanners
- Authors: Luigi Urbano, Gaetano Perrone, Simon Pietro Romano
- Year: 2022
- Venue: International Conference on Electrical, Computer and Energy Technologies (ICECET 2022), Prague, Czech Republic, 20-22 June 2022
- DOI: `10.1109/ICECET55527.2022.9872956` (present in supplied PDF metadata)
- Type of study: benchmark proposal and empirical scanner comparison
- Classification: CORE
- Themes: B, E, F, G, H, I

Research problem addressed:

The paper addresses limitations of the WAVSEP benchmark for evaluating web application vulnerability scanners, especially missing vulnerability classes/techniques and the lack of non-vulnerable test cases needed for false-positive evaluation.

Methodology:

The authors extend WAVSEP by adding new vulnerable and non-vulnerable test cases, select multiple web application vulnerability scanners, define effectiveness metrics, execute scanners against original and reinforced WAVSEP, and compare scanner results.

Tools/scanners/benchmarks evaluated:

- Benchmark: original WAVSEP and Reinforced WAVSEP.
- Scanners: Wapiti, Arachni, OWASP ZAP, Skipfish, Nessus, and Syhunt Community (scanner table and results, pp. 3-5).

Vulnerability classes relevant to this thesis:

The benchmark includes reflected XSS, DOM XSS, SQL injection, blind SQL injection, command injection, XML external entity, LFI/RFI, open redirect, and related classes (Tables I-III, pp. 3-4).

Main findings relevant to this thesis:

- The paper explicitly motivates benchmark negative/non-vulnerable cases as necessary for evaluating scanner false positives (Introduction and Section IV, pp. 1 and 3).
- It uses standard TP/TN/FP/FN-derived metrics such as precision, recall, and F-measure (Section IV, p. 3).
- It reports scanner results over Reinforced WAVSEP, including OWASP ZAP and other comparable scanners (Section V, pp. 4-5).
- It shows that benchmark updates can change scanner evaluation outcomes because reinforced cases include additional vulnerability techniques and non-vulnerable cases (Sections IV-V, pp. 3-5).

Limitations acknowledged by the authors:

- The paper frames original WAVSEP itself as limited because it was outdated, lacked relevant vulnerability classes/techniques, and lacked sufficient non-vulnerable cases (Introduction and Section IV, pp. 1 and 3).
- Future work is mentioned for extending and improving the benchmark further (Conclusion/future work, pp. 5-6).

Relevance to Section 2.1:

Highly relevant for benchmark design, false-positive/true-negative evaluation, and direct ZAP comparison. It supports the thesis design decision to include negative/control cases and maintain explicit ground truth for post-run scoring.

Specific claims useful to cite:

- Claim stated by paper: Benchmark platforms for web vulnerability scanners should include vulnerable and non-vulnerable cases because non-vulnerable cases are important for evaluating false positives. Location: Abstract/Introduction, p. 1; Section IV, p. 3.
- Claim stated by paper: Original WAVSEP had limitations, including outdated coverage and lack of certain vulnerability classes/techniques. Location: Introduction, p. 1; Section IV, p. 3.
- Claim stated by paper: Reinforced WAVSEP uses TP, TN, FP, and FN definitions and derived metrics including precision, recall, and F-measure. Location: Section IV, p. 3.
- Claim stated by paper: OWASP ZAP is included among evaluated scanners. Location: Scanner selection/results, pp. 3-5.
- Claim stated by paper: Scanner results differ between original and Reinforced WAVSEP because added cases change coverage and evaluation difficulty. Location: Section V, pp. 4-5.

Notes for use:

Use the paper for benchmark and metric design. If exact numbers from Tables V-VII are needed, verify directly from the PDF tables before citing.

---

### 9. Zhang et al. - Efficiency and Effectiveness of Web Application Vulnerability Detection Approaches: A Review

- Citation key suggestion: `zhang2021efficiency`
- Full title: Efficiency and Effectiveness of Web Application Vulnerability Detection Approaches: A Review
- Authors: Bing Zhang, Jingyue Li, Jiadong Ren, Guoyan Huang
- Year: 2021
- Venue: ACM Computing Surveys, 54(9), Article 190
- DOI: `10.1145/3474553`
- Type of study: systematic literature review
- Classification: CORE
- Themes: A, B, E, F, G, H

Research problem addressed:

The paper reviews web application vulnerability detection approaches with a focus on effectiveness and efficiency. It addresses the lack of comprehensive comparison across vulnerability-detection methods, measured artifacts, empirical metrics, and benchmark/test-suite usage.

Methodology:

The authors conducted a systematic literature review. They filtered 775 articles to 105 primary studies and classified approaches, artifacts, effectiveness metrics, efficiency metrics, evaluated applications, and test suites. They summarize injection and non-injection vulnerability-detection approaches separately.

Tools/scanners/benchmarks evaluated:

The paper reviews detection approaches rather than running a new tool experiment. It identifies web applications and test suites used by prior studies, including benchmark suites with known vulnerabilities.

Vulnerability classes relevant to this thesis:

The review explicitly covers injection vulnerabilities, including SQL injection and XSS, and other vulnerability types including parameter tampering, access control, workflow bypass, workflow violation, and IDOR (Sections 2 and 5, pp. 2-3 and pp. 17-21).

Main findings relevant to this thesis:

- The review found that 78 of 105 primary studies focused on injection vulnerabilities, showing that injection dominates the evaluated literature (Abstract/Introduction, pp. 1-2; Section 5.3, pp. 16-17).
- The paper reports that only a subset of injection studies achieved or reported strong FP/FN or precision/recall results, and many other approaches lacked adequate or satisfactory evaluation (Abstract/Introduction, pp. 1-2; Section 5.3, pp. 16-17).
- It highlights that efficiency reporting is incomplete and difficult to compare because time/memory metrics and experimental settings are often not comparable (Section 5.3, pp. 16-17 and pp. 21-22).
- It states that only a minority of primary studies present detailed numbers/types of vulnerabilities in evaluated applications/test suites, which limits precise FP/FN calculation (Abstract/Introduction, pp. 1-2; Section 5.4, pp. 27-31).
- It explicitly supports the need for benchmark applications/test suites with known vulnerability types and numbers (Section 5.4 and Conclusion, pp. 27-35).
- It shows that non-injection categories such as access control and IDOR are less thoroughly evaluated than injection categories (Sections 2 and 5.3, pp. 2-3 and pp. 17-21).

Limitations acknowledged by the authors:

- The systematic review is limited by search strategy, selected databases, filtering criteria, and paper selection/extraction decisions (Threats to validity, Section 6, pp. 31-34).
- The authors note that many primary studies do not report enough benchmark/test-suite detail or effectiveness/efficiency data, limiting comparability (Sections 5.4 and 7, pp. 27-35).

Relevance to Section 2.1:

Very relevant as a broad review of effectiveness, efficiency, benchmark design, and gaps in web application vulnerability detection research. It supports why the thesis should report TP/FP/FN/TN, efficiency, known ground truth, and limitations by vulnerability class.

Specific claims useful to cite:

- Claim stated by paper: 78 of 105 primary studies focused on injection vulnerabilities. Location: Abstract/Introduction, pp. 1-2; Section 5.3, pp. 16-17.
- Claim stated by paper: Only 21 of 105 primary studies presented detailed information about numbers/types of vulnerabilities in evaluated applications/test suites. Location: Abstract/Introduction, pp. 1-2; Section 5.4, pp. 27-31.
- Claim stated by paper: To calculate false positives and false negatives precisely, the number of vulnerabilities in the evaluated application/test suite must be known. Location: Section 5.4, pp. 27-31.
- Claim stated by paper: Efficiency results such as time and memory consumption are often missing or not comparable across studies. Location: Section 5.3, pp. 16-17 and pp. 21-22.
- Claim stated by paper: The research community needs more benchmark applications/test suites with known vulnerability types and numbers. Location: Conclusion, pp. 34-35.
- Claim stated by paper: Other categories such as access control/IDOR are less mature or less thoroughly evaluated than injection categories. Location: Sections 2 and 5.3, pp. 2-3 and pp. 17-21.

Notes for use:

This is a strong source for methodological motivation. Do not use it as direct evidence about one specific scanner's performance unless the paper directly reports that scanner-specific result.

---

### 10. Yang et al. - TPSQLi: Test Prioritization for SQL Injection Vulnerability Detection in Web Applications

- Citation key suggestion: `yang2024tpsqli`
- Full title: TPSQLi: Test Prioritization for SQL Injection Vulnerability Detection in Web Applications
- Authors: Guan-Yan Yang, Farn Wang, You-Zong Gu, Ya-Wen Teng, Kuo-Hui Yeh, Ping-Hsueh Ho, Wei-Ling Wen
- Year: 2024
- Venue: Applied Sciences, 14, Article 8365
- DOI: `10.3390/app14188365`
- Type of study: proposed SQL-injection test-prioritization method and empirical comparison
- Classification: SUPPORTING
- Themes: D, E, G, H, I

Research problem addressed:

The paper addresses test prioritization for SQL injection vulnerability detection. Its central problem is how to order SQL-injection testing techniques or payload classes so that vulnerabilities are exposed earlier and testing time is reduced.

Methodology:

The authors propose TPSQLi, a framework and prioritization algorithm for SQLi testing. The method extracts GET and POST parameters, applies a Test Prioritization Panel, executes SQLi testing techniques, records timing and success/failure feedback, and updates strength-weakness vectors that influence later test order. The prioritization algorithm is presented in Section 4.4 and Algorithm 1. The evaluation compares TPSQLi with ART4SQLi over two DVWA SQLi targets and eight real-world cases with publicly disclosed SQL injection vulnerabilities. The authors run five rounds of testing and report timing and false-positive-oriented metrics (Section 5, Tables 2-5, pp. 11-16).

Tools/scanners/benchmarks evaluated:

- TPSQLi, the authors' proposed framework/method.
- ART4SQLi, used as the comparison baseline.
- DVWA SQL-blind and DVWA SQL targets.
- Eight real-world cases with publicly disclosed SQL injection vulnerabilities.
- The paper also mentions ZAP and SQLMAP as tools where SQLi prioritization is limited or listed as an area requiring expansion, based on the authors' inspection of tool documentation/behavior (Motivation, pp. 2-3).

Vulnerability classes relevant to this thesis:

The paper is specific to SQL injection. It discusses several SQLi categories: boolean-based blind, union-based, stacked, inline queries, error-based, and time-based blind SQL injection (Section 2.3, pp. 4-5; Table 1, pp. 2-3).

Main findings relevant to this thesis:

- The paper directly supports treating security-test prioritization as a distinct effectiveness and efficiency problem: it argues that ordering tests can reduce testing cost and cause important tests to execute earlier (Section 2.2, p. 4).
- It distinguishes prioritization from selection and minimization: prioritization reorders test cases without removing them (Section 2.2, p. 4).
- In the SQLi setting, the authors use previous test outcomes, exploit timing, and success/failure feedback to adjust later test order (Sections 4.3-4.5, pp. 7-11).
- The evaluation reports that TPSQLi reduced time to expose vulnerabilities compared with ART4SQLi on most evaluated targets, while some targets saw no improvement where the original order was already optimal (Section 5.3, Table 4, p. 15; Table 5, p. 16; Conclusion, p. 17).
- The paper's evaluation emphasizes timing and efficiency, which is relevant to this thesis's concern with bounded testing budgets and time/request efficiency.

Limitations acknowledged by the authors:

- The paper does not present a separate limitations section.
- The method and evaluation are SQL-injection-specific and should not be generalized to XSS candidate ranking or broader attack-surface prioritization without further evidence.
- The evaluation compares against ART4SQLi rather than a broad set of DAST scanners, and the target set is limited to two DVWA SQLi targets and eight disclosed SQLi cases (Section 5, pp. 11-16).
- The authors' effectiveness discussion states that because TPSQLi terminates once the last valid payload is detected, neither true negatives nor false negatives are accounted for in that analysis (Section 5.3.3, p. 16). This limits direct comparability with evaluation designs that report full TP/FP/FN/TN case-level outcomes.
- Future work is framed around machine learning, including large language models and reinforcement learning, for further prioritization improvements (Conclusion, p. 17).

Relevance to Section 2.1:

Useful as direct academic support that security-test prioritization can be framed as an effectiveness/efficiency problem. However, its scope is narrower than this thesis: TPSQLi prioritizes SQLi testing techniques/payload order using previous outcomes and timing, whereas this thesis investigates ranking already discovered structured attack-surface candidates under a bounded LLM authority boundary. The paper should therefore be cited to support the general importance of prioritization, not as an equivalent method or direct precedent for LLM candidate ranking.

Specific claims useful to cite:

- Claim stated by paper: Test case prioritization orders tests so higher-priority tests are executed earlier and differs from test selection/minimization because it does not remove cases. Location: Section 2.2, p. 4.
- Claim stated by paper: The authors introduce a SQLi-specific prioritization method intended to improve testing efficiency by leveraging previous test outcomes and dynamic score updates. Location: Abstract, p. 1; Section 4.3, p. 7.
- Claim stated by paper: TPSQLi extracts parameters from GET and POST requests before prioritizing SQLi tests. Location: Section 4.2, p. 7.
- Claim stated by paper: The prioritization algorithm uses strength-weakness vectors, timing, and success/failure feedback to update test order. Location: Section 4.4 and Algorithm 1, pp. 7-10.
- Claim stated by paper: The evaluation uses two DVWA SQLi targets and eight real-world cases with publicly disclosed SQL injection vulnerabilities. Location: Section 5 and Table 2, pp. 11-12.
- Claim stated by paper: TPSQLi is compared with ART4SQLi using timing measurements and reported improvements on most targets. Location: Section 5.3, Table 4, p. 15; Table 5, p. 16.
- Claim stated by paper: The authors' analysis does not account for true negatives or false negatives because TPSQLi terminates once the last valid payload is detected. Location: Section 5.3.3, p. 16.
- Claim stated by paper: Future work includes exploring machine learning, including LLMs and reinforcement learning, for test prioritization. Location: Conclusion, p. 17.

Notes for use:

Do not imply that TPSQLi is equivalent to the proposed thesis framework. TPSQLi prioritizes SQLi technique/payload execution using historical timing and outcome feedback; this thesis's XSS ablation ranks existing discovered candidates with deterministic execution and verification held outside the LLM.

## Synthesis

### 1. Recommended CORE papers for Section 2.1

- `doupe2010johnny`: best source for early empirical evidence that black-box scanner effectiveness depends on crawling, input-vector discovery, attack generation, and response analysis; also strong for benchmark design and scanner FP/FN limitations.
- `doupe2012enemy`: best source for state-aware crawling and the discoverability problem in black-box scanning.
- `zhang2021efficiency`: best broad systematic review for effectiveness/efficiency, benchmark/test-suite limitations, and the relative maturity of injection versus non-injection vulnerability detection.
- `urbano2022reinforced`: best source for benchmark design with vulnerable and non-vulnerable cases and direct scanner comparison including ZAP.
- `koman2025scanme`: best recent source for fair DAST scanner evaluation, ZAP comparison, repeated scans, supported-scope evaluation, and scanner limitations across OWASP categories.
- `brandi2024sniping`: best source for input-handling vulnerability testing, input-point prioritization, oracle/verifier concerns, and ZAP comparison in a modern fuzzing context.
- `stafeev2024krawlers`: best recent source for crawling methodology, attack-surface discovery coverage, crawler-configuration effects, and reproducibility problems in crawler evaluation.

### 2. Recommended SUPPORTING papers

- `aydos2022security`: useful for high-level field mapping, terminology, DAST prevalence, and FP/FN concerns, but less useful for detailed scanner effectiveness.
- `khalil2018johnny`: useful supporting evidence for open-source scanner evaluation, ZAP, crawling difficulty, configured scans, and scanner speed/usability, but should be treated with caution because it is a master's thesis rather than a peer-reviewed paper.
- `yang2024tpsqli`: useful direct support for treating security-test prioritization as an efficiency problem, but it is SQLi-specific and not equivalent to this thesis's structured candidate-ranking problem.

### 3. Papers that can probably be excluded or used only sparingly

- `khalil2018johnny` should not carry central claims if the same point is supported by peer-reviewed papers such as Doupe et al., Koman and Janiszewski, or Urbano et al. It remains useful for practical ZAP/open-source scanner context.
- `aydos2022security` may be redundant if Section 2.1 becomes too long, because Zhang et al. provides a stronger effectiveness/efficiency review and Koman/Urbano/Doupe provide direct scanner evidence. However, Aydos remains useful for broad security-testing mapping.
- `yang2024tpsqli` can be used sparingly if Section 2.1 already has enough prioritization support from Brandi et al. and crawler/scanner workflow papers. Its value is strongest for one paragraph on test prioritization as an efficiency problem.

### 4. Chronological development of the field supported by this source set

- 2010: Doupe et al. evaluate black-box web vulnerability scanners using WackoPicko and show that crawling and realistic benchmark design are central to scanner effectiveness (`doupe2010johnny`).
- 2012: Doupe et al. extend the discussion from basic crawling to state-aware black-box testing, showing that state changes and unreachable code paths limit vulnerability discovery (`doupe2012enemy`).
- 2018: Khalil evaluates open-source scanners including ZAP across WIVET, WAVSEP, and WackoPicko, reinforcing that crawling coverage, configuration, and runtime/human effort affect scanner results (`khalil2018johnny`).
- 2021: Zhang et al. synthesize a decade of web application vulnerability detection research and highlight major gaps in effectiveness, efficiency, benchmark detail, and known ground truth (`zhang2021efficiency`).
- 2022: Aydos et al. map web application security testing literature and show the breadth of techniques, tools, automation levels, vulnerability classes, and FP/FN concerns (`aydos2022security`).
- 2022: Urbano et al. update WAVSEP into Reinforced WAVSEP, emphasizing negative/non-vulnerable cases and scanner-comparison metrics (`urbano2022reinforced`).
- 2024: Stafeev and Pellegrino systematize crawler use in security/web measurement studies and evaluate crawler configurations with code, link, and JavaScript coverage metrics, showing that crawling methodology and configuration choices materially affect discovered surface (`stafeev2024krawlers`).
- 2024: Brandi et al. propose a rule-based input-handling fuzzer and emphasize input-point prioritization, oracle design, payload/request-efficiency trade-offs, and ZAP comparison (`brandi2024sniping`).
- 2024: Yang et al. propose TPSQLi, a SQLi-specific test-prioritization approach that reorders SQLi testing techniques/payloads to improve efficiency relative to ART4SQLi (`yang2024tpsqli`).
- 2025: Koman and Janiszewski propose SCAnME, a recent multi-dimensional scanner-evaluation methodology, and provide modern ZAP/DAST baseline evidence (`koman2025scanme`).

### 5. Strongest documented limitations of traditional automated web security testing

- Crawling/discovery limits: scanners cannot test pages, states, or code paths they do not reach, and crawler configuration materially affects discovered surface. Strongest support: `doupe2010johnny`, `doupe2012enemy`, `khalil2018johnny`, `stafeev2024krawlers`.
- Stateful application behavior: state-changing actions and session/authentication behavior can reduce scanner coverage and accuracy. Strongest support: `doupe2012enemy`, `khalil2018johnny`.
- False positives and false negatives: scanner output requires evaluation against known ground truth and may contain both missed vulnerabilities and spurious alerts. Strongest support: `doupe2010johnny`, `zhang2021efficiency`, `koman2025scanme`, `urbano2022reinforced`, `aydos2022security`.
- Benchmark limitations: many test suites are incomplete, outdated, inaccessible, or lack known vulnerability counts and negative cases. Strongest support: `zhang2021efficiency`, `urbano2022reinforced`, `doupe2010johnny`, `koman2025scanme`.
- Efficiency and budget trade-offs: request volume, scan time, payload count, and configuration effort affect practical scanner use. Strongest support: `brandi2024sniping`, `koman2025scanme`, `khalil2018johnny`, `zhang2021efficiency`, `doupe2010johnny`.
- Test prioritization as an efficiency problem: ordering security tests can change how quickly vulnerabilities are exposed under time or budget constraints. Strongest support: `yang2024tpsqli` for SQLi-specific test ordering; `brandi2024sniping` for input-point prioritization in input-handling fuzzing; `stafeev2024krawlers` for discovery coverage under crawling parameters.
- Uneven vulnerability-class coverage: injection vulnerabilities are studied more heavily than access-control and logic flaws; scanners often perform better on some categories than others. Strongest support: `zhang2021efficiency`, `koman2025scanme`, `doupe2010johnny`.
- Oracle/verifier problem: deciding whether observations constitute confirmed vulnerability evidence is difficult and affects false positives. Strongest support: `brandi2024sniping`, `doupe2010johnny`, `koman2025scanme`.

### 6. Claims that still lack sufficient evidence in the current source set

- Claims about LLMs in web security testing are not supported by this Section 2.1 source set. They belong in later Section 2.2/2.3 sources on LLMs, software testing, and LLM-assisted security testing.
- Claims about PentestGPT or autonomous website hacking agents are not supported by these PDFs and require their original papers.
- Claims about OWASP ZAP's current 2026 behavior should not be made from these papers alone, because scanner versions and rules change. The current source set supports ZAP as a comparable scanner and historical baseline, not its latest capabilities.
- Claims about IDOR-specific black-box scanner effectiveness are only partially supported. Zhang et al. supports that access-control/IDOR-style vulnerabilities are less thoroughly evaluated than injection categories, and Koman supports scanner difficulty with broken access control, but more IDOR-specific original work would strengthen the thesis.
- Claims about candidate prioritization as an explicit ranking problem are now better supported, but still not fully covered. Yang et al. supports SQLi-specific test prioritization, and Brandi et al. supports input-point prioritization, but neither is equivalent to this thesis's LLM-based ranking of already discovered structured candidates across held-out XSS scenarios.
- Claims about reproducibility of proprietary hosted LLMs are outside this source set and should be supported by LLM evaluation/reproducibility literature.

### 7. Cited works inside these papers that appear important enough to obtain before writing

- Suto's 2007 and 2010 scanner case studies, because Khalil and other works discuss them as early scanner-evaluation evidence. Treat Khalil's discussion as secondary until the originals are checked.
- Bau et al.'s scanner-evaluation study, discussed by Khalil and other related-work sections, for older empirical scanner performance evidence.
- WIVET and original WAVSEP papers/documentation, if Section 2.1 needs benchmark history in detail.
- Original papers on access-control/IDOR detection cited by Zhang et al., especially if Section 2.1 or later sections need a stronger foundation for IDOR evaluation beyond injection-focused DAST.
- Papers on oracle problems in software testing cited by Brandi et al., if the thesis wants to discuss deterministic verification/oracle design beyond web-scanner comparisons.
- ART4SQLi, because Yang et al. compares TPSQLi against it and the original may be needed if the thesis discusses SQLi-specific security-test prioritization in detail.
- Alptekin et al., "Towards prioritizing vulnerability testing", cited by Yang et al., because it appears directly related to vulnerability-test prioritization beyond SQLi-specific payload ordering.
- Primary OWASP ZAP documentation or peer-reviewed scanner studies using the exact baseline style relevant to the thesis, if the final text makes detailed claims about ZAP's behavior or configuration.
