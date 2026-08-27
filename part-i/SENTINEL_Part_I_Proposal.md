---
title: SENTINEL — Graduation Project Part I (Approved Proposal Baseline)
status: FROZEN — this is the submitted Part I document. Do not silently change scope from it.
---

GRADUATION PROJECT I
# SENTINEL
An Evidence-Driven Agentic Investigation and Controlled Response System
for Security Operations
Project Proposal and Feasibility Documentation

| Program | B.Sc. Computer Science |
|---|---|
| Course | Graduation Project I |
| Team | [Student Names / IDs] |
| Supervisor | [Supervisor Name] |
| Department / College | [Department / College] |
| Academic Year | 2026 |

Proposal message: The alert is easy. The triage is the problem.

## Executive Summary
SENTINEL is a proposed AI-assisted security operations platform designed to reduce the time and effort required to investigate cybersecurity alerts. Traditional detection rules are effective at identifying suspicious patterns, but they often do not contain enough context to determine whether an event represents a real attack or legitimate activity. SENTINEL addresses this gap by combining a high-recall detection layer with a read-only, tool-using AI investigation agent that can gather additional evidence, correlate related events, consider benign explanations, reconstruct an attack chain, and propose an appropriate response.
The proposed system is deliberately designed around trust and measurability. The AI does not directly execute security actions. Instead, it produces evidence-backed findings and proposed actions; a deterministic policy engine decides whether an action is allowed, requires human approval, or must be denied. Approved actions are then executed through a separate controlled response component inside an isolated laboratory environment.
The project will be evaluated using paired attack and benign-look-alike scenarios. The planned study compares rule-based triage, single-shot LLM analysis, and adaptive tool-using investigation. This allows the team to measure whether agentic investigation provides real value beyond simply giving a language model a large amount of log data. The project therefore contributes both a complete software system and an evidence-based experimental evaluation suitable for a Computer Science graduation project.

> Why this proposal is strong SENTINEL is not a chatbot connected to security logs. It is a complete software system with detection, incident management, structured evidence acquisition, AI-assisted reasoning, deterministic safety controls, controlled response automation, and measurable evaluation.


## 1. Proposal at a Glance

| Project domain | Artificial Intelligence, Cybersecurity, Security Automation, Software Engineering |
|---|---|
| Primary problem | Security alerts often lack the context needed to distinguish real attacks from legitimate activity. |
| Proposed solution | A read-only AI investigation agent that gathers evidence using controlled tools and produces evidence-backed incident conclusions and response plans. |
| Human role | Human approval remains available for disruptive actions; autonomy is governed by a deterministic policy engine. |
| Planned environment | Controlled laboratory with authentic Windows/Linux/network telemetry and reproducible attack and benign scenarios. |
| Core comparison | Rules only vs. single-shot LLM vs. adaptive tool-using AI investigation. |
| Main outputs | Working platform, evaluation benchmark, technical report, experimental results, final demonstration. |
| Team size | Five Computer Science students with modular responsibilities and shared integration checkpoints. |


## 2. Introduction and Background
Modern security operations rely on many detection mechanisms such as authentication rules, process monitoring, network monitoring, and endpoint telemetry. These mechanisms can identify suspicious behavior quickly, but a security alert is usually only the beginning of an investigation. Analysts still need to gather context from several sources before deciding whether an alert is malicious, benign, or inconclusive. Current NIST incident-response guidance similarly treats detection, response, and recovery as connected parts of cybersecurity risk management [1].
This makes incident triage a suitable area for intelligent automation. The task is procedural and evidence-driven, but it is not completely static: the next piece of information an analyst needs depends on the evidence already discovered. For example, a burst of failed logins may indicate a brute-force attack, a stale service credential, or a legitimate user repeatedly entering the wrong password. The correct conclusion requires additional evidence such as source history, account role, change windows, post-login activity, and related events.
SENTINEL proposes to use an AI agent specifically for this adaptive investigation process. The agent will not replace the detection layer and will not be trusted with unrestricted control of the environment. Its role is to gather the right evidence, organize that evidence into an understandable incident explanation, and propose the next action under explicit safety constraints.

## 3. Problem Statement

> Problem statement Security operations teams can detect suspicious activity, but they still spend significant effort manually triaging alerts because the context needed to distinguish a real attack from legitimate activity is distributed across multiple data sources. Static rules cannot always decide which additional evidence is needed, while unrestricted AI automation introduces safety and trust concerns.

The project addresses two connected problems:
1. Investigation problem: a security alert often does not contain enough information to make a reliable incident decision, and the required evidence depends on what earlier evidence reveals.
1. Trust problem: a system that can recommend or perform containment actions must be constrained so that incorrect AI decisions cannot freely disrupt users, hosts, or services.

## 4. Motivation and Project Significance
- Combines modern AI agents with a real systems problem rather than using an LLM only for text generation.
- Requires substantial Computer Science work across backend engineering, databases, APIs, security telemetry, rule processing, agent orchestration, user interface design, testing, and evaluation.
- Produces measurable results instead of relying only on a visually impressive demonstration.
- Supports both cybersecurity-oriented careers and broader AI/software engineering careers.
- Introduces an explicit AI safety boundary: the AI investigates and proposes, while deterministic code authorizes and executes.

## 5. Proposed Solution
SENTINEL will operate as a closed-loop investigation and response platform. A controlled laboratory generates authentic telemetry. A detection layer raises alerts with intentionally high recall. Related alerts are grouped into incidents. A read-only AI investigation agent then uses a limited set of tools to retrieve the context required to decide whether the incident is malicious or benign. The agent produces a structured verdict, evidence references, likely attack behavior, risk factors, and a response plan. Deterministic components then calculate severity, apply autonomy policy, and authorize only permitted response actions.
Figure 1. Proposed high-level SENTINEL architecture.

### 5.1 Why an AI Agent Instead of a Single Prompt?
A single LLM prompt can analyze information that is already provided to it, but it does not decide which evidence to retrieve from separate systems unless that retrieval capability is explicitly engineered. SENTINEL uses an adaptive agent because the investigation is sequential: one finding creates the next question. The proposed evaluation will directly test whether this adaptive evidence acquisition is better than giving the same model a preassembled bundle of all available context.

### 5.2 Safety Boundary
The AI agent is read-only. It can query evidence and propose actions, but it cannot directly block an address, disable an account, or isolate a host. Proposed actions pass to a deterministic policy engine. The policy engine considers autonomy level, confidence, target type, reversibility, and protected entities before returning ALLOW, REQUIRE APPROVAL, or DENY. A separate executor performs only actions from a fixed catalog. This separation is a central design principle of the project and is consistent with current guidance on managing generative-AI risk and constraining agentic systems through explicit permissions and controls [6], [7].

## 6. Project Objectives
1.  Build a reproducible laboratory that produces authentic telemetry for attack and benign-look-alike activity.
2.  Implement a detection layer that raises security alerts from normalized telemetry.
3.  Implement a tool-using, read-only AI agent that gathers additional evidence and produces structured incident conclusions.
4.  Correlate evidence and related alerts into an understandable incident timeline and attack chain.
5.  Map observed malicious behavior to relevant MITRE ATT&CK techniques.
6.  Calculate risk/severity using deterministic code based on evidence-derived factors.
7.  Implement a deterministic autonomy and approval policy for security response actions.
8.  Execute a limited set of reversible response actions inside the laboratory environment.
9.  Build a labeled benchmark containing both attacks and benign look-alikes.
10.  Evaluate whether adaptive agentic investigation improves triage quality, false-positive handling, evidence use, and response quality compared with simpler baselines.

## 7. Proposed Academic and Technical Contribution
The project is intended to contribute more than a functional SOC-style dashboard. Its main proposed contributions are:

| Contribution | Purpose |
|---|---|
| Evidence-based investigation quality | Define required evidence for each incident class and measure both what the system acquired and what the model actually used in its verdict. |
| Fair comparison of investigation architectures | Compare rules, single-shot LLM analysis, exhaustive context, and adaptive tool-based investigation so improvements can be attributed to the architecture rather than simply more information. |
| Controlled AI autonomy | Separate AI recommendations from deterministic authorization and measure the difference between prohibited actions proposed by the model and prohibited actions actually executed by the system. |
| Paired attack/benign benchmark | Create reproducible attack cases and benign twins that trigger similar detections, allowing meaningful false-positive evaluation. |


## 8. Project Scope

### 8.1 Strong Target Scope
- Four attack scenario families with corresponding benign-look-alike variants.
- Windows/Linux/network telemetry in a controlled laboratory.
- Deterministic security detection rules and limited behavioral/volumetric scoring where it adds value.
- Incident correlation and case management.
- One read-only AI investigation agent with controlled evidence tools.
- Evidence citations and a provenance-carrying evidence graph for analyst verification.
- Deterministic risk scoring and policy-based autonomy levels.
- A small catalog of reversible response actions executed only inside the lab.
- A SOC-style dashboard focused on incidents, evidence, agent activity, approvals, and evaluation results.
- A development benchmark and a protected held-out benchmark for final results.

### 8.2 Explicitly Out of Scope for the Initial Project
- Attacking real external systems or networks.
- Allowing the LLM to execute arbitrary shell commands or unrestricted security actions.
- Building a full commercial SIEM platform.
- Multiple AI agents unless later evidence shows a clear technical need.
- Kubernetes or large-scale enterprise infrastructure that does not contribute to the research question.
- Training a large language model from scratch.
- Supporting dozens of attack types before the four core scenarios are complete and evaluated.

## 9. Planned Security Scenarios

| Scenario | What it tests |
|---|---|
| S1 — Credential attack leading to account compromise | Tests temporal correlation: many failed logins, a successful authentication, and post-login activity must be connected before deciding whether compromise occurred. |
| S2 — Privilege escalation and persistence | Tests multi-stage incident correlation and the ability to merge later suspicious activity into an evolving case. |
| S3 — Suspicious endpoint execution / living-off-the-land | Tests benign-vs-malicious disambiguation where similar command patterns may appear in both administrative work and attacker activity. |
| S4 — Data staging and exfiltration indicators | Tests cross-source correlation, network/file evidence, volumetric reasoning, and business-impact context. |

Each malicious scenario will have benign look-alike cases that trigger similar detection logic. This prevents the evaluation from becoming a simple test of whether obvious attack patterns can be recognized.

## 10. Proposed Methodology
1.  Create an isolated laboratory containing monitored hosts, a routed attacker segment, telemetry collection, and controlled response points.
2.  Generate authentic attack and benign activity and normalize the resulting telemetry into a common event format.
3.  Apply deterministic detection logic to produce alerts and group related alerts into incidents.
4.  Run the investigation agent on incidents using controlled read-only tools.
5.  Generate structured verdicts containing evidence citations, attack-chain information, risk factors, and proposed actions.
6.  Calculate risk and apply deterministic policy rules to authorize, deny, or require approval for response actions.
7.  Execute approved actions inside the lab and maintain a complete audit trail.
8.  Run the benchmark using multiple comparison arms and report statistical and operational metrics.

### 10.1 Laboratory Network and Enforcement Design
During feasibility design, the team identified an important networking issue: if attacker and victim systems share the same network segment, same-segment traffic can bypass a default gateway. A gateway-only block could therefore appear to succeed without actually stopping the traffic. SENTINEL addresses this by separating the routed attacker segment from the victim segment so cross-segment attack traffic passes through the gateway enforcement point. Host isolation is enforced locally on the monitored endpoint, while a separate management network preserves telemetry and responder control. This two-tier enforcement design distinguishes perimeter blocking from endpoint isolation and makes containment actions directly verifiable during evaluation and the live demonstration.

## 11. Evaluation Plan
The proposal will be evaluated as a system and as an experiment. The main comparison is designed to answer whether adaptive evidence acquisition provides value beyond simpler approaches.

| Evaluation arm | Purpose |
|---|---|
| A1 — Rules only | Traditional deterministic baseline with no LLM investigation. |
| A2a — Raw single-shot LLM | The model receives a capped raw event window and produces one verdict. |
| A2b — Full-context single-shot LLM | The model receives a deterministic bundle containing the same information universe available to the agent, but without adaptive retrieval. |
| A2c — Oracle evidence bundle | Research-only upper bound using exactly the ground-truth required evidence; separates retrieval failure from reasoning failure. |
| A3 — Tool-using agent | The proposed system adaptively selects which evidence to retrieve and stops when sufficient information is available. |


### 11.1 Planned Metrics
- Incident detection precision, recall, F1, and false-positive rate.
- Malicious / benign / inconclusive verdict accuracy.
- MITRE ATT&CK mapping precision/recall where applicable.
- Evidence Coverage: how much required evidence the system successfully obtained.
- Evidence Utilization: how much required evidence the model actually cited in its final verdict.
- Productive-call and redundant-call ratios for agentic investigation.
- Required-action recall and response-plan precision on malicious incidents.
- Benign no-action accuracy and unnecessary-action rate.
- Prohibited-action proposal rate (agent quality) and prohibited-action execution rate (system safety; target = 0).
- Latency, token usage, cost per incident, and run-to-run stability.

### 11.2 Benchmark Validity
To reduce evaluation bias, benchmark cases will be defined from scenario specifications before serious prompt tuning. Ground-truth evidence and expected actions will be independently reviewed. A development split will be used for tuning and iteration, while a held-out split will remain protected and will be used only for final evaluation. This prevents the team from repeatedly tuning the system against the same final test cases.

## 12. Preliminary Technology Plan

| Area | Planned technology |
|---|---|
| Backend | Python, FastAPI, Pydantic, SQLAlchemy |
| Database | PostgreSQL |
| Frontend | React, TypeScript, Vite |
| Deployment | Docker Compose |
| Telemetry | Windows Event Log / Sysmon [4], Linux logs, Fluent Bit [10], and Zeek [5] where required |
| Detection | Sigma-format rules [3] with a controlled evaluator |
| AI | A frontier LLM API during development; local-model comparison as an evaluation arm if resources allow |
| Security framework | MITRE ATT&CK [2] for technique taxonomy |
| Visualization | Evidence/timeline views in the dashboard |

The final implementation stack may be simplified if a component does not contribute to the project objectives. The project intentionally avoids infrastructure complexity that does not improve the research or system evaluation.

## 13. Proposed Team Responsibilities

| Team member | Primary responsibility |
|---|---|
| Member 1 | AI investigation agent, system architecture, evidence model, deterministic risk/policy design, evaluation definitions. |
| Member 2 | Laboratory, telemetry collection, detection engineering, incident correlation, response-side lab integration. |
| Member 3 | Backend services, PostgreSQL data layer, APIs, approval workflow, response orchestration, deployment. |
| Member 4 | Frontend dashboard, incident/evidence views, approval interface, evaluation visualization. |
| Member 5 | Scenario execution, benign twins, benchmark case population, threat-intelligence fixtures, integration/QA support. |


## 14. Project Phases and Timeline
The graduation project is divided into two major parts. This document covers Part I, while the full implementation is planned for Part II after proposal approval.

| Phase | Main activities |
|---|---|
| Part I — Proposal and Documentation | Define the problem, motivate the solution, establish scope, architecture, methodology, evaluation plan, feasibility, risks, and project schedule. Present the idea to the academic panel and obtain approval. |
| Part II — Implementation and Evaluation | Build the laboratory and software platform, integrate detection and agent components, execute the benchmark, analyze results, produce the final report, and demonstrate the system. |


### 14.1 Proposed Part II Implementation Shape

| Weeks | Target |
|---|---|
| 1–2 | Environment verification, contracts, first end-to-end vertical slice. |
| 3–4 | Core detection/correlation, evidence structures, initial benchmark cases. |
| 5–7 | Investigation tools, ATT&CK mapping, policy engine, all four scenarios end-to-end. |
| 8–9 | Early architecture comparison and tuning based on measured results. |
| 10–11 | Complete benchmark and final primary evaluation runs. |
| 12 | Statistical analysis and results chapter. |
| 13 | Integration hardening, final report, demo rehearsal. |
| 14 | Buffer and submission. |

Figure 2. Proposed 14-week Part II Gantt-style schedule.

## 15. Feasibility and Risk Management

| Risk | Mitigation |
|---|---|
| Lab/VM complexity | Time-box infrastructure decisions early and use simplified Linux/identity fallbacks if the Windows environment causes excessive delay. |
| AI does not outperform simpler baseline | Run the single-shot vs. agent comparison early enough to reposition the contribution around evidence disambiguation and safety if needed. |
| Evaluation bias | Predefine evidence classes, use independent validation, version benchmark definitions, and protect a held-out test split. |
| API cost / model dependency | Use replay/mocking during development; reserve paid calls for controlled experiments; include a local-model comparison if hardware permits. |
| Team variability | Keep interfaces modular and give critical architecture/evaluation ownership to the strongest members while isolating non-critical workstreams. |
| Unsafe automation | Keep the agent read-only, use a deterministic policy engine, restrict execution to a fixed catalog, and confine all actions to the laboratory. |


### 15.1 Planned Resources and Budget
The project is designed to use existing team hardware and mostly open-source software. No dedicated hardware purchase is assumed for the strong target. The main variable direct cost is controlled LLM API usage during formal evaluation; development will rely heavily on replay, fixtures, and mocks so paid calls are reserved for experiments. The exact API budget will be finalized before Part II once the model and final evaluation sample size are selected.

| Resource | Planned approach |
|---|---|
| Compute host | Existing team workstation; approximately 16 GB RAM is preferred for the full Windows + container laboratory. The design can be reduced if hardware is limited. |
| Windows environment | Windows Server evaluation VM for the lab; a separate workstation VM is optional if resources permit. |
| Open-source software | Python/FastAPI, PostgreSQL, React, Docker Compose, Sigma, Zeek, and Fluent Bit are planned without commercial platform licenses. |
| LLM API usage | One budget-capped project key; replay and mocking during development; paid calls concentrated on controlled benchmark runs. |
| Optional local model | Used only as an evaluation comparison if existing hardware supports it; not on the project critical path. |
| Network / safety | Virtual isolated networks only. No public or university production systems are used as attack targets. |


## 16. Ethical and Safety Considerations
- All attack generation will be limited to a controlled laboratory owned by the project team.
- No offensive experiments will target public services, university infrastructure, or third-party systems.
- The AI agent will have read-only investigation tools and no arbitrary command-execution capability.
- Response actions will be fixed, reversible where possible, auditable, and constrained by a deterministic policy engine.
- Protected entities and lab boundaries will be enforced at the executor/policy level, not only through prompting.
- Benchmark results and limitations will be reported honestly, including negative or inconclusive findings.

## 17. Expected Outcomes
- A working prototype of an evidence-driven AI-assisted incident triage and response platform.
- A controlled lab that can reproduce the selected attack and benign scenarios.
- A labeled benchmark and a protected held-out evaluation set.
- Quantitative comparison between rule-only, single-shot, and adaptive agentic investigation approaches.
- Measured safety behavior showing the difference between incorrect AI proposals and actions actually allowed by policy.
- A professional dashboard and final live demonstration suitable for academic assessment and portfolio use.
- A final report that clearly separates engineering achievement from experimental findings.

## 18. Why the Academic Panel Should Approve SENTINEL

| Reason | Why it matters |
|---|---|
| Clear problem | The project addresses a specific and understandable gap: alerts are easy to generate, but contextual triage remains difficult. |
| Justified use of AI | The agent is used where adaptive evidence acquisition is required; it is not added only for trend value. |
| Strong CS depth | The project spans system architecture, data modeling, APIs, security telemetry, rule processing, AI orchestration, UI, controlled execution, and experimental design. |
| Measurable | The team can test the central claim using controlled baselines, held-out cases, and objective evidence/response metrics. |
| Feasible | The strong target is ambitious but bounded to four scenario families and a controlled laboratory rather than enterprise-scale infrastructure. |
| Safe | The AI is read-only and every state-changing response is constrained by deterministic policy and a fixed executor. |
| Career relevance | The project demonstrates skills applicable to cybersecurity, AI engineering, backend/software engineering, data systems, and automation. |


## 19. Conclusion
SENTINEL is proposed as a complete Computer Science graduation project that combines artificial intelligence, cybersecurity, automation, software engineering, and experimental evaluation. Its central idea is simple to explain but technically deep: detection produces an alert, but intelligent investigation must decide what evidence is still missing before an incident can be resolved. The project uses a tool-using AI agent for that adaptive investigation while keeping response authority inside deterministic, auditable safety controls.
The proposal is intentionally designed to be testable. The final project will not claim success only because a demonstration works. It will compare simpler baselines with the proposed agentic architecture, use paired attack and benign scenarios, protect held-out cases from development tuning, and report both quality and safety metrics. This combination of practical engineering and measurable evaluation makes SENTINEL suitable for a strong five-person graduation project.

## 20. Related Work and Technical References
SENTINEL is grounded in established incident-response, detection, telemetry, and AI-risk-management work. NIST SP 800-61 Rev. 3 frames incident response as part of broader cybersecurity risk management [1]. MITRE ATT&CK provides a structured taxonomy of adversary tactics and techniques [2], while Sigma provides a vendor-agnostic rule specification for describing shareable log detections [3]. Sysmon and Zeek provide detailed endpoint and network telemetry respectively [4], [5], and Fluent Bit supports collection and shipping of Windows Event Log data [10].
The project's safety model is informed by current AI governance and agent-security guidance. NIST AI 600-1 focuses on trustworthy generative-AI risk management [6], while OWASP's guidance for secure agentic applications emphasizes permissions, tool controls, and limits on autonomous behavior [7]. These principles support SENTINEL's decision to keep the AI investigation agent read-only and place authorization and execution in deterministic components.
Recent research also demonstrates the potential of LLM-assisted security incident analysis. Cadet et al. evaluate retrieval-augmented LLM analysis across malware and multi-stage Active Directory incidents [8]. A 2026 survey by Lazer et al. identifies incident response and threat hunting as important defensive applications of agentic AI while also highlighting oversight and safety risks [9]. SENTINEL builds on this direction but places its experimental focus on adaptive evidence acquisition, paired malicious/benign scenarios, a protected held-out split, and a strict separation between AI proposals and deterministic response authorization.

### References
[1] A. Nelson, S. Rekhi, K. Scarfone, and M. Souppaya, “Incident Response Recommendations and Considerations for Cybersecurity Risk Management: A CSF 2.0 Community Profile,” NIST Special Publication 800-61 Rev. 3, Apr. 2025, doi: 10.6028/NIST.SP.800-61r3.
[2] The MITRE Corporation, “MITRE ATT&CK — Enterprise Tactics and Techniques,” MITRE ATT&CK, accessed Aug. 19, 2026.
[3] SigmaHQ, “Sigma Rules Specification,” Version 2.1.0, Aug. 2025.
[4] M. Russinovich and T. Garnier, “Sysmon,” Microsoft Sysinternals, Jun. 2026.
[5] Zeek Project, “Zeek Documentation,” Version 8.2.1, 2026.
[6] C. Autio et al., “Artificial Intelligence Risk Management Framework: Generative Artificial Intelligence Profile,” NIST AI 600-1, Jul. 2024, doi: 10.6028/NIST.AI.600-1.
[7] OWASP GenAI Security Project, “Securing Agentic Applications Guide 1.0,” Jul. 2025.
[8] X. Cadet et al., “Retrieval-Augmented LLMs for Security Incident Analysis,” arXiv:2603.18196, Mar. 2026.
[9] S. J. Lazer, K. Aryal, M. Gupta, and E. Bertino, “A Survey of Agentic AI and Cybersecurity: Challenges, Opportunities and Use-case Prototypes,” arXiv:2601.05293, Jan. 2026.
[10] Fluent Bit Project, “Windows Event Logs (winevtlog),” Fluent Bit Official Manual, accessed Aug. 19, 2026.

## Appendix A — 90-Second Panel Pitch
“Security tools are very good at raising alerts, but an alert does not automatically tell an analyst whether there is a real attack. A brute-force alert, for example, could be an attacker, a stale service credential, or a legitimate user. The difficult part is gathering the right context and deciding what the evidence actually means. SENTINEL is our proposed AI-assisted investigation and response platform. Instead of giving an LLM a log dump, we give a read-only AI agent controlled tools so it can retrieve authentication history, entity context, process information, change windows, and related evidence step by step. The AI cannot directly take disruptive actions. It proposes a response, then deterministic policy decides whether the action is allowed, requires approval, or is denied. We will evaluate the project using real telemetry from a controlled lab and compare rules-only, single-shot LLM analysis, and adaptive agentic investigation on both attacks and benign look-alikes. This lets us prove whether the agent architecture actually improves triage instead of only building an impressive interface.”

## Appendix B — Likely Panel Questions and Short Answers
Why do you need AI?
Because the missing context is not fixed. The system must decide which evidence to retrieve based on what earlier evidence shows. We will test this directly against a single-shot LLM baseline.
Is this just ChatGPT connected to logs?
No. The project includes telemetry, normalization, detection, incident correlation, controlled evidence tools, deterministic scoring/policy, response execution, benchmark design, and a comparative evaluation.
What if the AI makes a wrong decision?
The AI is read-only and cannot directly execute security actions. A deterministic policy engine can require approval or deny actions, and prohibited-action execution is a measured safety property.
How will you know whether it works?
We will use labeled attack and benign-look-alike cases, compare multiple baselines, protect a held-out set, and measure verdict accuracy, false positives, evidence use, response quality, efficiency, and safety.
Is the scope too large?
The strong target is limited to four carefully selected scenario families. Infrastructure that does not contribute to the objective is intentionally excluded, and advanced features are deferred unless the core system is complete.
What is the main academic contribution?
A measurable formulation of evidence-driven AI investigation quality, a fair comparison of adaptive investigation against simpler baselines, and a deterministic autonomy model that separates AI proposals from actual system actions.