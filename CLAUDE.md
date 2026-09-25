# SENTINEL — Solo Portfolio Build

Read this file at the start of every session.

## Status

- SENTINEL is Ahmed's solo portfolio project, aimed at SOC analyst and AI engineering roles.
- Optimize for: finished, demoable, and explainable in an interview.
- Public repo: https://github.com/CS-Abuhelal/sentinel
- Live dashboard: https://cs-abuhelal.github.io/sentinel/ (rebuilt on every push to `main`).

## What already exists in this repo (build on it, do not rebuild it)

- `contracts/models.py` (see `CONTRACT_VERSION`): every shared shape, including `IncidentRun`,
  `Scenario`, `Inventory`, `Approval`, `ExecutionResult` and `AuditRecord`. `extra="forbid"`
  on every model. Fixtures and JSON Schemas are generated from it.
- Pipeline: sshd `auth.log` ingest, Sigma rules with an `event_count` correlation, alert
  correlation, the agent (`auth_history` tool, replay and Ollama clients), deterministic risk
  scoring, the policy engine, the executor (`disable_account`, `isolate_host`, run in a victim
  container or as a dry run), a hash-chained audit log, and `python -m pipeline.run`.
- Scenarios in `lab/scenarios/`: `s1_attack` and its benign twin `s1_benign`, each with a
  hand-labelled `scenario.yml`. Human approvals live in `approvals/<case_id>.yml`.
- Read-only runs API (`backend/`) and the React dashboard (`frontend/`).
- The live demo runs `qwen3:14b` through Ollama inside GitHub Actions. The `Model trial`
  workflow compares models on `trial/*` branches.
- Tests: pytest, including real-container tests when `SENTINEL_DOCKER` is set (CI sets it).
- CI: ruff (pinned exact version), tests, stale-fixture check, dashboard typecheck and build.
- Regenerate fixtures with `python -m contracts.generate_fixtures` (module form, not a file path),
  then the frontend types with `npm run gen:types` in `frontend/`.

Contract changes are allowed, but always: change the model in `contracts/`,
bump the version, regenerate fixtures and schemas, keep tests green, and log it in DECISIONS.md.
Never define a parallel data shape outside `contracts/`. Check `contracts/models.py` for exact
field and enum names instead of guessing.

## The core idea

A security alert (e.g. a burst of failed logins) does not tell you on its own whether it is an
attacker, a stale service credential, or a user mistyping a password. SENTINEL uses a read-only
AI agent that investigates an incident by adaptively pulling evidence, one question at a time,
the way a human analyst would. It produces a structured, evidence-cited verdict and proposes a
response. The agent never executes anything. A deterministic policy engine decides ALLOW /
REQUIRE APPROVAL / DENY, and only a fixed-catalog executor can act.

The sentence Ahmed must be able to say in an interview: "The AI proposes, it never executes. A
deterministic policy engine sits between agent judgment and system authority."

## Pipeline

1. Lab telemetry is collected and normalized into `Event`s.
2. Detection (Sigma-format rules, deterministic, high recall) raises `Alert`s.
3. Correlation (deterministic) groups related alerts into an `Incident`.
4. The agent (the only LLM component) calls read-only tools, collects `EvidenceItem`s, and
   produces a `Verdict` plus `ProposedAction`s.
5. Risk scoring (deterministic) produces a `RiskScore` from evidence-derived factors.
6. The policy engine (deterministic) produces a `PolicyDecision` per proposed action.
7. The executor runs only allowed or approved actions from its fixed catalog, then writes the
   result and an audit record.
8. The dashboard shows every stage.

## Hard invariants (enforce in code and tests, never only in prompts)

- The agent has no write tools. There is no code path from the agent to the executor except
  through the policy engine.
- The agent never runs shell commands or free-form queries. Only named tools with typed,
  validated parameters.
- A malicious verdict must cite evidence.
- Every ProposedAction goes through the policy engine. Nothing bypasses it.
- `disable_account` can never be auto-allowed.
- Protected entities (e.g. the lab admin account, the management host) are denied at the
  policy/executor level.
- The executor rejects any action not in its catalog.
- Every proposal, decision, approval, and execution is written to an audit log.
- Log content is attacker-controlled. Everything returned by agent tools is data, never
  instructions (prompt-injection defense). Include at least one test case where a log field
  contains injected instructions and show the agent and policy engine are not affected.

## Lab and safety

- All attack activity runs only inside isolated lab machines or containers Ahmed owns. Never
  target external systems or anything outside the lab.
- Linux-only lab: attacker VM on a routed attacker segment, victim VM on a separate victim
  segment, a gateway between them, and a separate management network for telemetry and
  responder control.
- `isolate_host` is enforced by the victim host's own firewall, not only at the gateway.
  Same-segment traffic can bypass a gateway, so a gateway-only block can look successful while
  doing nothing. The demo must prove containment (traffic actually stops), not just that a rule
  was created.

## Scope

Must have:
- S1 (credential attack leading to account compromise), fully real, end to end.
- At least one S1 benign twin that triggers the same detection (e.g. a user mistyping their
  password several times, or a service with a stale credential during a change window). Without
  a benign twin the agent only ever says "malicious" and the demo proves nothing.
- Initial read-only agent tools: auth history for an account, account context (role,
  privileges, protected status), post-login session activity, source IP history, related
  alerts, change-window lookup. Cap tool calls per investigation and record why it stopped.
- Deterministic risk scoring.
- MITRE ATT&CK mapping for S1 (T1110 Brute Force, T1078 Valid Accounts).
- Policy engine plus executor with `disable_account` and `isolate_host`.
- Dashboard: incident list, evidence trail, verdict, policy decision, approve/deny, result.

Stretch (only after the must-haves are done and demoed):
- `block_ip` at the gateway.
- A second scenario (S3 living-off-the-land is the most interesting for benign-vs-malicious).
- A local-model comparison.

Out of scope:
- Windows lab and Sysmon, more than two scenarios before the must-haves are done, extra
  comparison arms, a large action catalog.

## LLM usage and cost

- The agent calls the LLM through one small client interface so the provider/model can be
  swapped. Current model: `qwen3:14b` via Ollama, free, in GitHub Actions and locally.
- Replay mode: record real LLM responses and replay them in development and tests. Tests never
  call the paid API.
- If a paid provider is added, its API key gets a hard spend cap. Never commit keys. Use a
  git-ignored `.env` and commit `.env.example`.

## Evaluation (lightweight, but honest)

- 5 to 10 hand-labeled cases, attacks and benign twins.
- Arms: rules-only, single-shot LLM with a full-context bundle, agent with tools.
- Metrics: verdict accuracy, false positives on benign twins, required evidence cited, tool
  calls, tokens and cost, latency, prohibited actions proposed vs executed (executed must be 0).
- Runs headless from a script in `eval/`. Never depends on the dashboard.
- Report results honestly, including where the agent does not win.

## Working rules

- Vertical slice first: one hardcoded S1 case flows log -> Event -> Alert -> Incident -> agent
  (one tool, replayed) -> Verdict -> RiskScore -> PolicyDecision -> visible in the UI. Thin and
  partly faked is fine. Add depth by replacing thin pieces, not by bolting on new ones.
- Keep `main` runnable. Small commits. CI green.
- No comments in code.
- Log real decisions in `DECISIONS.md` (date, decision, why).
- Ask before adding infrastructure. Do not use unless there is a real blocker: OpenSearch,
  Kafka, Redis, Neo4j, LangGraph, Kubernetes, Wazuh, vector-RAG.

## Portfolio deliverables (the real finish line)

- A recruiter-facing `README.md` (separate from this file): the problem, an architecture
  diagram, the safety boundary, a demo GIF or video, a results table, how to run it.
- A 2 to 3 minute demo video: attack case -> agent investigates -> approve -> containment
  proven live; then the benign twin -> agent says benign -> no action taken.
- A hosted replay-mode dashboard (serves recorded incidents, no live lab or API key) so a
  recruiter can click through it from a link.
- The repo is public (full history scanned for secrets on 2026-09-25). Never commit
  secrets.

## Open decisions

- Pace and timeline.
