# Decision Log

Format: **D-NN — Title** (date) → Decision / Why / Consequence. Newest at top.
Write the entry the day the decision is made, not afterwards.

---

## D-09 — Executor against a real victim container; approvals committed by a human (2026-09-25)

**Decision.** Contracts 1.3.0 add `Approval`, `ExecutionResult`, `CommandResult` and a
hash-chained `AuditRecord`. `IncidentRun` carries the approvals, executions and audit chain.
The executor runs approved catalog actions inside a real victim container (in GitHub Actions
and locally with Docker) and verifies them. The only source of approval is a file a human
commits to `approvals/<case_id>.yml`.

**Why.** Containment has to be shown working on a real system, not described. A committed file
keeps approval with a person, traceable in git history, without blocking every deploy on a
click.

**Consequence.** The executor re-checks the catalog, the decision, the approval, protection and
the target format before running anything. It never uses a shell. No AI-written file can
approve an action.

---

## D-08 — The live demo's agent is an open model running in GitHub Actions (2026-09-25)

**Decision.** The published demo runs every scenario through the agent live, using an
open-weight model served by Ollama inside the GitHub Actions build: `qwen3:14b` with thinking
off. The LLM client interface stays provider-neutral, and hand-written recordings remain for
offline runs and tests.

**Why.** Free, no account or API key, nothing leaves the pipeline, and it can't break when a
provider changes its free tier (GitHub Models was retired on 2026-07-30). In the model trial
(`docs/model-trial-2026-09-25.md`), `qwen3:8b` called the benign twin malicious and `qwen3:14b`
got both cases right. The cost is build time: about 15 minutes for the two cases.

**Consequence.** The dashboard shows each run's expected outcome next to the model's verdict, so
a wrong verdict is visible rather than hidden. Stronger configurations are compared with the
`Model trial` workflow before changing the default.

---

## D-07 — Contracts 1.2.0: Scenario with a hand-labelled expected outcome (2026-09-25)

**Decision.** Add `Scenario` (title, description, expected classification) and an optional
`IncidentRun.scenario`, loaded from `lab/scenarios/<case>/scenario.yml`.

**Why.** With a live model the verdict can be wrong. Visitors need to see what the right answer
was, and evaluation needs labelled cases.

**Consequence.** The scenario is attached to the run after the fact and is never passed to the
agent. A test checks that no part of it appears in the model's input.

---

## D-06 — Contracts 1.1.0: IncidentRun, Inventory, Verdict.stop_reason (2026-09-25)

**Decision.** Add `IncidentRun` (one incident through every stage; the run file and the API
response), `Inventory` with `AccountRecord` and `HostRecord` (roles, privileged and protected
flags), `InvestigationStopReason`, and a required `Verdict.stop_reason`.

**Why.** The vertical slice needs a run file shape, and it must live in `contracts/` rather
than beside it. Correlation, risk scoring and the policy engine all read the inventory. The
brief requires recording why each investigation stopped.

**Consequence.** Every producer of a `Verdict` must state its stop reason. The frontend
generates its types from `IncidentRun.schema.json`. JSON Schemas are now generated in
serialization mode, so fields the API always sends are required in the generated types.

---

## D-05 — Vertical slice stores results as JSON run files (2026-09-25)

**Decision.** `python -m pipeline.run` writes one `IncidentRun` JSON file per case to `runs/`.
The API only reads those files. Postgres is deferred.

**Why.** Docker is not installed on the dev machine, and the hosted replay-mode dashboard needs
recorded runs served from files anyway. A database adds nothing until approvals and the audit
log need durable, concurrent writes.

**Consequence.** Postgres (still the planned store under D-00) comes in with the executor and
approval flow. The pipeline stays callable without the API, which the eval harness needs.

---

## D-04 — Continue as a solo portfolio project (2026-09-25)

**Decision.** SENTINEL was not accepted as the team's graduation project. It continues as a
solo portfolio project. No team, no panel, no fixed 14-week schedule. The scope is cut to one
real scenario (S1) with at least one benign twin, the policy engine, a two-action executor, and a
dashboard. `CLAUDE.md` is replaced with the solo brief.

**Why.** The goal is now a finished, demoable project that can be explained in an interview.
Academic completeness is no longer the goal.

**Consequence.**
- D-01 is relaxed. Contracts can change, but every change bumps the version, regenerates
  fixtures and schemas, keeps tests green, and gets an entry here.
- D-02 is dropped. The sealed holdout split is gone, along with its CI check. Evaluation uses
  5 to 10 hand-labeled cases.
- D-03 is dropped. There is no week-based feature freeze.
- D-00 still holds.

---

## D-03 — Feature freeze at Week 7 (2026-08-27) — superseded by D-04

**Decision.** No new system features after week 7. Weeks 8–12 are evaluation and analysis only.

**Why.** Evaluation of a moving system produces results that cannot honestly be reported —
you can never say which version produced which number.

**Consequence.** Anything not built by week 7 is out of the project. Scope decisions must be
made before then, not deferred.

---

## D-02 — Holdout benchmark split assigned at case creation (2026-08-27) — superseded by D-04

**Decision.** Every benchmark case is assigned `dev` or `holdout` at authoring time, before
anyone has seen system performance on it. The holdout is stored separately with restricted
access and is not executed before week 10.

**Why.** Tuning against the final test set is the most common way student evaluations become
meaningless. Assigning at creation removes the possibility of selection bias entirely.

**Consequence.** One final run on the holdout. If results are poor, that is the reported
finding — no re-tuning.

---

## D-01 — Contracts frozen in Week 1, before any component logic (2026-08-27) — relaxed by D-04

**Decision.** Week 1 delivers `contracts/` — Pydantic models plus JSON Schema plus fixtures for
Event, Alert, Incident, EvidenceItem, Verdict, ProposedAction, PolicyDecision — merged to `main`
and frozen. No component logic is written before this lands. Authored by one person (Member 1),
reviewed by the team.

**Why.** Five workstreams consume and produce these shapes. Divergent assumptions surface at
integration, which in a 14-week project means too late to fix.

**Consequence.** Changes after week 4 are treated as formal decisions logged here, because they
break multiple workstreams simultaneously.

---

## D-00 — SENTINEL v1.1 design frozen (pre-Part II)

**Decision.** Committed constraints: no OpenSearch, Kafka, Redis, Neo4j, LangGraph, Kubernetes,
Wazuh, or vector-RAG. One read-only investigation agent. Deterministic risk scoring and policy.
PostgreSQL as primary store. FastAPI backend. React + TypeScript frontend. Docker Compose.
No exceptional-tier features until the core system is complete.

**Why.** Infrastructure complexity that does not serve the research question consumes the
schedule without improving the contribution.

**Consequence.** Architecture is not reopened unless a Week-1 verification spike reveals a real
blocker.
