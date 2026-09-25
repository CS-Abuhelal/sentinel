# Decision Log

Format: **D-NN — Title** (date) → Decision / Why / Consequence. Newest at top.
Write the entry the day the decision is made, not afterwards.
Superseded entries are removed, and numbers are never reused.

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

## D-04 — Scope and working rules (2026-09-25)

**Decision.** SENTINEL is built and maintained by one person and optimised to be finished,
demoable and explainable in an interview. The scope is one real scenario (S1) with at least one
benign twin, the policy engine, a two-action executor, and a dashboard. Contracts may change,
but every change bumps the version, regenerates fixtures and schemas, keeps tests green, and
gets an entry here. Evaluation uses 5 to 10 hand-labelled cases. There is no feature freeze.

**Why.** A small, finished system that can be demonstrated end to end is worth more than a
larger plan that is half built.

**Consequence.** New work deepens the existing stages instead of adding new ones. D-00 still
holds.

---

## D-00 — Core architecture constraints (2026-08-27)

**Decision.** No OpenSearch, Kafka, Redis, Neo4j, LangGraph, Kubernetes, Wazuh, or vector-RAG.
One read-only investigation agent. Deterministic risk scoring and policy. PostgreSQL as the
primary store when a database is needed. FastAPI backend. React + TypeScript frontend. Docker
for local services. No stretch features until the core system is complete.

**Why.** Infrastructure that does not serve the core question (can an agent investigate well
while a deterministic layer keeps authority) costs time without improving the result.

**Consequence.** The architecture is only reopened when a real blocker appears.
