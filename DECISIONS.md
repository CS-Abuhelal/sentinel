# Decision Log

Format: **D-NN — Title** (date) → Decision / Why / Consequence. Newest at top.
Write the entry the day the decision is made, not afterwards.

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
