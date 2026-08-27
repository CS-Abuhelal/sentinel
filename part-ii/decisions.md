---
title: SENTINEL — Architecture Decision Log
status: LIVE — append when a decision is made, not afterwards. Newest at top.
---

# Decision Log

Format: **D-NN — Title** (date) → Decision / Why / Consequence.
Write the entry the day the decision is made. Reconstructing these in week 13 for the report
is painful and produces worse reasoning than what actually happened.

---

## D-03 — Feature freeze at Week 7 (2026-08-27)

**Decision.** No new system features after week 7. Weeks 8–12 are evaluation and analysis only.

**Why.** Evaluation of a moving system produces results that cannot honestly be reported —
you can never say which version produced which number.

**Consequence.** Anything not built by week 7 is out of the project. Scope decisions must be
made before then, not deferred.

---

## D-02 — Holdout benchmark split assigned at case creation (2026-08-27)

**Decision.** Every benchmark case is assigned `dev` or `holdout` at authoring time, before
anyone has seen system performance on it. The holdout is stored separately with restricted
access and is not executed before week 10.

**Why.** Tuning against the final test set is the most common way student evaluations become
meaningless. Assigning at creation removes the possibility of selection bias entirely.

**Consequence.** One final run on the holdout. If results are poor, that is the reported
finding — no re-tuning.

---

## D-01 — Contracts frozen in Week 1, before any component logic (2026-08-27)

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
