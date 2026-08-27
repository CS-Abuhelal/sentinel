---
title: SENTINEL Part II — How We Actually Build It
status: LIVE — this is the working plan. Update it; do not fork it.
baseline: part-i/SENTINEL_Part_I_Proposal.md (frozen)
---

# Part II Operating Plan

Part I was one person writing a document. Part II is five people writing code against each
other's assumptions for fourteen weeks. Those fail in completely different ways. Part I fails
if the idea is weak. **Part II fails at integration** — five workstreams that each work alone
and do not fit together in week 11, with no time left to fix it.

Everything below exists to prevent that one failure.

---

## 1. The three rules that decide whether this works

**Rule 1 — Contracts before code.** No one writes logic until the data shapes are merged into
`main` and frozen. Member 2 emits Alerts, member 1's agent consumes Incidents, member 3 stores
them, member 4 renders them, member 5 labels them. If those five people each invent their own
idea of what an Alert looks like, week 11 is a rewrite. Week 1 produces the schemas. Nothing
else.

**Rule 2 — Vertical slice before depth.** By end of week 2 the system must run end to end on
one hardcoded case: log file → normalized event → one rule fires → one alert → one incident →
agent with exactly one tool → verdict → risk score → policy decision → visible in the UI.
Every piece is thin and partly faked. That is fine. What matters is that the wire is connected.
Depth is added later by replacing thin pieces, never by connecting new ones under deadline.

**Rule 3 — Everyone ships fixtures.** Every component publishes a sample-output JSON file in
the repo. The frontend is built against fixture incidents, not a running backend. The agent is
developed against replayed evidence, not live LLM calls. This is what lets five people work in
parallel instead of in a queue, and it is also what keeps the API bill near zero until the real
evaluation runs.

---

## 2. Week 0 — gates that must close before week 1

Do not start week 1 until all six are true. Starting early with any of these open is how teams
lose three weeks.

| Gate | Owner | Done means |
|---|---|---|
| Panel approval of Part I | Member 1 | Written approval, scope not renegotiated |
| GitHub repo + all 5 members with push access | Member 3 | `main` protected, PRs required |
| Lab host confirmed | Member 2 | A machine with ~16 GB RAM that can run Windows Server VM + containers, physically available |
| LLM API key with a hard spend cap | Member 1 | Key exists, budget cap set, cost visible to the team |
| Everyone can run `docker compose up` | Member 3 | All 5 members, on their own machines, on day 1 |
| Weekly integration slot on the calendar | All | A fixed 2-hour block, same time every week, non-negotiable |

---

## 3. Repository shape

One repo. Monorepo. Do not split into five repos — that is the same integration failure
wearing a different hat.

```
sentinel/
  contracts/          # THE most important folder. Pydantic models + JSON Schema + fixtures.
    models.py         #   Event, Alert, Incident, EvidenceItem, Verdict, ProposedAction, PolicyDecision
    fixtures/         #   one sample JSON per model — everyone codes against these
  lab/                # Vagrant/Docker definitions, scenario scripts, telemetry collection config
    scenarios/        #   S1..S4 attack scripts + benign twins, each reproducible
  detection/          # Sigma rules + the evaluator, alert generation, incident correlation
  agent/              # Investigation agent, tool definitions, prompts, replay harness
  policy/             # Deterministic risk scoring + autonomy policy engine + action executor
  backend/            # FastAPI app, SQLAlchemy models, migrations, API routes, approval workflow
  frontend/           # React + TypeScript + Vite dashboard
  benchmark/
    dev/              # development split — tune against this freely
    holdout/          # SEALED. See §6.
  eval/               # experiment runner for arms A1, A2a, A2b, A2c, A3; metrics; analysis
  docs/               # decisions log, weekly status, final report drafts
  docker-compose.yml
```

**Git workflow:** trunk-based. Short-lived branches named `member2/sigma-evaluator`, PR into
`main`, one reviewer, squash merge. No long-running feature branches — a branch alive for three
weeks is an integration failure being incubated.

**`main` must always run the vertical slice.** That is the single health check. If a PR breaks
it, the PR is reverted, not debugged in place.

---

## 4. Week-by-week build order

Weeks map to the Part I schedule; this adds what "done" actually means.

| Week | Target | Done means |
|---|---|---|
| 1 | Contracts + environment | `contracts/` merged and frozen. Every member has run the stack locally. Lab VMs boot and produce a log file. |
| 2 | **Vertical slice** | One hardcoded case runs end to end and is visible in the UI. Demo-able. |
| 3–4 | Real detection + evidence model | S1 fully real: authentic telemetry → Sigma rules → alerts → correlated incident. Evidence tool interface defined. First ~10 benchmark cases written. |
| 5 | Agent tools + S2 | Agent has its real read-only tool set. Evidence citations working. S2 end to end. |
| 6 | Policy + risk + S3 | Deterministic risk scoring, policy engine returning ALLOW/APPROVE/DENY, executor with fixed action catalog. S3 end to end. |
| 7 | S4 + all four green | All four scenarios and their benign twins run end to end. ATT&CK mapping in place. **Feature freeze on the core system.** |
| 8 | First real comparison | Run A1 / A2b / A3 on the dev split. This is the moment of truth — see §7. |
| 9 | Tuning on dev split only | Improve prompts, tools, stopping criteria. Holdout stays sealed. |
| 10–11 | Full benchmark + final runs | Complete case population. Final runs of all arms, multiple seeds, on the holdout. |
| 12 | Analysis | Metrics computed, statistics done, results chapter written. |
| 13 | Hardening + report + rehearsal | Final report complete. Demo rehearsed at least twice on the real lab. |
| 14 | Buffer | Nothing new. Submission. |

**Feature freeze in week 7 is the load-bearing date.** Weeks 8–12 are evaluation, and evaluation
on a system that is still changing produces results you cannot report. Anything not built by
week 7 is not in the project.

---

## 5. Who does what, and what happens if someone underperforms

The Part I table assigns ownership. Part II adds the isolation strategy that was a stated design
goal: the project must survive members 4 and 5 underperforming, without lowering the standard.

| Member | Owns | On the critical path? | If they stall |
|---|---|---|---|
| 1 | Agent, architecture, evidence model, risk/policy design, evaluation definitions | **Yes — highest** | Project stops. This role cannot slip. |
| 2 | Lab, telemetry, detection engineering, correlation, response-side lab integration | **Yes** | Falls back to replayed telemetry captured early; scenarios reduce from 4 to 3. |
| 3 | Backend, PostgreSQL, APIs, approval workflow, orchestration, deployment | Yes — connective | Member 1 absorbs the API layer; contracts make this survivable. |
| 4 | Frontend dashboard, incident/evidence/approval views, eval visualization | **No** | Dashboard degrades to a minimal read-only view. Evaluation is unaffected — it runs headless. |
| 5 | Scenario execution, benign twins, benchmark population, threat-intel fixtures, QA | **No** | Members 1 and 2 absorb case authoring; benchmark shrinks in size, not in design. |

The isolation works because of one structural fact: **the evaluation runs headless.** The
experiment does not go through the dashboard. So if member 4 delivers nothing, the academic
contribution is still intact and only the demo suffers. Protect that property — never let
evaluation depend on the frontend.

**Week 1 assignments, concretely:**

- **Member 1** — write `contracts/models.py`. All seven models. This is a solo task on purpose;
  design by committee here produces mush. Circulate for review, merge by day 4.
- **Member 2** — build the lab: attacker segment routed separately from victim segment (per the
  Part I enforcement design), get Sysmon and Linux logs landing in a file. Do not write
  detection rules yet.
- **Member 3** — repo scaffolding, `docker-compose.yml`, FastAPI skeleton, PostgreSQL with
  migrations, health endpoint. Everyone must be able to `docker compose up` by day 5.
- **Member 4** — React + Vite skeleton, routing, layout, incident list rendering from
  `contracts/fixtures/incident.json`. No backend dependency.
- **Member 5** — write the S1 scenario spec and its benign twin spec in prose: what happens,
  what evidence should exist, what the correct verdict is. Specification, not execution.

---

## 6. The holdout split — the rule everybody breaks

The stated commitment was that held-out cases are assigned at creation and **physically
protected** from development evaluation. Mechanically:

1. When a benchmark case is authored, it is assigned `dev` or `holdout` at that moment, by
   coin flip, before anyone has seen how the system performs on it.
2. `benchmark/holdout/` is encrypted, or lives in a separate private repo that only member 1 and
   the supervisor can read.
3. **It is not run before week 10.** Not once. Not to "sanity check". A single peek and the
   held-out claim is gone, and the honest thing would be to say so in the report.
4. The final run on the holdout happens once. If results are bad, that is the finding — it gets
   reported, not re-tuned.

This is the single most defensible thing in the whole project and it costs nothing except
discipline.

---

## 7. Week 8 is the decision point

At week 8 the first real comparison runs: does the tool-using agent (A3) actually beat the
full-context single-shot baseline (A2b)?

- **If yes** — proceed as planned. The central claim holds.
- **If no** — do not hide it and do not spend weeks 9–12 forcing it. Reposition the contribution,
  exactly as the Part I risk table already commits to: the finding becomes "adaptive retrieval
  did not improve verdict accuracy on this benchmark, but the deterministic safety boundary
  eliminated prohibited-action execution, and evidence utilization differed measurably." That
  is a legitimate, publishable, defensible negative result — and a panel respects it far more
  than a suspiciously clean win.

Running this comparison in week 8 rather than week 11 is what makes that repositioning possible.
Do not let it slip.

---

## 8. How to use this Claude project across sessions

Code lives in GitHub. This project holds the shared brain — the things a new session (or a
teammate) needs in order to be useful without re-deriving everything.

**Docs kept here:**

- `part-i/` — the frozen proposal. Reference, not editable scope.
- `part-ii/00-part-ii-operating-plan.md` — this file.
- `part-ii/01-interface-contracts.md` — the frozen data shapes, in prose, once week 1 lands.
- `part-ii/decisions.md` — every architectural decision, with the date and the reason. Written
  when the decision is made, not reconstructed in week 13 for the report.
- `part-ii/status.md` — one short entry per week: what shipped, what slipped, what is blocked.

**Session pattern:** one session = one workstream ("build the Sigma evaluator", "design the
policy engine", "write the results chapter"). Start by reading the relevant project doc. End by
writing back what changed to `decisions.md` or `status.md`. A session that ends without updating
either one has left nothing behind for the next one.

**Cost note:** the decisions log is not bureaucracy — it is the raw material of the final report.
Weeks 12–13 are far easier when fourteen weeks of reasoning were written down as they happened.

---

## 9. What I would worry about, in order

1. **Week 2 vertical slice slips.** Everything downstream compresses. Watch this date harder
   than any other.
2. **The lab eats week 3 and 4.** Windows Server + Sysmon + routed segments is genuinely fiddly.
   The Part I risk table already allows a Linux/identity fallback — decide to use it early, not
   after two lost weeks.
3. **Contracts get renegotiated in week 6.** If the models change after week 4, four workstreams
   break at once. Get them right in week 1 and treat changes as a formal decision.
4. **Nobody writes benchmark cases until week 9.** They are boring and unglamorous and they are
   the entire evaluation. Member 5 must be producing cases from week 3 onward.
5. **API spend spikes during development.** Replay and mock aggressively. Paid calls belong to
   controlled experiment runs only.
