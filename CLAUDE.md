# SENTINEL — Rules for AI Assistants

**Every AI assistant working in this repository must follow this file.**
Claude Code reads it automatically. Cursor users: copy these rules into `.cursorrules`.
If you are an AI and you are reading this, these rules override your defaults.

---

## What this project is

SENTINEL is a university graduation project: an AI-assisted security operations platform.

A controlled lab produces real telemetry. Detection rules raise alerts. Related alerts become
an incident. A **read-only** AI agent investigates that incident using a fixed set of tools,
gathers evidence, and produces a structured verdict plus proposed response actions.
**Deterministic code** — not the AI — then decides whether an action is allowed, needs human
approval, or is denied.

The academic claim being tested: *does an adaptive tool-using agent investigate better than a
single-shot LLM given the same information?* Everything in this repo exists to build that
system and measure that claim honestly.

---

## The three rules that matter most

### Rule 1 — NEVER invent a data shape

All shared data structures live in `contracts/models.py`. Import them:

```python
from contracts.models import Event, Alert, Incident, EvidenceItem, Verdict
```

**Do not** write your own `class Alert`, your own alert dictionary, or your own JSON shape for
anything that already exists in `contracts/`. Five people are building five components against
these models. A component that invents its own shape will not integrate, and the problem will
not be discovered until it is too late to fix.

If a contract is missing a field you need: **stop and tell the human to raise it with the
team.** Do not add the field yourself. Do not work around it with a side dictionary. Do not
subclass it locally.

### Rule 2 — Stay inside your folder

Each team member owns one folder. Only edit files inside the folder you are working in, plus
`tests/`. Do not "helpfully" refactor, reformat, or fix files elsewhere in the repo — that
creates merge conflicts for four other people.

The one exception: nobody edits `contracts/` except the architecture owner.

### Rule 3 — The human must understand the code

This is a graduation project. Each student is examined individually and must explain their own
code to an academic panel without AI help.

So: prefer clear, simple code over clever code. Explain what you wrote in plain language.
If the human does not understand something you produced, rewrite it simpler — do not defend it.
Never generate hundreds of lines at once; work in small pieces the human can follow.

---

## Frozen technical decisions — do not suggest alternatives

The architecture is committed. These are settled and are **not** to be reopened:

| Area | Decision |
|---|---|
| Backend | Python + FastAPI + Pydantic + SQLAlchemy |
| Database | PostgreSQL — the only datastore |
| Frontend | React + TypeScript + Vite |
| Deployment | Docker Compose |
| Detection | Sigma-format rules with a custom evaluator |
| Agent | **One** read-only investigation agent |
| Risk + policy | Deterministic Python. **Never** an LLM. |

**Explicitly banned** — do not propose, install, or scaffold these:
OpenSearch, Elasticsearch, Kafka, Redis, Neo4j, LangGraph, LangChain agents, Kubernetes,
Wazuh, vector databases, RAG-over-embeddings, or any second AI agent.

Every one of these was considered and rejected. They add infrastructure complexity without
improving the research question. If you think one is needed, say so once and let the human
decide — do not add it.

---

## The safety boundary — never violate this

This is the core design principle of the whole project:

- The AI agent is **read-only**. It can query evidence. It cannot change anything.
- The agent **proposes** actions. It never executes them.
- A deterministic policy engine returns `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`.
- A separate executor runs only actions from a fixed catalog, only inside the lab.

Therefore, when writing agent code:

- Agent tools must **only read**. No tool may write, delete, block, disable, or isolate anything.
- Never give the agent shell access, `exec`, `subprocess`, or arbitrary SQL.
- Never let the LLM decide whether an action is permitted. That is Python's job, in `policy/`.
- Never bypass the policy engine "for testing". Use a test policy, not no policy.

A prohibited action reaching the executor is a **project failure**, not a bug. The measured
target is zero.

---

## Folder ownership

| Folder | Owner | Contains |
|---|---|---|
| `contracts/` | Member 1 (architecture) | Shared models. **Frozen — nobody else edits.** |
| `agent/` | Member 1 | Investigation agent, tools, prompts, replay harness |
| `policy/` | Member 1 | Risk scoring, autonomy policy, action executor |
| `eval/` | Member 1 | Experiment runner, arms A1–A3, metrics |
| `lab/` | Member 2 | VM definitions, attack + benign scenarios, telemetry collection |
| `detection/` | Member 2 | Sigma rules, rule evaluator, alert generation, correlation |
| `backend/` | Member 3 | FastAPI app, database models, migrations, API, approvals |
| `frontend/` | Member 4 | React dashboard |
| `benchmark/` | Member 5 | Labeled test cases and ground truth |
| `docs/` | Everyone | Decisions log, status log |

---

## The benchmark holdout — absolute rule

`benchmark/holdout/` is **sealed**.

Never read it. Never run anything against it. Never write code that loads it, unless the human
explicitly says "this is the final week 10 evaluation run."

Tuning against held-out test data destroys the scientific validity of the entire project. If
you are asked to "just check performance quickly", use `benchmark/dev/` instead and say why.

---

## Code conventions

- Python 3.11+, type hints on every function signature
- Pydantic v2 for all data models
- `ruff` for linting and formatting
- `pytest` for tests, in `tests/`
- Absolute imports from the repo root
- Timestamps: always UTC, always timezone-aware
- `snake_case` in Python, `camelCase` in TypeScript — the API layer converts between them

**Do not write code comments.** The team's convention is clean, self-explanatory code with
descriptive names instead of comments. Docstrings on public functions are fine.

---

## Git workflow

- Branch from `main`, named `member2/sigma-evaluator` style
- Keep pull requests under ~300 lines
- Branches live at most 3 days
- `main` must always run the vertical slice — if a PR breaks it, the PR is reverted
- Pull `main` before starting work, every single time

---

## What "done" means right now

Current phase: **Week 1 — contracts and environment only.**

Do not build detection logic, agent reasoning, or dashboard features yet. Week 1 delivers the
shared models, a working local environment for all five members, and lab VMs that produce a
log file. Week 2 delivers one hardcoded case running end to end through every component.

Depth comes after the wire is connected. Never the other way round.
