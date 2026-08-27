# SENTINEL

An evidence-driven agentic investigation and controlled response system for security operations.

B.Sc. Computer Science graduation project. Part I (proposal) is in `part-i/`.
Part II (implementation) is what lives in this repository.

---

## What it does

A controlled lab produces real telemetry. Detection rules raise alerts. Related alerts are
correlated into an incident. A **read-only** AI agent investigates that incident using a fixed
set of evidence tools, then produces a structured verdict and proposed response actions.
**Deterministic Python** — never the AI — decides whether each action is allowed, needs human
approval, or is denied.

The question being measured: does an adaptive tool-using agent investigate better than a
single-shot LLM given the same information?

---

## Read this first

**Everyone: read `CLAUDE.md` before writing any code**, and point your AI assistant at it.
It contains the rules that keep five people's work compatible.

Then read `part-ii/00-part-ii-operating-plan.md` for the schedule and who owns what.

---

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest                            # 22 contract tests should pass
```

Regenerate fixtures and JSON schemas after any change to `contracts/models.py`:

```bash
python -m contracts.generate_fixtures
```

---

## Layout

| Folder | Owner | Contains |
|---|---|---|
| `contracts/` | Member 1 | Shared data models. **Frozen — nobody else edits.** |
| `agent/` | Member 1 | Investigation agent, tools, prompts |
| `policy/` | Member 1 | Risk scoring, autonomy policy, action executor |
| `eval/` | Member 1 | Experiment runner, arms A1–A3, metrics |
| `lab/` | Member 2 | VMs, attack and benign scenarios, telemetry |
| `detection/` | Member 2 | Sigma rules, evaluator, alerting, correlation |
| `backend/` | Member 3 | FastAPI, database, API, approvals |
| `frontend/` | Member 4 | React dashboard |
| `benchmark/` | Member 5 | Labeled cases and ground truth |

---

## Working with fixtures

`contracts/fixtures/` holds one complete S1 case — a credential attack leading to account
compromise — represented at every stage of the pipeline. Build against these instead of waiting
for someone else's component to be finished.

`contracts/fixtures/s1_full_case.json` is the whole case in one file.

---

## The rule that matters most

Never define your own version of a shape that already exists in `contracts/`. Import it:

```python
from contracts.models import Event, Alert, Incident, EvidenceItem, Verdict
```

Five components consume these models. One person inventing their own `Alert` is how the project
fails at integration in week 11.

---

## Current phase

**Week 1 — contracts and environment only.** No detection logic, agent reasoning, or dashboard
features yet. Week 2 delivers one hardcoded case running end to end through every component.
