# SENTINEL

An evidence-driven agentic investigation and controlled response system for security operations.

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

| Folder | Contains |
|---|---|
| `contracts/` | Shared data models, fixtures, JSON Schemas |
| `agent/` | Investigation agent, tools, prompts |
| `policy/` | Risk scoring, autonomy policy, action executor |
| `eval/` | Experiment runner, arms, metrics |
| `lab/` | VMs, attack and benign scenarios, telemetry |
| `detection/` | Sigma rules, evaluator, alerting, correlation |
| `backend/` | FastAPI, database, API, approvals |
| `frontend/` | React dashboard |
| `benchmark/` | Labeled cases and ground truth |

Design decisions are logged in `DECISIONS.md`.

---

## Working with fixtures

`contracts/fixtures/` holds one complete S1 case — a credential attack leading to account
compromise — represented at every stage of the pipeline.

`contracts/fixtures/s1_full_case.json` is the whole case in one file.

Never define a separate version of a shape that already exists in `contracts/`. Import it:

```python
from contracts.models import Event, Alert, Incident, EvidenceItem, Verdict
```
