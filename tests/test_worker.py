from __future__ import annotations

from datetime import UTC, datetime

import httpx
from sqlalchemy.engine import Engine

from agent.llm import Recording, ReplayClient
from backend.app.incidents import get_run, incident_status, incident_summaries
from backend.app.store import insert_alert
from contracts.models import IncidentStatus, PolicyOutcome
from pipeline.worker import model_state, pc_inventory, run_once
from tests.conftest import make_wazuh_alert

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
BURST = {"rule_id": "60204", "level": 10, "techniques": ["T1110"],
         "description": "Multiple Windows Logon Failures"}


def _model(*responses: dict) -> ReplayClient:
    return ReplayClient(
        Recording(source="handwritten", model_name="test", responses=list(responses))
    )


FINAL = {
    "type": "final",
    "payload": {
        "classification": "benign",
        "confidence": 0.7,
        "summary": "The owner was testing with runas.",
        "techniques": [],
        "attack_chain": [],
        "cited_evidence": ["E1"],
        "risk_factors": [],
        "proposed_actions": [],
        "recommendations": [
            {"title": "Nothing urgent", "priority": 10, "steps": ["Keep Wazuh running."],
             "evidence": ["E1"]}
        ],
    },
}


def _store(db: Engine, wazuh_id: str, minute: int, **kwargs: object) -> None:
    live, payload = make_wazuh_alert(wazuh_id, minute, **kwargs)
    insert_alert(db, live, payload)


def test_pc_inventory_marks_every_host_personal() -> None:
    inventory = pc_inventory(["my-pc"])
    assert inventory.is_personal("my-pc")


def test_run_once_groups_and_investigates(db: Engine) -> None:
    for n in range(1, 6):
        _store(db, f"10.{n}", n)
    _store(db, "10.9", 6, **BURST)
    model = _model({"type": "tool_call", "tool": "related_alerts", "args": {"hours": 1}}, FINAL)
    result = run_once(db, model, lambda: NOW, model_ready=True)
    assert result["grouped"] == 6
    [queued] = [s for s in incident_summaries(db) if s.max_level == 10]
    incident_id = queued.incident.incident_id
    assert result["investigated"] == incident_id
    run = get_run(db, incident_id)
    assert run is not None
    assert run.verdict.classification.value == "benign"
    assert run.evidence[0].tool_name == "related_alerts"
    assert run.evidence[0].content["total_alerts"] == 6
    assert incident_status(db, incident_id) is IncidentStatus.CLOSED_BENIGN
    assert all(d.outcome is PolicyOutcome.DENY for d in run.policy_decisions)


def test_without_the_model_only_grouping_happens(db: Engine) -> None:
    _store(db, "11.1", 1, **BURST)
    result = run_once(db, _model(FINAL), lambda: NOW, model_ready=False)
    assert result == {"grouped": 1, "investigated": None}
    [summary] = incident_summaries(db)
    assert summary.incident.status is IncidentStatus.QUEUED


def test_a_broken_answer_marks_the_incident_failed(db: Engine) -> None:
    _store(db, "12.1", 1, **BURST)
    broken = {"type": "final", "payload": {"classification": "maybe"}}
    result = run_once(db, _model(broken), lambda: NOW, model_ready=True)
    assert incident_status(db, result["investigated"]) is IncidentStatus.INVESTIGATION_FAILED


def test_model_state_needs_the_model_to_be_pulled() -> None:
    def tags(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"models": [{"name": "qwen3:14b"}]})

    ok = model_state("http://ollama:11434", "qwen3:14b", transport=httpx.MockTransport(tags))
    missing = model_state("http://ollama:11434", "llama3:8b", transport=httpx.MockTransport(tags))
    assert ok.reachable is True
    assert missing.reachable is False and "llama3:8b" in (missing.detail or "")


def test_model_state_when_ollama_is_down() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    state = model_state("http://ollama:11434", "qwen3:14b", transport=httpx.MockTransport(refuse))
    assert state.reachable is False
