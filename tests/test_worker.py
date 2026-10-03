from __future__ import annotations

import logging
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy.engine import Engine

import pipeline.worker as worker_module
from agent.llm import Recording, ReplayClient
from backend.app.incidents import get_run, incident_status, incident_summaries, set_status
from backend.app.store import insert_alert
from contracts.models import (
    Classification,
    IncidentStatus,
    InvestigationStopReason,
    PolicyOutcome,
    ServiceState,
)
from pipeline.grouping import group_new_alerts
from pipeline.worker import (
    acquire_worker_lock,
    main,
    model_state,
    pc_inventory,
    release_worker_lock,
    run_once,
)
from tests.conftest import REPO, make_wazuh_alert

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
PC_RECORDING = REPO / "tests" / "data" / "pc_incident.qwen3-14b.json"
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


def _recording_file(tmp_path: Path) -> Path:
    path = tmp_path / "replay.json"
    path.write_text(
        Recording(source="handwritten", model_name="test", responses=[FINAL]).model_dump_json(),
        encoding="utf-8",
    )
    return path


def test_main_runs_one_cycle(
    db: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store(db, "14.1", 1)
    monkeypatch.setattr(worker_module, "get_engine", lambda: db)
    argv = ["--once", "--llm", "replay", "--recording", str(_recording_file(tmp_path))]
    assert main(argv) == 0
    assert len(incident_summaries(db)) == 1


def test_main_requeues_investigations_cut_short(
    db: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _store(db, "16.1", 1, **BURST)
    group_new_alerts(db, NOW)
    [summary] = incident_summaries(db)
    incident_id = summary.incident.incident_id
    set_status(db, incident_id, IncidentStatus.INVESTIGATING, NOW)
    monkeypatch.setattr(worker_module, "get_engine", lambda: db)
    argv = ["--once", "--llm", "replay", "--recording", str(_recording_file(tmp_path))]
    assert main(argv) == 0
    assert get_run(db, incident_id) is not None


def test_main_survives_a_failing_cycle(
    db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken(*args: object, **kwargs: object) -> dict[str, object]:
        raise RuntimeError("the database went away")

    monkeypatch.setattr(worker_module, "get_engine", lambda: db)
    monkeypatch.setattr(worker_module, "run_once", broken)
    argv = ["--once", "--llm", "replay", "--recording", str(_recording_file(tmp_path))]
    with caplog.at_level(logging.ERROR, logger="pipeline.worker"):
        assert main(argv) == 1
    assert "Worker cycle failed" in caplog.text
    assert "the database went away" in caplog.text


def test_replay_needs_a_recording() -> None:
    with pytest.raises(SystemExit):
        main(["--once", "--llm", "replay"])


def test_the_recorded_qwen_run_on_the_pc_replays(db: Engine) -> None:
    for n in range(10):
        _store(db, f"20.{n}", 20 + n)
    _store(db, "20.99", 30, **BURST)
    result = run_once(db, ReplayClient.from_file(PC_RECORDING), lambda: NOW, model_ready=True)
    run = get_run(db, result["investigated"])
    assert run is not None
    verdict = run.verdict
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert verdict.model_name == "ollama:qwen3:14b"
    assert verdict.classification is Classification.BENIGN
    assert [e.tool_name for e in run.evidence] == [
        "rule_context",
        "auth_history",
        "related_alerts",
        "process_activity",
    ]
    assert run.evidence[1].content["total_failures"] == 11
    assert run.policy_decisions == []
    assert run.executions == []
    assert verdict.recommendations
    assert all(advice.evidence_ids for advice in verdict.recommendations)


def test_a_failure_before_the_model_is_asked_marks_the_incident_failed(
    db: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _store(db, "17.1", 1, **BURST)

    def broken(*args: object) -> list[object]:
        raise RuntimeError("the alerts could not be read")

    monkeypatch.setattr(worker_module, "incident_alerts", broken)
    with caplog.at_level(logging.WARNING, logger="pipeline.worker"):
        result = run_once(db, _model(FINAL), lambda: NOW, model_ready=True)
    assert incident_status(db, result["investigated"]) is IncidentStatus.INVESTIGATION_FAILED
    [record] = [r for r in caplog.records if "failed" in r.getMessage()]
    assert record.exc_info is not None
    assert "the alerts could not be read" in caplog.text


def test_only_one_worker_holds_the_lock(
    db: Engine,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    first = acquire_worker_lock(db)
    assert first is not None
    try:
        assert acquire_worker_lock(db) is None
        monkeypatch.setattr(worker_module, "get_engine", lambda: db)
        argv = ["--once", "--llm", "replay", "--recording", str(_recording_file(tmp_path))]
        with caplog.at_level(logging.ERROR, logger="pipeline.worker"):
            assert main(argv) == 1
        assert "Another worker is already running." in caplog.text
    finally:
        release_worker_lock(first)
    second = acquire_worker_lock(db)
    assert second is not None
    release_worker_lock(second)
    assert main(argv) == 0


class StopWorker(Exception):
    pass


def test_the_ollama_client_is_built_once(
    db: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[tuple[str, str]] = []
    checks: list[str] = []
    naps: list[float] = []

    def client(model: str, base_url: str) -> object:
        built.append((model, base_url))
        return SimpleNamespace(model_name="fake")

    def state(base_url: str, model: str) -> ServiceState:
        checks.append(base_url)
        return ServiceState(reachable=False, detail="Ollama unreachable: test")

    def sleep(seconds: float) -> None:
        naps.append(seconds)
        if len(naps) == 3:
            raise StopWorker

    monkeypatch.setattr(worker_module, "get_engine", lambda: db)
    monkeypatch.setattr(worker_module, "OllamaClient", client)
    monkeypatch.setattr(worker_module, "model_state", state)
    monkeypatch.setattr(worker_module, "time", SimpleNamespace(sleep=sleep))
    with pytest.raises(StopWorker):
        main(["--interval", "0", "--ollama-url", "http://ollama.test:11434"])
    assert built == [("qwen3:14b", "http://ollama.test:11434")]
    assert len(checks) == 3
    second = acquire_worker_lock(db)
    assert second is not None
    release_worker_lock(second)


def test_the_worker_re_exports_model_state() -> None:
    from agent.ollama import model_state as shared

    assert model_state is shared


def test_an_empty_ollama_url_falls_back_to_localhost(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    class Stop(Exception):
        pass

    def fake_client(model: str, base_url: str) -> None:
        seen["url"] = base_url
        raise Stop

    monkeypatch.setenv("OLLAMA_URL", "")
    monkeypatch.setattr(worker_module, "get_engine", lambda: None)
    monkeypatch.setattr(worker_module, "OllamaClient", fake_client)
    with pytest.raises(Stop):
        main(["--once"])
    assert seen["url"] == "http://localhost:11434"
