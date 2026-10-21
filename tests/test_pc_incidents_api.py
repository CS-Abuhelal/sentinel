from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from agent.llm import LLMResponse, Message, ReplayClient, ToolSpec
from backend.app.db import get_engine
from backend.app.incidents import (
    get_run,
    incident_summaries,
    save_incident,
    save_run,
    set_status,
    unfinished_incidents,
)
from backend.app.main import app
from backend.app.pc import get_backfill_state, get_sync_runner
from backend.app.probes import HttpProbe, ModelProbe, get_model_probe, get_wazuh_probe
from backend.app.store import insert_alert
from backend.app.sync import SyncRunner
from contracts.models import Classification, IncidentRun, IncidentStatus, PcFeed, ServiceState
from pipeline.worker import run_once
from tests.conftest import REPO, make_wazuh_alert
from tests.test_worker import BURST, FINAL, _model

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)
RUN = IncidentRun.model_validate_json(
    (REPO / "contracts" / "fixtures" / "incident_run.json").read_text(encoding="utf-8")
)
RELATED = {"type": "tool_call", "tool": "related_alerts", "args": {"hours": 1}}


@pytest.fixture
def client(db: Engine) -> Iterator[TestClient]:
    app.dependency_overrides[get_engine] = lambda: db
    app.dependency_overrides[get_wazuh_probe] = lambda: HttpProbe(url=None)
    app.dependency_overrides[get_model_probe] = lambda: ModelProbe(base_url=None)
    app.dependency_overrides[get_backfill_state] = lambda: ServiceState(reachable=True)
    app.dependency_overrides[get_sync_runner] = lambda: SyncRunner(None)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_feed_lists_incidents_and_queue(client: TestClient, db: Engine) -> None:
    queued = RUN.incident.model_copy(update={"status": IncidentStatus.QUEUED})
    save_incident(db, queued, "my-pc", "k", 3, 10, NOW)
    feed = PcFeed.model_validate(client.get("/api/pc/feed").json())
    assert feed.status.queue_length == 1
    assert feed.status.model.detail == "OLLAMA_URL is not set."
    [summary] = feed.incidents
    assert summary.incident.incident_id == RUN.incident.incident_id


def test_run_detail(client: TestClient, db: Engine) -> None:
    save_incident(db, RUN.incident, "my-pc", "k", 3, 10, NOW)
    path = f"/api/pc/incidents/{RUN.incident.incident_id}"
    assert client.get(path).status_code == 409
    save_run(db, RUN, NOW)
    assert IncidentRun.model_validate(client.get(path).json()) == RUN
    assert client.get("/api/pc/incidents/inc_missing").status_code == 404


def test_retry(client: TestClient, db: Engine) -> None:
    save_incident(db, RUN.incident, "my-pc", "k", 3, 10, NOW)
    path = f"/api/pc/incidents/{RUN.incident.incident_id}/retry"
    assert client.post(path).status_code == 409
    set_status(db, RUN.incident.incident_id, IncidentStatus.INVESTIGATION_FAILED, NOW)
    response = client.post(path)
    assert (response.status_code, response.json()) == (202, {"status": "queued"})
    assert client.post("/api/pc/incidents/inc_missing/retry").status_code == 404


class Peeking:
    def __init__(self, db: Engine, inner: ReplayClient) -> None:
        self.db = db
        self.inner = inner
        self.unfinished: list[list[str]] = []

    @property
    def model_name(self) -> str:
        return self.inner.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        self.unfinished.append(unfinished_incidents(self.db))
        return self.inner.complete(messages, tools)


def test_retry_forgets_the_failed_run(client: TestClient, db: Engine) -> None:
    live, payload = make_wazuh_alert("15.1", 1, **BURST)
    insert_alert(db, live, payload)
    broken = {"type": "final", "payload": {"classification": "maybe"}}
    incident_id = run_once(db, _model(broken), lambda: NOW, model_ready=True)["investigated"]
    assert isinstance(incident_id, str)
    assert get_run(db, incident_id) is not None
    assert client.post(f"/api/pc/incidents/{incident_id}/retry").status_code == 202
    [summary] = incident_summaries(db)
    assert summary.incident.status is IncidentStatus.QUEUED
    assert summary.classification is None
    assert summary.recommendation_count == 0
    assert client.get(f"/api/pc/incidents/{incident_id}").status_code == 409
    peeking = Peeking(db, _model(RELATED, FINAL))
    assert run_once(db, peeking, lambda: NOW, model_ready=True)["investigated"] == incident_id
    assert peeking.unfinished == [[incident_id], [incident_id]]
    [summary] = incident_summaries(db)
    assert summary.classification is Classification.BENIGN
