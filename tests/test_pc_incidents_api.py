from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.incidents import save_incident, save_run, set_status
from backend.app.main import app
from backend.app.pc import get_backfill_state
from backend.app.probes import HttpProbe, get_model_probe, get_wazuh_probe
from contracts.models import IncidentRun, IncidentStatus, PcFeed, ServiceState
from tests.conftest import REPO

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)
RUN = IncidentRun.model_validate_json(
    (REPO / "contracts" / "fixtures" / "incident_run.json").read_text(encoding="utf-8")
)


@pytest.fixture
def client(db: Engine) -> Iterator[TestClient]:
    app.dependency_overrides[get_engine] = lambda: db
    app.dependency_overrides[get_wazuh_probe] = lambda: HttpProbe(url=None)
    app.dependency_overrides[get_model_probe] = lambda: HttpProbe(
        url=None, name="Ollama", missing="OLLAMA_URL"
    )
    app.dependency_overrides[get_backfill_state] = lambda: ServiceState(reachable=True)
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
