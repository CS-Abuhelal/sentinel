from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.findings import open_findings, set_advice, upsert_findings
from backend.app.main import app
from backend.app.pc import get_backfill_state
from backend.app.probes import HttpProbe, ModelProbe, get_model_probe, get_wazuh_probe
from backend.app.sync import SyncRunner
from contracts.models import HostAssessment, PcFeed, Recommendation, ServiceState
from tests.conftest import make_finding

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
RUNNER: dict[str, SyncRunner] = {}


def _broken() -> None:
    raise RuntimeError("no indexer in tests")


@pytest.fixture
def client(db: Engine) -> Iterator[TestClient]:
    from backend.app.pc import get_sync_runner

    RUNNER["current"] = SyncRunner(_broken, engine=lambda: db, clock=lambda: NOW)
    app.dependency_overrides[get_engine] = lambda: db
    app.dependency_overrides[get_wazuh_probe] = lambda: HttpProbe(url=None)
    app.dependency_overrides[get_model_probe] = lambda: ModelProbe(base_url=None)
    app.dependency_overrides[get_backfill_state] = lambda: ServiceState(reachable=True)
    app.dependency_overrides[get_sync_runner] = lambda: RUNNER["current"]
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_no_findings_is_a_404(client: TestClient) -> None:
    response = client.get("/api/pc/assessment")
    assert response.status_code == 404
    assert response.json()["detail"] == "No open findings yet. Rescan to pull them from Wazuh."


def test_assessment_of_the_busiest_host(client: TestClient, db: Engine) -> None:
    upsert_findings(db, "my-pc", [make_finding("a", priority=80), make_finding("b")], NOW)
    upsert_findings(db, "tiny-pc", [make_finding("c", host="tiny-pc")], NOW)
    [a, _] = open_findings(db, "my-pc")
    set_advice(
        db,
        a.finding_id,
        Recommendation(title="Fix", priority=80, steps=["Do it."], finding_ids=[a.finding_id]),
        "ollama:qwen3:14b",
        NOW,
    )
    view = HostAssessment.model_validate(client.get("/api/pc/assessment").json())
    assert view.host == "my-pc"
    assert [f.key for f in view.findings] == ["a", "b"]
    assert len(view.recommendations) == 1
    other = HostAssessment.model_validate(client.get("/api/pc/assessment?host=tiny-pc").json())
    assert [f.key for f in other.findings] == ["c"]


def test_rescan_starts_once_and_needs_an_indexer(client: TestClient) -> None:
    runner = RUNNER["current"]
    runner._lock.acquire()
    assert client.post("/api/pc/rescan").status_code == 409
    runner._lock.release()
    response = client.post("/api/pc/rescan")
    assert (response.status_code, response.json()) == (202, {"status": "started"})
    RUNNER["current"] = SyncRunner(None)
    assert client.post("/api/pc/rescan").status_code == 503


def test_feed_reports_the_sync_state(client: TestClient) -> None:
    feed = PcFeed.model_validate(client.get("/api/pc/feed").json())
    assert feed.status.sync.detail == "Not synced yet."
