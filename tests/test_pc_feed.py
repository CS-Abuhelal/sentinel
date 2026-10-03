from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.main import app
from backend.app.pc import NOT_RUN, get_backfill_state
from backend.app.store import insert_alert
from backend.app.wazuh import WazuhApiProbe, get_wazuh_probe
from contracts.models import PcFeed, ServiceState
from tests.conftest import make_live_alert

BACKFILLED = ServiceState(reachable=True, detail="Backfilled 0 of 0 alerts at 10:00:00 UTC.")


@pytest.fixture
def client(db: Engine) -> Iterator[TestClient]:
    probe = WazuhApiProbe(url=None)
    app.dependency_overrides[get_engine] = lambda: db
    app.dependency_overrides[get_wazuh_probe] = lambda: probe
    app.dependency_overrides[get_backfill_state] = lambda: BACKFILLED
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_empty_feed(client: TestClient) -> None:
    response = client.get("/api/pc/feed")
    assert response.status_code == 200
    feed = PcFeed.model_validate(response.json())
    assert feed.alerts == []
    assert feed.status.alert_count == 0
    assert feed.status.last_alert_at is None
    assert feed.status.wazuh_api.reachable is False
    assert feed.status.backfill == BACKFILLED


def test_backfill_state_defaults_to_not_run() -> None:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    assert get_backfill_state(request) == NOT_RUN


def test_feed_is_newest_first_and_limited(client: TestClient, db: Engine) -> None:
    for n in (1, 2, 3):
        live, payload = make_live_alert(f"3.{n}", minute=n)
        insert_alert(db, live, payload)
    feed = PcFeed.model_validate(client.get("/api/pc/feed?limit=2").json())
    assert [a.wazuh_id for a in feed.alerts] == ["3.3", "3.2"]
    assert feed.status.alert_count == 3
    assert feed.status.last_alert_at == datetime(2026, 9, 27, 9, 3, tzinfo=UTC)


@pytest.mark.parametrize("limit", [0, 1001])
def test_limit_is_bounded(client: TestClient, limit: int) -> None:
    assert client.get(f"/api/pc/feed?limit={limit}").status_code == 422
