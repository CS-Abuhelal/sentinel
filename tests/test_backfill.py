from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.backfill import backfill, fetch_alerts, search_body
from backend.app.main import app
from backend.app.store import alert_count, insert_alert
from contracts.models import ServiceState
from tests.conftest import make_live_alert

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        base_url="https://wazuh.indexer:9200", transport=httpx.MockTransport(handler)
    )


def _hits(payloads: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": [{"_source": p} for p in payloads]}})


def test_search_body_without_since() -> None:
    body = search_body(None)
    assert body["size"] == 5000
    assert body["sort"] == [{"timestamp": {"order": "asc"}}]
    assert body["query"]["bool"]["filter"] == [{"range": {"rule.level": {"gte": 3}}}]


def test_search_body_with_since() -> None:
    since = datetime(2026, 9, 27, 9, 5, tzinfo=UTC)
    filters = search_body(since)["query"]["bool"]["filter"]
    assert filters[1] == {"range": {"timestamp": {"gte": since.isoformat()}}}


def test_fetch_alerts_searches_the_alerts_index() -> None:
    _, payload = make_live_alert("2.1", minute=1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/wazuh-alerts-4.x-*/_search"
        assert json.loads(request.content)["size"] == 5000
        return _hits([payload])

    assert fetch_alerts(_client(handler), since=None) == [payload]


def test_backfill_stores_valid_alerts_once(db: Engine) -> None:
    payloads = [make_live_alert(f"2.{n}", minute=n)[1] for n in (1, 2)] + [{"id": "broken"}]
    client = _client(lambda request: _hits(payloads))
    first = backfill(db, client, NOW)
    second = backfill(db, client, NOW)
    assert first.reachable is True
    assert first.detail is not None and first.detail.startswith("Backfilled 2 of 3 alerts")
    assert second.detail is not None and second.detail.startswith("Backfilled 0 of 3 alerts")
    assert alert_count(db) == 2


def test_backfill_starts_from_the_newest_stored_alert(db: Engine) -> None:
    live, payload = make_live_alert("2.5", minute=5)
    insert_alert(db, live, payload)
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return _hits([])

    backfill(db, _client(handler), NOW)
    since = seen[0]["query"]["bool"]["filter"][1]["range"]["timestamp"]["gte"]
    assert datetime.fromisoformat(since) == datetime(2026, 9, 27, 9, 5, tzinfo=UTC)


def test_backfill_reports_an_unreachable_indexer(
    db: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    state = backfill(db, _client(refuse), NOW)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Backfill failed")
    assert "Wazuh backfill failed" in caplog.text


def test_backfill_reports_a_malformed_answer(db: Engine) -> None:
    client = _client(lambda request: httpx.Response(200, json={"hits": {"hits": None}}))
    state = backfill(db, client, NOW)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Backfill failed")


def test_startup_without_an_indexer_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    try:
        with TestClient(app):
            assert app.state.backfill == ServiceState(
                reachable=False, detail="WAZUH_INDEXER_URL is not set."
            )
    finally:
        del app.state.backfill
