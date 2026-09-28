from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.backfill import (
    IndexerSettings,
    backfill,
    backfill_cursor,
    fetch_alerts,
    search_body,
)
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


def test_backfill_cursor_is_none_without_stored_alerts(db: Engine) -> None:
    assert backfill_cursor(db) is None


def test_backfill_cursor_looks_back_ten_minutes(db: Engine) -> None:
    live, payload = make_live_alert("2.5", minute=5)
    insert_alert(db, live, payload)
    assert backfill_cursor(db) == datetime(2026, 9, 27, 8, 55, tzinfo=UTC)


def test_backfill_ignores_alerts_stored_after_the_cursor_was_computed(db: Engine) -> None:
    live, payload = make_live_alert("2.5", minute=5)
    insert_alert(db, live, payload)
    cursor = backfill_cursor(db)
    assert cursor is not None
    other_live, other_payload = make_live_alert("2.30", minute=30)
    insert_alert(db, other_live, other_payload)
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return _hits([])

    backfill(db, _client(handler), NOW, since=cursor)
    since_value = seen[0]["query"]["bool"]["filter"][1]["range"]["timestamp"]["gte"]
    assert datetime.fromisoformat(since_value) == cursor


def test_backfill_stores_valid_alerts_once(db: Engine) -> None:
    payloads = [make_live_alert(f"2.{n}", minute=n)[1] for n in (1, 2)] + [{"id": "broken"}]
    client = _client(lambda request: _hits(payloads))
    first = backfill(db, client, NOW, since=None)
    second = backfill(db, client, NOW, since=None)
    assert first.reachable is True
    assert first.detail is not None and first.detail.startswith("Backfilled 2 of 3 alerts")
    assert second.detail is not None and second.detail.startswith("Backfilled 0 of 3 alerts")
    assert alert_count(db) == 2


def test_backfill_pages_past_the_limit(db: Engine, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("backend.app.backfill.LIMIT", 2)
    pages = [
        [make_live_alert(f"3.{n}", minute=n)[1] for n in (1, 2)],
        [make_live_alert("3.3", minute=3)[1]],
    ]
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return _hits(pages.pop(0))

    state = backfill(db, _client(handler), NOW, since=None)
    assert len(requests) == 2
    since_value = requests[1]["query"]["bool"]["filter"][1]["range"]["timestamp"]["gte"]
    assert datetime.fromisoformat(since_value) == datetime(2026, 9, 27, 9, 2, tzinfo=UTC)
    assert state.detail is not None and state.detail.startswith("Backfilled 3 of 3 alerts")
    assert alert_count(db) == 3


def test_backfill_stops_at_the_page_limit(
    db: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr("backend.app.backfill.LIMIT", 1)
    monkeypatch.setattr("backend.app.backfill.MAX_PAGES", 3)
    counter = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        counter["n"] += 1
        _, payload = make_live_alert(f"4.{counter['n']}", minute=counter["n"])
        return _hits([payload])

    state = backfill(db, _client(handler), NOW, since=None)
    assert counter["n"] == 3
    assert state.reachable is True
    assert state.detail is not None
    assert state.detail.endswith("Stopped at the 3-page limit.")
    assert "Wazuh backfill stopped" in caplog.text


def test_backfill_reports_an_unreachable_indexer(
    db: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    state = backfill(db, _client(refuse), NOW, since=None)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Backfill failed")
    assert "Wazuh backfill failed" in caplog.text


def test_backfill_reports_a_malformed_answer(db: Engine) -> None:
    client = _client(lambda request: httpx.Response(200, json={"hits": {"hits": None}}))
    state = backfill(db, client, NOW, since=None)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Backfill failed")


def test_indexer_settings_from_env_requires_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    assert IndexerSettings.from_env() is None


def test_indexer_settings_from_env_reads_all_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200/")
    monkeypatch.setenv("WAZUH_INDEXER_USER", "admin")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "secret")
    monkeypatch.setenv("WAZUH_CA_CERT", "/certs/ca.pem")
    settings = IndexerSettings.from_env()
    assert settings is not None
    assert settings.url == "https://wazuh.indexer:9200"
    assert (settings.user, settings.password, settings.ca_cert) == (
        "admin",
        "secret",
        "/certs/ca.pem",
    )


def test_indexer_settings_client_without_ca(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")
    monkeypatch.delenv("WAZUH_INDEXER_USER", raising=False)
    monkeypatch.delenv("WAZUH_INDEXER_PASSWORD", raising=False)
    monkeypatch.delenv("WAZUH_CA_CERT", raising=False)
    settings = IndexerSettings.from_env()
    assert settings is not None
    with settings.client() as client:
        assert str(client.base_url) == "https://wazuh.indexer:9200"


def test_startup_without_an_indexer_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    try:
        with TestClient(app):
            assert app.state.backfill == ServiceState(
                reachable=False, detail="WAZUH_INDEXER_URL is not set."
            )
    finally:
        del app.state.backfill
        del app.state.sync


def test_startup_with_a_broken_engine_reports_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://wazuh.indexer:9200")

    def broken_engine() -> Engine:
        raise RuntimeError("no database")

    monkeypatch.setattr("backend.app.main.get_engine", broken_engine)
    try:
        with TestClient(app):
            assert app.state.backfill.reachable is False
            assert app.state.backfill.detail is not None
            assert app.state.backfill.detail.startswith("Backfill failed")
    finally:
        del app.state.backfill
        del app.state.sync
