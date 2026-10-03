from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.main import app
from backend.app.store import alert_count
from tests.conftest import wazuh_payload

URL = "/api/ingest/wazuh"
TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    yield
    app.dependency_overrides.clear()


def _client(engine: object, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SENTINEL_INGEST_TOKEN", TOKEN)
    app.dependency_overrides[get_engine] = lambda: engine
    return TestClient(app)


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return _client(object(), monkeypatch)


@pytest.fixture
def online(db: Engine, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return _client(db, monkeypatch)


def _body() -> bytes:
    return json.dumps(wazuh_payload("logon_failure")).encode()


def test_alert_is_stored_once(online: TestClient, db: Engine) -> None:
    first = online.post(URL, content=_body(), headers=AUTH)
    second = online.post(URL, content=_body(), headers=AUTH)
    assert (first.status_code, first.json()) == (202, {"stored": True})
    assert (second.status_code, second.json()) == (202, {"stored": False})
    assert alert_count(db) == 1


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}]
)
def test_wrong_or_missing_token_is_rejected(offline: TestClient, headers: dict) -> None:
    assert offline.post(URL, content=_body(), headers=headers).status_code == 401


def test_ingest_is_off_without_a_token(
    offline: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SENTINEL_INGEST_TOKEN")
    assert offline.post(URL, content=_body(), headers=AUTH).status_code == 503


def test_oversized_alert_is_rejected(offline: TestClient) -> None:
    body = b'{"padding": "' + b"a" * 1_000_001 + b'"}'
    assert offline.post(URL, content=body, headers=AUTH).status_code == 413


def test_oversized_alert_without_a_declared_length_is_rejected(offline: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"padding": "'
        for _ in range(11):
            yield b"a" * 100_000
        yield b'"}'

    assert offline.post(URL, content=chunks(), headers=AUTH).status_code == 413


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"id": "1"}'])
def test_malformed_alert_is_rejected(offline: TestClient, body: bytes) -> None:
    assert offline.post(URL, content=body, headers=AUTH).status_code == 422
