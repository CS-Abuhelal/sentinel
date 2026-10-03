from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from backend.app.probes import HttpProbe as WazuhApiProbe
from backend.app.probes import ModelProbe, get_model_probe


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _probe(
    handler: Callable[[httpx.Request], httpx.Response], clock: Clock | None = None
) -> tuple[WazuhApiProbe, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    probe = WazuhApiProbe(
        url="https://wazuh.manager:55000",
        transport=httpx.MockTransport(record),
        clock=clock or Clock(),
    )
    return probe, seen


def test_no_url_means_offline() -> None:
    state = WazuhApiProbe(url=None).state()
    assert state.reachable is False
    assert state.detail is not None and "WAZUH_API_URL" in state.detail


def test_any_http_answer_means_online() -> None:
    probe, _ = _probe(lambda request: httpx.Response(401))
    state = probe.state()
    assert state.reachable is True
    assert state.detail == "Wazuh API answered HTTP 401."


def test_connection_error_means_offline() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    probe, _ = _probe(refuse)
    state = probe.state()
    assert state.reachable is False
    assert state.detail is not None and "connection refused" in state.detail


def test_answer_is_cached_for_30_seconds() -> None:
    clock = Clock()
    probe, seen = _probe(lambda request: httpx.Response(401), clock)
    probe.state()
    clock.now = 29.9
    probe.state()
    assert len(seen) == 1
    clock.now = 30.0
    probe.state()
    assert len(seen) == 2


def test_the_model_probe_names_itself() -> None:
    probe = WazuhApiProbe(url=None, name="Ollama", missing="OLLAMA_URL")
    assert probe.state().detail == "OLLAMA_URL is not set."


def _tags(*names: str) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": [{"name": name} for name in names]})

    return handler


def test_the_model_probe_needs_a_url() -> None:
    state = ModelProbe(base_url=None).state()
    assert (state.reachable, state.detail) == (False, "OLLAMA_URL is not set.")


def test_the_model_probe_is_offline_until_the_model_is_pulled() -> None:
    missing = ModelProbe(
        base_url="http://ollama:11434", transport=httpx.MockTransport(_tags("llama3:8b"))
    ).state()
    assert missing.reachable is False
    assert missing.detail == "Ollama is up but qwen3:14b is not pulled."
    ready = ModelProbe(
        base_url="http://ollama:11434", transport=httpx.MockTransport(_tags("qwen3:14b"))
    ).state()
    assert ready.reachable is True


def test_the_model_probe_is_offline_when_ollama_is_down() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    probe = ModelProbe(base_url="http://ollama:11434", transport=httpx.MockTransport(refuse))
    assert probe.state().reachable is False


def test_the_model_probe_is_cached_for_30_seconds() -> None:
    clock = Clock()
    seen: list[httpx.Request] = []
    tags = _tags("qwen3:14b")

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return tags(request)

    probe = ModelProbe(
        base_url="http://ollama:11434", clock=clock, transport=httpx.MockTransport(record)
    )
    probe.state()
    clock.now = 29.9
    probe.state()
    assert len(seen) == 1
    clock.now = 30.0
    probe.state()
    assert len(seen) == 2


def test_the_model_probe_reads_its_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    get_model_probe.cache_clear()
    monkeypatch.setenv("OLLAMA_URL", "http://ollama.test:11434")
    monkeypatch.delenv("OLLAMA_MODEL", raising=False)
    try:
        probe = get_model_probe()
        assert (probe.base_url, probe.model) == ("http://ollama.test:11434", "qwen3:14b")
        get_model_probe.cache_clear()
        monkeypatch.setenv("OLLAMA_MODEL", "qwen3:8b")
        assert get_model_probe().model == "qwen3:8b"
        get_model_probe.cache_clear()
        monkeypatch.delenv("OLLAMA_URL")
        assert get_model_probe().state().detail == "OLLAMA_URL is not set."
    finally:
        get_model_probe.cache_clear()
