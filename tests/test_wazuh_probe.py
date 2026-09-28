from __future__ import annotations

from collections.abc import Callable

import httpx

from backend.app.probes import HttpProbe as WazuhApiProbe


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
