from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache

import httpx

from contracts.models import ServiceState


@dataclass
class HttpProbe:
    url: str | None
    name: str = "Wazuh API"
    missing: str = "WAZUH_API_URL"
    verify: bool = False
    ttl_seconds: float = 30.0
    clock: Callable[[], float] = time.monotonic
    transport: httpx.BaseTransport | None = None
    _state: ServiceState | None = field(default=None, init=False)
    _checked_at: float = field(default=0.0, init=False)

    def state(self) -> ServiceState:
        if self.url is None:
            return ServiceState(reachable=False, detail=f"{self.missing} is not set.")
        now = self.clock()
        if self._state is None or now - self._checked_at >= self.ttl_seconds:
            self._state = self._check(self.url)
            self._checked_at = now
        return self._state

    def _check(self, url: str) -> ServiceState:
        try:
            with httpx.Client(
                verify=self.verify, timeout=2.0, transport=self.transport
            ) as client:
                response = client.get(url)
        except httpx.HTTPError as error:
            return ServiceState(reachable=False, detail=f"{self.name} unreachable: {error}")
        return ServiceState(
            reachable=True, detail=f"{self.name} answered HTTP {response.status_code}."
        )


@cache
def get_wazuh_probe() -> HttpProbe:
    return HttpProbe(url=os.environ.get("WAZUH_API_URL") or None)


@cache
def get_model_probe() -> HttpProbe:
    base = os.environ.get("OLLAMA_URL")
    return HttpProbe(
        url=f"{base.rstrip('/')}/api/tags" if base else None,
        name="Ollama",
        missing="OLLAMA_URL",
        verify=True,
    )
