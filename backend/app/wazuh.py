from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache

import httpx

from contracts.models import ServiceState


@dataclass
class WazuhApiProbe:
    url: str | None
    ttl_seconds: float = 30.0
    clock: Callable[[], float] = time.monotonic
    transport: httpx.BaseTransport | None = None
    _state: ServiceState | None = field(default=None, init=False)
    _checked_at: float = field(default=0.0, init=False)

    def state(self) -> ServiceState:
        if self.url is None:
            return ServiceState(reachable=False, detail="WAZUH_API_URL is not set.")
        now = self.clock()
        if self._state is None or now - self._checked_at >= self.ttl_seconds:
            self._state = self._check(self.url)
            self._checked_at = now
        return self._state

    def _check(self, url: str) -> ServiceState:
        try:
            with httpx.Client(verify=False, timeout=2.0, transport=self.transport) as client:
                response = client.get(url)
        except httpx.HTTPError as error:
            return ServiceState(reachable=False, detail=f"Wazuh API unreachable: {error}")
        return ServiceState(
            reachable=True, detail=f"Wazuh API answered HTTP {response.status_code}."
        )


@cache
def get_wazuh_probe() -> WazuhApiProbe:
    return WazuhApiProbe(url=os.environ.get("WAZUH_API_URL") or None)
