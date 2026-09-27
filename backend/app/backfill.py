from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.engine import Engine

from backend.app.store import insert_alert, newest_alert_time
from contracts.models import ServiceState
from ingest.wazuh import WazuhAlertError, live_alert

ALERTS_INDEX = "wazuh-alerts-4.x-*"
MIN_LEVEL = 3
LIMIT = 5000


@dataclass(frozen=True)
class IndexerSettings:
    url: str
    user: str
    password: str
    ca_cert: str | None = None

    @classmethod
    def from_env(cls) -> IndexerSettings | None:
        url = os.environ.get("WAZUH_INDEXER_URL")
        if not url:
            return None
        return cls(
            url=url.rstrip("/"),
            user=os.environ.get("WAZUH_INDEXER_USER", ""),
            password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
            ca_cert=os.environ.get("WAZUH_CA_CERT") or None,
        )

    def client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.url,
            auth=(self.user, self.password),
            verify=self.ca_cert or True,
            timeout=10.0,
        )


def search_body(since: datetime | None, limit: int = LIMIT) -> dict[str, Any]:
    filters: list[dict[str, Any]] = [{"range": {"rule.level": {"gte": MIN_LEVEL}}}]
    if since is not None:
        filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})
    return {
        "size": limit,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": filters}},
    }


def fetch_alerts(
    client: httpx.Client, since: datetime | None, limit: int = LIMIT
) -> list[dict[str, Any]]:
    response = client.post(f"/{ALERTS_INDEX}/_search", json=search_body(since, limit))
    response.raise_for_status()
    return [hit["_source"] for hit in response.json()["hits"]["hits"]]


def backfill(engine: Engine, client: httpx.Client, now: datetime) -> ServiceState:
    try:
        payloads = fetch_alerts(client, newest_alert_time(engine))
    except (httpx.HTTPError, KeyError, ValueError) as error:
        return ServiceState(reachable=False, detail=f"Backfill failed: {error}")
    stored = 0
    for payload in payloads:
        try:
            live = live_alert(payload, received_at=now)
        except WazuhAlertError:
            continue
        stored += insert_alert(engine, live, payload)
    return ServiceState(
        reachable=True,
        detail=f"Backfilled {stored} of {len(payloads)} alerts at {now:%H:%M:%S} UTC.",
    )
