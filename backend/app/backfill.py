from __future__ import annotations

import logging
import os
import ssl
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.engine import Engine

from backend.app.store import insert_alert, newest_alert_time
from contracts.models import ServiceState
from ingest.wazuh import WazuhAlertError, live_alert, parse_timestamp

logger = logging.getLogger(__name__)

ALERTS_INDEX = "wazuh-alerts-4.x-*"
MIN_LEVEL = 3
LIMIT = 5000
LOOKBACK = timedelta(minutes=10)
MAX_PAGES = 20
RETRY_BACKFILL = timedelta(seconds=30)


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
        verify: ssl.SSLContext | bool = True
        if self.ca_cert:
            verify = ssl.create_default_context(cafile=self.ca_cert)
        return httpx.Client(
            base_url=self.url,
            auth=(self.user, self.password),
            verify=verify,
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


def backfill_cursor(engine: Engine) -> datetime | None:
    newest = newest_alert_time(engine)
    if newest is None:
        return None
    return newest - LOOKBACK


def backfill(
    engine: Engine, client: httpx.Client, now: datetime, since: datetime | None
) -> ServiceState:
    cursor = since
    stored_total = 0
    fetched_total = 0
    pages = 0
    hit_page_limit = False
    while True:
        try:
            payloads = fetch_alerts(client, cursor, LIMIT)
        except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
            logger.warning("Wazuh backfill failed: %s", error)
            return ServiceState(reachable=False, detail=f"Backfill failed: {error}")
        pages += 1
        fetched_total += len(payloads)
        for payload in payloads:
            try:
                live = live_alert(payload, received_at=now)
            except WazuhAlertError:
                continue
            stored_total += insert_alert(engine, live, payload)
        if len(payloads) < LIMIT:
            break
        if pages >= MAX_PAGES:
            hit_page_limit = True
            break
        try:
            next_cursor = parse_timestamp(str(payloads[-1]["timestamp"]))
        except WazuhAlertError:
            break
        if cursor is not None and next_cursor <= cursor:
            break
        cursor = next_cursor
    detail = f"Backfilled {stored_total} of {fetched_total} alerts at {now:%H:%M:%S} UTC."
    if hit_page_limit:
        logger.warning("Wazuh backfill stopped at the %s-page limit.", MAX_PAGES)
        detail = f"{detail} Stopped at the {MAX_PAGES}-page limit."
    return ServiceState(reachable=True, detail=detail)


def backfill_until_done(
    engine: Engine,
    client_factory: Callable[[], httpx.Client],
    since: datetime | None,
    report: Callable[[ServiceState], None],
    stop: threading.Event,
    *,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    retry: timedelta = RETRY_BACKFILL,
) -> ServiceState:
    while True:
        try:
            with client_factory() as client:
                state = backfill(engine, client, clock(), since)
        except Exception as error:
            logger.warning("Wazuh backfill failed: %s", error)
            state = ServiceState(reachable=False, detail=f"Backfill failed: {error}")
        if state.reachable:
            report(state)
            return state
        failure = (state.detail or "Backfill failed").rstrip(".")
        seconds = int(retry.total_seconds())
        report(ServiceState(reachable=False, detail=f"{failure}. Retrying in {seconds} seconds."))
        if stop.wait(retry.total_seconds()):
            return state
