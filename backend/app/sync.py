from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.engine import Engine

from backend.app.backfill import ALERTS_INDEX
from backend.app.db import get_engine
from backend.app.findings import record_sync, related_alert_count, upsert_findings
from contracts.models import Finding, ServiceState
from ingest.wazuh_findings import FindingError, sca_check_key, sca_finding, vulnerability_finding
from policy.priority import prioritize

logger = logging.getLogger(__name__)

VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
MAX_DOCS = 10000
MANAGER_AGENT_ID = "000"
SYNC_INTERVAL = timedelta(hours=6)
RELATED_WINDOW = timedelta(days=7)
SKIP_MANAGER = [{"term": {"agent.id": MANAGER_AGENT_ID}}]


def utcnow() -> datetime:
    return datetime.now(UTC)


def vulnerability_search() -> dict[str, Any]:
    return {"size": MAX_DOCS, "query": {"bool": {"must_not": SKIP_MANAGER}}}


def sca_search() -> dict[str, Any]:
    return {
        "size": MAX_DOCS,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "sca"}},
                    {"term": {"data.sca.type": "check"}},
                ],
                "must_not": SKIP_MANAGER,
            }
        },
    }


def fetch(client: httpx.Client, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
    response = client.post(f"/{index}/_search", json=body)
    response.raise_for_status()
    return [hit["_source"] for hit in response.json()["hits"]["hits"]]


def latest_checks(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    latest = []
    for alert in alerts:
        try:
            key = sca_check_key(alert)
        except FindingError:
            continue
        if key not in seen:
            seen.add(key)
            latest.append(alert)
    return latest


def collect(
    vulnerabilities: list[dict[str, Any]], checks: list[dict[str, Any]], now: datetime
) -> dict[str, list[Finding]]:
    by_host: dict[str, list[Finding]] = {}
    for doc in vulnerabilities:
        try:
            finding = vulnerability_finding(doc, now)
        except FindingError:
            continue
        by_host.setdefault(finding.host, []).append(finding)
    for alert in checks:
        try:
            host = sca_check_key(alert)[0]
            finding = sca_finding(alert, now)
        except FindingError:
            continue
        found = by_host.setdefault(host, [])
        if finding is not None:
            found.append(finding)
    return by_host


def sync(engine: Engine, client: httpx.Client, now: datetime) -> ServiceState:
    try:
        vulnerabilities = fetch(client, VULNERABILITIES_INDEX, vulnerability_search())
        checks = latest_checks(fetch(client, ALERTS_INDEX, sca_search()))
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
        logger.warning("Wazuh sync failed: %s", error)
        record_sync(engine, now, now, False, str(error), 0)
        return ServiceState(reachable=False, detail=f"Sync failed: {error}")
    since = now - RELATED_WINDOW
    total = 0
    resolved = 0
    for host, found in collect(vulnerabilities, checks, now).items():
        ranked = [
            prioritize(f, related_alert_count(engine, host, f.package, since) if f.package else 0)
            for f in found
        ]
        opened, closed = upsert_findings(engine, host, ranked, now)
        total += opened
        resolved += closed
    record_sync(engine, now, now, True, None, total)
    detail = f"Synced {total} open findings at {now:%H:%M:%S} UTC."
    if resolved:
        detail = f"{detail} {resolved} resolved."
    return ServiceState(reachable=True, detail=detail)


class SyncRunner:
    def __init__(
        self,
        client_factory: Callable[[], httpx.Client] | None,
        engine: Callable[[], Engine] = get_engine,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._client_factory = client_factory
        self._engine = engine
        self._clock = clock
        self._lock = threading.Lock()
        self.state = ServiceState(
            reachable=False,
            detail="Not synced yet." if client_factory else "WAZUH_INDEXER_URL is not set.",
        )

    @property
    def configured(self) -> bool:
        return self._client_factory is not None

    def start(self) -> bool:
        if not self.configured or not self._lock.acquire(blocking=False):
            return False
        threading.Thread(target=self._run_and_release, daemon=True).start()
        return True

    def run(self) -> bool:
        if not self.configured or not self._lock.acquire(blocking=False):
            return False
        self._run_and_release()
        return True

    def every(self, interval: timedelta, stop: threading.Event) -> None:
        while not stop.is_set():
            self.start()
            stop.wait(interval.total_seconds())

    def _run_and_release(self) -> None:
        try:
            self.state = ServiceState(reachable=self.state.reachable, detail="Sync is running.")
            if self._client_factory is None:
                return
            with self._client_factory() as client:
                self.state = sync(self._engine(), client, self._clock())
        except Exception as error:
            logger.warning("Wazuh sync failed: %s", error)
            self.state = ServiceState(reachable=False, detail=f"Sync failed: {error}")
        finally:
            self._lock.release()
