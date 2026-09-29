from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from backend.app.backfill import ALERTS_INDEX
from backend.app.db import get_engine
from backend.app.findings import record_sync, related_alert_count, upsert_findings
from contracts.models import Finding, ServiceState
from ingest.wazuh_findings import (
    FindingError,
    sca_check_key,
    sca_cleared_key,
    sca_finding,
    vulnerability_finding,
)
from policy.priority import prioritize

logger = logging.getLogger(__name__)

VULNERABILITIES_INDEX = "wazuh-states-vulnerabilities-*"
MAX_DOCS = 10000
MANAGER_AGENT_ID = "000"
SYNC_INTERVAL = timedelta(hours=6)
RETRY_AFTER_FAILURE = timedelta(minutes=5)
RELATED_WINDOW = timedelta(days=7)
SKIP_MANAGER = [{"term": {"agent.id": MANAGER_AGENT_ID}}]
CUT_OFF = " The {} results were cut off, so none were marked resolved."


@dataclass(frozen=True)
class Page:
    docs: list[dict[str, Any]]
    truncated: bool


@dataclass(frozen=True)
class Collected:
    findings: dict[str, list[Finding]]
    resolvable: dict[str, set[str]]


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


def fetch(client: httpx.Client, index: str, body: dict[str, Any]) -> Page:
    response = client.post(f"/{index}/_search", json=body)
    response.raise_for_status()
    hits = response.json()["hits"]
    docs = [hit["_source"] for hit in hits["hits"]]
    return Page(docs, _truncated(hits.get("total"), len(docs)))


def _truncated(total: Any, returned: int) -> bool:
    if isinstance(total, dict):
        return total.get("relation") == "gte" or int(total.get("value", 0)) > returned
    if isinstance(total, int):
        return total > returned
    return False


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
) -> Collected:
    by_host: dict[str, list[Finding]] = {}
    resolvable: dict[str, set[str]] = {}
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
            cleared = sca_cleared_key(alert)
        except FindingError:
            continue
        found = by_host.setdefault(host, [])
        if finding is not None:
            found.append(finding)
        if cleared is not None:
            resolvable.setdefault(host, set()).add(cleared)
    return Collected(by_host, resolvable)


def sync(engine: Engine, client: httpx.Client, clock: Callable[[], datetime]) -> ServiceState:
    started = clock()
    try:
        vulnerabilities = fetch(client, VULNERABILITIES_INDEX, vulnerability_search())
        checks = fetch(client, ALERTS_INDEX, sca_search())
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as error:
        return _failed(engine, started, clock(), error)
    collected = collect(vulnerabilities.docs, latest_checks(checks.docs), started)
    since = started - RELATED_WINDOW
    total = 0
    resolved = 0
    try:
        for host, found in collected.findings.items():
            ranked = [
                prioritize(
                    f, related_alert_count(engine, host, f.package, since) if f.package else 0
                )
                for f in found
            ]
            opened, closed = upsert_findings(
                engine,
                host,
                ranked,
                started,
                set() if checks.truncated else collected.resolvable.get(host, set()),
                resolve_vulnerabilities=not vulnerabilities.truncated,
            )
            total += opened
            resolved += closed
    except SQLAlchemyError as error:
        return _failed(engine, started, clock(), error)
    finished = clock()
    record_sync(engine, started, finished, True, None, total)
    detail = f"Synced {total} open findings at {finished:%H:%M:%S} UTC."
    if resolved:
        detail = f"{detail} {resolved} resolved."
    if vulnerabilities.truncated:
        detail += CUT_OFF.format("vulnerability")
    if checks.truncated:
        detail += CUT_OFF.format("security check")
    return ServiceState(reachable=True, detail=detail)


def _failed(
    engine: Engine, started: datetime, finished: datetime, error: Exception
) -> ServiceState:
    logger.warning("Wazuh sync failed: %s", error)
    record_sync(engine, started, finished, False, str(error), 0)
    return ServiceState(reachable=False, detail=f"Sync failed: {error}")


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
            ok = self.run() and self.state.reachable
            stop.wait((interval if ok else RETRY_AFTER_FAILURE).total_seconds())

    def _run_and_release(self) -> None:
        try:
            self.state = ServiceState(reachable=self.state.reachable, detail="Sync is running.")
            if self._client_factory is None:
                return
            with self._client_factory() as client:
                self.state = sync(self._engine(), client, self._clock)
        except Exception as error:
            logger.warning("Wazuh sync failed: %s", error)
            self.state = ServiceState(reachable=False, detail=f"Sync failed: {error}")
        finally:
            self._lock.release()
