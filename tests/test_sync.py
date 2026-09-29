from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

from backend.app.db import sync_runs
from backend.app.findings import last_successful_sync, open_findings
from backend.app.sync import (
    MAX_DOCS,
    SyncRunner,
    collect,
    latest_checks,
    sca_search,
    sync,
    vulnerability_search,
)
from contracts.models import FindingKind
from tests.conftest import wazuh_payload

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
POLICY = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"


def _hits(docs: list[dict[str, Any]], total: dict[str, Any] | None = None) -> httpx.Response:
    hits: dict[str, Any] = {"hits": [{"_source": d} for d in docs]}
    if total is not None:
        hits["total"] = total
    return httpx.Response(200, json={"hits": hits})


def _client(
    vulnerabilities: list[dict],
    checks: list[dict],
    vulnerability_total: dict[str, Any] | None = None,
    check_total: dict[str, Any] | None = None,
) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["size"] == MAX_DOCS
        if request.url.path == "/wazuh-states-vulnerabilities-*/_search":
            return _hits(vulnerabilities, vulnerability_total)
        if request.url.path == "/wazuh-alerts-4.x-*/_search":
            return _hits(checks, check_total)
        return httpx.Response(404)

    return httpx.Client(
        base_url="https://wazuh.indexer:9200", transport=httpx.MockTransport(handler)
    )


def _check(check_id: str, result: str, when: str) -> dict[str, Any]:
    alert = copy.deepcopy(wazuh_payload("sca_check_failed"))
    alert["data"]["sca"]["check"]["id"] = check_id
    alert["data"]["sca"]["check"]["result"] = result
    alert["timestamp"] = when
    return alert


def test_searches_skip_the_manager_and_ask_for_checks() -> None:
    assert vulnerability_search()["query"]["bool"]["must_not"] == [{"term": {"agent.id": "000"}}]
    body = sca_search()
    assert body["sort"] == [{"timestamp": {"order": "desc"}}]
    assert {"term": {"data.sca.type": "check"}} in body["query"]["bool"]["filter"]


def test_latest_checks_keeps_the_newest_result_per_check() -> None:
    newest = _check("1", "passed", "2026-09-28T10:00:00.000+0000")
    older = _check("1", "failed", "2026-09-27T10:00:00.000+0000")
    other = _check("2", "failed", "2026-09-27T10:00:00.000+0000")
    broken = {"agent": {"name": "my-pc"}}
    assert latest_checks([newest, older, other, broken]) == [newest, other]


def test_collect_groups_by_host_and_keeps_hosts_whose_checks_passed() -> None:
    vulnerabilities = [wazuh_payload("vulnerability_state"), {"agent": {}}]
    passed = _check("3", "passed", "2026-09-28T10:00:00.000+0000")
    passed["agent"]["name"] = "clean-pc"
    skipped = _check("4", "not applicable", "2026-09-28T10:00:00.000+0000")
    collected = collect(
        vulnerabilities,
        [_check("2", "failed", "2026-09-27T10:00:00.000+0000"), passed, skipped],
        NOW,
    )
    by_host = collected.findings
    assert sorted(by_host) == ["clean-pc", "my-pc"]
    assert by_host["clean-pc"] == []
    assert sorted(f.kind for f in by_host["my-pc"]) == [
        FindingKind.CONFIGURATION,
        FindingKind.VULNERABILITY,
    ]
    assert collected.resolvable == {
        "clean-pc": {f"sca:{POLICY}:3"},
        "my-pc": {f"sca:{POLICY}:4"},
    }


def test_sync_stores_prioritized_findings_and_resolves_fixed_ones(db: Engine) -> None:
    failed = _check("26138", "failed", "2026-09-27T23:17:30.577+0000")
    state = sync(db, _client([wazuh_payload("vulnerability_state")], [failed]), lambda: NOW)
    assert state.reachable is True
    assert state.detail == "Synced 2 open findings at 12:00:00 UTC."
    [vuln, check] = open_findings(db, "my-pc")
    assert (vuln.priority, check.priority) == (96, 55)
    assert check.key == f"sca:{POLICY}:26138"
    now_passed = _check("26138", "passed", "2026-09-28T11:00:00.000+0000")
    later = NOW + timedelta(hours=6)
    client = _client([wazuh_payload("vulnerability_state")], [now_passed, failed])
    state = sync(db, client, lambda: later)
    assert state.detail == "Synced 1 open findings at 18:00:00 UTC. 1 resolved."
    assert [f.kind for f in open_findings(db, "my-pc")] == [FindingKind.VULNERABILITY]
    assert last_successful_sync(db) == later


def test_a_failed_sync_is_recorded(db: Engine) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(
        base_url="https://wazuh.indexer:9200", transport=httpx.MockTransport(refuse)
    )
    state = sync(db, client, lambda: NOW)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Sync failed:")
    assert last_successful_sync(db) is None
    [run] = _runs(db)
    assert run.ok is False


def test_runner_runs_once_at_a_time(db: Engine) -> None:
    def factory() -> httpx.Client:
        return _client([wazuh_payload("vulnerability_state")], [])

    runner = SyncRunner(factory, engine=lambda: db, clock=lambda: NOW)
    assert runner.configured is True
    assert runner.state.detail == "Not synced yet."
    runner._lock.acquire()
    assert runner.start() is False
    assert runner.run() is False
    runner._lock.release()
    assert runner.run() is True
    assert runner.state.detail == "Synced 1 open findings at 12:00:00 UTC."


def test_runner_without_an_indexer_does_nothing() -> None:
    runner = SyncRunner(None)
    assert runner.configured is False
    assert runner.start() is False
    assert runner.state.detail == "WAZUH_INDEXER_URL is not set."


def test_runner_survives_a_broken_client_factory(db: Engine) -> None:
    def broken() -> httpx.Client:
        raise RuntimeError("no certificate")

    runner = SyncRunner(broken, engine=lambda: db, clock=lambda: NOW)
    assert runner.run() is True
    assert runner.state.reachable is False
    assert runner.state.detail == "Sync failed: no certificate"


def _runs(db: Engine) -> list[Any]:
    with db.connect() as connection:
        return list(connection.execute(select(sync_runs).order_by(sync_runs.c.started_at)))


def test_a_failed_check_missing_from_the_sync_stays_open(db: Engine) -> None:
    failed = _check("26138", "failed", "2026-09-27T23:17:30.577+0000")
    sync(db, _client([wazuh_payload("vulnerability_state")], [failed]), lambda: NOW)
    later = NOW + timedelta(hours=6)
    state = sync(db, _client([wazuh_payload("vulnerability_state")], []), lambda: later)
    assert state.detail == "Synced 2 open findings at 18:00:00 UTC."
    assert sorted(f.kind for f in open_findings(db, "my-pc")) == [
        FindingKind.CONFIGURATION,
        FindingKind.VULNERABILITY,
    ]


def test_a_vulnerability_missing_from_the_state_index_is_resolved(db: Engine) -> None:
    sync(db, _client([wazuh_payload("vulnerability_state")], []), lambda: NOW)
    state = sync(db, _client([], [_check("1", "passed", "2026-09-28T10:00:00.000+0000")]),
                 lambda: NOW + timedelta(hours=6))
    assert state.detail == "Synced 0 open findings at 18:00:00 UTC. 1 resolved."
    assert open_findings(db, "my-pc") == []


def test_truncated_results_resolve_nothing(db: Engine) -> None:
    failed = _check("26138", "failed", "2026-09-27T23:17:30.577+0000")
    sync(db, _client([wazuh_payload("vulnerability_state")], [failed]), lambda: NOW)
    passed = _check("26138", "passed", "2026-09-28T11:00:00.000+0000")
    client = _client(
        [],
        [passed],
        vulnerability_total={"value": 10000, "relation": "gte"},
        check_total={"value": 25000, "relation": "eq"},
    )
    state = sync(db, client, lambda: NOW + timedelta(hours=6))
    assert state.reachable is True
    assert state.detail == (
        "Synced 2 open findings at 18:00:00 UTC. The vulnerability results were cut off, so "
        "none were marked resolved. The security check results were cut off, so none were "
        "marked resolved."
    )
    assert len(open_findings(db, "my-pc")) == 2


def test_a_sync_records_when_it_started_and_finished(db: Engine) -> None:
    times = iter([NOW, NOW + timedelta(seconds=7)])
    state = sync(db, _client([wazuh_payload("vulnerability_state")], []), lambda: next(times))
    assert state.detail == "Synced 1 open findings at 12:00:07 UTC."
    [run] = _runs(db)
    assert (run.started_at, run.finished_at, run.ok, run.found) == (
        NOW,
        NOW + timedelta(seconds=7),
        True,
        1,
    )
    [finding] = open_findings(db, "my-pc")
    assert finding.last_seen == NOW


def test_a_database_failure_while_storing_is_recorded(
    db: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*args: object, **kwargs: object) -> tuple[int, int]:
        raise SQLAlchemyError("database went away")

    monkeypatch.setattr("backend.app.sync.upsert_findings", broken)
    times = iter([NOW, NOW + timedelta(seconds=3)])
    state = sync(db, _client([wazuh_payload("vulnerability_state")], []), lambda: next(times))
    assert state.reachable is False
    assert state.detail == "Sync failed: database went away"
    [run] = _runs(db)
    assert (run.started_at, run.finished_at, run.ok, run.error) == (
        NOW,
        NOW + timedelta(seconds=3),
        False,
        "database went away",
    )


class CountingStop:
    def __init__(self, rounds: int) -> None:
        self.rounds = rounds
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return len(self.waits) >= self.rounds

    def wait(self, seconds: float) -> bool:
        self.waits.append(seconds)
        return self.is_set()


def test_every_retries_soon_after_a_failure_and_waits_the_interval_after_a_success(
    db: Engine,
) -> None:
    attempts: list[int] = []

    def factory() -> httpx.Client:
        attempts.append(len(attempts))
        if len(attempts) == 1:
            raise RuntimeError("indexer is starting")
        return _client([wazuh_payload("vulnerability_state")], [])

    runner = SyncRunner(factory, engine=lambda: db, clock=lambda: NOW)
    stop = CountingStop(rounds=3)
    runner.every(timedelta(hours=6), stop)
    assert stop.waits == [300.0, 21600.0, 21600.0]
    assert attempts == [0, 1, 2]
    assert runner.state.detail == "Synced 1 open findings at 12:00:00 UTC."


def test_every_retries_soon_when_another_sync_holds_the_lock(db: Engine) -> None:
    runner = SyncRunner(lambda: _client([], []), engine=lambda: db, clock=lambda: NOW)
    runner._lock.acquire()
    stop = CountingStop(rounds=1)
    runner.every(timedelta(hours=6), stop)
    runner._lock.release()
    assert stop.waits == [300.0]
