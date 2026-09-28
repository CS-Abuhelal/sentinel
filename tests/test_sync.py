from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from sqlalchemy.engine import Engine

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


def _hits(docs: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": [{"_source": d} for d in docs]}})


def _client(vulnerabilities: list[dict], checks: list[dict]) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["size"] == MAX_DOCS
        if request.url.path == "/wazuh-states-vulnerabilities-*/_search":
            return _hits(vulnerabilities)
        if request.url.path == "/wazuh-alerts-4.x-*/_search":
            return _hits(checks)
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
    by_host = collect(
        vulnerabilities,
        [_check("2", "failed", "2026-09-27T10:00:00.000+0000"), passed],
        NOW,
    )
    assert sorted(by_host) == ["clean-pc", "my-pc"]
    assert by_host["clean-pc"] == []
    assert sorted(f.kind for f in by_host["my-pc"]) == [
        FindingKind.CONFIGURATION,
        FindingKind.VULNERABILITY,
    ]


def test_sync_stores_prioritized_findings_and_resolves_fixed_ones(db: Engine) -> None:
    failed = _check("26138", "failed", "2026-09-27T23:17:30.577+0000")
    state = sync(db, _client([wazuh_payload("vulnerability_state")], [failed]), NOW)
    assert state.reachable is True
    assert state.detail == "Synced 2 open findings at 12:00:00 UTC."
    [vuln, check] = open_findings(db, "my-pc")
    assert (vuln.priority, check.priority) == (96, 70)
    assert check.key == f"sca:{POLICY}:26138"
    now_passed = _check("26138", "passed", "2026-09-28T11:00:00.000+0000")
    later = NOW + timedelta(hours=6)
    state = sync(db, _client([wazuh_payload("vulnerability_state")], [now_passed, failed]), later)
    assert state.detail == "Synced 1 open findings at 18:00:00 UTC. 1 resolved."
    assert [f.kind for f in open_findings(db, "my-pc")] == [FindingKind.VULNERABILITY]
    assert last_successful_sync(db) == later


def test_a_failed_sync_is_recorded(db: Engine) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    client = httpx.Client(
        base_url="https://wazuh.indexer:9200", transport=httpx.MockTransport(refuse)
    )
    state = sync(db, client, NOW)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Sync failed:")
    assert last_successful_sync(db) is None


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
