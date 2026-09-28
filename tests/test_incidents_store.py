from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import insert
from sqlalchemy.engine import Engine

from agent.tools.base import ToolContext
from agent.tools.wazuh import MAX_HISTORY, RELATED_ALERTS, RULE_CONTEXT
from backend.app.db import wazuh_alerts
from backend.app.incidents import (
    HISTORY_LIMIT,
    StoreHistory,
    find_open_incident,
    get_run,
    host_alerts,
    host_auth_events,
    incident_alerts,
    incident_status,
    incident_summaries,
    mark_grouped,
    next_queued_incident,
    queue_length,
    requeue,
    rule_count,
    save_incident,
    save_run,
    set_status,
    unfinished_incidents,
    ungrouped_alerts,
)
from backend.app.store import insert_alert
from contracts.models import Entity, EntityType, Incident, IncidentRun, IncidentStatus, LiveAlert
from ingest.wazuh import live_alert
from pipeline.grouping import new_incident
from pipeline.worker import investigation_events
from tests.conftest import RECEIVED_AT, REPO, make_wazuh_alert

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def _incident(incident_id: str, minute: int, status: IncidentStatus) -> Incident:
    moment = datetime(2026, 9, 27, 9, minute, tzinfo=UTC)
    return Incident(
        incident_id=incident_id,
        title="Logon failures on my-pc",
        status=status,
        created_at=moment,
        window_start=moment,
        window_end=moment,
        alert_ids=[f"alr_{incident_id}"],
        entities=[Entity(entity_type=EntityType.HOST, value="my-pc")],
    )


def _store(db: Engine, wazuh_id: str, minute: int, **kwargs: object) -> None:
    live, payload = make_wazuh_alert(wazuh_id, minute, **kwargs)
    insert_alert(db, live, payload)


def _store_many(db: Engine, alerts: list[tuple[LiveAlert, dict[str, Any]]]) -> None:
    rows = [
        {
            "wazuh_id": live.wazuh_id,
            "alert_time": live.event.timestamp,
            "received_at": live.received_at,
            "agent_name": live.event.host,
            "rule_id": live.alert.rule_id,
            "level": live.level,
            "payload": payload,
            "event": live.event.model_dump(mode="json"),
            "alert": live.alert.model_dump(mode="json"),
        }
        for live, payload in alerts
    ]
    with db.begin() as connection:
        connection.execute(insert(wazuh_alerts), rows)


def _before_nine(prefix: str, count: int, **kwargs: Any) -> list[tuple[LiveAlert, Any]]:
    return [
        make_wazuh_alert(f"{prefix}.{n}", n % 60, hour=1 + (n // 60) % 8, **kwargs)
        for n in range(count)
    ]


def _with_text(wazuh_id: str, minute: int, text: str, **kwargs: Any) -> LiveAlert:
    _, payload = make_wazuh_alert(wazuh_id, minute, **kwargs)
    payload["full_log"] = text
    return live_alert(payload, received_at=RECEIVED_AT)


SCA_CHECK: dict[str, Any] = {"rule_id": "19007", "level": 7, "groups": ["sca"], "techniques": []}
BURST: dict[str, Any] = {
    "rule_id": "60204",
    "level": 10,
    "groups": ["windows", "windows_security", "authentication_failures"],
    "techniques": ["T1110"],
}


def test_ungrouped_alerts_are_oldest_first_and_leave_once_grouped(db: Engine) -> None:
    _store(db, "4.2", 2)
    _store(db, "4.1", 1)
    assert [a.wazuh_id for a in ungrouped_alerts(db)] == ["4.1", "4.2"]
    mark_grouped(db, "4.1", None, NOW)
    assert [a.wazuh_id for a in ungrouped_alerts(db)] == ["4.2"]


def test_open_incident_lookup_respects_key_status_and_window(db: Engine) -> None:
    save_incident(db, _incident("inc_a", 5, IncidentStatus.LOW_PRIORITY), "my-pc", "k", 1, 5, NOW)
    save_incident(db, _incident("inc_b", 6, IncidentStatus.INVESTIGATING), "my-pc", "k", 1, 9, NOW)
    since = datetime(2026, 9, 27, 9, 0, tzinfo=UTC)
    found = find_open_incident(db, "my-pc", "k", since)
    assert found is not None
    assert (found.incident.incident_id, found.alert_count, found.max_level) == ("inc_a", 1, 5)
    assert find_open_incident(db, "my-pc", "other", since) is None
    assert find_open_incident(db, "my-pc", "k", since + timedelta(minutes=30)) is None


def test_save_incident_upserts(db: Engine) -> None:
    incident = _incident("inc_c", 5, IncidentStatus.LOW_PRIORITY)
    save_incident(db, incident, "my-pc", "k", 1, 5, NOW)
    queued = incident.model_copy(update={"status": IncidentStatus.QUEUED})
    save_incident(db, queued, "my-pc", "k", 3, 10, NOW)
    [summary] = incident_summaries(db)
    assert summary.incident.updated_at == NOW
    assert (summary.alert_count, summary.max_level) == (3, 10)
    assert summary.incident.status is IncidentStatus.QUEUED
    assert incident_status(db, "inc_c") is IncidentStatus.QUEUED
    assert queue_length(db) == 1


def test_next_queued_incident_is_the_oldest(db: Engine) -> None:
    save_incident(db, _incident("inc_new", 20, IncidentStatus.QUEUED), "my-pc", "a", 1, 9, NOW)
    save_incident(db, _incident("inc_old", 10, IncidentStatus.QUEUED), "my-pc", "b", 1, 9, NOW)
    save_incident(db, _incident("inc_low", 1, IncidentStatus.LOW_PRIORITY), "my-pc", "c", 1, 3, NOW)
    assert (found := next_queued_incident(db)) is not None and found.incident_id == "inc_old"
    set_status(db, "inc_old", IncidentStatus.INVESTIGATING, NOW)
    assert incident_status(db, "inc_old") is IncidentStatus.INVESTIGATING
    [row] = [s for s in incident_summaries(db) if s.incident.incident_id == "inc_old"]
    assert row.incident.status is IncidentStatus.INVESTIGATING
    assert (found := next_queued_incident(db)) is not None and found.incident_id == "inc_new"


def test_incident_alerts_and_host_history(db: Engine) -> None:
    _store(db, "5.1", 1)
    _store(db, "5.2", 2, rule_id="60204", level=10)
    _store(db, "5.3", 50)
    mark_grouped(db, "5.1", "inc_h", NOW)
    mark_grouped(db, "5.2", "inc_h", NOW)
    assert [a.wazuh_id for a in incident_alerts(db, "inc_h")] == ["5.1", "5.2"]
    start = datetime(2026, 9, 27, 9, 0, tzinfo=UTC)
    end = datetime(2026, 9, 27, 9, 10, tzinfo=UTC)
    assert [a.wazuh_id for a in host_alerts(db, "my-pc", start, end)] == ["5.1", "5.2"]
    assert host_alerts(db, "other-pc", start, end) == []
    assert rule_count(db, "my-pc", "wazuh-60122", start, end + timedelta(hours=1)) == 2
    history = StoreHistory(db, "my-pc", start - timedelta(days=30))
    assert [a.wazuh_id for a in history.alerts(start, end)] == ["5.1", "5.2"]
    assert history.rule_count("wazuh-60204", start, end) == 1


def test_runs_round_trip_and_feed_the_summary(db: Engine) -> None:
    fixture = REPO / "contracts" / "fixtures" / "incident_run.json"
    run = IncidentRun.model_validate_json(fixture.read_text(encoding="utf-8"))
    save_incident(db, run.incident, "my-pc", "k", 2, 9, NOW)
    assert get_run(db, run.incident.incident_id) is None
    save_run(db, run, NOW)
    assert get_run(db, run.incident.incident_id) == run
    [summary] = incident_summaries(db)
    assert summary.classification is run.verdict.classification
    assert summary.recommendation_count == len(run.verdict.recommendations)
    assert summary.incident.status is run.incident.status
    assert get_run(db, "inc_missing") is None
    assert incident_status(db, "inc_missing") is None


def test_unfinished_incidents_are_investigating_without_a_run(db: Engine) -> None:
    save_incident(db, _incident("inc_u", 5, IncidentStatus.INVESTIGATING), "my-pc", "k", 1, 9, NOW)
    save_incident(db, _incident("inc_q", 6, IncidentStatus.QUEUED), "my-pc", "j", 1, 9, NOW)
    assert unfinished_incidents(db) == ["inc_u"]


def test_requeue_forgets_the_run(db: Engine) -> None:
    fixture = REPO / "contracts" / "fixtures" / "incident_run.json"
    run = IncidentRun.model_validate_json(fixture.read_text(encoding="utf-8"))
    failed = run.model_copy(
        update={
            "incident": run.incident.model_copy(
                update={"status": IncidentStatus.INVESTIGATION_FAILED}
            )
        }
    )
    save_incident(db, failed.incident, "my-pc", "k", 2, 9, NOW)
    save_run(db, failed, NOW)
    later = NOW + timedelta(minutes=5)
    requeue(db, failed.incident.incident_id, later)
    assert get_run(db, failed.incident.incident_id) is None
    assert incident_status(db, failed.incident.incident_id) is IncidentStatus.QUEUED
    [summary] = incident_summaries(db)
    assert summary.incident.status is IncidentStatus.QUEUED
    assert summary.incident.updated_at == later
    assert summary.classification is None
    assert queue_length(db) == 1


def test_security_checks_do_not_crowd_out_the_incident(db: Engine) -> None:
    older = _with_text(
        "30.0", 0, "An older burst.", hour=0, description="An older wording", **BURST
    )
    own = _with_text(
        "30.9",
        30,
        "Burst of failed logons for sentinel-test-nobody.",
        description="Multiple Windows Logon Failures",
        **BURST,
    )
    _store_many(
        db,
        [
            (older, older.event.raw),
            *_before_nine("sca", HISTORY_LIMIT + 1, **SCA_CHECK),
            (own, own.event.raw),
        ],
    )
    incident = new_incident(own)
    history = StoreHistory(db, "my-pc", incident.window_start - timedelta(days=30))
    context = ToolContext(incident=incident, events=[own.event], history=history)

    related = RELATED_ALERTS.run(RELATED_ALERTS.params.model_validate({"hours": 72}), context)
    rules = {entry["rule_id"]: entry for entry in related.content["rules"]}
    assert rules["wazuh-60204"]["in_incident"] is True
    assert rules["wazuh-60204"]["count"] == 2
    assert related.content["truncated"] is False

    checks = RELATED_ALERTS.run(
        RELATED_ALERTS.params.model_validate({"hours": 72, "rule_group": "sca"}), context
    )
    assert checks.content["truncated"] is True

    described = RULE_CONTEXT.run(RULE_CONTEXT.params.model_validate({"rule_id": "60204"}), context)
    assert described.content["description"] == "Multiple Windows Logon Failures"
    assert described.content["example"] == "Burst of failed logons for sentinel-test-nobody."

    start = datetime(2026, 9, 26, 0, 0, tzinfo=UTC)
    end = datetime(2026, 9, 28, 0, 0, tzinfo=UTC)
    assert [a.wazuh_id for a in host_alerts(db, "my-pc", start, end)] == ["30.0", "30.9"]
    assert [a.wazuh_id for a in host_alerts(db, "my-pc", start, end, limit=1)] == ["30.9"]
    everything = host_alerts(db, "my-pc", start, end, include_posture=True)
    assert len(everything) == HISTORY_LIMIT
    assert everything[-1].wazuh_id == "30.9"
    assert "30.0" not in {a.wazuh_id for a in everything}
    assert everything == sorted(everything, key=lambda a: a.event.timestamp)


def test_rule_sample_prefers_the_incident_then_the_newest(db: Engine) -> None:
    _store(db, "31.1", 5, rule_id="60204", description="Older", hour=1)
    _store(db, "31.2", 5, rule_id="60204", description="Newest", hour=3)
    _store(db, "31.3", 5, rule_id="60204", description="Too old", hour=0)
    since = datetime(2026, 9, 27, 0, 30, tzinfo=UTC)
    history = StoreHistory(db, "my-pc", since)
    sample = history.rule_sample("wazuh-60204", ["alr_not_stored"])
    assert sample is not None and sample.alert.rule_name == "Newest"
    assert history.rule_sample("wazuh-99999", []) is None
    [too_old] = [a for a in host_alerts(db, "my-pc", since - timedelta(hours=1), NOW)
                 if a.wazuh_id == "31.3"]
    own = history.rule_sample("wazuh-60204", [too_old.alert.alert_id])
    assert own is not None and own.wazuh_id == "31.3"
    assert StoreHistory(db, "other-pc", since).rule_sample("wazuh-60204", []) is None


def test_host_auth_events_are_the_newest_logons(db: Engine) -> None:
    _store(db, "32.1", 1)
    _store(db, "32.2", 2, rule_id="92052", groups=["windows", "sysmon", "sysmon_event1"])
    _store(db, "32.3", 3, groups=["sca"])
    _store(db, "32.4", 4)
    start = datetime(2026, 9, 27, 9, 0, tzinfo=UTC)
    end = datetime(2026, 9, 27, 9, 10, tzinfo=UTC)
    events = host_auth_events(db, "my-pc", start, end)
    assert [e.event_id for e in events] == ["evt_wz_32_1", "evt_wz_32_4"]
    newest = host_auth_events(db, "my-pc", start, end, limit=1)
    assert [e.event_id for e in newest] == ["evt_wz_32_4"]
    assert host_auth_events(db, "other-pc", start, end) == []


def test_investigation_events_keep_recent_logons(db: Engine) -> None:
    process = {"rule_id": "92052", "groups": ["windows", "sysmon", "sysmon_event1"]}
    _store_many(db, _before_nine("proc", HISTORY_LIMIT + 1, **process))
    _store(db, "33.1", 20)
    own, payload = make_wazuh_alert("33.2", 30, **BURST)
    insert_alert(db, own, payload)
    events = investigation_events(db, new_incident(own), [own])
    assert [e.event_id for e in events] == ["evt_wz_33_1", "evt_wz_33_2"]


def test_the_agent_s_history_cap_matches_the_store_s() -> None:
    assert MAX_HISTORY == HISTORY_LIMIT
