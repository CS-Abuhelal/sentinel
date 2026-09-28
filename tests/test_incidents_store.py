from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.engine import Engine

from backend.app.incidents import (
    StoreHistory,
    find_open_incident,
    get_run,
    host_alerts,
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
from contracts.models import Entity, EntityType, Incident, IncidentRun, IncidentStatus
from tests.conftest import REPO, make_wazuh_alert

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
    history = StoreHistory(db, "my-pc")
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
