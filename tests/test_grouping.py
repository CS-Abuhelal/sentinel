from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from backend.app.incidents import incident_alerts, incident_summaries, ungrouped_alerts
from backend.app.store import insert_alert
from contracts.models import (
    EntityType,
    IncidentStatus,
    PcIncidentSummary,
)
from pipeline.grouping import (
    extend_incident,
    group_key,
    group_new_alerts,
    is_posture,
    new_incident,
    triage,
)
from tests.conftest import make_wazuh_alert

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
SCA = ["sca"]
BURST = {
    "rule_id": "60204",
    "level": 10,
    "description": "Multiple Windows Logon Failures",
    "groups": ["windows", "windows_security", "authentication_failures"],
    "techniques": ["T1110"],
}


def _store(db: Engine, wazuh_id: str, minute: int, **kwargs: object) -> None:
    live, payload = make_wazuh_alert(wazuh_id, minute, **kwargs)
    insert_alert(db, live, payload)


def test_key_uses_the_first_technique_or_the_rule() -> None:
    assert group_key(make_wazuh_alert("1", 0)[0]) == "my-pc|T1531"
    assert group_key(make_wazuh_alert("2", 0, techniques=[])[0]) == "my-pc|wazuh-60122"


def test_posture_alerts_are_recognised() -> None:
    assert is_posture(make_wazuh_alert("1", 0, groups=["sca"])[0])
    assert is_posture(make_wazuh_alert("2", 0, groups=["vulnerability-detector"])[0])
    assert not is_posture(make_wazuh_alert("3", 0)[0])


def test_triage_threshold() -> None:
    assert triage(6) is IncidentStatus.LOW_PRIORITY
    assert triage(7) is IncidentStatus.QUEUED


def test_new_and_extended_incidents_carry_entities_and_window() -> None:
    first = make_wazuh_alert("1", 1)[0]
    incident = new_incident(first)
    assert incident.status is IncidentStatus.LOW_PRIORITY
    assert incident.title == "Logon Failure - Unknown user or bad password on my-pc"
    assert [(e.entity_type, e.value) for e in incident.entities] == [
        (EntityType.HOST, "my-pc"),
        (EntityType.ACCOUNT, "sentinel-test-nobody"),
        (EntityType.IP_ADDRESS, "127.0.0.1"),
    ]
    summary = PcIncidentSummary(
        incident=incident, alert_count=1, max_level=first.level
    )
    later = make_wazuh_alert("2", 9, level=10, user="user1")[0]
    extended = extend_incident(summary, later)
    assert (extended.alert_count, extended.max_level) == (2, 10)
    assert extended.incident.status is IncidentStatus.QUEUED
    assert extended.incident.window_end == later.event.timestamp
    assert extended.incident.alert_ids == [
        first.alert.alert_id,
        later.alert.alert_id,
    ]
    assert (
        (EntityType.ACCOUNT, "user1")
        in [(e.entity_type, e.value) for e in extended.incident.entities]
    )


def test_grouping_builds_incidents_from_new_alerts(db: Engine) -> None:
    _store(db, "6.1", 1)
    _store(db, "6.2", 5)
    _store(db, "6.3", 6, **BURST)
    _store(db, "6.4", 7, groups=SCA, techniques=[])
    assert group_new_alerts(db, NOW) == 4
    assert ungrouped_alerts(db) == []
    summaries = {s.incident.title: s for s in incident_summaries(db)}
    failures = summaries["Logon Failure - Unknown user or bad password on my-pc"]
    burst = summaries["Multiple Windows Logon Failures on my-pc"]
    assert (failures.alert_count, failures.incident.status) == (
        2,
        IncidentStatus.LOW_PRIORITY,
    )
    assert (burst.alert_count, burst.incident.status) == (1, IncidentStatus.QUEUED)
    assert len(summaries) == 2
    ids = [a.wazuh_id for a in incident_alerts(db, failures.incident.incident_id)]
    assert ids == ["6.1", "6.2"]


def test_a_quiet_hour_starts_a_new_incident(db: Engine) -> None:
    _store(db, "7.1", 0, hour=9)
    _store(db, "7.2", 30, hour=10)
    group_new_alerts(db, NOW)
    assert len(incident_summaries(db)) == 2


def test_an_alert_exactly_one_hour_later_joins_the_incident(db: Engine) -> None:
    _store(db, "7.5", 0, hour=9)
    _store(db, "7.6", 0, hour=10)
    group_new_alerts(db, NOW)
    [summary] = incident_summaries(db)
    assert summary.alert_count == 2


def test_a_serious_alert_promotes_a_low_priority_incident(db: Engine) -> None:
    _store(db, "8.1", 1)
    group_new_alerts(db, NOW)
    _store(db, "8.2", 2, level=12)
    group_new_alerts(db, NOW)
    [summary] = incident_summaries(db)
    assert (summary.alert_count, summary.max_level) == (2, 12)
    assert summary.incident.status is IncidentStatus.QUEUED
