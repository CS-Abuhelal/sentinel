from __future__ import annotations

from datetime import UTC, datetime, timedelta

from contracts.models import (
    AccountRecord,
    Alert,
    Entity,
    EntityType,
    Event,
    EventCategory,
    HostRecord,
    IncidentStatus,
    Inventory,
    NetworkInfo,
    Severity,
    TelemetrySource,
)
from detection.correlate import correlate

T0 = datetime(2026, 9, 25, 2, 0, 0, tzinfo=UTC)
INVENTORY = Inventory(
    accounts={
        "jdoe": AccountRecord(role="developer"),
        "labadmin": AccountRecord(role="admin", protected=True),
    },
    hosts={"victim-web-01": HostRecord(role="web server")},
)


def _event(offset: int, user: str, src_ip: str) -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=offset),
        source=TelemetrySource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="ssh_login_failed",
        host="victim-web-01",
        user=user,
        outcome="failure",
        network=NetworkInfo(src_ip=src_ip),
    )


def _alert(events: list[Event], user: str, src_ip: str) -> Alert:
    return Alert(
        rule_id="r1",
        rule_name="SSH password brute force",
        rule_severity=Severity.MEDIUM,
        timestamp=events[-1].timestamp,
        host="victim-web-01",
        user=user,
        src_ip=src_ip,
        description="test",
        event_ids=[e.event_id for e in events],
    )


def test_single_alert_becomes_incident() -> None:
    events = [_event(0, "jdoe", "10.66.0.10"), _event(60, "jdoe", "10.66.0.10")]
    alert = _alert(events, "jdoe", "10.66.0.10")
    [incident] = correlate([alert], events, INVENTORY, case_id="s1_attack")
    assert incident.title == "Possible account compromise: jdoe on victim-web-01"
    assert incident.status is IncidentStatus.NEW
    assert incident.alert_ids == [alert.alert_id]
    assert incident.window_start == events[0].timestamp
    assert incident.window_end == events[1].timestamp
    assert incident.created_at == alert.timestamp
    assert incident.case_id == "s1_attack"
    assert incident.entities == [
        Entity(entity_type=EntityType.HOST, value="victim-web-01"),
        Entity(entity_type=EntityType.ACCOUNT, value="jdoe"),
        Entity(entity_type=EntityType.IP_ADDRESS, value="10.66.0.10"),
    ]


def test_alerts_for_same_host_and_user_merge() -> None:
    first = [_event(0, "jdoe", "10.66.0.10")]
    second = [_event(300, "jdoe", "10.66.0.11")]
    alerts = [_alert(first, "jdoe", "10.66.0.10"), _alert(second, "jdoe", "10.66.0.11")]
    [incident] = correlate(alerts, first + second, INVENTORY)
    assert incident.alert_ids == [a.alert_id for a in alerts]
    assert [e.value for e in incident.entities if e.entity_type is EntityType.IP_ADDRESS] == [
        "10.66.0.10",
        "10.66.0.11",
    ]
    assert incident.window_end == second[0].timestamp


def test_different_users_become_separate_incidents() -> None:
    jdoe = [_event(0, "jdoe", "10.66.0.10")]
    other = [_event(0, "labadmin", "10.66.0.10")]
    incidents = correlate(
        [_alert(jdoe, "jdoe", "10.66.0.10"), _alert(other, "labadmin", "10.66.0.10")],
        jdoe + other,
        INVENTORY,
    )
    assert len(incidents) == 2


def test_protected_flags_come_from_inventory() -> None:
    events = [_event(0, "labadmin", "10.66.0.10")]
    [incident] = correlate([_alert(events, "labadmin", "10.66.0.10")], events, INVENTORY)
    account = next(e for e in incident.entities if e.entity_type is EntityType.ACCOUNT)
    assert account.is_protected is True
