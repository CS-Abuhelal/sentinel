from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from contracts.models import EventCategory, Severity, TelemetrySource
from ingest.wazuh import (
    WazuhAlertError,
    category_for_groups,
    convert,
    live_alert,
    parse_timestamp,
    severity_for_level,
)

DATA = Path(__file__).resolve().parent / "data" / "wazuh"


def _payload(name: str) -> dict[str, Any]:
    return json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))


def test_logon_failure_becomes_an_authentication_failure() -> None:
    payload = _payload("logon_failure")
    event, alert = convert(payload)
    assert event.source is TelemetrySource.WAZUH
    assert event.category is EventCategory.AUTHENTICATION
    assert event.outcome == "failure"
    assert event.event_type == "wazuh:60122"
    assert (event.host, event.user) == ("my-pc", "user1")
    assert event.network is not None and event.network.src_ip == "127.0.0.1"
    assert event.timestamp == datetime(2026, 9, 27, 9, 30, 0, 123000, tzinfo=UTC)
    assert event.raw == payload
    assert alert.rule_id == "wazuh-60122"
    assert alert.rule_severity is Severity.LOW
    assert alert.suggested_techniques == ["T1531"]
    assert alert.event_ids == [event.event_id]
    assert (event.event_id, alert.alert_id) == (
        "evt_wz_1790501400_1042",
        "alr_wz_1790501400_1042",
    )


def test_logon_failure_records_the_program_that_tried_to_log_on() -> None:
    event, _ = convert(_payload("logon_failure"))
    assert event.process is not None
    assert event.process.name == "C:\\Windows\\System32\\svchost.exe"
    assert (event.process.command_line, event.process.parent_name) == (None, None)


def test_real_wazuh_alert_normalizes_doubled_backslashes() -> None:
    payload = _payload("logon_failure_real")
    event, alert = convert(payload)
    assert event.category is EventCategory.AUTHENTICATION
    assert event.outcome == "failure"
    assert event.user == "sentinel-test-nobody"
    assert event.host == "my-pc"
    assert alert.rule_id == "wazuh-60122"
    assert alert.rule_severity is Severity.LOW
    assert event.process is not None
    assert event.process.name == "C:\\Windows\\System32\\svchost.exe"
    assert event.raw == payload


def test_eventdata_doubled_backslashes_become_single() -> None:
    payload = _payload("logon_failure")
    payload["data"]["win"]["eventdata"]["image"] = r"C:\\Temp\\a.exe"
    payload["data"]["win"]["eventdata"]["commandLine"] = r"\\\\srv\\share\\x.ps1"
    event, _ = convert(payload)
    assert event.process is not None
    assert event.process.name == r"C:\Temp\a.exe"
    assert event.process.command_line == r"\\srv\share\x.ps1"
    assert payload["data"]["win"]["eventdata"]["image"] == r"C:\\Temp\\a.exe"


def test_process_alert_keeps_the_process_details() -> None:
    event, alert = convert(_payload("process_sysmon"))
    assert event.category is EventCategory.PROCESS
    assert event.process is not None
    assert event.process.name.endswith("powershell.exe")
    assert "-EncodedCommand" in event.process.command_line
    assert event.process.parent_name == "C:\\Windows\\explorer.exe"
    assert event.user is None
    assert alert.rule_severity is Severity.HIGH
    assert alert.suggested_techniques == ["T1059.001"]


def test_file_integrity_alert_keeps_the_path() -> None:
    event, alert = convert(_payload("fim_change"))
    assert event.category is EventCategory.FILE
    assert event.file_path == "c:\\windows\\system32\\drivers\\etc\\hosts"
    assert alert.rule_severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "level,severity",
    [
        (0, Severity.INFO),
        (3, Severity.INFO),
        (4, Severity.LOW),
        (6, Severity.LOW),
        (7, Severity.MEDIUM),
        (9, Severity.MEDIUM),
        (10, Severity.HIGH),
        (12, Severity.HIGH),
        (13, Severity.CRITICAL),
        (15, Severity.CRITICAL),
    ],
)
def test_level_maps_to_severity(level: int, severity: Severity) -> None:
    assert severity_for_level(level) is severity


def test_unknown_groups_are_other() -> None:
    assert category_for_groups(["ossec", "rootcheck"]) is EventCategory.OTHER


@pytest.mark.parametrize(
    "group,category",
    [
        ("authentication_failed", EventCategory.AUTHENTICATION),
        ("authentication_success", EventCategory.AUTHENTICATION),
        ("authentication_failures", EventCategory.AUTHENTICATION),
        ("win_authentication_failed", EventCategory.AUTHENTICATION),
        ("sysmon_event1", EventCategory.PROCESS),
        ("syscheck", EventCategory.FILE),
        ("adduser", EventCategory.ACCOUNT_MANAGEMENT),
        ("group_changed", EventCategory.ACCOUNT_MANAGEMENT),
        ("account_changed", EventCategory.ACCOUNT_MANAGEMENT),
        ("privilege", EventCategory.PRIVILEGE),
    ],
)
def test_category_for_groups_covers_each_real_group(group: str, category: EventCategory) -> None:
    assert category_for_groups([group]) is category


def test_timestamps_accept_compact_and_z_offsets() -> None:
    expected = datetime(2026, 9, 27, 9, 30, tzinfo=UTC)
    assert parse_timestamp("2026-09-27T12:30:00+0300") == expected
    assert parse_timestamp("2026-09-27T09:30:00Z") == expected
    with pytest.raises(WazuhAlertError):
        parse_timestamp("2026-09-27T09:30:00")


def test_dash_means_empty() -> None:
    payload = _payload("logon_failure")
    payload["data"]["win"]["eventdata"]["ipAddress"] = "-"
    payload["data"]["win"]["eventdata"]["targetUserName"] = "-"
    event, alert = convert(payload)
    assert event.network is None
    assert (event.user, alert.src_ip) == (None, None)


@pytest.mark.parametrize("field", ["id", "timestamp", "rule", "agent"])
def test_missing_required_field_is_rejected(field: str) -> None:
    payload = _payload("logon_failure")
    del payload[field]
    with pytest.raises(WazuhAlertError, match=field):
        convert(payload)


@pytest.mark.parametrize("level", [-1, 16, "5", None])
def test_bad_level_is_rejected(level: object) -> None:
    payload = _payload("logon_failure")
    payload["rule"]["level"] = level
    with pytest.raises(WazuhAlertError):
        convert(payload)


@pytest.mark.parametrize("groups", [1, "authentication_failed"])
def test_non_list_groups_are_rejected(groups: object) -> None:
    payload = _payload("logon_failure")
    payload["rule"]["groups"] = groups
    with pytest.raises(WazuhAlertError):
        convert(payload)


def test_groups_with_non_string_items_are_rejected() -> None:
    payload = _payload("logon_failure")
    payload["rule"]["groups"] = ["windows", 1]
    with pytest.raises(WazuhAlertError):
        convert(payload)


def test_empty_id_is_rejected() -> None:
    payload = _payload("logon_failure")
    payload["id"] = ""
    with pytest.raises(WazuhAlertError):
        convert(payload)


def test_live_alert_wraps_the_conversion() -> None:
    received = datetime(2026, 9, 27, 9, 30, 2, tzinfo=UTC)
    live = live_alert(_payload("logon_failure"), received_at=received)
    assert (live.wazuh_id, live.level, live.received_at) == ("1790501400.1042", 5, received)
    assert live.alert.event_ids == [live.event.event_id]
