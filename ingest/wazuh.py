from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from contracts.models import (
    Alert,
    Event,
    EventCategory,
    LiveAlert,
    NetworkInfo,
    ProcessInfo,
    Severity,
    TelemetrySource,
)

REQUIRED_FIELDS = ("id", "timestamp", "rule", "agent")

CATEGORY_GROUPS: tuple[tuple[EventCategory, frozenset[str]], ...] = (
    (
        EventCategory.AUTHENTICATION,
        frozenset({"authentication_failed", "authentication_success", "win_authentication"}),
    ),
    (EventCategory.PROCESS, frozenset({"sysmon_event1", "process"})),
    (EventCategory.FILE, frozenset({"syscheck"})),
    (EventCategory.ACCOUNT_MANAGEMENT, frozenset({"adduser", "group_changed", "account_changed"})),
    (EventCategory.PRIVILEGE, frozenset({"privilege"})),
)


class WazuhAlertError(ValueError):
    pass


def severity_for_level(level: int) -> Severity:
    if level <= 3:
        return Severity.INFO
    if level <= 6:
        return Severity.LOW
    if level <= 9:
        return Severity.MEDIUM
    if level <= 12:
        return Severity.HIGH
    return Severity.CRITICAL


def category_for_groups(groups: list[str]) -> EventCategory:
    present = set(groups)
    for category, names in CATEGORY_GROUPS:
        if present & names:
            return category
    return EventCategory.OTHER


def parse_timestamp(value: str) -> datetime:
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip()).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise WazuhAlertError(f"Unreadable timestamp: {value!r}") from error
    if moment.tzinfo is None:
        raise WazuhAlertError(f"Timestamp has no time zone: {value!r}")
    return moment


def convert(payload: dict[str, Any]) -> tuple[Event, Alert]:
    missing = [field for field in REQUIRED_FIELDS if field not in payload]
    if missing:
        raise WazuhAlertError(f"Wazuh alert is missing: {', '.join(missing)}.")
    rule = _mapping(payload, "rule")
    agent = _mapping(payload, "agent")
    rule_id = _text(rule.get("id"))
    host = _text(agent.get("name"))
    if rule_id is None or host is None:
        raise WazuhAlertError("Wazuh alert needs rule.id and agent.name.")
    level = _level(rule)
    groups = [str(group) for group in rule.get("groups") or []]
    description = _text(rule.get("description")) or f"Wazuh rule {rule_id}"
    timestamp = parse_timestamp(str(payload["timestamp"]))
    eventdata = _eventdata(payload)
    user = _text(eventdata.get("targetUserName"))
    src_ip = _text(eventdata.get("ipAddress"))
    slug = re.sub(r"[^A-Za-z0-9]", "_", str(payload["id"]))
    event = Event(
        event_id=f"evt_wz_{slug}",
        timestamp=timestamp,
        source=TelemetrySource.WAZUH,
        category=category_for_groups(groups),
        event_type=f"wazuh:{rule_id}",
        host=host,
        user=user,
        outcome=_outcome(groups),
        process=_process(eventdata),
        network=NetworkInfo(src_ip=src_ip) if src_ip else None,
        file_path=_file_path(payload),
        message=description,
        raw=payload,
    )
    alert = Alert(
        alert_id=f"alr_wz_{slug}",
        rule_id=f"wazuh-{rule_id}",
        rule_name=description,
        rule_severity=severity_for_level(level),
        timestamp=timestamp,
        host=host,
        user=user,
        src_ip=src_ip,
        description=description,
        event_ids=[event.event_id],
        suggested_techniques=_techniques(rule),
    )
    return event, alert


def live_alert(payload: dict[str, Any], received_at: datetime) -> LiveAlert:
    event, alert = convert(payload)
    return LiveAlert(
        wazuh_id=str(payload["id"]),
        received_at=received_at,
        level=_level(_mapping(payload, "rule")),
        event=event,
        alert=alert,
    )


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload[key]
    if not isinstance(value, dict):
        raise WazuhAlertError(f"'{key}' must be an object.")
    return value


def _level(rule: dict[str, Any]) -> int:
    level = rule.get("level")
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 15:
        raise WazuhAlertError(f"rule.level must be a whole number from 0 to 15, got {level!r}.")
    return level


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text


def _eventdata(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    win = data.get("win") if isinstance(data, dict) else None
    eventdata = win.get("eventdata") if isinstance(win, dict) else None
    return eventdata if isinstance(eventdata, dict) else {}


def _outcome(groups: list[str]) -> str:
    if "authentication_failed" in groups or "win_authentication_failed" in groups:
        return "failure"
    if "authentication_success" in groups:
        return "success"
    return "unknown"


def _process(eventdata: dict[str, Any]) -> ProcessInfo | None:
    name = (
        _text(eventdata.get("image"))
        or _text(eventdata.get("newProcessName"))
        or _text(eventdata.get("processName"))
    )
    command_line = _text(eventdata.get("commandLine"))
    parent = _text(eventdata.get("parentImage"))
    if name is None and command_line is None and parent is None:
        return None
    return ProcessInfo(name=name, command_line=command_line, parent_name=parent)


def _file_path(payload: dict[str, Any]) -> str | None:
    syscheck = payload.get("syscheck")
    return _text(syscheck.get("path")) if isinstance(syscheck, dict) else None


def _techniques(rule: dict[str, Any]) -> list[str]:
    mitre = rule.get("mitre")
    ids = mitre.get("id") if isinstance(mitre, dict) else None
    return [str(technique) for technique in ids] if isinstance(ids, list) else []
