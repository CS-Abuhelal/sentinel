from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime

from contracts.models import Event, EventCategory, NetworkInfo, TelemetrySource

_LINE = re.compile(r"^(?P<timestamp>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<message>.*)$")
_LOGIN = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>\S+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<src_ip>\S+) port (?P<src_port>\d+) ssh2$"
)


def parse_auth_log(lines: Iterable[str], case_id: str | None = None) -> list[Event]:
    events = []
    for line in lines:
        event = _parse_line(line.rstrip("\r\n"), case_id)
        if event is not None:
            events.append(event)
    return events


def _parse_line(line: str, case_id: str | None) -> Event | None:
    envelope = _LINE.match(line)
    if envelope is None:
        return None
    login = _LOGIN.match(envelope["message"])
    if login is None:
        return None
    try:
        timestamp = datetime.fromisoformat(envelope["timestamp"])
    except ValueError:
        return None
    succeeded = login["result"] == "Accepted"
    return Event(
        timestamp=timestamp,
        source=TelemetrySource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="ssh_login_succeeded" if succeeded else "ssh_login_failed",
        host=envelope["host"],
        user=login["user"],
        outcome="success" if succeeded else "failure",
        network=NetworkInfo(
            src_ip=login["src_ip"],
            src_port=int(login["src_port"]),
            dst_port=22,
            protocol="tcp",
        ),
        message=envelope["message"],
        raw={
            "line": line,
            "pid": int(envelope["pid"]),
            "method": login["method"],
            "invalid_user": login["invalid"] is not None,
        },
        case_id=case_id,
    )
