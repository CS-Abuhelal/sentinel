from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from contracts.models import EventCategory, TelemetrySource
from ingest.linux_auth import parse_auth_log

S1_LOG = Path(__file__).resolve().parents[1] / "lab" / "scenarios" / "s1_attack" / "auth.log"

FAILED = (
    "2026-09-25T02:11:04.512031+00:00 victim-web-01 sshd[1958]: "
    "Failed password for jdoe from 10.66.0.10 port 51251 ssh2"
)
INVALID = (
    "2026-09-25T02:10:14.419463+00:00 victim-web-01 sshd[1951]: "
    "Failed password for invalid user admin from 10.66.0.10 port 51230 ssh2"
)
ACCEPTED = (
    "2026-09-25T02:17:03.088412+00:00 victim-web-01 sshd[1982]: "
    "Accepted password for jdoe from 10.66.0.10 port 51268 ssh2"
)


def test_failed_password_line() -> None:
    [event] = parse_auth_log([FAILED], case_id="s1_attack")
    assert event.timestamp == datetime(2026, 9, 25, 2, 11, 4, 512031, tzinfo=UTC)
    assert event.source is TelemetrySource.LINUX_AUTH
    assert event.category is EventCategory.AUTHENTICATION
    assert event.event_type == "ssh_login_failed"
    assert event.outcome == "failure"
    assert event.host == "victim-web-01"
    assert event.user == "jdoe"
    assert event.network is not None
    assert event.network.src_ip == "10.66.0.10"
    assert event.network.src_port == 51251
    assert event.network.dst_port == 22
    assert event.network.protocol == "tcp"
    assert event.message == "Failed password for jdoe from 10.66.0.10 port 51251 ssh2"
    assert event.raw == {"line": FAILED, "pid": 1958, "method": "password", "invalid_user": False}
    assert event.case_id == "s1_attack"


def test_invalid_user_line() -> None:
    [event] = parse_auth_log([INVALID])
    assert event.user == "admin"
    assert event.raw["invalid_user"] is True
    assert event.outcome == "failure"


def test_accepted_line() -> None:
    [event] = parse_auth_log([ACCEPTED])
    assert event.event_type == "ssh_login_succeeded"
    assert event.outcome == "success"


def test_unrelated_lines_are_skipped() -> None:
    lines = [
        "2026-09-25T02:10:12.301442+00:00 victim-web-01 sshd[1951]: "
        "Invalid user admin from 10.66.0.10 port 51230",
        "2026-09-21T17:17:01.002231+00:00 victim-web-01 CRON[2237]: "
        "pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
        "",
        "not a log line",
    ]
    assert parse_auth_log(lines) == []


def test_s1_log_event_counts() -> None:
    events = parse_auth_log(S1_LOG.read_text(encoding="utf-8").splitlines())
    jdoe_failures = [e for e in events if e.user == "jdoe" and e.outcome == "failure"]
    jdoe_successes = [e for e in events if e.user == "jdoe" and e.outcome == "success"]
    invalid = [e for e in events if e.raw["invalid_user"]]
    assert len(events) == 32
    assert len(jdoe_failures) == 24
    assert len(jdoe_successes) == 5
    assert len(invalid) == 3
