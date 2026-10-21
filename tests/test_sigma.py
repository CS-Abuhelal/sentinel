from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from contracts.models import Event, EventCategory, NetworkInfo, Severity, TelemetrySource
from detection.sigma import RuleError, detect, load_rules
from ingest.linux_auth import parse_auth_log

REPO = Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "detection" / "rules"
S1_LOG = REPO / "lab" / "scenarios" / "s1_attack" / "auth.log"
T0 = datetime(2026, 9, 25, 2, 0, 0, tzinfo=UTC)

BASE_RULE = """
title: SSH failed password
id: base-1
name: ssh_failed_password
logsource:
  product: linux
  service: auth
detection:
  selection:
    event_type: ssh_login_failed
  condition: selection
level: low
"""


def _failure(offset_seconds: int, user: str = "jdoe", src_ip: str = "10.66.0.10") -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=offset_seconds),
        source=TelemetrySource.LINUX_AUTH,
        category=EventCategory.AUTHENTICATION,
        event_type="ssh_login_failed",
        host="victim-web-01",
        user=user,
        outcome="failure",
        network=NetworkInfo(src_ip=src_ip, dst_port=22, protocol="tcp"),
    )


def _write(directory: Path, name: str, text: str) -> None:
    (directory / name).write_text(text, encoding="utf-8")


def test_s1_log_raises_one_bruteforce_alert() -> None:
    events = parse_auth_log(S1_LOG.read_text(encoding="utf-8").splitlines(), case_id="s1_attack")
    [alert] = detect(events, load_rules(RULES_DIR), case_id="s1_attack")
    failures = [e for e in events if e.user == "jdoe" and e.outcome == "failure"]
    assert alert.rule_name == "SSH password brute force"
    assert alert.rule_id == "2b7e4d19-a3c6-4f58-8e0b-6c1d9f2a7e35"
    assert alert.rule_severity is Severity.MEDIUM
    assert alert.suggested_techniques == ["T1110.001"]
    assert alert.host == "victim-web-01"
    assert alert.user == "jdoe"
    assert alert.src_ip == "10.66.0.10"
    assert alert.event_ids == [e.event_id for e in failures]
    assert alert.timestamp == failures[-1].timestamp
    assert alert.case_id == "s1_attack"


def test_threshold_reached_fires() -> None:
    events = [_failure(i * 15) for i in range(10)]
    assert len(detect(events, load_rules(RULES_DIR))) == 1


def test_below_threshold_does_not_fire() -> None:
    events = [_failure(i * 15) for i in range(9)]
    assert detect(events, load_rules(RULES_DIR)) == []


def test_failures_spread_beyond_timespan_do_not_fire() -> None:
    events = [_failure(i * 70) for i in range(10)]
    assert detect(events, load_rules(RULES_DIR)) == []


def test_groups_are_kept_apart() -> None:
    events = [_failure(i * 15, src_ip="10.66.0.10") for i in range(6)]
    events += [_failure(i * 15, src_ip="10.66.0.11") for i in range(6)]
    events += [_failure(i * 15, user="other") for i in range(6)]
    assert detect(events, load_rules(RULES_DIR)) == []


def test_base_rule_referenced_by_correlation_raises_no_alert_of_its_own() -> None:
    events = [_failure(i * 15) for i in range(3)]
    assert detect(events, load_rules(RULES_DIR)) == []


def test_standalone_base_rule_alerts_per_event(tmp_path: Path) -> None:
    _write(tmp_path, "base.yml", BASE_RULE)
    events = [_failure(0), _failure(30)]
    alerts = detect(events, load_rules(tmp_path))
    assert [a.event_ids for a in alerts] == [[events[0].event_id], [events[1].event_id]]
    assert all(a.rule_severity is Severity.LOW for a in alerts)


@pytest.mark.parametrize(
    "old,new",
    [
        ("  condition: selection", "  condition: selection and not filter"),
        ("    event_type: ssh_login_failed", "    message|contains: Failed"),
        ("    event_type: ssh_login_failed", "    command_line: bash"),
        ("  service: auth", "  service: sshd"),
        ("level: low", "level: low\nfields:\n  - user"),
    ],
)
def test_unsupported_base_rule_features_fail_to_load(tmp_path: Path, old: str, new: str) -> None:
    assert old in BASE_RULE
    _write(tmp_path, "base.yml", BASE_RULE.replace(old, new))
    with pytest.raises(RuleError):
        load_rules(tmp_path)


def test_unsupported_correlation_type_fails_to_load(tmp_path: Path) -> None:
    _write(tmp_path, "base.yml", BASE_RULE)
    text = (RULES_DIR / "ssh_password_bruteforce.yml").read_text(encoding="utf-8")
    _write(tmp_path, "corr.yml", text.replace("type: event_count", "type: temporal"))
    with pytest.raises(RuleError):
        load_rules(tmp_path)


def test_correlation_referencing_unknown_rule_fails_to_load(tmp_path: Path) -> None:
    text = (RULES_DIR / "ssh_password_bruteforce.yml").read_text(encoding="utf-8")
    _write(tmp_path, "corr.yml", text)
    with pytest.raises(RuleError):
        load_rules(tmp_path)
