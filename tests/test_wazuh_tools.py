from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from agent.tools import WAZUH_TOOLS
from agent.tools.base import ToolContext
from agent.tools.wazuh import MAX_HISTORY, PROCESS_ACTIVITY, RELATED_ALERTS, RULE_CONTEXT
from contracts.models import EvidenceClass, LiveAlert
from ingest.wazuh import is_posture, live_alert
from pipeline.grouping import new_incident
from tests.conftest import RECEIVED_AT, make_wazuh_alert


class FakeHistory:
    def __init__(self, alerts: list[LiveAlert], honours_posture: bool = True) -> None:
        self._alerts = alerts
        self._honours_posture = honours_posture
        self.windows: list[tuple[datetime, datetime]] = []
        self.include_posture: list[bool] = []

    def alerts(
        self, start: datetime, end: datetime, include_posture: bool = False
    ) -> list[LiveAlert]:
        self.windows.append((start, end))
        self.include_posture.append(include_posture)
        skip_posture = self._honours_posture and not include_posture
        return [
            a
            for a in self._alerts
            if start <= a.event.timestamp <= end
            and not (skip_posture and is_posture(a.event.raw))
        ]

    def rule_sample(self, rule_id: str, preferred_alert_ids: list[str]) -> LiveAlert | None:
        matches = [a for a in self._alerts if a.alert.rule_id == rule_id]
        own = [a for a in matches if a.alert.alert_id in preferred_alert_ids]
        pool = own or matches
        return max(pool, key=lambda a: a.event.timestamp) if pool else None

    def rule_count(self, rule_id: str, start: datetime, end: datetime) -> int:
        return sum(
            1
            for a in self._alerts
            if a.alert.rule_id == rule_id and start <= a.event.timestamp < end
        )


def _context(history: FakeHistory | None, anchor: LiveAlert) -> ToolContext:
    return ToolContext(incident=new_incident(anchor), events=[anchor.event], history=history)


BURST = make_wazuh_alert("9.1", 10, level=10, rule_id="60204", techniques=["T1110"])[0]
FAILS = [make_wazuh_alert(f"9.{n}", n) for n in range(2, 7)]
SHELL = make_wazuh_alert(
    "9.9",
    12,
    level=12,
    rule_id="92052",
    description="Powershell with an encoded command",
    groups=["windows", "sysmon", "sysmon_event1"],
    process="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    command_line="powershell.exe -EncodedCommand ZQBjAGgAbwA=",
)[0]
OLD = make_wazuh_alert("9.20", 10, rule_id="60204", hour=1)[0]
HISTORY = FakeHistory([BURST, *(a for a, _ in FAILS), SHELL, OLD])

SCA = make_wazuh_alert("9.30", 11, level=7, rule_id="19007", groups=["sca"], techniques=[])[0]
POSTURE_HISTORY = FakeHistory([BURST, *(a for a, _ in FAILS), SHELL, OLD, SCA])


def test_wazuh_toolset() -> None:
    assert set(WAZUH_TOOLS) == {
        "auth_history",
        "related_alerts",
        "process_activity",
        "rule_context",
    }


def test_related_alerts_groups_by_rule_around_the_incident() -> None:
    params = RELATED_ALERTS.params.model_validate({"hours": 1})
    result = RELATED_ALERTS.run(params, _context(HISTORY, BURST))
    rules = {entry["rule_id"]: entry for entry in result.content["rules"]}
    assert rules["wazuh-60122"]["count"] == 5
    assert rules["wazuh-60204"]["in_incident"] is True
    assert "wazuh-92052" in rules
    assert result.content["total_alerts"] == 7
    assert RELATED_ALERTS.evidence_class is EvidenceClass.RELATED_ALERTS
    assert BURST.event.event_id in result.source_event_ids


def test_related_alerts_can_filter_by_group() -> None:
    params = RELATED_ALERTS.params.model_validate({"hours": 1, "rule_group": "sysmon"})
    result = RELATED_ALERTS.run(params, _context(HISTORY, BURST))
    assert [entry["rule_id"] for entry in result.content["rules"]] == ["wazuh-92052"]
    assert HISTORY.include_posture[-1] is False
    assert result.content["security_checks_included"] is False


def test_related_alerts_skips_posture_alerts_by_default() -> None:
    params = RELATED_ALERTS.params.model_validate({"hours": 1})
    result = RELATED_ALERTS.run(params, _context(POSTURE_HISTORY, BURST))
    rule_ids = {entry["rule_id"] for entry in result.content["rules"]}
    assert POSTURE_HISTORY.include_posture[-1] is False
    assert "wazuh-19007" not in rule_ids
    assert result.content["total_alerts"] == 7
    assert result.content["security_checks_included"] is False
    assert "security-check (sca) results are not included" in result.summary.lower()


def test_related_alerts_still_drops_posture_alerts_the_history_returns() -> None:
    history = FakeHistory([BURST, *(a for a, _ in FAILS), SHELL, OLD, SCA], honours_posture=False)
    params = RELATED_ALERTS.params.model_validate({"hours": 1})
    result = RELATED_ALERTS.run(params, _context(history, BURST))
    rule_ids = {entry["rule_id"] for entry in result.content["rules"]}
    assert "wazuh-19007" not in rule_ids
    assert result.content["security_checks_included"] is False
    assert result.content["total_alerts"] == 7
    assert "security-check" in result.summary.lower()


def test_related_alerts_can_still_ask_for_posture_alerts() -> None:
    params = RELATED_ALERTS.params.model_validate({"hours": 1, "rule_group": "sca"})
    result = RELATED_ALERTS.run(params, _context(POSTURE_HISTORY, BURST))
    rule_ids = {entry["rule_id"] for entry in result.content["rules"]}
    assert POSTURE_HISTORY.include_posture[-1] is True
    assert "wazuh-19007" in rule_ids
    assert result.content["security_checks_included"] is True
    assert "not included" not in result.summary


def test_history_tools_say_when_the_history_was_cut_off() -> None:
    params = RELATED_ALERTS.params.model_validate({"hours": 1})
    assert RELATED_ALERTS.run(params, _context(HISTORY, BURST)).content["truncated"] is False
    full = FakeHistory([SHELL] * MAX_HISTORY)
    assert RELATED_ALERTS.run(params, _context(full, BURST)).content["truncated"] is True
    process = PROCESS_ACTIVITY.params.model_validate({"process": "powershell.exe"})
    assert PROCESS_ACTIVITY.run(process, _context(HISTORY, BURST)).content["truncated"] is False
    assert PROCESS_ACTIVITY.run(process, _context(full, BURST)).content["truncated"] is True


def test_process_activity_matches_name_case_insensitively() -> None:
    params = PROCESS_ACTIVITY.params.model_validate(
        {"process": "PowerShell.exe", "hours": 2}
    )
    result = PROCESS_ACTIVITY.run(params, _context(HISTORY, BURST))
    [entry] = result.content["matches"]
    assert entry["rule_id"] == "wazuh-92052"
    assert "-EncodedCommand" in entry["command_line"]
    assert PROCESS_ACTIVITY.evidence_class is EvidenceClass.PROCESS_LINEAGE


def test_rule_context_compares_with_the_baseline() -> None:
    params = RULE_CONTEXT.params.model_validate({"rule_id": "60204"})
    result = RULE_CONTEXT.run(params, _context(HISTORY, BURST))
    content = result.content
    assert content["rule_id"] == "wazuh-60204"
    assert content["description"] == "Logon Failure - Unknown user or bad password"
    assert content["fired_in_incident_window"] == 1
    assert content["fired_in_previous_30_days"] == 1
    assert RULE_CONTEXT.evidence_class is EvidenceClass.BASELINE_COMPARISON


def test_rule_context_describes_the_incident_s_own_alert() -> None:
    older, payload = make_wazuh_alert(
        "9.50", 10, rule_id="60204", description="An older wording", hour=2
    )
    payload["full_log"] = "The older alert's text."
    older = live_alert(payload, received_at=RECEIVED_AT)
    own, payload = make_wazuh_alert(
        "9.51", 10, level=10, rule_id="60204", description="Multiple Windows Logon Failures"
    )
    payload["full_log"] = "The incident's own text."
    own = live_alert(payload, received_at=RECEIVED_AT)
    newer = make_wazuh_alert("9.52", 50, rule_id="60204", description="A newer wording")[0]
    history = FakeHistory([older, own, newer])
    params = RULE_CONTEXT.params.model_validate({"rule_id": "60204"})
    result = RULE_CONTEXT.run(params, _context(history, own))
    assert result.content["description"] == "Multiple Windows Logon Failures"
    assert result.content["example"] == "The incident's own text."
    assert result.source_event_ids == [own.event.event_id]


def test_rule_context_example_is_none_without_a_sample() -> None:
    params = RULE_CONTEXT.params.model_validate({"rule_id": "99999"})
    result = RULE_CONTEXT.run(params, _context(HISTORY, BURST))
    assert result.content["example"] is None


def test_rule_context_returns_example_text_from_full_log() -> None:
    live, payload = make_wazuh_alert("9.40", 15, rule_id="19010", groups=["sca"], techniques=[])
    payload["full_log"] = (
        "  NTFS Alternate data stream found:  'C:\\WINDOWS\\tracing:?'.   "
        "Possible hidden content. "
    )
    live = live_alert(payload, received_at=RECEIVED_AT)
    history = FakeHistory([live])
    params = RULE_CONTEXT.params.model_validate({"rule_id": "19010"})
    result = RULE_CONTEXT.run(params, _context(history, live))
    assert result.content["example"] == (
        "NTFS Alternate data stream found: 'C:\\WINDOWS\\tracing:?'. Possible hidden content."
    )


def test_rule_context_falls_back_to_the_windows_event_message() -> None:
    live, payload = make_wazuh_alert("9.41", 16, rule_id="19011", groups=["sca"], techniques=[])
    payload["data"]["win"]["system"]["message"] = "Some   collapsed   message   from windows."
    live = live_alert(payload, received_at=RECEIVED_AT)
    history = FakeHistory([live])
    params = RULE_CONTEXT.params.model_validate({"rule_id": "19011"})
    result = RULE_CONTEXT.run(params, _context(history, live))
    assert result.content["example"] == "Some collapsed message from windows."


def test_rule_context_example_is_truncated_to_600_chars() -> None:
    live, payload = make_wazuh_alert("9.42", 17, rule_id="19012", groups=["sca"], techniques=[])
    payload["full_log"] = "x" * 700
    live = live_alert(payload, received_at=RECEIVED_AT)
    history = FakeHistory([live])
    params = RULE_CONTEXT.params.model_validate({"rule_id": "19012"})
    result = RULE_CONTEXT.run(params, _context(history, live))
    assert result.content["example"] == "x" * 600


def test_tools_say_so_when_there_is_no_history() -> None:
    params = RELATED_ALERTS.params.model_validate({})
    result = RELATED_ALERTS.run(params, _context(None, BURST))
    assert result.content == {}
    assert "no alert history" in result.summary.lower()


def test_parameters_are_bounded() -> None:
    with pytest.raises(ValidationError):
        RELATED_ALERTS.params.model_validate({"hours": 73})
    with pytest.raises(ValidationError):
        RULE_CONTEXT.params.model_validate({"rule_id": "rm -rf"})
    with pytest.raises(ValidationError):
        PROCESS_ACTIVITY.params.model_validate({"process": ""})
