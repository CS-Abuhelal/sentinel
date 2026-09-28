from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from agent.tools import WAZUH_TOOLS
from agent.tools.base import ToolContext
from agent.tools.wazuh import PROCESS_ACTIVITY, RELATED_ALERTS, RULE_CONTEXT
from contracts.models import EvidenceClass, LiveAlert
from pipeline.grouping import new_incident
from tests.conftest import make_wazuh_alert


class FakeHistory:
    def __init__(self, alerts: list[LiveAlert]) -> None:
        self._alerts = alerts
        self.windows: list[tuple[datetime, datetime]] = []

    def alerts(self, start: datetime, end: datetime) -> list[LiveAlert]:
        self.windows.append((start, end))
        return [a for a in self._alerts if start <= a.event.timestamp <= end]

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
