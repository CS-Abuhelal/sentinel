from __future__ import annotations

from datetime import timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import EvidenceClass, LiveAlert
from ingest.wazuh import is_posture, rule_groups

BASELINE_DAYS = 30
MAX_RULES = 25
MAX_MATCHES = 25
MAX_SOURCES = 200
MAX_DETAIL_CHARS = 600
NO_HISTORY = ToolResult(
    summary="There is no alert history for this host.", content={}, source_event_ids=[]
)


class _Params(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RelatedAlertsParams(_Params):
    hours: int = Field(default=24, ge=1, le=72)
    rule_group: str | None = Field(default=None, min_length=1, max_length=64)


class ProcessActivityParams(_Params):
    process: str = Field(min_length=1, max_length=260)
    hours: int = Field(default=24, ge=1, le=72)


class RuleContextParams(_Params):
    rule_id: str = Field(pattern=r"^(wazuh-)?\d{1,6}$")


def related_alerts(params: RelatedAlertsParams, context: ToolContext) -> ToolResult:
    if context.history is None:
        return NO_HISTORY
    incident = context.incident
    span = timedelta(hours=params.hours)
    alerts = context.history.alerts(incident.window_start - span, incident.window_end + span)
    if params.rule_group:
        alerts = [a for a in alerts if params.rule_group in _groups(a)]
        posture_alerts_skipped = 0
    else:
        before_posture_skip = len(alerts)
        alerts = [a for a in alerts if not is_posture(a.event.raw)]
        posture_alerts_skipped = before_posture_skip - len(alerts)
    own = set(incident.alert_ids)
    rules: dict[str, dict[str, Any]] = {}
    for live in alerts:
        entry = rules.setdefault(
            live.alert.rule_id,
            {
                "rule_id": live.alert.rule_id,
                "description": live.alert.rule_name,
                "level": live.level,
                "groups": _groups(live),
                "count": 0,
                "first_seen": live.event.timestamp.isoformat(),
                "last_seen": live.event.timestamp.isoformat(),
                "in_incident": False,
            },
        )
        entry["count"] += 1
        entry["last_seen"] = live.event.timestamp.isoformat()
        entry["in_incident"] = entry["in_incident"] or live.alert.alert_id in own
    ordered = sorted(rules.values(), key=lambda e: (-e["count"], e["rule_id"]))[:MAX_RULES]
    content = {
        "hours": params.hours,
        "total_alerts": len(alerts),
        "rules": ordered,
        "posture_alerts_skipped": posture_alerts_skipped,
    }
    parts = [
        f"{len(alerts)} alerts on the host within {params.hours} h of the incident."
    ]
    parts += [
        f"{e['rule_id']} x{e['count']}: {e['description']}" for e in ordered[:5]
    ]
    if posture_alerts_skipped:
        parts.append(
            "Security-check results are left out; ask with rule_group 'sca' to see them."
        )
    return ToolResult(
        summary=" ".join(parts),
        content=content,
        source_event_ids=[a.event.event_id for a in alerts][:MAX_SOURCES],
    )


def process_activity(params: ProcessActivityParams, context: ToolContext) -> ToolResult:
    if context.history is None:
        return NO_HISTORY
    incident = context.incident
    span = timedelta(hours=params.hours)
    needle = params.process.lower()
    matches = [
        live
        for live in context.history.alerts(
            incident.window_start - span, incident.window_end + span
        )
        if any(needle in (value or "").lower() for value in _process_fields(live))
    ]
    entries = [
        {
            "time": live.event.timestamp.isoformat(),
            "rule_id": live.alert.rule_id,
            "description": live.alert.rule_name,
            "process": live.event.process.name if live.event.process else None,
            "command_line": (
                live.event.process.command_line if live.event.process else None
            ),
            "parent": live.event.process.parent_name if live.event.process else None,
            "user": live.event.user,
        }
        for live in matches[:MAX_MATCHES]
    ]
    return ToolResult(
        summary=(
            f"{len(matches)} alerts within {params.hours} h of the incident involve a "
            f"process matching {params.process!r}."
        ),
        content={"process": params.process, "hours": params.hours, "matches": entries},
        source_event_ids=[live.event.event_id for live in matches][:MAX_SOURCES],
    )


def rule_context(params: RuleContextParams, context: ToolContext) -> ToolResult:
    if context.history is None:
        return NO_HISTORY
    rule_id = (
        params.rule_id
        if params.rule_id.startswith("wazuh-")
        else f"wazuh-{params.rule_id}"
    )
    incident = context.incident
    window_end = incident.window_end + timedelta(seconds=1)
    baseline_start = incident.window_start - timedelta(days=BASELINE_DAYS)
    in_window = context.history.rule_count(rule_id, incident.window_start, window_end)
    before = context.history.rule_count(rule_id, baseline_start, incident.window_start)
    sample = next(
        (
            live
            for live in context.history.alerts(baseline_start, window_end)
            if live.alert.rule_id == rule_id
        ),
        None,
    )
    content = {
        "rule_id": rule_id,
        "description": sample.alert.rule_name if sample else None,
        "groups": _groups(sample) if sample else [],
        "mitre": sample.alert.suggested_techniques if sample else [],
        "fired_in_incident_window": in_window,
        "fired_in_previous_30_days": before,
        "average_per_day_before": round(before / BASELINE_DAYS, 2),
        "example": _detail(sample),
    }
    return ToolResult(
        summary=(
            f"{rule_id} fired {in_window} times in the incident window and {before} "
            f"times in the {BASELINE_DAYS} days before it."
        ),
        content=content,
        source_event_ids=[sample.event.event_id] if sample else [],
    )


def _groups(live: LiveAlert) -> list[str]:
    return rule_groups(live.event.raw)


def _detail(live: LiveAlert | None) -> str | None:
    if live is None:
        return None
    raw = live.event.raw
    full_log = raw.get("full_log")
    text = full_log if isinstance(full_log, str) and full_log else None
    if text is None:
        data = raw.get("data")
        win = data.get("win") if isinstance(data, dict) else None
        system = win.get("system") if isinstance(win, dict) else None
        message = system.get("message") if isinstance(system, dict) else None
        text = message if isinstance(message, str) and message else None
    if text is None:
        return None
    return " ".join(text.split())[:MAX_DETAIL_CHARS]


def _process_fields(live: LiveAlert) -> list[str | None]:
    process = live.event.process
    if process is None:
        return []
    return [process.name, process.command_line, process.parent_name]


RELATED_ALERTS = Tool(
    name="related_alerts",
    description=(
        "Other Wazuh alerts on the same PC around the incident window, grouped by rule "
        "with counts. Security-check (SCA) results are left out unless rule_group asks "
        "for them. Optionally filter by a Wazuh rule group such as 'sysmon', 'syscheck' "
        "or 'sca'."
    ),
    params=RelatedAlertsParams,
    evidence_class=EvidenceClass.RELATED_ALERTS,
    run=related_alerts,
)

PROCESS_ACTIVITY = Tool(
    name="process_activity",
    description=(
        "Alerts on the same PC that involve a process, matched by image name, path, "
        "command line or parent, with the command lines."
    ),
    params=ProcessActivityParams,
    evidence_class=EvidenceClass.PROCESS_LINEAGE,
    run=process_activity,
)

RULE_CONTEXT = Tool(
    name="rule_context",
    description=(
        "What a Wazuh rule means (description, groups, MITRE), an example of the "
        "alert's own text, and how often it fired on this PC in the incident window "
        "compared with the 30 days before."
    ),
    params=RuleContextParams,
    evidence_class=EvidenceClass.BASELINE_COMPARISON,
    run=rule_context,
)
