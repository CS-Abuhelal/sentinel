from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult, source_ip
from contracts.models import EventCategory, EvidenceClass


class SourceIpHistoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1, max_length=64)
    lookback_hours: int = Field(default=168, ge=1, le=720)


def source_ip_history(params: SourceIpHistoryParams, context: ToolContext) -> ToolResult:
    incident = context.incident
    range_start = incident.window_start - timedelta(hours=params.lookback_hours)
    range_end = max((e.timestamp for e in context.events), default=incident.window_end)
    events = sorted(
        (
            e
            for e in context.events
            if e.category is EventCategory.AUTHENTICATION
            and source_ip(e) == params.ip
            and range_start <= e.timestamp <= range_end
        ),
        key=lambda e: e.timestamp,
    )
    accounts: dict[str, dict[str, Any]] = {}
    for event in events:
        name = event.user or "unknown"
        entry = accounts.setdefault(
            name,
            {
                "account": name,
                "failures": 0,
                "successes": 0,
                "first_seen": event.timestamp.isoformat(),
                "last_seen": event.timestamp.isoformat(),
            },
        )
        if event.outcome == "failure":
            entry["failures"] += 1
        elif event.outcome == "success":
            entry["successes"] += 1
        entry["last_seen"] = event.timestamp.isoformat()
    content = {
        "ip": params.ip,
        "range_start": range_start.isoformat(),
        "range_end": range_end.isoformat(),
        "total_events": len(events),
        "accounts": list(accounts.values()),
    }
    return ToolResult(
        summary=_summary(params.ip, content, range_start, range_end),
        content=content,
        source_event_ids=[e.event_id for e in events],
    )


def _summary(ip: str, content: dict[str, Any], start: datetime, end: datetime) -> str:
    window = f"between {start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC"
    if not content["accounts"]:
        return f"No authentication events from {ip} {window}."
    parts = ", ".join(
        f"{a['account']} ({a['failures']} failed, {a['successes']} successful)"
        for a in content["accounts"]
    )
    count = len(content["accounts"])
    return f"{ip} tried {count} account{'' if count == 1 else 's'} {window}: {parts}."


SOURCE_IP_HISTORY = Tool(
    name="source_ip_history",
    description=(
        "Every account one source IP tried to log in as, with failed and successful logins per "
        "account, from lookback_hours before the incident window up to the latest event."
    ),
    params=SourceIpHistoryParams,
    evidence_class=EvidenceClass.NETWORK_ACTIVITY,
    run=source_ip_history,
)
