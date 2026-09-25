from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import Event, EventCategory, EvidenceClass


class AuthHistoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str = Field(min_length=1, max_length=256)
    lookback_hours: int = Field(default=168, ge=1, le=720)


def auth_history(params: AuthHistoryParams, context: ToolContext) -> ToolResult:
    incident = context.incident
    range_start = incident.window_start - timedelta(hours=params.lookback_hours)
    range_end = max((e.timestamp for e in context.events), default=incident.window_end)
    events = sorted(
        (
            e
            for e in context.events
            if e.category is EventCategory.AUTHENTICATION
            and e.user == params.account
            and range_start <= e.timestamp <= range_end
        ),
        key=lambda e: e.timestamp,
    )
    by_source = _by_source(events)
    known = sorted(
        {
            _src_ip(e)
            for e in events
            if e.outcome == "success" and e.timestamp < incident.window_start
        }
    )
    after_failures = _success_after_failures(events, incident.window_start)
    content = {
        "account": params.account,
        "range_start": range_start.isoformat(),
        "range_end": range_end.isoformat(),
        "total_failures": sum(1 for e in events if e.outcome == "failure"),
        "total_successes": sum(1 for e in events if e.outcome == "success"),
        "by_source_ip": by_source,
        "success_after_failures": after_failures,
        "known_source_ips": known,
    }
    return ToolResult(
        summary=_summary(content, range_start, range_end),
        content=content,
        source_event_ids=[e.event_id for e in events],
    )


def _by_source(events: list[Event]) -> list[dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    for event in events:
        src_ip = _src_ip(event)
        entry = entries.setdefault(
            src_ip,
            {
                "src_ip": src_ip,
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
    return list(entries.values())


def _success_after_failures(events: list[Event], window_start: datetime) -> list[dict[str, Any]]:
    found = []
    for src_ip in dict.fromkeys(_src_ip(e) for e in events):
        failures = 0
        for event in (e for e in events if _src_ip(e) == src_ip):
            if event.outcome == "failure":
                failures += 1
            elif event.outcome == "success":
                if event.timestamp >= window_start and failures:
                    found.append(
                        {
                            "src_ip": src_ip,
                            "failures_before": failures,
                            "success_at": event.timestamp.isoformat(),
                        }
                    )
                    break
                failures = 0
    return found


def _summary(content: dict[str, Any], range_start: datetime, range_end: datetime) -> str:
    known = content["known_source_ips"]
    parts = [
        f"{content['account']}: {content['total_failures']} failed and "
        f"{content['total_successes']} successful logins between "
        f"{_short(range_start)} and {_short(range_end)}."
    ]
    for entry in content["success_after_failures"]:
        novelty = (
            " This source had no successful logins before the incident."
            if entry["src_ip"] not in known
            else ""
        )
        parts.append(
            f"Successful login from {entry['src_ip']} after {entry['failures_before']} "
            f"consecutive failures, at {_short(datetime.fromisoformat(entry['success_at']))}."
            f"{novelty}"
        )
    parts.append(
        f"Sources with successful logins before the incident: {', '.join(known) or 'none'}."
    )
    return " ".join(parts)


def _short(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _src_ip(event: Event) -> str:
    if event.network is None or event.network.src_ip is None:
        return "unknown"
    return event.network.src_ip


AUTH_HISTORY = Tool(
    name="auth_history",
    description=(
        "Authentication history for one account: failed and successful logins per source IP, "
        "from lookback_hours before the incident window up to the latest available event. "
        "Reports successes that followed failures from the same source and the sources the "
        "account used successfully before the incident."
    ),
    params=AuthHistoryParams,
    evidence_class=EvidenceClass.AUTH_HISTORY,
    run=auth_history,
)
