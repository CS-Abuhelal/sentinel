from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import ChangeWindow, EvidenceClass


class ChangeWindowsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str | None = Field(default=None, max_length=256)
    host: str | None = Field(default=None, max_length=256)
    ip: str | None = Field(default=None, max_length=64)
    hours_around: int = Field(default=24, ge=0, le=168)


def change_windows(params: ChangeWindowsParams, context: ToolContext) -> ToolResult:
    incident = context.incident
    start = incident.window_start - timedelta(hours=params.hours_around)
    end = incident.window_end + timedelta(hours=params.hours_around)
    found = [
        change
        for change in sorted(context.changes, key=lambda c: (c.start, c.change_id))
        if change.start <= end and change.end >= start and _mentions(change, params)
    ]
    content = {
        "range_start": start.isoformat(),
        "range_end": end.isoformat(),
        "account": params.account,
        "host": params.host,
        "ip": params.ip,
        "changes": [change.model_dump(mode="json") for change in found],
    }
    if found:
        listed = "; ".join(
            f"{c.change_id} {c.title} ({c.start:%Y-%m-%d %H:%M} to {c.end:%Y-%m-%d %H:%M} UTC)"
            for c in found
        )
        summary = f"{len(found)} documented change{'' if len(found) == 1 else 's'}: {listed}."
    else:
        summary = "No documented change covers this time for the given account, host or IP."
    return ToolResult(summary=summary, content=content, source_event_ids=[])


def _mentions(change: ChangeWindow, params: ChangeWindowsParams) -> bool:
    if params.account is None and params.host is None and params.ip is None:
        return True
    return (
        (params.account is not None and params.account in change.accounts)
        or (params.host is not None and params.host in change.hosts)
        or (params.ip is not None and params.ip in change.source_ips)
    )


CHANGE_WINDOWS = Tool(
    name="change_windows",
    description=(
        "Documented, approved changes (for example password rotations or network changes) that "
        "overlap the incident window, plus or minus hours_around, and mention the given "
        "account, host or IP. With none given, lists every overlapping change."
    ),
    params=ChangeWindowsParams,
    evidence_class=EvidenceClass.CHANGE_WINDOW,
    run=change_windows,
)
