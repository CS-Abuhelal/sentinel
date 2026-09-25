from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from contracts.models import ActionType, Approval, PolicyDecision, PolicyOutcome, ProposedAction


class ApprovalEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ActionType
    target: str = Field(min_length=1)
    decision: Literal["approve", "deny"]
    by: str = Field(min_length=1)
    note: str | None = None


class ApprovalFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approvals: list[ApprovalEntry] = Field(default_factory=list)


def load_approvals(path: Path) -> list[ApprovalEntry]:
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ApprovalFile.model_validate(data).approvals


def match_approval(
    entries: list[ApprovalEntry],
    action: ProposedAction,
    decision: PolicyDecision,
    source: str,
    now: Callable[[], datetime],
) -> Approval | None:
    if decision.outcome is not PolicyOutcome.REQUIRE_APPROVAL:
        return None
    for entry in entries:
        if entry.action is action.action_type and entry.target == action.target_value:
            return Approval(
                decision_id=decision.decision_id,
                action_id=action.action_id,
                incident_id=decision.incident_id,
                approved=entry.decision == "approve",
                decided_by=entry.by,
                decided_at=now(),
                source=source,
                note=entry.note,
            )
    return None
