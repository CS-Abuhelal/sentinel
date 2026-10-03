from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from pydantic import BaseModel

from agent.llm import ToolSpec
from contracts.models import (
    ChangeWindow,
    Event,
    EvidenceClass,
    Finding,
    Incident,
    Inventory,
    LiveAlert,
)


class HostHistory(Protocol):
    def alerts(
        self, start: datetime, end: datetime, include_posture: bool = False
    ) -> list[LiveAlert]: ...

    def rule_count(self, rule_id: str, start: datetime, end: datetime) -> int: ...

    def rule_sample(self, rule_id: str, preferred_alert_ids: list[str]) -> LiveAlert | None: ...

    def findings(self, package: str | None) -> list[Finding]: ...


@dataclass(frozen=True)
class ToolContext:
    incident: Incident
    events: list[Event]
    history: HostHistory | None = None
    inventory: Inventory | None = None
    changes: list[ChangeWindow] = field(default_factory=list)


def source_ip(event: Event) -> str:
    if event.network is None or event.network.src_ip is None:
        return "unknown"
    return event.network.src_ip


@dataclass(frozen=True)
class ToolResult:
    summary: str
    content: dict[str, Any]
    source_event_ids: list[str]


@dataclass(frozen=True)
class Tool:
    name: str
    description: str
    params: type[BaseModel]
    evidence_class: EvidenceClass
    run: Callable[[Any, ToolContext], ToolResult]

    def spec(self) -> ToolSpec:
        return ToolSpec(
            name=self.name,
            description=self.description,
            parameters=self.params.model_json_schema(),
        )
