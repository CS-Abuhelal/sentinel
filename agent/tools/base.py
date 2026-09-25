from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from agent.llm import ToolSpec
from contracts.models import Event, EvidenceClass, Incident


@dataclass(frozen=True)
class ToolContext:
    incident: Incident
    events: list[Event]


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
