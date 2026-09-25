from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    tool: str
    args: dict[str, Any]


@dataclass(frozen=True)
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_call: ToolCall | None = None


@dataclass(frozen=True)
class FinalAnswer:
    payload: dict[str, Any]


LLMResponse = ToolCall | FinalAnswer


class LLMClient(Protocol):
    @property
    def model_name(self) -> str: ...

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse: ...


class ReplayExhausted(RuntimeError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RecordedToolCall(_Strict):
    type: Literal["tool_call"]
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class RecordedFinal(_Strict):
    type: Literal["final"]
    payload: dict[str, Any]


class Recording(_Strict):
    source: Literal["handwritten", "recorded"]
    model_name: str
    responses: list[Annotated[RecordedToolCall | RecordedFinal, Field(discriminator="type")]]


class ReplayClient:
    def __init__(self, recording: Recording) -> None:
        self._recording = recording
        self._position = 0

    @classmethod
    def from_file(cls, path: Path) -> ReplayClient:
        return cls(Recording.model_validate_json(path.read_text(encoding="utf-8")))

    @property
    def model_name(self) -> str:
        return self._recording.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        responses = self._recording.responses
        if self._position >= len(responses):
            raise ReplayExhausted(
                f"the recording has {len(responses)} responses and the agent asked for more"
            )
        recorded = responses[self._position]
        self._position += 1
        if isinstance(recorded, RecordedToolCall):
            return ToolCall(tool=recorded.tool, args=dict(recorded.args))
        return FinalAnswer(payload=recorded.payload)


class RecordingClient:
    def __init__(self, inner: LLMClient) -> None:
        self._inner = inner
        self._responses: list[RecordedToolCall | RecordedFinal] = []

    @property
    def model_name(self) -> str:
        return self._inner.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        response = self._inner.complete(messages, tools)
        if isinstance(response, ToolCall):
            self._responses.append(
                RecordedToolCall(type="tool_call", tool=response.tool, args=response.args)
            )
        else:
            self._responses.append(RecordedFinal(type="final", payload=response.payload))
        return response

    def recording(self) -> Recording:
        return Recording(
            source="recorded", model_name=self.model_name, responses=list(self._responses)
        )
