from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.llm import (
    FinalAnswer,
    Message,
    Recording,
    RecordingClient,
    ReplayClient,
    ReplayExhausted,
    ToolCall,
    ToolSpec,
)

RECORDING = {
    "source": "handwritten",
    "model_name": "replay:handwritten",
    "responses": [
        {"type": "tool_call", "tool": "auth_history", "args": {"account": "jdoe"}},
        {"type": "final", "payload": {"classification": "benign"}},
    ],
}


def test_replay_returns_responses_in_order_then_raises() -> None:
    client = ReplayClient(Recording.model_validate(RECORDING))
    assert client.model_name == "replay:handwritten"
    assert client.complete([], []) == ToolCall(tool="auth_history", args={"account": "jdoe"})
    assert client.complete([], []) == FinalAnswer(payload={"classification": "benign"})
    with pytest.raises(ReplayExhausted):
        client.complete([], [])


def test_replay_from_file(tmp_path: Path) -> None:
    path = tmp_path / "recording.json"
    path.write_text(json.dumps(RECORDING), encoding="utf-8")
    client = ReplayClient.from_file(path)
    assert isinstance(client.complete([], []), ToolCall)


USAGE = {"input_tokens": 100, "output_tokens": 20, "elapsed_ms": 1500}
USAGE_RECORDING = {
    "source": "recorded",
    "model_name": "ollama:test",
    "responses": [
        {"type": "tool_call", "tool": "auth_history", "args": {"account": "jdoe"}, **USAGE},
        {"type": "final", "payload": {"classification": "benign"}, **USAGE},
    ],
}


class Scripted:
    model_name = "scripted"

    def __init__(self, *responses: ToolCall | FinalAnswer) -> None:
        self._responses = list(responses)

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> ToolCall | FinalAnswer:
        return self._responses.pop(0)


def test_replay_returns_recorded_usage() -> None:
    client = ReplayClient(Recording.model_validate(USAGE_RECORDING))
    call = client.complete([], [])
    final = client.complete([], [])
    assert isinstance(call, ToolCall)
    assert isinstance(final, FinalAnswer)
    for response in (call, final):
        assert (response.input_tokens, response.output_tokens, response.elapsed_ms) == (
            100,
            20,
            1500,
        )


def test_recording_client_copies_usage_into_the_recording() -> None:
    inner = Scripted(
        ToolCall(tool="auth_history", args={"account": "jdoe"}, **USAGE),
        FinalAnswer(payload={"classification": "benign"}, **USAGE),
    )
    client = RecordingClient(inner)
    client.complete([], [])
    client.complete([], [])
    recording = client.recording()
    assert recording.model_dump(mode="json")["responses"] == USAGE_RECORDING["responses"]
    assert Recording.model_validate_json(recording.model_dump_json()) == recording


def test_a_recording_without_usage_loads_with_zeros() -> None:
    client = ReplayClient(Recording.model_validate(RECORDING))
    for response in (client.complete([], []), client.complete([], [])):
        assert isinstance(response, ToolCall | FinalAnswer)
        assert (response.input_tokens, response.output_tokens, response.elapsed_ms) == (0, 0, 0)


def test_recording_rejects_unknown_response_type() -> None:
    bad = {**RECORDING, "responses": [{"type": "shell", "command": "id"}]}
    with pytest.raises(ValidationError):
        Recording.model_validate(bad)
