from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.llm import FinalAnswer, Recording, ReplayClient, ReplayExhausted, ToolCall

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


def test_recording_rejects_unknown_response_type() -> None:
    bad = {**RECORDING, "responses": [{"type": "shell", "command": "id"}]}
    with pytest.raises(ValidationError):
        Recording.model_validate(bad)
