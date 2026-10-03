from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from agent.investigate import investigate
from agent.llm import FinalAnswer, Message, RecordingClient, ReplayClient, ToolCall, ToolSpec
from agent.ollama import OllamaClient, OllamaError
from contracts.models import Classification, InvestigationStopReason

SPEC = ToolSpec(name="auth_history", description="d", parameters={"type": "object"})


class FakeOllama:
    def __init__(self, *replies: dict[str, Any], status: int = 200) -> None:
        self.replies = list(replies)
        self.status = status
        self.requests: list[dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content))
        if self.status != 200:
            return httpx.Response(self.status, text="model not found")
        return httpx.Response(200, json={"message": self.replies.pop(0), "done": True})

    def client(self) -> OllamaClient:
        return OllamaClient("qwen3:8b", transport=httpx.MockTransport(self))


def _tool_reply(name: str, arguments: Any) -> dict[str, Any]:
    return {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": name, "arguments": arguments}}],
    }


def _text_reply(content: str) -> dict[str, Any]:
    return {"role": "assistant", "content": content}


def test_request_shape() -> None:
    fake = FakeOllama(_text_reply("{}"))
    messages = [
        Message("system", "s"),
        Message("user", "u"),
        Message("assistant", "", tool_call=ToolCall(tool="auth_history", args={"account": "a"})),
        Message("tool", '{"ref": "E1"}'),
    ]
    fake.client().complete(messages, [SPEC])
    [body] = fake.requests
    assert body["model"] == "qwen3:8b"
    assert body["stream"] is False
    assert body["think"] is False
    assert body["options"]["temperature"] == 0
    assert body["options"]["num_predict"] == 2048
    assert body["tools"] == [
        {
            "type": "function",
            "function": {"name": "auth_history", "description": "d", "parameters": SPEC.parameters},
        }
    ]
    assert body["messages"][2] == {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": "auth_history", "arguments": {"account": "a"}}}],
    }
    assert body["messages"][3] == {
        "role": "tool",
        "content": '{"ref": "E1"}',
        "tool_name": "auth_history",
    }


def test_model_name() -> None:
    assert FakeOllama().client().model_name == "ollama:qwen3:8b"


def test_thinking_mode() -> None:
    fake = FakeOllama(_text_reply("{}"))
    client = OllamaClient("qwen3:14b", think=True, transport=httpx.MockTransport(fake))
    client.complete([], [SPEC])
    assert fake.requests[0]["think"] is True
    assert client.model_name == "ollama:qwen3:14b thinking"


@pytest.mark.parametrize(
    "arguments", [{"account": "jdoe"}, '{"account": "jdoe"}'], ids=["object", "string"]
)
def test_tool_call_reply(arguments: Any) -> None:
    fake = FakeOllama(_tool_reply("auth_history", arguments))
    assert fake.client().complete([], [SPEC]) == ToolCall(
        tool="auth_history", args={"account": "jdoe"}
    )


@pytest.mark.parametrize(
    "content",
    [
        '{"classification": "benign"}',
        'Here is my verdict:\n```json\n{"classification": "benign"}\n```',
        '<think>hmm</think>\n{"classification": "benign"}',
        'Verdict: {"classification": "benign"} done',
    ],
    ids=["bare", "fenced", "think_tags", "surrounded"],
)
def test_final_answer_reply(content: str) -> None:
    fake = FakeOllama(_text_reply(content))
    assert fake.client().complete([], [SPEC]) == FinalAnswer(payload={"classification": "benign"})


def _usage_client(**counts: int) -> OllamaClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"message": _text_reply('{"classification": "benign"}'), "done": True, **counts},
        )

    return OllamaClient("qwen3:8b", transport=httpx.MockTransport(handler))


def test_final_answer_carries_token_counts_and_elapsed_time() -> None:
    client = _usage_client(prompt_eval_count=321, eval_count=45)
    answer = client.complete([], [SPEC])
    assert isinstance(answer, FinalAnswer)
    assert answer.payload == {"classification": "benign"}
    assert answer.input_tokens == 321
    assert answer.output_tokens == 45
    assert answer.elapsed_ms >= 0


def test_tool_call_carries_token_counts_and_elapsed_time() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "message": _tool_reply("auth_history", {"account": "jdoe"}),
                "prompt_eval_count": 500,
                "eval_count": 12,
            },
        )

    client = OllamaClient("qwen3:8b", transport=httpx.MockTransport(handler))
    call = client.complete([], [SPEC])
    assert isinstance(call, ToolCall)
    assert call.input_tokens == 500
    assert call.output_tokens == 12
    assert call.elapsed_ms >= 0


def test_missing_token_counts_are_zero() -> None:
    answer = _usage_client().complete([], [SPEC])
    assert isinstance(answer, FinalAnswer)
    assert (answer.input_tokens, answer.output_tokens) == (0, 0)


def test_unparseable_reply_becomes_empty_answer() -> None:
    fake = FakeOllama(_text_reply("I think this is malicious."))
    assert fake.client().complete([], [SPEC]) == FinalAnswer(payload={})


def test_a_closed_client_releases_its_connection_and_sends_nothing_more() -> None:
    fake = FakeOllama(_text_reply("{}"), _text_reply("{}"))
    client = fake.client()
    client.complete([Message("user", "u")], [])
    client.close()
    with pytest.raises(RuntimeError, match="closed"):
        client.complete([Message("user", "u")], [])
    assert len(fake.requests) == 1


def test_closing_twice_is_harmless() -> None:
    client = FakeOllama().client()
    client.close()
    client.close()


def test_http_error_raises() -> None:
    with pytest.raises(OllamaError, match="404"):
        FakeOllama(status=404).client().complete([], [SPEC])


def test_live_investigation_end_to_end(s1) -> None:
    final = {
        "classification": "malicious",
        "confidence": 0.8,
        "summary": "Brute force then success.",
        "cited_evidence": ["E1"],
    }
    fake = FakeOllama(
        _tool_reply("auth_history", {"account": "jdoe"}), _text_reply(json.dumps(final))
    )
    recorder = RecordingClient(fake.client())
    verdict, evidence = investigate(s1.incident, s1.alerts, s1.events, recorder)
    assert verdict.classification is Classification.MALICIOUS
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert verdict.model_name == "ollama:qwen3:8b"
    assert verdict.cited_evidence_ids == [evidence[0].evidence_id]
    recording = recorder.recording()
    assert recording.source == "recorded"
    assert recording.model_name == "ollama:qwen3:8b"
    replayed, _ = investigate(s1.incident, s1.alerts, s1.events, ReplayClient(recording))
    assert replayed.classification is Classification.MALICIOUS


def test_cut_off_answer_becomes_invalid_output(s1) -> None:
    runaway = {
        "role": "assistant",
        "content": '{"classification": "malicious", "summary": "the the the',
    }
    fake = FakeOllama(_tool_reply("auth_history", {"account": "jdoe"}), runaway)
    verdict, _ = investigate(s1.incident, s1.alerts, s1.events, fake.client())
    assert verdict.stop_reason is InvestigationStopReason.INVALID_OUTPUT
    assert verdict.classification is Classification.INCONCLUSIVE
    assert verdict.proposed_actions == []
