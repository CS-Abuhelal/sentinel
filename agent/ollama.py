from __future__ import annotations

import json
import re
from typing import Any

import httpx

from agent.llm import FinalAnswer, LLMResponse, Message, ToolCall, ToolSpec

DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:8b"

_THINK = re.compile(r"<think>.*?</think>", re.DOTALL)
_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_URL,
        timeout: float = 900.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._model = model
        self._http = httpx.Client(base_url=base_url, timeout=timeout, transport=transport)

    @property
    def model_name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        body = {
            "model": self._model,
            "messages": _messages(messages),
            "tools": [_tool(spec) for spec in tools],
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_ctx": 16384},
        }
        response = self._http.post("/api/chat", json=body)
        if response.status_code != 200:
            raise OllamaError(f"Ollama returned {response.status_code}: {response.text[:300]}")
        message = response.json().get("message") or {}
        calls = message.get("tool_calls") or []
        if calls:
            function = calls[0].get("function") or {}
            arguments = function.get("arguments") or {}
            if isinstance(arguments, str):
                arguments = _json_object(arguments) or {}
            return ToolCall(tool=str(function.get("name", "")), args=arguments)
        return FinalAnswer(payload=_json_object(str(message.get("content") or "")) or {})


def _messages(messages: list[Message]) -> list[dict[str, Any]]:
    converted = []
    last_tool = None
    for message in messages:
        item: dict[str, Any] = {"role": message.role, "content": message.content}
        if message.tool_call is not None:
            last_tool = message.tool_call.tool
            item["tool_calls"] = [
                {"function": {"name": message.tool_call.tool, "arguments": message.tool_call.args}}
            ]
        if message.role == "tool" and last_tool is not None:
            item["tool_name"] = last_tool
        converted.append(item)
    return converted


def _tool(spec: ToolSpec) -> dict[str, Any]:
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    }


def _json_object(text: str) -> dict[str, Any] | None:
    text = _THINK.sub("", text).strip()
    fenced = _FENCE.search(text)
    candidates = [text]
    if fenced:
        candidates.insert(0, fenced.group(1))
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    return None
