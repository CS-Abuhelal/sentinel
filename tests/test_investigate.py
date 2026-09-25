from __future__ import annotations

import ast
import json
from typing import Any

import pytest

from agent.investigate import MAX_TOOL_CALLS, investigate
from agent.llm import LLMResponse, Message, Recording, ReplayClient, ReplayExhausted, ToolSpec
from contracts.models import (
    ActionType,
    Classification,
    EvaluationArm,
    InvestigationStopReason,
)
from tests.conftest import REPO, S1_RECORDING

AUTH_CALL = {"type": "tool_call", "tool": "auth_history", "args": {"account": "jdoe"}}


class Capturing:
    def __init__(self, inner: ReplayClient) -> None:
        self.inner = inner
        self.calls: list[list[Message]] = []

    @property
    def model_name(self) -> str:
        return self.inner.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        self.calls.append(list(messages))
        return self.inner.complete(messages, tools)


def _client(*responses: dict[str, Any]) -> ReplayClient:
    return ReplayClient(
        Recording(source="handwritten", model_name="test", responses=list(responses))
    )


def _final(**overrides: Any) -> dict[str, Any]:
    payload = {
        "classification": "malicious",
        "confidence": 0.8,
        "summary": "test",
        "cited_evidence": ["E1"],
    }
    payload.update(overrides)
    return {"type": "final", "payload": payload}


def test_s1_recording_produces_malicious_verdict(s1) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    verdict, evidence = investigate(incident, alerts, events, ReplayClient.from_file(S1_RECORDING))
    [item] = evidence
    assert item.tool_name == "auth_history"
    assert item.tool_query == {"account": "jdoe", "lookback_hours": 168}
    assert item.incident_id == incident.incident_id
    assert verdict.classification is Classification.MALICIOUS
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert verdict.arm is EvaluationArm.A3_TOOL_USING_AGENT
    assert verdict.model_name == "replay:handwritten"
    assert verdict.tool_calls_made == 1
    assert verdict.cited_evidence_ids == [item.evidence_id]
    assert verdict.techniques == ["T1110.001", "T1078"]
    assert [s.evidence_ids for s in verdict.attack_chain] == [[item.evidence_id]] * 2
    [action] = verdict.proposed_actions
    assert action.action_type is ActionType.DISABLE_ACCOUNT
    assert action.target_value == "jdoe"
    assert action.evidence_ids == [item.evidence_id]


def test_tool_results_reach_the_model_as_json_data(s1) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    client = Capturing(_client(AUTH_CALL, _final()))
    investigate(incident, alerts, events, client)
    first, second = client.calls
    assert [m.role for m in first] == ["system", "user"]
    assert str(MAX_TOOL_CALLS) in first[0].content
    assert "{max_tool_calls}" not in first[0].content
    assert incident.incident_id in first[1].content
    tool_message = second[-1]
    assert tool_message.role == "tool"
    body = json.loads(tool_message.content)
    assert body["ref"] == "E1"
    assert body["data"]["content"]["total_failures"] == 24


@pytest.mark.parametrize(
    "responses",
    [
        [{"type": "tool_call", "tool": "run_shell", "args": {"cmd": "id"}}],
        [{"type": "tool_call", "tool": "auth_history", "args": {"account": "jdoe", "x": 1}}],
        [{"type": "tool_call", "tool": "auth_history", "args": {}}],
        [AUTH_CALL, _final(cited_evidence=[])],
        [AUTH_CALL, _final(cited_evidence=["E9"])],
        [AUTH_CALL, _final(classification="compromised")],
        [AUTH_CALL, _final(confidence=3)],
        [AUTH_CALL, _final(unexpected="field")],
        [
            AUTH_CALL,
            _final(
                proposed_actions=[
                    {
                        "action_type": "disable_account",
                        "target_type": "account",
                        "target_value": "jdoe",
                        "justification": "x",
                        "evidence": ["E2"],
                    }
                ]
            ),
        ],
    ],
    ids=[
        "unknown_tool",
        "extra_param",
        "missing_param",
        "malicious_without_citation",
        "unknown_ref",
        "bad_classification",
        "bad_confidence",
        "extra_field",
        "action_cites_unknown_ref",
    ],
)
def test_invalid_output_falls_back_to_inconclusive(s1, responses) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    verdict, _ = investigate(incident, alerts, events, _client(*responses))
    assert verdict.stop_reason is InvestigationStopReason.INVALID_OUTPUT
    assert verdict.classification is Classification.INCONCLUSIVE
    assert verdict.confidence == 0.0
    assert verdict.proposed_actions == []
    assert verdict.cited_evidence_ids == []


def test_tool_call_cap_stops_investigation(s1) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    responses = [AUTH_CALL] * (MAX_TOOL_CALLS + 1)
    verdict, evidence = investigate(incident, alerts, events, _client(*responses))
    assert verdict.stop_reason is InvestigationStopReason.TOOL_CALL_CAP
    assert verdict.tool_calls_made == MAX_TOOL_CALLS
    assert len(evidence) == MAX_TOOL_CALLS
    assert verdict.classification is Classification.INCONCLUSIVE


def test_benign_verdict_without_citations_is_accepted(s1) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    responses = [_final(classification="benign", cited_evidence=[])]
    verdict, evidence = investigate(incident, alerts, events, _client(*responses))
    assert verdict.classification is Classification.BENIGN
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert evidence == []


def test_exhausted_replay_raises(s1) -> None:
    incident, alerts, events = s1.incident, s1.alerts, s1.events
    with pytest.raises(ReplayExhausted):
        investigate(incident, alerts, events, _client(AUTH_CALL))


FORBIDDEN_MODULES = {"policy", "pipeline", "backend", "subprocess", "os", "shutil", "socket"}
FORBIDDEN_CALLS = {"eval", "exec", "__import__", "compile"}


def test_agent_cannot_reach_execution() -> None:
    for path in (REPO / "agent").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                modules = [node.module or ""]
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, f"{path} calls {node.func.id}"
                continue
            else:
                continue
            for module in modules:
                assert module.split(".")[0] not in FORBIDDEN_MODULES, f"{path} imports {module}"
