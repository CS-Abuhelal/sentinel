from __future__ import annotations

import json
from typing import Any

import pytest

from agent.llm import FinalAnswer, LLMResponse, Message, ToolCall, ToolSpec
from agent.single_shot import bundle_queries
from contracts.models import EvaluationArm, Incident
from eval import run as eval_run
from pipeline.run import INVENTORY_FILE, load_inventory
from tests.conftest import REPO

SCENARIOS = REPO / "lab" / "scenarios"
CASES = eval_run.discover_cases()
A2B = EvaluationArm.A2B_FULL_CONTEXT
A3 = EvaluationArm.A3_TOOL_USING_AGENT
LAB_TOOLS = ["auth_history", "account_context", "source_ip_history", "change_windows"]
LABEL_FIELDS = ("expected_classification", "required_evidence")
BENIGN_FINAL = {
    "classification": "benign",
    "confidence": 0.9,
    "summary": "A normal explanation fits.",
    "cited_evidence": ["E1"],
}


class Spy:
    def __init__(self) -> None:
        self.conversation: list[Message] = []
        self.plan: list[tuple[str, dict[str, Any]]] | None = None

    @property
    def model_name(self) -> str:
        return "spy"

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        self.conversation = list(messages)
        if self.plan is None:
            self.plan = self._queries(messages) if tools else []
        answered = sum(1 for message in messages if message.role == "tool")
        if answered < len(self.plan):
            tool, args = self.plan[answered]
            return ToolCall(tool=tool, args=args)
        return FinalAnswer(payload=dict(BENIGN_FINAL))

    @staticmethod
    def _queries(messages: list[Message]) -> list[tuple[str, dict[str, Any]]]:
        data = json.loads(messages[1].content.split("\n", 1)[1])
        return bundle_queries(Incident.model_validate(data["incident"]))


def run_with_spy(case_id: str, arm: EvaluationArm) -> tuple[Spy, str]:
    lab = eval_run.Lab(load_inventory(INVENTORY_FILE), eval_run.load_rules(eval_run.RULES_DIR))
    spy = Spy()
    lab.run(case_id, arm, spy)
    return spy, "\n".join(message.content for message in spy.conversation)


def test_every_lab_case_is_checked() -> None:
    assert len(CASES) == 8


@pytest.mark.parametrize("arm", [A2B, A3])
@pytest.mark.parametrize("case_id", CASES)
def test_the_label_never_reaches_the_model(case_id: str, arm: EvaluationArm) -> None:
    scenario = eval_run.load_scenario(SCENARIOS / case_id / "scenario.yml")
    assert scenario is not None
    _, seen = run_with_spy(case_id, arm)
    assert case_id not in seen
    for field in LABEL_FIELDS:
        assert field not in seen
    assert scenario.title not in seen
    assert scenario.description not in seen


@pytest.mark.parametrize("case_id", CASES)
def test_the_single_call_sees_the_whole_bundle_this_test_inspects(case_id: str) -> None:
    spy, seen = run_with_spy(case_id, A2B)
    assert [message.role for message in spy.conversation] == ["system", "user"]
    assert "Evidence:" in seen
    assert [f'"tool": "{name}"' in seen for name in LAB_TOOLS] == [True] * 4


@pytest.mark.parametrize("case_id", CASES)
def test_the_agent_sees_every_tool_result_this_test_inspects(case_id: str) -> None:
    spy, _ = run_with_spy(case_id, A3)
    assert [message.role for message in spy.conversation].count("tool") == 4
    called = [m.tool_call.tool for m in spy.conversation if m.tool_call is not None]
    assert called == LAB_TOOLS
