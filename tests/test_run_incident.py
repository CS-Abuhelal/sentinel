from __future__ import annotations

from datetime import UTC, datetime

from agent.investigate import PC_PROMPT
from agent.llm import Recording, ReplayClient
from agent.tools import WAZUH_TOOLS
from contracts.models import ActionType, HostRecord, Inventory, PolicyOutcome
from executor.approvals import ApprovalEntry
from pipeline.grouping import new_incident
from pipeline.run import run_incident
from tests.conftest import make_wazuh_alert

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)
PC = Inventory(hosts={"my-pc": HostRecord(role="monitored PC", personal=True)})


def _model(*responses: dict) -> ReplayClient:
    recording = Recording(source="handwritten", model_name="test", responses=list(responses))
    return ReplayClient(recording)


def _final(**overrides: object) -> dict:
    payload = {
        "classification": "malicious",
        "confidence": 0.8,
        "summary": "Someone is guessing passwords.",
        "techniques": ["T1110"],
        "attack_chain": [],
        "cited_evidence": ["E1"],
        "risk_factors": [],
        "proposed_actions": [
            {
                "action_type": "isolate_host",
                "target_type": "host",
                "target_value": "my-pc",
                "justification": "Contain it.",
                "evidence": ["E1"],
            }
        ],
        "recommendations": [
            {
                "title": "Stop the guessing",
                "priority": 90,
                "steps": ["Check who is at the PC.", "Turn off the firewall."],
                "evidence": ["E1"],
            }
        ],
    }
    payload.update(overrides)
    return {"type": "final", "payload": payload}


def test_actions_on_the_pc_are_denied_and_advice_is_vetted() -> None:
    live = make_wazuh_alert("1.1", 1, level=10, rule_id="60204")[0]
    model = _model(
        {"type": "tool_call", "tool": "auth_history", "args": {"account": "sentinel-test-nobody"}},
        _final(),
    )
    approval = ApprovalEntry(
        action=ActionType.ISOLATE_HOST, target="my-pc", decision="approve", by="Ahmed Helal"
    )
    run = run_incident(
        "pc-test",
        [live.event],
        [live.alert],
        new_incident(live),
        PC,
        model,
        now=lambda: NOW,
        tools=WAZUH_TOOLS,
        system_prompt=PC_PROMPT,
        approvals=[approval],
        runner_for=lambda host: None,
    )
    [decision] = run.policy_decisions
    assert (decision.outcome, decision.matched_rule) == (
        PolicyOutcome.DENY,
        "personal_host_advice_only",
    )
    assert run.executions == []
    [advice] = run.verdict.recommendations
    assert advice.steps == ["Check who is at the PC."]
    assert advice.dropped_steps == ["Turn off the firewall."]
    assert run.alerts == [live.alert]
