from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from agent.llm import LLMResponse, Message, Recording, ReplayClient, ToolSpec
from agent.single_shot import SINGLE_SHOT_NOTE, bundle_queries, single_shot
from contracts.models import (
    Classification,
    Entity,
    EntityType,
    EvaluationArm,
    InvestigationStopReason,
    Severity,
)
from eval.arms import RULES_CONFIDENCE, rules_only
from pipeline.run import run_incident
from tests.conftest import S1Case

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=UTC)
BUNDLE_TOOLS = ["auth_history", "account_context", "source_ip_history", "change_windows"]


class Spy:
    def __init__(self, *responses: dict[str, Any]) -> None:
        self.inner = ReplayClient(
            Recording(source="handwritten", model_name="spy-model", responses=list(responses))
        )
        self.messages: list[list[Message]] = []
        self.tools: list[list[ToolSpec]] = []

    @property
    def model_name(self) -> str:
        return self.inner.model_name

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        self.messages.append(list(messages))
        self.tools.append(list(tools))
        return self.inner.complete(messages, tools)


def _final(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "classification": "benign",
        "confidence": 0.9,
        "summary": "A planned password rotation explains the failures.",
        "cited_evidence": ["E1"],
    }
    payload.update(overrides)
    return {"type": "final", "payload": payload}


def test_rules_only_calls_every_alert_malicious(s1: S1Case) -> None:
    verdict, evidence = rules_only(s1.incident, s1.alerts, s1.events, None)
    top = max((a.rule_severity for a in s1.alerts), key=list(RULES_CONFIDENCE).index)
    assert verdict.arm is EvaluationArm.A1_RULES_ONLY
    assert verdict.classification is Classification.MALICIOUS
    assert verdict.confidence == RULES_CONFIDENCE[top] == 0.6
    assert verdict.incident_id == s1.incident.incident_id
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert evidence == []
    assert verdict.cited_evidence_ids == []
    assert verdict.proposed_actions == []
    assert verdict.tool_calls_made == 0
    assert verdict.input_tokens == 0
    assert verdict.output_tokens == 0
    assert verdict.model_name is None
    assert {a.rule_name for a in s1.alerts} == {"SSH password brute force"}
    assert "SSH password brute force" in verdict.summary


def test_rules_only_takes_the_top_severity_and_names_only_those_rules(s1: S1Case) -> None:
    template = s1.alerts[0]
    alerts = [
        template.model_copy(update={"rule_name": "Quiet rule", "rule_severity": Severity.LOW}),
        template.model_copy(update={"rule_name": "Beta rule", "rule_severity": Severity.HIGH}),
        template.model_copy(update={"rule_name": "Alpha rule", "rule_severity": Severity.HIGH}),
        template.model_copy(update={"rule_name": "Beta rule", "rule_severity": Severity.HIGH}),
    ]
    verdict, _ = rules_only(s1.incident, alerts, s1.events, None, now=lambda: NOW)
    assert verdict.confidence == RULES_CONFIDENCE[Severity.HIGH]
    assert "Alpha rule, Beta rule" in verdict.summary
    assert "Quiet rule" not in verdict.summary
    assert verdict.produced_at == NOW


def test_rules_confidence_rises_with_severity() -> None:
    assert list(RULES_CONFIDENCE) == [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ]
    values = list(RULES_CONFIDENCE.values())
    assert values == sorted(values)


def test_the_bundle_asks_about_the_incident_own_account_host_and_ip(s1: S1Case) -> None:
    assert bundle_queries(s1.incident) == [
        ("auth_history", {"account": "jdoe"}),
        ("account_context", {"account": "jdoe"}),
        ("source_ip_history", {"ip": "10.66.0.10"}),
        (
            "change_windows",
            {"account": "jdoe", "host": "victim-web-01", "ip": "10.66.0.10"},
        ),
    ]


def test_the_bundle_skips_queries_whose_subject_is_missing(s1: S1Case) -> None:
    host_only = s1.incident.model_copy(
        update={"entities": [Entity(entity_type=EntityType.HOST, value="victim-web-01")]}
    )
    assert bundle_queries(host_only) == [("change_windows", {"host": "victim-web-01"})]
    nothing = s1.incident.model_copy(update={"entities": []})
    assert bundle_queries(nothing) == []


def test_the_bundle_takes_the_first_entity_of_each_type(s1: S1Case) -> None:
    entities = [
        Entity(entity_type=EntityType.ACCOUNT, value="first"),
        Entity(entity_type=EntityType.ACCOUNT, value="second"),
        Entity(entity_type=EntityType.IP_ADDRESS, value="10.0.0.1"),
        Entity(entity_type=EntityType.IP_ADDRESS, value="10.0.0.2"),
    ]
    incident = s1.incident.model_copy(update={"entities": entities})
    assert bundle_queries(incident) == [
        ("auth_history", {"account": "first"}),
        ("account_context", {"account": "first"}),
        ("source_ip_history", {"ip": "10.0.0.1"}),
        ("change_windows", {"account": "first", "ip": "10.0.0.1"}),
    ]


def test_single_shot_answers_from_the_bundle_with_no_tools(s1: S1Case) -> None:
    spy = Spy(_final())
    verdict, evidence = single_shot(
        s1.incident, s1.alerts, s1.events, spy, inventory=s1.inventory, now=lambda: NOW
    )
    assert [item.tool_name for item in evidence] == BUNDLE_TOOLS
    assert [item.incident_id for item in evidence] == [s1.incident.incident_id] * 4
    assert all(item.retrieved_at == NOW for item in evidence)
    assert verdict.arm is EvaluationArm.A2B_FULL_CONTEXT
    assert verdict.classification is Classification.BENIGN
    assert verdict.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert verdict.tool_calls_made == 0
    assert verdict.model_name == "spy-model"
    assert verdict.produced_at == NOW
    assert verdict.cited_evidence_ids == [evidence[0].evidence_id]
    assert evidence[0].tool_name == "auth_history"
    assert spy.tools == [[]]
    assert len(spy.messages) == 1


def test_single_shot_sends_the_whole_bundle_in_one_message(s1: S1Case) -> None:
    spy = Spy(_final())
    _, evidence = single_shot(s1.incident, s1.alerts, s1.events, spy, inventory=s1.inventory)
    [(system, user)] = spy.messages
    assert system.role == "system"
    assert system.content.endswith("\n\n" + SINGLE_SHOT_NOTE)
    assert "{max_tool_calls}" not in system.content
    assert "at most 0 tool calls" in system.content
    assert user.role == "user"
    prefix, _, listing = user.content.partition("\n\nEvidence:\n")
    assert s1.incident.incident_id in prefix
    shown = json.loads(listing)
    assert [entry["ref"] for entry in shown] == ["E1", "E2", "E3", "E4"]
    assert [entry["tool"] for entry in shown] == BUNDLE_TOOLS
    for entry, item in zip(shown, evidence, strict=True):
        assert entry["data"] == {"summary": item.summary, "content": item.content}
    assert shown[0]["data"]["content"]["total_failures"] == 24
    assert shown[1]["data"]["content"]["account"] == "jdoe"


def test_single_shot_records_the_one_response_usage(s1: S1Case) -> None:
    response = _final()
    response.update(input_tokens=1200, output_tokens=80, elapsed_ms=450)
    verdict, _ = single_shot(s1.incident, s1.alerts, s1.events, Spy(response))
    assert verdict.input_tokens == 1200
    assert verdict.output_tokens == 80
    assert verdict.latency_ms == 450


def test_single_shot_falls_back_to_wall_time_when_the_model_reports_none(
    s1: S1Case, monkeypatch: pytest.MonkeyPatch
) -> None:
    readings = iter([5.0, 5.25])
    monkeypatch.setattr(
        "agent.single_shot.time", SimpleNamespace(perf_counter=lambda: next(readings))
    )
    verdict, _ = single_shot(s1.incident, s1.alerts, s1.events, Spy(_final()))
    assert verdict.latency_ms == 250


def test_a_tool_call_instead_of_an_answer_is_the_fallback(s1: S1Case) -> None:
    call = {"type": "tool_call", "tool": "auth_history", "args": {"account": "jdoe"}}
    verdict, evidence = single_shot(s1.incident, s1.alerts, s1.events, Spy(call))
    assert verdict.classification is Classification.INCONCLUSIVE
    assert verdict.stop_reason is InvestigationStopReason.INVALID_OUTPUT
    assert verdict.arm is EvaluationArm.A2B_FULL_CONTEXT
    assert verdict.tool_calls_made == 0
    assert verdict.proposed_actions == []
    assert len(evidence) == 4


def test_a_citation_the_bundle_does_not_have_is_the_fallback(s1: S1Case) -> None:
    verdict, evidence = single_shot(
        s1.incident, s1.alerts, s1.events, Spy(_final(cited_evidence=["E9"]))
    )
    assert verdict.classification is Classification.INCONCLUSIVE
    assert verdict.stop_reason is InvestigationStopReason.INVALID_OUTPUT
    assert verdict.cited_evidence_ids == []
    assert len(evidence) == 4


def test_a_malicious_single_shot_verdict_must_still_cite_evidence(s1: S1Case) -> None:
    uncited = _final(classification="malicious", cited_evidence=[])
    verdict, _ = single_shot(s1.incident, s1.alerts, s1.events, Spy(uncited))
    assert verdict.classification is Classification.INCONCLUSIVE
    assert verdict.stop_reason is InvestigationStopReason.INVALID_OUTPUT


def test_single_shot_tolerates_the_pipeline_keywords(s1: S1Case) -> None:
    verdict, _ = single_shot(
        s1.incident,
        s1.alerts,
        s1.events,
        Spy(_final()),
        now=lambda: NOW,
        system_prompt="ignored",
        history=None,
        inventory=s1.inventory,
        changes=[],
    )
    assert verdict.arm is EvaluationArm.A2B_FULL_CONTEXT


def test_the_rules_only_arm_runs_through_the_real_pipeline(s1: S1Case) -> None:
    incident = s1.incident.model_copy(deep=True)
    run = run_incident(
        "s1_attack",
        s1.events,
        s1.alerts,
        incident,
        s1.inventory,
        Spy(),
        investigator=rules_only,
    )
    assert run.verdict.arm is EvaluationArm.A1_RULES_ONLY
    assert run.verdict.classification is Classification.MALICIOUS
    assert run.policy_decisions == []
    assert run.executions == []
    assert run.evidence == []


def test_the_single_shot_arm_runs_through_the_real_pipeline(s1: S1Case) -> None:
    incident = s1.incident.model_copy(deep=True)
    spy = Spy(_final())
    run = run_incident(
        "s1_attack",
        s1.events,
        s1.alerts,
        incident,
        s1.inventory,
        spy,
        investigator=single_shot,
    )
    assert run.verdict.arm is EvaluationArm.A2B_FULL_CONTEXT
    assert [item.tool_name for item in run.evidence] == BUNDLE_TOOLS
    assert run.verdict.cited_evidence_ids == [run.evidence[0].evidence_id]
    assert spy.tools == [[]]
