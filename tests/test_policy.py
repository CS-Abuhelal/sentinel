from __future__ import annotations

from datetime import UTC, datetime

import pytest

from contracts.models import (
    ActionType,
    AutonomyLevel,
    Classification,
    EntityType,
    EvaluationArm,
    InvestigationStopReason,
    PolicyOutcome,
    ProposedAction,
    RiskScore,
    Verdict,
)
from policy.engine import decide
from policy.risk import severity_for

NOW = datetime(2026, 9, 25, 2, 20, tzinfo=UTC)
ACCOUNT = EntityType.ACCOUNT
HOST = EntityType.HOST
MALICIOUS = Classification.MALICIOUS


def _verdict(incident_id: str, classification: Classification) -> Verdict:
    return Verdict(
        incident_id=incident_id,
        arm=EvaluationArm.A3_TOOL_USING_AGENT,
        classification=classification,
        confidence=0.9,
        summary="test",
        produced_at=NOW,
        stop_reason=InvestigationStopReason.VERDICT_REACHED,
    )


def _risk(incident_id: str, score: int) -> RiskScore:
    return RiskScore(
        incident_id=incident_id, score=score, severity=severity_for(score), computed_at=NOW
    )


def _action(action_type: ActionType, target_type: EntityType, value: str) -> ProposedAction:
    return ProposedAction(
        action_type=action_type, target_type=target_type, target_value=value, justification="t"
    )


def _decide(s1, action: ProposedAction, classification: Classification, score: int = 80):
    incident = s1.incident
    return decide(
        action,
        _verdict(incident.incident_id, classification),
        incident,
        _risk(incident.incident_id, score),
        s1.inventory,
        NOW,
    )


RULE_CASES = [
    (ActionType.NO_ACTION, ACCOUNT, "jdoe", Classification.BENIGN, "allow", "no_action"),
    (
        ActionType.BLOCK_IP,
        EntityType.IP_ADDRESS,
        "10.66.0.10",
        MALICIOUS,
        "deny",
        "not_in_executor_catalog",
    ),
    (
        ActionType.KILL_PROCESS,
        EntityType.PROCESS,
        "1234",
        MALICIOUS,
        "deny",
        "not_in_executor_catalog",
    ),
    (
        ActionType.DISABLE_ACCOUNT,
        HOST,
        "victim-web-01",
        MALICIOUS,
        "deny",
        "target_type_mismatch",
    ),
    (ActionType.DISABLE_ACCOUNT, ACCOUNT, "labadmin", MALICIOUS, "deny", "protected_target"),
    (ActionType.ISOLATE_HOST, HOST, "mgmt-01", MALICIOUS, "deny", "protected_target"),
    (
        ActionType.DISABLE_ACCOUNT,
        ACCOUNT,
        "someone_else",
        MALICIOUS,
        "deny",
        "target_not_in_incident",
    ),
    (
        ActionType.DISABLE_ACCOUNT,
        ACCOUNT,
        "jdoe",
        Classification.BENIGN,
        "deny",
        "verdict_not_malicious",
    ),
    (
        ActionType.DISABLE_ACCOUNT,
        ACCOUNT,
        "jdoe",
        Classification.INCONCLUSIVE,
        "deny",
        "verdict_not_malicious",
    ),
    (
        ActionType.DISABLE_ACCOUNT,
        ACCOUNT,
        "jdoe",
        MALICIOUS,
        "require_approval",
        "disable_account_requires_approval",
    ),
    (
        ActionType.ISOLATE_HOST,
        HOST,
        "victim-web-01",
        MALICIOUS,
        "require_approval",
        "isolate_host_requires_approval",
    ),
]


@pytest.mark.parametrize("action_type,target_type,value,classification,outcome,rule", RULE_CASES)
def test_policy_rules(s1, action_type, target_type, value, classification, outcome, rule) -> None:
    action = _action(action_type, target_type, value)
    decision = _decide(s1, action, classification)
    assert (decision.outcome.value, decision.matched_rule) == (outcome, rule)
    assert decision.action_id == action.action_id
    assert decision.incident_id == s1.incident.incident_id
    assert decision.autonomy_level is AutonomyLevel.ACT_WITH_APPROVAL
    assert decision.risk_score == 80
    assert decision.decided_at == NOW
    assert decision.reason


def test_protected_target_is_flagged(s1) -> None:
    decision = _decide(s1, _action(ActionType.DISABLE_ACCOUNT, ACCOUNT, "labadmin"), MALICIOUS)
    assert decision.target_is_protected is True


@pytest.mark.parametrize("score", [0, 35, 80, 100])
@pytest.mark.parametrize("classification", list(Classification))
def test_disable_account_is_never_allowed(s1, score, classification) -> None:
    action = _action(ActionType.DISABLE_ACCOUNT, ACCOUNT, "jdoe")
    decision = _decide(s1, action, classification, score)
    assert decision.outcome is not PolicyOutcome.ALLOW
