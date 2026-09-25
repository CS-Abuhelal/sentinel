from __future__ import annotations

from datetime import datetime

from contracts.models import (
    ActionType,
    AutonomyLevel,
    Classification,
    EntityType,
    Incident,
    Inventory,
    PolicyDecision,
    PolicyOutcome,
    ProposedAction,
    RiskScore,
    Verdict,
)

EXECUTOR_CATALOG = frozenset({ActionType.DISABLE_ACCOUNT, ActionType.ISOLATE_HOST})
TARGET_TYPES = {
    ActionType.DISABLE_ACCOUNT: EntityType.ACCOUNT,
    ActionType.ISOLATE_HOST: EntityType.HOST,
}
AUTONOMY = AutonomyLevel.ACT_WITH_APPROVAL


def decide(
    action: ProposedAction,
    verdict: Verdict,
    incident: Incident,
    risk: RiskScore,
    inventory: Inventory,
    now: datetime,
) -> PolicyDecision:
    protected = inventory.is_protected(action.target_type, action.target_value)
    rule, outcome, reason = _evaluate(action, verdict, incident, protected)
    return PolicyDecision(
        action_id=action.action_id,
        incident_id=incident.incident_id,
        outcome=outcome,
        autonomy_level=AUTONOMY,
        risk_score=risk.score,
        matched_rule=rule,
        reason=reason,
        target_is_protected=protected,
        decided_at=now,
    )


def _evaluate(
    action: ProposedAction, verdict: Verdict, incident: Incident, protected: bool
) -> tuple[str, PolicyOutcome, str]:
    kind = action.action_type
    target = f"{action.target_type.value} {action.target_value}"
    if kind is ActionType.NO_ACTION:
        return "no_action", PolicyOutcome.ALLOW, "Nothing is executed."
    if kind not in EXECUTOR_CATALOG:
        return (
            "not_in_executor_catalog",
            PolicyOutcome.DENY,
            f"{kind.value} is not in the executor catalog, so it can never run.",
        )
    if action.target_type is not TARGET_TYPES[kind]:
        return (
            "target_type_mismatch",
            PolicyOutcome.DENY,
            f"{kind.value} must target a {TARGET_TYPES[kind].value}, not a "
            f"{action.target_type.value}.",
        )
    if protected:
        return (
            "protected_target",
            PolicyOutcome.DENY,
            f"The {target} is protected. No automated response may touch it.",
        )
    in_incident = any(
        e.entity_type is action.target_type and e.value == action.target_value
        for e in incident.entities
    )
    if not in_incident:
        return (
            "target_not_in_incident",
            PolicyOutcome.DENY,
            f"The {target} is not an entity in this incident.",
        )
    if verdict.classification is not Classification.MALICIOUS:
        return (
            "verdict_not_malicious",
            PolicyOutcome.DENY,
            f"The verdict is {verdict.classification.value}. Response actions need a "
            "malicious verdict.",
        )
    if kind is ActionType.DISABLE_ACCOUNT:
        return (
            "disable_account_requires_approval",
            PolicyOutcome.REQUIRE_APPROVAL,
            "Disabling an account locks out a real person, so it always needs human approval.",
        )
    if kind is ActionType.ISOLATE_HOST:
        return (
            "isolate_host_requires_approval",
            PolicyOutcome.REQUIRE_APPROVAL,
            f"Host isolation needs human approval at the {AUTONOMY.value} autonomy level.",
        )
    return "default_deny", PolicyOutcome.DENY, "No rule allows this action."
