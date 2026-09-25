"""Contract round-trip tests.

Every fixture must load back into its model. If someone changes a model without
regenerating fixtures, or hand-edits a fixture into a shape the model rejects, these
fail immediately instead of in week 9.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.models import (
    AccountRecord,
    Alert,
    Approval,
    AuditRecord,
    Classification,
    EntityType,
    Event,
    EvidenceItem,
    ExecutionResult,
    ExecutionStatus,
    HostRecord,
    Incident,
    IncidentRun,
    Inventory,
    PolicyDecision,
    PolicyOutcome,
    ProposedAction,
    RiskScore,
    Verdict,
)

FIXTURES = Path(__file__).resolve().parents[1] / "contracts" / "fixtures"

FIXTURE_MODEL_MAP = {
    "event_failed_login": Event,
    "event_successful_login": Event,
    "event_process_create": Event,
    "alert_bruteforce": Alert,
    "alert_encoded_powershell": Alert,
    "incident": Incident,
    "evidence_auth_history": EvidenceItem,
    "evidence_entity_context": EvidenceItem,
    "evidence_change_window": EvidenceItem,
    "risk_score": RiskScore,
    "proposed_action_block_ip": ProposedAction,
    "proposed_action_disable_account": ProposedAction,
    "verdict": Verdict,
    "policy_decision_allow": PolicyDecision,
    "policy_decision_require_approval": PolicyDecision,
    "incident_run": IncidentRun,
    "approval": Approval,
    "execution_result": ExecutionResult,
    "audit_record": AuditRecord,
}


def _load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name,model", FIXTURE_MODEL_MAP.items())
def test_fixture_round_trips(name: str, model: type) -> None:
    parsed = model.model_validate(_load(name))
    reparsed = model.model_validate(json.loads(parsed.model_dump_json()))
    assert reparsed == parsed


def test_extra_fields_are_rejected() -> None:
    payload = _load("alert_bruteforce")
    payload["invented_field"] = "this should not be allowed"
    with pytest.raises(ValidationError):
        Alert.model_validate(payload)


def test_confidence_bounds_enforced() -> None:
    payload = _load("verdict")
    payload["confidence"] = 1.7
    with pytest.raises(ValidationError):
        Verdict.model_validate(payload)


def test_alert_requires_at_least_one_event() -> None:
    payload = _load("alert_bruteforce")
    payload["event_ids"] = []
    with pytest.raises(ValidationError):
        Alert.model_validate(payload)


def test_cited_evidence_exists_in_case_bundle() -> None:
    bundle = json.loads((FIXTURES / "s1_full_case.json").read_text(encoding="utf-8"))
    available = {e["evidence_id"] for e in bundle["evidence"]}
    for evidence_id in bundle["verdict"]["cited_evidence_ids"]:
        assert evidence_id in available, f"verdict cites unknown evidence {evidence_id}"


def test_proposed_actions_all_have_policy_decisions() -> None:
    bundle = json.loads((FIXTURES / "s1_full_case.json").read_text(encoding="utf-8"))
    proposed = {a["action_id"] for a in bundle["verdict"]["proposed_actions"]}
    decided = {d["action_id"] for d in bundle["policy_decisions"]}
    assert proposed == decided, "every proposed action must reach the policy engine"


def test_disable_account_never_auto_allowed() -> None:
    """The safety boundary, asserted as a test rather than trusted to a prompt."""
    bundle = json.loads((FIXTURES / "s1_full_case.json").read_text(encoding="utf-8"))
    actions = {a["action_id"]: a for a in bundle["verdict"]["proposed_actions"]}
    for decision in bundle["policy_decisions"]:
        action = actions[decision["action_id"]]
        if action["action_type"] == "disable_account":
            assert decision["outcome"] != PolicyOutcome.ALLOW.value


def test_malicious_verdict_carries_attack_chain() -> None:
    verdict = Verdict.model_validate(_load("verdict"))
    if verdict.classification is Classification.MALICIOUS:
        assert verdict.attack_chain, "a malicious verdict must reconstruct an attack chain"
        assert verdict.cited_evidence_ids, "a malicious verdict must cite evidence"


def test_verdict_requires_stop_reason() -> None:
    payload = _load("verdict")
    del payload["stop_reason"]
    with pytest.raises(ValidationError):
        Verdict.model_validate(payload)


def _inventory() -> Inventory:
    return Inventory(
        accounts={
            "jdoe": AccountRecord(role="developer"),
            "labadmin": AccountRecord(role="lab administrator", privileged=True, protected=True),
        },
        hosts={
            "victim-web-01": HostRecord(role="web server"),
            "mgmt-01": HostRecord(role="management host", protected=True),
        },
    )


@pytest.mark.parametrize(
    "entity_type,value,expected",
    [
        (EntityType.ACCOUNT, "labadmin", True),
        (EntityType.ACCOUNT, "jdoe", False),
        (EntityType.ACCOUNT, "unknown", False),
        (EntityType.HOST, "mgmt-01", True),
        (EntityType.HOST, "victim-web-01", False),
        (EntityType.IP_ADDRESS, "mgmt-01", False),
    ],
)
def test_inventory_is_protected(entity_type: EntityType, value: str, expected: bool) -> None:
    assert _inventory().is_protected(entity_type, value) is expected


def test_inventory_is_privileged() -> None:
    inventory = _inventory()
    assert inventory.is_privileged("labadmin") is True
    assert inventory.is_privileged("jdoe") is False
    assert inventory.is_privileged("unknown") is False


def test_incident_run_execution_lists_default_to_empty() -> None:
    payload = _load("incident_run")
    for key in ("approvals", "executions", "audit"):
        del payload[key]
    run = IncidentRun.model_validate(payload)
    assert (run.approvals, run.executions, run.audit) == ([], [], [])


def test_rejected_execution_ran_nothing() -> None:
    payload = _load("execution_result")
    payload["status"] = ExecutionStatus.REJECTED.value
    payload["commands"] = []
    assert ExecutionResult.model_validate(payload).commands == []


def test_approval_needs_a_person() -> None:
    payload = _load("approval")
    payload["decided_by"] = ""
    with pytest.raises(ValidationError):
        Approval.model_validate(payload)
