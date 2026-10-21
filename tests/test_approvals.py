from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from contracts.models import (
    ActionType,
    AutonomyLevel,
    EntityType,
    PolicyDecision,
    PolicyOutcome,
    ProposedAction,
)
from executor.approvals import load_approvals, match_approval

NOW = datetime(2026, 9, 25, 2, 30, tzinfo=UTC)
FILE = """
approvals:
  - action: disable_account
    target: jdoe
    decision: approve
    by: Ahmed Helal
    note: Guessed password used from an unknown source.
  - action: disable_account
    target: svc_backup
    decision: deny
    by: Ahmed Helal
"""


def _pair(target: str, outcome=PolicyOutcome.REQUIRE_APPROVAL):
    action = ProposedAction(
        action_type=ActionType.DISABLE_ACCOUNT,
        target_type=EntityType.ACCOUNT,
        target_value=target,
        justification="t",
    )
    decision = PolicyDecision(
        action_id=action.action_id,
        incident_id="inc_1",
        outcome=outcome,
        autonomy_level=AutonomyLevel.ACT_WITH_APPROVAL,
        risk_score=80,
        matched_rule="r",
        reason="r",
        decided_at=NOW,
    )
    return action, decision


@pytest.fixture
def entries(tmp_path: Path):
    path = tmp_path / "case.yml"
    path.write_text(FILE, encoding="utf-8")
    return load_approvals(path)


def test_approve_entry_becomes_an_approval(entries) -> None:
    action, decision = _pair("jdoe")
    approval = match_approval(entries, action, decision, "approvals/case.yml", lambda: NOW)
    assert approval is not None
    assert approval.approved is True
    assert approval.decided_by == "Ahmed Helal"
    assert approval.decision_id == decision.decision_id
    assert approval.action_id == action.action_id
    assert approval.incident_id == "inc_1"
    assert approval.source == "approvals/case.yml"
    assert approval.note == "Guessed password used from an unknown source."


def test_deny_entry_becomes_a_denial(entries) -> None:
    action, decision = _pair("svc_backup")
    approval = match_approval(entries, action, decision, "f", lambda: NOW)
    assert approval is not None and approval.approved is False


def test_no_entry_for_the_target(entries) -> None:
    action, decision = _pair("labadmin")
    assert match_approval(entries, action, decision, "f", lambda: NOW) is None


@pytest.mark.parametrize("outcome", [PolicyOutcome.DENY, PolicyOutcome.ALLOW])
def test_approvals_only_answer_decisions_that_ask_for_one(entries, outcome) -> None:
    action, decision = _pair("jdoe", outcome)
    assert match_approval(entries, action, decision, "f", lambda: NOW) is None


def test_missing_file_means_no_approvals(tmp_path: Path) -> None:
    assert load_approvals(tmp_path / "absent.yml") == []


@pytest.mark.parametrize(
    "text",
    [
        "approvals:\n  - action: rm_rf\n    target: x\n    decision: approve\n    by: a\n",
        "approvals:\n  - action: disable_account\n    target: x\n    decision: maybe\n    by: a\n",
        "approvals:\n  - action: disable_account\n    target: x\n"
        "    decision: approve\n    by: ''\n",
        "approvals:\n  - action: disable_account\n    target: x\n    decision: approve\n",
        "approve_everything: true\n",
    ],
)
def test_malformed_file_is_rejected(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad.yml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValidationError):
        load_approvals(path)
