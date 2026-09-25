from __future__ import annotations

import ast
from datetime import UTC, datetime

import pytest

from contracts.models import (
    ActionType,
    Approval,
    AutonomyLevel,
    CommandResult,
    EntityType,
    ExecutionStatus,
    PolicyDecision,
    PolicyOutcome,
    ProposedAction,
)
from executor.core import execute
from executor.runners import DryRunRunner
from tests.conftest import REPO

NOW = datetime(2026, 9, 25, 2, 30, tzinfo=UTC)
HOST = "victim-web-01"


class FakeHost:
    dry_run = False

    def __init__(self, fail: str | None = None, ignore_lock: bool = False) -> None:
        self.locked = False
        self.session = True
        self.isolated = False
        self.fail = fail
        self.ignore_lock = ignore_lock
        self.calls: list[list[str]] = []

    def run(self, argv: list[str]) -> CommandResult:
        self.calls.append(argv)
        if argv[0] == self.fail:
            return CommandResult(argv=argv, exit_code=1, output="boom")
        if argv[0] == "usermod":
            self.locked = not self.ignore_lock
            return CommandResult(argv=argv, exit_code=0)
        if argv[0] == "pkill":
            had = self.session
            self.session = False
            return CommandResult(argv=argv, exit_code=0 if had else 1)
        if argv[0] == "passwd":
            state = "L" if self.locked else "P"
            return CommandResult(
                argv=argv, exit_code=0, output=f"{argv[-1]} {state} 2026-09-25 0 99999 7 -1"
            )
        if argv[0] == "pgrep":
            return CommandResult(
                argv=argv, exit_code=0 if self.session else 1, output="1234" if self.session else ""
            )
        if argv[:2] == ["nft", "list"]:
            if not self.isolated:
                return CommandResult(argv=argv, exit_code=1, output="No such file or directory")
            return CommandResult(
                argv=argv,
                exit_code=0,
                output="chain input { policy drop; }\nchain output { policy drop; }",
            )
        if argv[0] == "nft":
            self.isolated = True
            return CommandResult(argv=argv, exit_code=0)
        return CommandResult(argv=argv, exit_code=127, output="unknown command")


def _action(action_type=ActionType.DISABLE_ACCOUNT, target_type=EntityType.ACCOUNT, value="jdoe"):
    return ProposedAction(
        action_type=action_type, target_type=target_type, target_value=value, justification="t"
    )


def _decision(incident, action, outcome=PolicyOutcome.REQUIRE_APPROVAL) -> PolicyDecision:
    return PolicyDecision(
        action_id=action.action_id,
        incident_id=incident.incident_id,
        outcome=outcome,
        autonomy_level=AutonomyLevel.ACT_WITH_APPROVAL,
        risk_score=80,
        matched_rule="test",
        reason="test",
        decided_at=NOW,
    )


def _approval(decision, approved=True) -> Approval:
    return Approval(
        decision_id=decision.decision_id,
        action_id=decision.action_id,
        incident_id=decision.incident_id,
        approved=approved,
        decided_by="Ahmed Helal",
        decided_at=NOW,
        source="approvals/test.yml",
    )


def _run(s1, action, decision, approval, host=None):
    host = host if host is not None else FakeHost()
    results = execute(
        decision, action, s1.incident, s1.inventory, approval, {HOST: host}.get, lambda: NOW
    )
    return results, host


def test_approved_disable_account_locks_and_ends_sessions(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    [result], host = _run(s1, action, decision, _approval(decision))
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.verified is True
    assert result.host == HOST
    assert result.dry_run is False
    assert [c.argv for c in result.commands] == [
        ["usermod", "--lock", "--expiredate", "1", "jdoe"],
        ["pkill", "-KILL", "-u", "jdoe"],
    ]
    assert " P " in result.before[0].output and result.before[1].exit_code == 0
    assert " L " in result.verification[0].output and result.verification[1].exit_code == 1
    assert host.locked and not host.session


def test_approved_isolate_host_applies_firewall(s1) -> None:
    action = _action(ActionType.ISOLATE_HOST, EntityType.HOST, HOST)
    decision = _decision(s1.incident, action)
    [result], host = _run(s1, action, decision, _approval(decision))
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.verified is True
    assert all(argv[0] == "nft" for argv in (c.argv for c in result.commands))
    assert host.isolated


def test_dry_run_records_commands_without_verifying(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    runner = DryRunRunner()
    [result] = execute(
        decision,
        action,
        s1.incident,
        s1.inventory,
        _approval(decision),
        lambda h: runner,
        lambda: NOW,
    )
    assert result.status is ExecutionStatus.SUCCEEDED
    assert result.dry_run is True
    assert result.verified is None
    assert result.before == [] and result.verification == []
    assert runner.calls == [c.argv for c in result.commands]


def _rejected(results, host, reason_part: str) -> None:
    [result] = results
    assert result.status is ExecutionStatus.REJECTED
    assert reason_part in result.reason
    assert result.commands == []
    assert host.calls == []


def test_action_outside_catalog_is_rejected(s1) -> None:
    action = _action(ActionType.BLOCK_IP, EntityType.IP_ADDRESS, "10.66.0.10")
    decision = _decision(s1.incident, action, PolicyOutcome.ALLOW)
    _rejected(*_run(s1, action, decision, None), "catalog")


def test_decision_for_another_action_is_rejected(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, _action())
    _rejected(*_run(s1, action, decision, _approval(decision)), "does not belong")


def test_denied_decision_never_runs(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action, PolicyOutcome.DENY)
    _rejected(*_run(s1, action, decision, _approval(decision)), "denied")


def test_require_approval_without_approval_is_rejected(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    _rejected(*_run(s1, action, decision, None), "human approval")


def test_denied_approval_is_rejected(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    _rejected(
        *_run(s1, action, decision, _approval(decision, approved=False)), "Ahmed Helal denied"
    )


def test_approval_for_another_decision_is_rejected(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    other = _decision(s1.incident, action)
    _rejected(*_run(s1, action, decision, _approval(other)), "human approval")


def test_disable_account_never_runs_on_allow_alone(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action, PolicyOutcome.ALLOW)
    _rejected(*_run(s1, action, decision, None), "human approval")


def test_protected_target_is_rejected_even_with_approval(s1) -> None:
    action = _action(value="labadmin")
    decision = _decision(s1.incident, action)
    _rejected(*_run(s1, action, decision, _approval(decision)), "protected")


def test_target_type_mismatch_is_rejected(s1) -> None:
    action = _action(ActionType.DISABLE_ACCOUNT, EntityType.HOST, HOST)
    decision = _decision(s1.incident, action)
    _rejected(*_run(s1, action, decision, _approval(decision)), "must target")


@pytest.mark.parametrize("value", ["jdoe; rm -rf /", "../root", "$(id)", "JDOE", "-u", ""])
def test_malformed_account_name_is_rejected(s1, value: str) -> None:
    action = _action(value=value)
    decision = _decision(s1.incident, action)
    _rejected(*_run(s1, action, decision, _approval(decision)), "not a valid")


def test_host_without_runner_is_rejected(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    results = execute(
        decision,
        action,
        s1.incident,
        s1.inventory,
        _approval(decision),
        lambda h: None,
        lambda: NOW,
    )
    [result] = results
    assert result.status is ExecutionStatus.REJECTED
    assert "no execution target" in result.reason


def test_failed_command_stops_and_fails(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    [result], host = _run(s1, action, decision, _approval(decision), FakeHost(fail="usermod"))
    assert result.status is ExecutionStatus.FAILED
    assert [c.argv[0] for c in result.commands] == ["usermod"]
    assert "usermod" in result.reason


def test_failed_verification_fails(s1) -> None:
    action = _action()
    decision = _decision(s1.incident, action)
    [result], _ = _run(s1, action, decision, _approval(decision), FakeHost(ignore_lock=True))
    assert result.status is ExecutionStatus.FAILED
    assert result.verified is False
    assert "verification" in result.reason


def _imports(package: str) -> set[str]:
    found = set()
    for path in (REPO / package).rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {alias.name.split(".")[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                found.add(node.module.split(".")[0])
    return found


def test_executor_does_not_depend_on_the_agent() -> None:
    assert "agent" not in _imports("executor")


def test_only_the_executor_runs_processes() -> None:
    for package in ("agent", "policy", "detection", "ingest", "pipeline", "backend", "contracts"):
        assert "subprocess" not in _imports(package), package
