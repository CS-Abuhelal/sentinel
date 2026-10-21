from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent.llm import ReplayClient
from contracts.models import (
    AuditKind,
    AuditRecord,
    ExecutionStatus,
    IncidentRun,
    IncidentStatus,
)
from executor.approvals import ApprovalEntry
from executor.audit import verify_chain
from pipeline.run import INVENTORY_FILE, RECORDINGS_DIR, REPO, load_inventory, main, run_pipeline
from tests.conftest import S1_LOG, S1_RECORDING
from tests.test_executor import FakeHost

NOW = datetime(2026, 9, 25, 2, 30, tzinfo=UTC)
APPROVE_JDOE = ApprovalEntry(
    action="disable_account", target="jdoe", decision="approve", by="Ahmed Helal"
)
DENY_JDOE = ApprovalEntry(
    action="disable_account", target="jdoe", decision="deny", by="Ahmed Helal"
)


def _run(
    approvals=None,
    runner_for=None,
    log: Path = S1_LOG,
    recording: Path = S1_RECORDING,
    case="s1_attack",
):
    return run_pipeline(
        log.read_text(encoding="utf-8").splitlines(),
        case,
        load_inventory(INVENTORY_FILE),
        ReplayClient.from_file(recording),
        now=lambda: NOW,
        approvals=approvals,
        approval_source=f"approvals/{case}.yml",
        runner_for=runner_for,
    )


def test_without_approval_nothing_runs_and_the_incident_waits() -> None:
    run = _run()
    assert run.approvals == []
    assert run.executions == []
    assert run.incident.status is IncidentStatus.AWAITING_APPROVAL
    assert [r.kind for r in run.audit] == [AuditKind.PROPOSAL, AuditKind.DECISION]
    assert verify_chain(run.audit)


def test_approved_action_runs_on_a_real_host_and_resolves_the_incident() -> None:
    host = FakeHost()
    run = _run([APPROVE_JDOE], {"victim-web-01": host}.get)
    [approval] = run.approvals
    [execution] = run.executions
    [decision] = run.policy_decisions
    assert approval.decided_by == "Ahmed Helal"
    assert approval.decision_id == decision.decision_id
    assert approval.source == "approvals/s1_attack.yml"
    assert execution.status is ExecutionStatus.SUCCEEDED
    assert execution.verified is True
    assert host.locked and not host.session
    assert run.incident.status is IncidentStatus.RESOLVED
    assert [r.kind for r in run.audit] == [
        AuditKind.PROPOSAL,
        AuditKind.DECISION,
        AuditKind.APPROVAL,
        AuditKind.EXECUTION,
    ]
    assert [r.subject_id for r in run.audit] == [
        decision.action_id,
        decision.decision_id,
        approval.approval_id,
        execution.execution_id,
    ]
    assert verify_chain(run.audit)
    assert IncidentRun.model_validate_json(run.model_dump_json()) == run


def test_dry_run_is_recorded_but_does_not_resolve() -> None:
    run = _run([APPROVE_JDOE])
    [execution] = run.executions
    assert execution.dry_run is True
    assert execution.status is ExecutionStatus.SUCCEEDED
    assert run.incident.status is IncidentStatus.INVESTIGATING


def test_denied_approval_is_recorded_and_nothing_runs() -> None:
    host = FakeHost()
    run = _run([DENY_JDOE], {"victim-web-01": host}.get)
    [approval] = run.approvals
    [execution] = run.executions
    assert approval.approved is False
    assert execution.status is ExecutionStatus.REJECTED
    assert host.calls == []
    assert run.incident.status is IncidentStatus.INVESTIGATING
    assert verify_chain(run.audit)


def test_benign_twin_has_nothing_to_audit() -> None:
    log = REPO / "lab" / "scenarios" / "s1_benign" / "auth.log"
    run = _run(
        [APPROVE_JDOE], None, log, RECORDINGS_DIR / "s1_benign.handwritten.json", "s1_benign"
    )
    assert run.audit == [] and run.executions == []
    assert run.incident.status is IncidentStatus.CLOSED_BENIGN


def test_cli_reads_approvals_and_appends_the_audit_log(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    approvals = tmp_path / "approvals"
    approvals.mkdir()
    (approvals / "s1_attack.yml").write_text(
        "approvals:\n  - action: disable_account\n    target: jdoe\n"
        "    decision: approve\n    by: Ahmed Helal\n",
        encoding="utf-8",
    )
    audit_log = tmp_path / "audit.jsonl"
    argv = [
        str(S1_LOG),
        "--out",
        str(tmp_path),
        "--approvals",
        str(approvals),
        "--audit-log",
        str(audit_log),
    ]
    assert main(argv) == 0
    run = IncidentRun.model_validate_json((tmp_path / "s1_attack.json").read_text(encoding="utf-8"))
    lines = audit_log.read_text(encoding="utf-8").splitlines()
    assert [AuditRecord.model_validate_json(line) for line in lines] == run.audit
    output = capsys.readouterr().out
    assert "approval  Ahmed Helal approved disable_account jdoe" in output
    assert "execution disable_account jdoe on victim-web-01: succeeded (dry run)" in output
    assert "audit     4 records, chain intact" in output
