from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent.llm import ReplayClient
from contracts.models import (
    CONTRACT_VERSION,
    Classification,
    IncidentRun,
    IncidentStatus,
    PolicyOutcome,
)
from pipeline.run import INVENTORY_FILE, load_inventory, main, run_pipeline
from tests.conftest import S1_LOG, S1_RECORDING

NOW = datetime(2026, 9, 25, 2, 20, tzinfo=UTC)


def _run(lines: list[str]) -> IncidentRun:
    return run_pipeline(
        lines,
        "s1_attack",
        load_inventory(INVENTORY_FILE),
        ReplayClient.from_file(S1_RECORDING),
        now=lambda: NOW,
    )


def test_s1_end_to_end() -> None:
    run = _run(S1_LOG.read_text(encoding="utf-8").splitlines())
    assert run.case_id == "s1_attack"
    assert run.contract_version == CONTRACT_VERSION
    assert len(run.events) == 32
    [alert] = run.alerts
    assert run.incident.alert_ids == [alert.alert_id]
    assert run.incident.status is IncidentStatus.AWAITING_APPROVAL
    assert run.incident.updated_at == NOW
    assert run.verdict.classification is Classification.MALICIOUS
    assert set(run.verdict.cited_evidence_ids) <= {e.evidence_id for e in run.evidence}
    assert run.risk_score.score == 80
    [action] = run.verdict.proposed_actions
    [decision] = run.policy_decisions
    assert decision.action_id == action.action_id
    assert decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
    assert decision.matched_rule == "disable_account_requires_approval"
    assert IncidentRun.model_validate_json(run.model_dump_json()) == run


def test_log_without_alerts_raises() -> None:
    lines = S1_LOG.read_text(encoding="utf-8").splitlines()
    baseline = [line for line in lines if not line.startswith("2026-09-25")]
    with pytest.raises(ValueError, match="exactly one incident"):
        _run(baseline)


def test_main_writes_run_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(S1_LOG), "--out", str(tmp_path)]) == 0
    run = IncidentRun.model_validate_json((tmp_path / "s1_attack.json").read_text(encoding="utf-8"))
    assert run.verdict.classification is Classification.MALICIOUS
    output = capsys.readouterr().out
    assert "require_approval" in output
    assert "s1_attack.json" in output
