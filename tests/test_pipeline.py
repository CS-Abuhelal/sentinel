from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent.llm import Recording, ReplayClient
from contracts.models import (
    CONTRACT_VERSION,
    Classification,
    IncidentRun,
    IncidentStatus,
    PolicyOutcome,
)
from pipeline import run as run_module
from pipeline.run import INVENTORY_FILE, load_inventory, load_scenario, main, run_pipeline
from tests.conftest import S1_LOG, S1_RECORDING
from tests.test_investigate import Capturing
from tests.test_ollama import FakeOllama

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


def test_scenario_is_attached_but_never_shown_to_the_agent() -> None:
    scenario = load_scenario(S1_LOG.parent / "scenario.yml")
    assert scenario is not None
    client = Capturing(ReplayClient.from_file(S1_RECORDING))
    run = run_pipeline(
        S1_LOG.read_text(encoding="utf-8").splitlines(),
        "s1_attack",
        load_inventory(INVENTORY_FILE),
        client,
        now=lambda: NOW,
        scenario=scenario,
    )
    assert run.scenario == scenario
    assert run.scenario.expected_classification is Classification.MALICIOUS
    seen = " ".join(m.content for call in client.calls for m in call)
    assert scenario.title not in seen
    assert scenario.description not in seen
    assert "expected_classification" not in seen


def test_every_scenario_has_an_expected_outcome() -> None:
    for log in sorted((S1_LOG.parents[1]).glob("*/auth.log")):
        assert load_scenario(log.parent / "scenario.yml") is not None, log.parent.name


def test_log_without_alerts_raises() -> None:
    lines = S1_LOG.read_text(encoding="utf-8").splitlines()
    baseline = [line for line in lines if not line.startswith("2026-09-25")]
    with pytest.raises(ValueError, match="exactly one incident"):
        _run(baseline)


def test_main_with_live_model_records_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    final = {
        "classification": "malicious",
        "confidence": 0.7,
        "summary": "Password guessing followed by a successful login.",
        "cited_evidence": ["E1"],
    }
    fake = FakeOllama(
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {"function": {"name": "auth_history", "arguments": {"account": "jdoe"}}}
            ],
        },
        {"role": "assistant", "content": json.dumps(final)},
    )
    monkeypatch.setattr(run_module, "OllamaClient", lambda model, base_url, think: fake.client())
    recording_path = tmp_path / "recorded.json"
    argv = [str(S1_LOG), "--llm", "ollama", "--out", str(tmp_path), "--record", str(recording_path)]
    assert main(argv) == 0
    run = IncidentRun.model_validate_json((tmp_path / "s1_attack.json").read_text(encoding="utf-8"))
    assert run.verdict.model_name == "ollama:qwen3:8b"
    recording = Recording.model_validate_json(recording_path.read_text(encoding="utf-8"))
    assert recording.source == "recorded"
    assert [r.type for r in recording.responses] == ["tool_call", "final"]


def test_main_writes_run_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(S1_LOG), "--out", str(tmp_path)]) == 0
    run = IncidentRun.model_validate_json((tmp_path / "s1_attack.json").read_text(encoding="utf-8"))
    assert run.verdict.classification is Classification.MALICIOUS
    output = capsys.readouterr().out
    assert "require_approval" in output
    assert "s1_attack.json" in output
