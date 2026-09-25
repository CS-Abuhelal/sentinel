from __future__ import annotations

from datetime import UTC, datetime

from agent.llm import ReplayClient
from contracts.models import Classification, IncidentStatus, Severity
from pipeline.run import INVENTORY_FILE, RECORDINGS_DIR, REPO, load_inventory, run_pipeline

NOW = datetime(2026, 9, 25, 1, 20, tzinfo=UTC)
LOG = REPO / "lab" / "scenarios" / "s1_benign" / "auth.log"


def test_benign_twin_triggers_the_same_detection_and_closes_benign() -> None:
    run = run_pipeline(
        LOG.read_text(encoding="utf-8").splitlines(),
        "s1_benign",
        load_inventory(INVENTORY_FILE),
        ReplayClient.from_file(RECORDINGS_DIR / "s1_benign.handwritten.json"),
        now=lambda: NOW,
    )
    [alert] = run.alerts
    assert alert.rule_name == "SSH password brute force"
    assert alert.user == "svc_backup"
    assert len(alert.event_ids) == 12
    assert run.verdict.classification is Classification.BENIGN
    assert run.verdict.proposed_actions == []
    assert run.policy_decisions == []
    assert run.incident.status is IncidentStatus.CLOSED_BENIGN
    assert run.risk_score.factors == {
        "alert_severity": 15,
        "failed_attempts": 10,
        "success_after_failures": 25,
        "new_source_ip": 0,
        "privileged_account": 0,
    }
    assert run.risk_score.score == 50
    assert run.risk_score.severity is Severity.MEDIUM
