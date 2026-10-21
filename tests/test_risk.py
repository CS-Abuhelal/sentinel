from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agent.investigate import investigate
from agent.llm import ReplayClient
from contracts.models import AccountRecord, Inventory, Severity
from policy.risk import score_risk, severity_for
from tests.conftest import S1_RECORDING

NOW = datetime(2026, 9, 25, 2, 20, tzinfo=UTC)


@pytest.fixture(scope="module")
def s1_evidence(s1):
    _, evidence = investigate(
        s1.incident, s1.alerts, s1.events, ReplayClient.from_file(S1_RECORDING)
    )
    return evidence


def test_s1_risk(s1, s1_evidence) -> None:
    risk = score_risk(s1.incident, s1.alerts, s1_evidence, s1.inventory, NOW)
    assert risk.factors == {
        "alert_severity": 15,
        "failed_attempts": 20,
        "success_after_failures": 25,
        "new_source_ip": 20,
        "privileged_account": 0,
    }
    assert risk.score == 80
    assert risk.severity is Severity.CRITICAL
    assert risk.incident_id == s1.incident.incident_id
    assert risk.computed_at == NOW


def test_without_evidence_only_alert_severity_counts(s1) -> None:
    risk = score_risk(s1.incident, s1.alerts, [], s1.inventory, NOW)
    assert risk.score == 15
    assert risk.severity is Severity.LOW


def test_privileged_account_adds_points(s1, s1_evidence) -> None:
    inventory = Inventory(accounts={"jdoe": AccountRecord(role="admin", privileged=True)})
    risk = score_risk(s1.incident, s1.alerts, s1_evidence, inventory, NOW)
    assert risk.factors["privileged_account"] == 15
    assert risk.score == 95


def test_score_is_capped(s1, s1_evidence) -> None:
    alerts = [a.model_copy(update={"rule_severity": Severity.CRITICAL}) for a in s1.alerts]
    inventory = Inventory(accounts={"jdoe": AccountRecord(role="admin", privileged=True)})
    risk = score_risk(s1.incident, alerts, s1_evidence, inventory, NOW)
    assert risk.score == 100


def test_history_of_accounts_outside_the_incident_is_ignored(s1, s1_evidence) -> None:
    [item] = s1_evidence
    other = item.model_copy(
        update={"tool_query": {"account": "someone_else", "lookback_hours": 168}}
    )
    risk = score_risk(s1.incident, s1.alerts, [other], s1.inventory, NOW)
    assert risk.score == 15


@pytest.mark.parametrize(
    "score,severity",
    [
        (0, Severity.INFO),
        (14, Severity.INFO),
        (15, Severity.LOW),
        (34, Severity.LOW),
        (35, Severity.MEDIUM),
        (59, Severity.MEDIUM),
        (60, Severity.HIGH),
        (79, Severity.HIGH),
        (80, Severity.CRITICAL),
        (100, Severity.CRITICAL),
    ],
)
def test_severity_bands(score: int, severity: Severity) -> None:
    assert severity_for(score) is severity
