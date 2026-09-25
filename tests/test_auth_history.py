from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from agent.tools import TOOLS
from agent.tools.auth_history import AuthHistoryParams, auth_history
from agent.tools.base import ToolContext
from contracts.models import EvidenceClass


@pytest.fixture(scope="module")
def s1_context(s1) -> ToolContext:
    return ToolContext(incident=s1.incident, events=s1.events)


def test_s1_auth_history(s1_context: ToolContext) -> None:
    result = auth_history(AuthHistoryParams(account="jdoe"), s1_context)
    content = result.content
    assert content["account"] == "jdoe"
    assert content["total_failures"] == 24
    assert content["total_successes"] == 5
    assert content["known_source_ips"] == ["10.77.0.50"]
    assert content["success_after_failures"] == [
        {
            "src_ip": "10.66.0.10",
            "failures_before": 24,
            "success_at": "2026-09-25T02:17:03.088412+00:00",
        }
    ]
    by_ip = {entry["src_ip"]: entry for entry in content["by_source_ip"]}
    assert (by_ip["10.77.0.50"]["failures"], by_ip["10.77.0.50"]["successes"]) == (0, 4)
    assert (by_ip["10.66.0.10"]["failures"], by_ip["10.66.0.10"]["successes"]) == (24, 1)
    start = s1_context.incident.window_start - timedelta(hours=168)
    assert content["range_start"] == start.isoformat()
    assert len(result.source_event_ids) == 29
    assert "10.66.0.10" in result.summary


def test_lookback_limits_history(s1_context: ToolContext) -> None:
    result = auth_history(AuthHistoryParams(account="jdoe", lookback_hours=24), s1_context)
    assert result.content["total_successes"] == 2
    assert result.content["known_source_ips"] == ["10.77.0.50"]


def test_unknown_account_returns_empty_history(s1_context: ToolContext) -> None:
    result = auth_history(AuthHistoryParams(account="nobody"), s1_context)
    assert result.content["total_failures"] == 0
    assert result.content["success_after_failures"] == []
    assert result.source_event_ids == []


@pytest.mark.parametrize(
    "args",
    [
        {"account": "jdoe", "extra": 1},
        {"account": "jdoe", "lookback_hours": 0},
        {"account": "jdoe", "lookback_hours": 721},
        {"account": ""},
        {},
    ],
)
def test_params_are_validated(args: dict) -> None:
    with pytest.raises(ValidationError):
        AuthHistoryParams.model_validate(args)


def test_registry() -> None:
    tool = TOOLS["auth_history"]
    assert tool.evidence_class is EvidenceClass.AUTH_HISTORY
    spec = tool.spec()
    assert spec.name == "auth_history"
    assert set(spec.parameters["properties"]) == {"account", "lookback_hours"}
