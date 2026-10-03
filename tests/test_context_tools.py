from __future__ import annotations

from datetime import timedelta

from agent.tools import TOOLS
from agent.tools.account_context import AccountContextParams, account_context
from agent.tools.base import ToolContext
from agent.tools.change_windows import ChangeWindowsParams, change_windows
from agent.tools.source_ip_history import SourceIpHistoryParams, source_ip_history
from contracts.models import ChangeWindow, EvidenceClass


def _context(s1, changes=()) -> ToolContext:
    return ToolContext(
        incident=s1.incident, events=s1.events, inventory=s1.inventory, changes=list(changes)
    )


def test_tools_are_registered_in_order() -> None:
    assert list(TOOLS) == ["auth_history", "account_context", "source_ip_history", "change_windows"]
    assert TOOLS["account_context"].evidence_class is EvidenceClass.ENTITY_CONTEXT
    assert TOOLS["source_ip_history"].evidence_class is EvidenceClass.NETWORK_ACTIVITY
    assert TOOLS["change_windows"].evidence_class is EvidenceClass.CHANGE_WINDOW


def test_account_context_reports_the_inventory_record(s1) -> None:
    result = account_context(AccountContextParams(account="labadmin"), _context(s1))
    assert result.content == {
        "account": "labadmin",
        "known": True,
        "role": "lab administrator",
        "privileged": True,
        "protected": True,
    }
    assert "privileged" in result.summary and "protected" in result.summary
    unknown = account_context(AccountContextParams(account="nobody"), _context(s1))
    assert unknown.content["known"] is False
    assert "not in the inventory" in unknown.summary


def test_source_ip_history_lists_every_account_the_ip_tried(s1) -> None:
    result = source_ip_history(SourceIpHistoryParams(ip="10.66.0.10"), _context(s1))
    tried = [(a["account"], a["failures"], a["successes"]) for a in result.content["accounts"]]
    assert tried == [("admin", 1, 0), ("test", 1, 0), ("oracle", 1, 0), ("jdoe", 24, 1)]
    assert result.content["total_events"] == 28
    assert len(result.source_event_ids) == 28
    assert "tried 4 accounts" in result.summary
    known = source_ip_history(SourceIpHistoryParams(ip="10.77.0.50"), _context(s1))
    assert [a["account"] for a in known.content["accounts"]] == ["jdoe"]
    none = source_ip_history(SourceIpHistoryParams(ip="192.0.2.1"), _context(s1))
    assert none.content["accounts"] == []
    assert "No authentication events" in none.summary


def test_change_windows_finds_overlapping_changes_that_mention_the_subject(s1) -> None:
    start = s1.incident.window_start
    covering = ChangeWindow(
        change_id="CHG-1",
        title="Rotate jdoe",
        start=start - timedelta(hours=1),
        end=start + timedelta(hours=1),
        accounts=["jdoe"],
    )
    elsewhere = ChangeWindow(
        change_id="CHG-2",
        title="Patch db",
        start=start - timedelta(hours=1),
        end=start + timedelta(hours=1),
        hosts=["victim-db-01"],
    )
    long_ago = ChangeWindow(
        change_id="CHG-3",
        title="Old",
        start=start - timedelta(days=10),
        end=start - timedelta(days=9),
        accounts=["jdoe"],
    )
    context = _context(s1, [covering, elsewhere, long_ago])
    found = change_windows(ChangeWindowsParams(account="jdoe"), context)
    assert [c["change_id"] for c in found.content["changes"]] == ["CHG-1"]
    everything = change_windows(ChangeWindowsParams(), context)
    assert [c["change_id"] for c in everything.content["changes"]] == ["CHG-1", "CHG-2"]
    nothing = change_windows(ChangeWindowsParams(ip="198.51.100.9"), context)
    assert nothing.content["changes"] == []
    assert "No documented change" in nothing.summary
