from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from contracts.models import AuditKind
from executor.audit import GENESIS, AuditLog, record_hash, verify_chain

T0 = datetime(2026, 9, 25, 2, 20, tzinfo=UTC)


def _log() -> AuditLog:
    ticks = iter(T0 + timedelta(seconds=i) for i in range(100))
    log = AuditLog(now=lambda: next(ticks))
    log.append(AuditKind.PROPOSAL, "inc_1", "act_1", "disable_account jdoe proposed", {"a": 1})
    log.append(AuditKind.DECISION, "inc_1", "pol_1", "require_approval", {"rule": "r"})
    log.append(AuditKind.APPROVAL, "inc_1", "apr_1", "approved by Ahmed", {"by": "Ahmed"})
    log.append(AuditKind.EXECUTION, "inc_1", "exe_1", "succeeded", {"verified": True})
    return log


def test_records_are_chained() -> None:
    records = _log().records
    assert [r.sequence for r in records] == [0, 1, 2, 3]
    assert records[0].prev_hash == GENESIS
    for previous, record in zip(records, records[1:], strict=False):
        assert record.prev_hash == previous.hash
    assert all(record.hash == record_hash(record) for record in records)
    assert len({r.hash for r in records}) == 4
    assert verify_chain(records)


def test_empty_chain_is_valid() -> None:
    assert verify_chain([])


def test_edited_record_breaks_the_chain() -> None:
    records = _log().records
    records[1] = records[1].model_copy(update={"summary": "allow"})
    assert not verify_chain(records)


def test_edited_payload_breaks_the_chain() -> None:
    records = _log().records
    records[2] = records[2].model_copy(update={"payload": {"by": "someone else"}})
    assert not verify_chain(records)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_deleted_record_breaks_the_chain(index: int) -> None:
    records = _log().records
    del records[index]
    assert not verify_chain(records)


def test_reordered_records_break_the_chain() -> None:
    records = _log().records
    records[1], records[2] = records[2], records[1]
    assert not verify_chain(records)


def test_rehashing_an_edit_still_breaks_the_next_link() -> None:
    records = _log().records
    edited = records[1].model_copy(update={"summary": "allow"})
    records[1] = edited.model_copy(update={"hash": record_hash(edited)})
    assert not verify_chain(records)


def test_log_can_continue_an_existing_chain() -> None:
    first = _log()
    resumed = AuditLog(now=lambda: T0, records=first.records)
    resumed.append(AuditKind.EXECUTION, "inc_1", "exe_2", "second host", {})
    assert verify_chain(resumed.records)
    assert resumed.records[-1].sequence == 4
