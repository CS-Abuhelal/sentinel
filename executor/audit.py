from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import datetime
from typing import Any

from contracts.models import AuditKind, AuditRecord

GENESIS = "0" * 64


def record_hash(record: AuditRecord) -> str:
    body = record.model_dump(mode="json", exclude={"hash"})
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def verify_chain(records: list[AuditRecord]) -> bool:
    previous = GENESIS
    for index, record in enumerate(records):
        if record.sequence != index or record.prev_hash != previous:
            return False
        if record.hash != record_hash(record):
            return False
        previous = record.hash
    return True


class AuditLog:
    def __init__(
        self, now: Callable[[], datetime], records: list[AuditRecord] | None = None
    ) -> None:
        self._now = now
        self.records: list[AuditRecord] = list(records or [])

    def append(
        self,
        kind: AuditKind,
        incident_id: str,
        subject_id: str,
        summary: str,
        payload: dict[str, Any] | None = None,
    ) -> AuditRecord:
        draft = AuditRecord(
            sequence=len(self.records),
            recorded_at=self._now(),
            kind=kind,
            incident_id=incident_id,
            subject_id=subject_id,
            summary=summary,
            payload=payload or {},
            prev_hash=self.records[-1].hash if self.records else GENESIS,
            hash="",
        )
        record = draft.model_copy(update={"hash": record_hash(draft)})
        self.records.append(record)
        return record
