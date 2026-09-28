from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, insert, not_, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Engine

from backend.app.db import findings as findings_table
from backend.app.db import sync_runs, wazuh_alerts
from backend.app.incidents import IS_POSTURE
from contracts.models import Finding, FindingStatus, HostAssessment, Recommendation
from policy.priority import sort_key

ADVICE_READY = "ready"
ADVICE_FAILED = "failed"
OPEN = FindingStatus.OPEN.value
RESOLVED = FindingStatus.RESOLVED.value


def upsert_findings(
    engine: Engine, host: str, found: list[Finding], now: datetime
) -> tuple[int, int]:
    table = findings_table
    keys = {finding.key for finding in found}
    with engine.begin() as connection:
        existing = {
            row.key: row
            for row in connection.execute(
                select(
                    table.c.key,
                    table.c.finding_id,
                    table.c.first_seen,
                    table.c.status,
                    table.c.finding,
                ).where(table.c.host == host)
            )
        }
        for finding in found:
            old = existing.get(finding.key)
            update_fields = {"status": FindingStatus.OPEN, "last_seen": now}
            if old is not None:
                update_fields |= {"finding_id": old.finding_id, "first_seen": old.first_seen}
            current = finding.model_copy(update=update_fields)
            values = {
                "kind": current.kind.value,
                "status": OPEN,
                "priority": current.priority,
                "first_seen": current.first_seen,
                "last_seen": now,
                "finding": current.model_dump(mode="json"),
            }
            connection.execute(
                pg_insert(table)
                .values(finding_id=current.finding_id, host=host, key=current.key, **values)
                .on_conflict_do_update(constraint="uq_findings_host_key", set_=values)
            )
        resolved = 0
        for key, row in existing.items():
            if key in keys or row.status != OPEN:
                continue
            closed = Finding.model_validate(row.finding).model_copy(
                update={"status": FindingStatus.RESOLVED}
            )
            connection.execute(
                update(table)
                .where(table.c.finding_id == row.finding_id)
                .values(status=RESOLVED, finding=closed.model_dump(mode="json"))
            )
            resolved += 1
        connection.execute(
            update(table)
            .where(
                table.c.host == host,
                table.c.status == OPEN,
                table.c.advice_state == ADVICE_FAILED,
            )
            .values(advice_state=None, advice_model=None, advice_at=None)
        )
    return len(found), resolved


def open_findings(engine: Engine, host: str, package: str | None = None) -> list[Finding]:
    table = findings_table
    statement = select(table.c.finding).where(table.c.host == host, table.c.status == OPEN)
    if package:
        statement = statement.where(table.c.finding["package"].astext.ilike(f"%{package}%"))
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return sorted((Finding.model_validate(row.finding) for row in rows), key=sort_key)


def finding_hosts(engine: Engine) -> list[str]:
    table = findings_table
    count = func.count().label("open_count")
    statement = (
        select(table.c.host, count)
        .where(table.c.status == OPEN)
        .group_by(table.c.host)
        .order_by(count.desc(), table.c.host)
    )
    with engine.connect() as connection:
        return [row.host for row in connection.execute(statement)]


def advice_states(engine: Engine, host: str) -> dict[str, str]:
    table = findings_table
    statement = select(table.c.finding_id, table.c.advice_state).where(
        table.c.host == host, table.c.advice_state.is_not(None)
    )
    with engine.connect() as connection:
        return {row.finding_id: row.advice_state for row in connection.execute(statement)}


def next_finding_to_advise(engine: Engine, top: int = 10) -> Finding | None:
    for host in finding_hosts(engine):
        states = advice_states(engine, host)
        for finding in open_findings(engine, host)[:top]:
            if finding.finding_id not in states:
                return finding
    return None


def set_advice(
    engine: Engine,
    finding_id: str,
    recommendation: Recommendation | None,
    model_name: str,
    now: datetime,
) -> None:
    table = findings_table
    values = {
        "advice": None if recommendation is None else recommendation.model_dump(mode="json"),
        "advice_state": ADVICE_FAILED if recommendation is None else ADVICE_READY,
        "advice_model": model_name,
        "advice_at": now,
    }
    with engine.begin() as connection:
        connection.execute(update(table).where(table.c.finding_id == finding_id).values(**values))


def assessment(engine: Engine, host: str, now: datetime) -> HostAssessment | None:
    found = open_findings(engine, host)
    if not found:
        return None
    table = findings_table
    statement = (
        select(table.c.finding_id, table.c.advice, table.c.advice_model, table.c.advice_at)
        .where(table.c.host == host, table.c.status == OPEN, table.c.advice_state == ADVICE_READY)
        .order_by(table.c.advice_at.desc())
    )
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    advice = {row.finding_id: Recommendation.model_validate(row.advice) for row in rows}
    return HostAssessment(
        host=host,
        created_at=now,
        synced_at=last_successful_sync(engine) or now,
        findings=[finding.model_copy(update={"raw": {}}) for finding in found],
        recommendations=[advice[f.finding_id] for f in found if f.finding_id in advice],
        model_name=rows[0].advice_model if rows else None,
    )


def record_sync(
    engine: Engine,
    started: datetime,
    finished: datetime,
    ok: bool,
    error: str | None,
    found: int,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            insert(sync_runs).values(
                started_at=started, finished_at=finished, ok=ok, error=error, found=found
            )
        )


def last_successful_sync(engine: Engine) -> datetime | None:
    statement = select(func.max(sync_runs.c.finished_at)).where(sync_runs.c.ok.is_(True))
    with engine.connect() as connection:
        return connection.execute(statement).scalar_one()


def related_alert_count(engine: Engine, host: str, package: str, since: datetime) -> int:
    pattern = f"%{package}%"
    statement = (
        select(func.count())
        .select_from(wazuh_alerts)
        .where(
            wazuh_alerts.c.agent_name == host,
            wazuh_alerts.c.alert_time >= since,
            not_(IS_POSTURE),
            or_(
                wazuh_alerts.c.event["process"]["name"].astext.ilike(pattern),
                wazuh_alerts.c.payload["full_log"].astext.ilike(pattern),
            ),
        )
    )
    with engine.connect() as connection:
        return connection.execute(statement).scalar_one()
