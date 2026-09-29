from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import Text, func, insert, literal, not_, or_, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.engine import Connection, Engine

from backend.app.db import findings as findings_table
from backend.app.db import sync_runs, wazuh_alerts
from backend.app.store import IS_POSTURE
from contracts.models import Finding, FindingKind, FindingStatus, HostAssessment, Recommendation
from policy.priority import sort_key

ADVICE_READY = "ready"
ADVICE_FAILED = "failed"
RETRY_FAILED_ADVICE = timedelta(hours=1)
OPEN = FindingStatus.OPEN.value
RESOLVED = FindingStatus.RESOLVED.value
VULNERABILITY = FindingKind.VULNERABILITY.value
NO_ADVICE = {"advice": None, "advice_state": None, "advice_model": None, "advice_at": None}
WITHOUT_RAW = findings_table.c.finding.op("-", return_type=JSONB)(literal("raw", Text))
PACKAGE_TYPE = findings_table.c.finding[("raw", "package", "type")].astext


@dataclass(frozen=True)
class StoredAdvice:
    state: str
    covers: frozenset[str]
    at: datetime | None


def upsert_findings(
    engine: Engine,
    host: str,
    found: list[Finding],
    now: datetime,
    resolvable_config_keys: set[str] | None = None,
    resolve_vulnerabilities: bool = True,
) -> tuple[int, int]:
    table = findings_table
    keys = {finding.key for finding in found}
    cleared = resolvable_config_keys or set()
    with engine.begin() as connection:
        existing = {
            row.key: row
            for row in connection.execute(
                select(
                    table.c.key,
                    table.c.kind,
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
        kept = 0
        for key, row in existing.items():
            if key in keys or row.status != OPEN:
                continue
            if row.kind == VULNERABILITY:
                resolves = resolve_vulnerabilities
            else:
                resolves = key in cleared
            if not resolves:
                kept += 1
                continue
            closed = Finding.model_validate(row.finding).model_copy(
                update={"status": FindingStatus.RESOLVED}
            )
            connection.execute(
                update(table)
                .where(table.c.finding_id == row.finding_id)
                .values(status=RESOLVED, finding=closed.model_dump(mode="json"), **NO_ADVICE)
            )
            resolved += 1
        connection.execute(
            update(table)
            .where(
                table.c.host == host,
                table.c.status == OPEN,
                table.c.advice_state == ADVICE_FAILED,
            )
            .values(**NO_ADVICE)
        )
    return len(found) + kept, resolved


def open_findings(engine: Engine, host: str, package: str | None = None) -> list[Finding]:
    table = findings_table
    statement = select(WITHOUT_RAW.label("finding"), PACKAGE_TYPE.label("package_type")).where(
        table.c.host == host, table.c.status == OPEN
    )
    if package:
        statement = statement.where(
            table.c.finding["package"].astext.ilike(f"%{_literal(package)}%", escape="\\")
        )
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return sorted((_light(row.finding, row.package_type) for row in rows), key=sort_key)


def _light(data: dict[str, Any], package_type: str | None) -> Finding:
    raw = {} if package_type is None else {"package": {"type": package_type}}
    return Finding.model_validate({**data, "raw": raw})


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


def stored_advice(engine: Engine, host: str) -> dict[str, StoredAdvice]:
    table = findings_table
    statement = select(
        table.c.finding_id,
        table.c.advice_state,
        table.c.advice_at,
        table.c.advice["finding_ids"].label("covers"),
    ).where(table.c.host == host, table.c.advice_state.is_not(None))
    with engine.connect() as connection:
        return {
            row.finding_id: StoredAdvice(
                row.advice_state, frozenset(row.covers or []), row.advice_at
            )
            for row in connection.execute(statement)
        }


def advice_unit(finding: Finding) -> str:
    return _unit(finding.kind.value, finding.package, finding.finding_id)


def _unit(kind: str, package: str | None, finding_id: str) -> str:
    if kind == VULNERABILITY and package:
        return "package:" + package.lower()
    return "finding:" + finding_id


def next_finding_to_advise(engine: Engine, now: datetime, top: int = 10) -> Finding | None:
    for host in finding_hosts(engine):
        stored = stored_advice(engine, host)
        units: dict[str, list[Finding]] = {}
        for finding in open_findings(engine, host):
            unit = advice_unit(finding)
            if unit in units:
                units[unit].append(finding)
            elif len(units) < top:
                units[unit] = [finding]
        for members in units.values():
            if not _advised(members, stored, now):
                return members[0]
    return None


def _advised(members: list[Finding], stored: dict[str, StoredAdvice], now: datetime) -> bool:
    open_ids = {f.finding_id for f in members}
    newest = max(f.first_seen for f in members)
    for member in members:
        advice = stored.get(member.finding_id)
        if advice is None:
            continue
        if advice.state == ADVICE_READY and open_ids <= advice.covers:
            return True
        if (
            advice.state == ADVICE_FAILED
            and advice.at is not None
            and advice.at > newest
            and now - advice.at < RETRY_FAILED_ADVICE
        ):
            return True
    return False


def unit_findings(engine: Engine, finding: Finding) -> list[Finding]:
    unit = advice_unit(finding)
    return [f for f in open_findings(engine, finding.host) if advice_unit(f) == unit]


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
        others = _other_members(connection, finding_id)
        if others:
            connection.execute(
                update(table).where(table.c.finding_id.in_(others)).values(**NO_ADVICE)
            )


def _other_members(connection: Connection, finding_id: str) -> list[str]:
    table = findings_table
    package = table.c.finding["package"].astext.label("package")
    lead = connection.execute(
        select(table.c.host, table.c.kind, package).where(table.c.finding_id == finding_id)
    ).one_or_none()
    if lead is None:
        return []
    unit = _unit(lead.kind, lead.package, finding_id)
    rows = connection.execute(
        select(table.c.finding_id, table.c.kind, package).where(
            table.c.host == lead.host,
            table.c.finding_id != finding_id,
            table.c.advice_state.is_not(None),
        )
    )
    return [row.finding_id for row in rows if _unit(row.kind, row.package, row.finding_id) == unit]


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
        synced_at=last_successful_sync(engine) or max(f.last_seen for f in found),
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


def _literal(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def related_alert_count(engine: Engine, host: str, package: str, since: datetime) -> int:
    pattern = f"%{_literal(package)}%"
    statement = (
        select(func.count())
        .select_from(wazuh_alerts)
        .where(
            wazuh_alerts.c.agent_name == host,
            wazuh_alerts.c.alert_time >= since,
            not_(IS_POSTURE),
            or_(
                wazuh_alerts.c.event["process"]["name"].astext.ilike(pattern, escape="\\"),
                wazuh_alerts.c.payload["full_log"].astext.ilike(pattern, escape="\\"),
            ),
        )
    )
    with engine.connect() as connection:
        return connection.execute(statement).scalar_one()
