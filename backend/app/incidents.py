from __future__ import annotations

from datetime import datetime, timedelta

from pydantic import TypeAdapter
from sqlalchemy import (
    ColumnElement,
    Text,
    and_,
    cast,
    func,
    null,
    or_,
    select,
    true,
    type_coerce,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, Insert, array, insert
from sqlalchemy.engine import Engine
from sqlalchemy.sql.dml import Update

from backend.app.db import incidents, wazuh_alerts
from backend.app.store import LIVE_COLUMNS, live_alert_from_row
from contracts.models import (
    Classification,
    Event,
    EventCategory,
    Incident,
    IncidentRun,
    IncidentStatus,
    LiveAlert,
    PcIncidentSummary,
)
from ingest.wazuh import POSTURE_GROUPS

OPEN_STATUSES = (IncidentStatus.QUEUED.value, IncidentStatus.LOW_PRIORITY.value)
HISTORY_LIMIT = 2000
GROUP_WINDOW = timedelta(minutes=60)
MAX_INCIDENT_SPAN = timedelta(hours=24)


def ungrouped_alerts(engine: Engine, limit: int = 500) -> list[LiveAlert]:
    statement = (
        select(*LIVE_COLUMNS)
        .where(wazuh_alerts.c.grouped_at.is_(None))
        .order_by(wazuh_alerts.c.alert_time, wazuh_alerts.c.wazuh_id)
        .limit(limit)
    )
    with engine.connect() as connection:
        return [live_alert_from_row(row) for row in connection.execute(statement)]


def _mark_statement(wazuh_id: str, incident_id: str | None, now: datetime) -> Update:
    return (
        update(wazuh_alerts)
        .where(wazuh_alerts.c.wazuh_id == wazuh_id)
        .values(grouped_at=now, incident_id=incident_id)
    )


def mark_grouped(engine: Engine, wazuh_id: str, incident_id: str | None, now: datetime) -> None:
    with engine.begin() as connection:
        connection.execute(_mark_statement(wazuh_id, incident_id, now))


def find_open_incident(
    engine: Engine, host: str, group_key: str, at: datetime
) -> PcIncidentSummary | None:
    statement = (
        select(incidents.c.incident, incidents.c.alert_count, incidents.c.max_level)
        .where(
            incidents.c.host == host,
            incidents.c.group_key == group_key,
            incidents.c.status.in_(OPEN_STATUSES),
            incidents.c.last_alert_at >= at - GROUP_WINDOW,
            incidents.c.first_alert_at <= at + GROUP_WINDOW,
            incidents.c.first_alert_at >= at - MAX_INCIDENT_SPAN,
            incidents.c.last_alert_at <= at + MAX_INCIDENT_SPAN,
        )
        .order_by(incidents.c.last_alert_at.desc())
        .limit(1)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).first()
    if row is None:
        return None
    return PcIncidentSummary(
        incident=Incident.model_validate(row.incident),
        alert_count=row.alert_count,
        max_level=row.max_level,
    )


def _save_statement(
    incident: Incident,
    host: str,
    group_key: str,
    alert_count: int,
    max_level: int,
    now: datetime,
) -> Insert:
    values = {
        "host": host,
        "group_key": group_key,
        "status": incident.status.value,
        "first_alert_at": incident.window_start,
        "last_alert_at": incident.window_end,
        "max_level": max_level,
        "alert_count": alert_count,
        "incident": incident.model_copy(update={"updated_at": now}).model_dump(mode="json"),
        "updated_at": now,
    }
    return (
        insert(incidents)
        .values(incident_id=incident.incident_id, **values)
        .on_conflict_do_update(index_elements=[incidents.c.incident_id], set_=values)
    )


def save_incident(
    engine: Engine,
    incident: Incident,
    host: str,
    group_key: str,
    alert_count: int,
    max_level: int,
    now: datetime,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            _save_statement(incident, host, group_key, alert_count, max_level, now)
        )


def save_incident_and_mark(
    engine: Engine,
    incident: Incident,
    host: str,
    group_key: str,
    alert_count: int,
    max_level: int,
    wazuh_id: str,
    now: datetime,
) -> None:
    with engine.begin() as connection:
        connection.execute(
            _save_statement(incident, host, group_key, alert_count, max_level, now)
        )
        connection.execute(_mark_statement(wazuh_id, incident.incident_id, now))


def next_queued_incident(engine: Engine) -> Incident | None:
    statement = (
        select(incidents.c.incident)
        .where(incidents.c.status == IncidentStatus.QUEUED.value)
        .order_by(incidents.c.first_alert_at, incidents.c.incident_id)
        .limit(1)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).first()
    return None if row is None else Incident.model_validate(row.incident)


def set_status(engine: Engine, incident_id: str, status: IncidentStatus, now: datetime) -> None:
    with engine.begin() as connection:
        row = connection.execute(
            select(incidents.c.incident).where(incidents.c.incident_id == incident_id)
        ).first()
        if row is None:
            return
        incident = Incident.model_validate(row.incident).model_copy(
            update={"status": status, "updated_at": now}
        )
        connection.execute(
            update(incidents)
            .where(incidents.c.incident_id == incident_id)
            .values(
                status=status.value, incident=incident.model_dump(mode="json"), updated_at=now
            )
        )


def requeue(engine: Engine, incident_id: str, now: datetime) -> None:
    queued = IncidentStatus.QUEUED.value
    patch = {"status": queued, "updated_at": TypeAdapter(datetime).dump_python(now, mode="json")}
    statement = (
        update(incidents)
        .where(incidents.c.incident_id == incident_id)
        .values(
            status=queued,
            run=null(),
            incident=incidents.c.incident.op("||")(type_coerce(patch, JSONB)),
            updated_at=now,
        )
    )
    with engine.begin() as connection:
        connection.execute(statement)


def incident_status(engine: Engine, incident_id: str) -> IncidentStatus | None:
    with engine.connect() as connection:
        value = connection.execute(
            select(incidents.c.status).where(incidents.c.incident_id == incident_id)
        ).scalar_one_or_none()
    return None if value is None else IncidentStatus(value)


def incident_alerts(engine: Engine, incident_id: str) -> list[LiveAlert]:
    statement = (
        select(*LIVE_COLUMNS)
        .where(wazuh_alerts.c.incident_id == incident_id)
        .order_by(wazuh_alerts.c.alert_time, wazuh_alerts.c.wazuh_id)
    )
    with engine.connect() as connection:
        return [live_alert_from_row(row) for row in connection.execute(statement)]


def _host_window(host: str, start: datetime, end: datetime) -> list[ColumnElement[bool]]:
    return [
        wazuh_alerts.c.agent_name == host,
        wazuh_alerts.c.alert_time >= start,
        wazuh_alerts.c.alert_time <= end,
    ]


NEWEST_FIRST = (wazuh_alerts.c.alert_time.desc(), wazuh_alerts.c.wazuh_id.desc())
IS_POSTURE = func.coalesce(
    wazuh_alerts.c.payload["rule"]["groups"].has_any(
        cast(array(sorted(POSTURE_GROUPS)), ARRAY(Text))
    ),
    False,
)


def host_alerts(
    engine: Engine,
    host: str,
    start: datetime,
    end: datetime,
    limit: int = HISTORY_LIMIT,
    include_posture: bool = False,
) -> list[LiveAlert]:
    conditions = _host_window(host, start, end)
    if not include_posture:
        conditions.append(~IS_POSTURE)
    statement = select(*LIVE_COLUMNS).where(*conditions).order_by(*NEWEST_FIRST).limit(limit)
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return [live_alert_from_row(row) for row in reversed(rows)]


def host_auth_events(
    engine: Engine, host: str, start: datetime, end: datetime, limit: int = HISTORY_LIMIT
) -> list[Event]:
    statement = (
        select(wazuh_alerts.c.event)
        .where(
            *_host_window(host, start, end),
            wazuh_alerts.c.event["category"].astext == EventCategory.AUTHENTICATION.value,
        )
        .order_by(*NEWEST_FIRST)
        .limit(limit)
    )
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return [Event.model_validate(row.event) for row in reversed(rows)]


def rule_sample(
    engine: Engine,
    host: str,
    rule_id: str,
    preferred_alert_ids: list[str],
    since: datetime,
    until: datetime | None = None,
) -> LiveAlert | None:
    own = wazuh_alerts.c.alert["alert_id"].astext.in_(preferred_alert_ids)
    statement = (
        select(*LIVE_COLUMNS)
        .where(
            wazuh_alerts.c.agent_name == host,
            wazuh_alerts.c.rule_id == rule_id,
            or_(
                own,
                and_(
                    wazuh_alerts.c.alert_time >= since,
                    wazuh_alerts.c.alert_time <= until if until else true(),
                ),
            ),
        )
        .order_by(own.desc(), *NEWEST_FIRST)
        .limit(1)
    )
    with engine.connect() as connection:
        row = connection.execute(statement).first()
    return None if row is None else live_alert_from_row(row)


def rule_count(engine: Engine, host: str, rule_id: str, start: datetime, end: datetime) -> int:
    statement = (
        select(func.count())
        .select_from(wazuh_alerts)
        .where(
            wazuh_alerts.c.agent_name == host,
            wazuh_alerts.c.rule_id == rule_id,
            wazuh_alerts.c.alert_time >= start,
            wazuh_alerts.c.alert_time < end,
        )
    )
    with engine.connect() as connection:
        return connection.execute(statement).scalar_one()


def save_run(engine: Engine, run: IncidentRun, now: datetime) -> None:
    statement = (
        update(incidents)
        .where(incidents.c.incident_id == run.incident.incident_id)
        .values(
            run=run.model_dump(mode="json"),
            status=run.incident.status.value,
            incident=run.incident.model_dump(mode="json"),
            updated_at=now,
        )
    )
    with engine.begin() as connection:
        connection.execute(statement)


def get_run(engine: Engine, incident_id: str) -> IncidentRun | None:
    with engine.connect() as connection:
        value = connection.execute(
            select(incidents.c.run).where(incidents.c.incident_id == incident_id)
        ).scalar_one_or_none()
    return None if value is None else IncidentRun.model_validate(value)


def incident_summaries(engine: Engine, limit: int = 100) -> list[PcIncidentSummary]:
    verdict = incidents.c.run["verdict"]
    statement = (
        select(
            incidents.c.incident,
            incidents.c.alert_count,
            incidents.c.max_level,
            verdict["classification"].astext.label("classification"),
            func.coalesce(func.jsonb_array_length(verdict["recommendations"]), 0).label("advice"),
        )
        .order_by(incidents.c.last_alert_at.desc(), incidents.c.incident_id)
        .limit(limit)
    )
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return [
        PcIncidentSummary(
            incident=Incident.model_validate(row.incident),
            alert_count=row.alert_count,
            max_level=row.max_level,
            classification=Classification(row.classification) if row.classification else None,
            recommendation_count=row.advice,
        )
        for row in rows
    ]


def queue_length(engine: Engine) -> int:
    statement = (
        select(func.count())
        .select_from(incidents)
        .where(incidents.c.status == IncidentStatus.QUEUED.value)
    )
    with engine.connect() as connection:
        return connection.execute(statement).scalar_one()


def unfinished_incidents(engine: Engine) -> list[str]:
    statement = (
        select(incidents.c.incident_id)
        .where(
            incidents.c.status == IncidentStatus.INVESTIGATING.value, incidents.c.run.is_(None)
        )
        .order_by(incidents.c.incident_id)
    )
    with engine.connect() as connection:
        return list(connection.execute(statement).scalars())


class StoreHistory:
    def __init__(
        self, engine: Engine, host: str, since: datetime, until: datetime | None = None
    ) -> None:
        self._engine = engine
        self._host = host
        self._since = since
        self._until = until

    def alerts(
        self, start: datetime, end: datetime, include_posture: bool = False
    ) -> list[LiveAlert]:
        return host_alerts(
            self._engine, self._host, start, end, include_posture=include_posture
        )

    def rule_count(self, rule_id: str, start: datetime, end: datetime) -> int:
        return rule_count(self._engine, self._host, rule_id, start, end)

    def rule_sample(self, rule_id: str, preferred_alert_ids: list[str]) -> LiveAlert | None:
        return rule_sample(
            self._engine, self._host, rule_id, preferred_alert_ids, self._since, self._until
        )
