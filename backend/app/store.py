from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine

from backend.app.db import wazuh_alerts
from contracts.models import Alert, Event, LiveAlert

LIVE_COLUMNS = (
    wazuh_alerts.c.wazuh_id,
    wazuh_alerts.c.received_at,
    wazuh_alerts.c.level,
    wazuh_alerts.c.event,
    wazuh_alerts.c.alert,
)


def live_alert_from_row(row: Any) -> LiveAlert:
    return LiveAlert(
        wazuh_id=row.wazuh_id,
        received_at=row.received_at,
        level=row.level,
        event=Event.model_validate(row.event),
        alert=Alert.model_validate(row.alert),
    )


def insert_alert(engine: Engine, live: LiveAlert, payload: dict[str, Any]) -> bool:
    statement = (
        insert(wazuh_alerts)
        .values(
            wazuh_id=live.wazuh_id,
            alert_time=live.event.timestamp,
            received_at=live.received_at,
            agent_name=live.event.host,
            rule_id=live.alert.rule_id,
            level=live.level,
            payload=payload,
            event=live.event.model_dump(mode="json"),
            alert=live.alert.model_dump(mode="json"),
        )
        .on_conflict_do_nothing(index_elements=[wazuh_alerts.c.wazuh_id])
    )
    with engine.begin() as connection:
        result = connection.execute(statement, execution_options={"preserve_rowcount": True})
        return result.rowcount == 1


def latest_alerts(engine: Engine, limit: int) -> list[LiveAlert]:
    statement = (
        select(*LIVE_COLUMNS)
        .order_by(wazuh_alerts.c.alert_time.desc(), wazuh_alerts.c.wazuh_id.desc())
        .limit(limit)
    )
    with engine.connect() as connection:
        return [live_alert_from_row(row) for row in connection.execute(statement)]


def alert_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return connection.execute(select(func.count()).select_from(wazuh_alerts)).scalar_one()


def newest_alert_time(engine: Engine) -> datetime | None:
    with engine.connect() as connection:
        return connection.execute(select(func.max(wazuh_alerts.c.alert_time))).scalar_one()
