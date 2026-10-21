from __future__ import annotations

import os
from functools import cache

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine

metadata = MetaData()

wazuh_alerts = Table(
    "wazuh_alerts",
    metadata,
    Column("wazuh_id", String, primary_key=True),
    Column("alert_time", DateTime(timezone=True), nullable=False, index=True),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("agent_name", String, nullable=False),
    Column("rule_id", String, nullable=False),
    Column("level", Integer, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("event", JSONB, nullable=False),
    Column("alert", JSONB, nullable=False),
    Column("incident_id", String, nullable=True),
    Column("grouped_at", DateTime(timezone=True), nullable=True, index=True),
)

incidents = Table(
    "incidents",
    metadata,
    Column("incident_id", String, primary_key=True),
    Column("host", String, nullable=False),
    Column("group_key", String, nullable=False),
    Column("status", String, nullable=False),
    Column("first_alert_at", DateTime(timezone=True), nullable=False),
    Column("last_alert_at", DateTime(timezone=True), nullable=False, index=True),
    Column("max_level", Integer, nullable=False),
    Column("alert_count", Integer, nullable=False),
    Column("incident", JSONB, nullable=False),
    Column("run", JSONB, nullable=True),
    Column("updated_at", DateTime(timezone=True), nullable=False),
    Index("ix_incidents_open", "host", "group_key", "status"),
)

findings = Table(
    "findings",
    metadata,
    Column("finding_id", String, primary_key=True),
    Column("host", String, nullable=False),
    Column("key", String, nullable=False),
    Column("kind", String, nullable=False),
    Column("status", String, nullable=False),
    Column("priority", Integer, nullable=False),
    Column("first_seen", DateTime(timezone=True), nullable=False),
    Column("last_seen", DateTime(timezone=True), nullable=False),
    Column("finding", JSONB, nullable=False),
    Column("advice", JSONB, nullable=True),
    Column("advice_state", String, nullable=True),
    Column("advice_model", String, nullable=True),
    Column("advice_at", DateTime(timezone=True), nullable=True),
    UniqueConstraint("host", "key", name="uq_findings_host_key"),
    Index("ix_findings_open", "host", "status"),
)

sync_runs = Table(
    "sync_runs",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("started_at", DateTime(timezone=True), nullable=False),
    Column("finished_at", DateTime(timezone=True), nullable=False),
    Column("ok", Boolean, nullable=False),
    Column("error", String, nullable=True),
    Column("found", Integer, nullable=False),
)


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Start the stack with docker compose.")
    return url


@cache
def get_engine() -> Engine:
    return create_engine(database_url(), pool_pre_ping=True)
