from __future__ import annotations

import os
from functools import cache

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine
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
)


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Start the stack with docker compose.")
    return url


@cache
def get_engine() -> Engine:
    return create_engine(database_url(), pool_pre_ping=True)
