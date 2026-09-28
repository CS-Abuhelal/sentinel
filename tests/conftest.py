from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from contracts.models import Alert, Event, Incident, Inventory, LiveAlert
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log
from ingest.wazuh import live_alert
from pipeline.run import load_inventory

REPO = Path(__file__).resolve().parents[1]
S1_LOG = REPO / "lab" / "scenarios" / "s1_attack" / "auth.log"
S1_RECORDING = REPO / "agent" / "recordings" / "s1_attack.handwritten.json"
INVENTORY_FILE = REPO / "lab" / "inventory.yml"


@dataclass(frozen=True)
class S1Case:
    events: list[Event]
    alerts: list[Alert]
    incident: Incident
    inventory: Inventory


@pytest.fixture(scope="session")
def s1() -> S1Case:
    inventory = load_inventory(INVENTORY_FILE)
    events = parse_auth_log(S1_LOG.read_text(encoding="utf-8").splitlines(), case_id="s1_attack")
    alerts = detect(events, load_rules(REPO / "detection" / "rules"), case_id="s1_attack")
    [incident] = correlate(alerts, events, inventory, case_id="s1_attack")
    return S1Case(events=events, alerts=alerts, incident=incident, inventory=inventory)


WAZUH_DATA = REPO / "tests" / "data" / "wazuh"
RECEIVED_AT = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def wazuh_payload(name: str) -> dict[str, Any]:
    return json.loads((WAZUH_DATA / f"{name}.json").read_text(encoding="utf-8"))


def make_live_alert(
    wazuh_id: str, minute: int, level: int = 5
) -> tuple[LiveAlert, dict[str, Any]]:
    payload = wazuh_payload("logon_failure")
    payload["id"] = wazuh_id
    payload["timestamp"] = f"2026-09-27T09:{minute:02d}:00.000+0000"
    payload["rule"]["level"] = level
    return live_alert(payload, received_at=RECEIVED_AT), payload


@pytest.fixture(scope="session")
def pg_engine() -> Iterator[Engine]:
    url = os.environ.get("SENTINEL_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set SENTINEL_TEST_DATABASE_URL to run the database tests.")
    config = Config(str(REPO / "backend" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture
def db(pg_engine: Engine) -> Engine:
    with pg_engine.begin() as connection:
        connection.execute(text("TRUNCATE wazuh_alerts, incidents"))
    return pg_engine


def make_wazuh_alert(
    wazuh_id: str,
    minute: int,
    *,
    level: int = 5,
    rule_id: str = "60122",
    description: str = "Logon Failure - Unknown user or bad password",
    groups: list[str] | None = None,
    techniques: list[str] | None = None,
    user: str = "sentinel-test-nobody",
    hour: int = 9,
    process: str | None = None,
    command_line: str | None = None,
    day: int = 27,
) -> tuple[LiveAlert, dict[str, Any]]:
    payload = wazuh_payload("logon_failure")
    payload["id"] = wazuh_id
    payload["timestamp"] = f"2026-09-{day:02d}T{hour:02d}:{minute:02d}:00.000+0000"
    payload["rule"]["id"] = rule_id
    payload["rule"]["level"] = level
    payload["rule"]["description"] = description
    payload["rule"]["groups"] = groups or ["windows", "windows_security", "authentication_failed"]
    payload["rule"]["mitre"]["id"] = techniques if techniques is not None else ["T1531"]
    eventdata = payload["data"]["win"]["eventdata"]
    eventdata["targetUserName"] = user
    if process is not None:
        eventdata["image"] = process
    if command_line is not None:
        eventdata["commandLine"] = command_line
    return live_alert(payload, received_at=RECEIVED_AT), payload
