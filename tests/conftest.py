from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from contracts.models import Alert, Event, Incident, Inventory
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log

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
    inventory = Inventory.model_validate(yaml.safe_load(INVENTORY_FILE.read_text(encoding="utf-8")))
    events = parse_auth_log(S1_LOG.read_text(encoding="utf-8").splitlines(), case_id="s1_attack")
    alerts = detect(events, load_rules(REPO / "detection" / "rules"), case_id="s1_attack")
    [incident] = correlate(alerts, events, inventory, case_id="s1_attack")
    return S1Case(events=events, alerts=alerts, incident=incident, inventory=inventory)
