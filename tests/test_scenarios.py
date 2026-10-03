from __future__ import annotations

import pytest
import yaml

from contracts.models import Classification, Scenario
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log
from pipeline.run import INVENTORY_FILE, RULES_DIR, load_inventory
from tests.conftest import REPO

CASES = sorted(p.parent.name for p in (REPO / "lab" / "scenarios").glob("*/scenario.yml"))


def test_there_are_four_attack_benign_pairs() -> None:
    assert CASES == [f"s{n}_{kind}" for n in range(1, 5) for kind in ("attack", "benign")]


@pytest.mark.parametrize("case_id", CASES)
def test_each_case_yields_one_brute_force_incident(case_id: str) -> None:
    folder = REPO / "lab" / "scenarios" / case_id
    lines = (folder / "auth.log").read_text(encoding="utf-8").splitlines()
    events = parse_auth_log(lines, case_id)
    alerts = detect(events, load_rules(RULES_DIR), case_id)
    [incident] = correlate(alerts, events, load_inventory(INVENTORY_FILE), case_id)
    names = {a.rule_name for a in alerts if a.alert_id in incident.alert_ids}
    assert "SSH password brute force" in names
    scenario = Scenario.model_validate(yaml.safe_load((folder / "scenario.yml").read_text()))
    expected = Classification.MALICIOUS if case_id.endswith("attack") else Classification.BENIGN
    assert scenario.expected_classification is expected
    assert scenario.required_evidence


@pytest.mark.parametrize("case_id", ["s2_benign", "s4_benign"])
def test_benign_changes_cover_the_incident(case_id: str) -> None:
    folder = REPO / "lab" / "scenarios" / case_id
    scenario = Scenario.model_validate(yaml.safe_load((folder / "scenario.yml").read_text()))
    events = parse_auth_log((folder / "auth.log").read_text().splitlines(), case_id)
    alerts = detect(events, load_rules(RULES_DIR), case_id)
    [incident] = correlate(alerts, events, load_inventory(INVENTORY_FILE), case_id)
    [change] = scenario.changes
    assert change.start <= incident.window_start and change.end >= incident.window_end
