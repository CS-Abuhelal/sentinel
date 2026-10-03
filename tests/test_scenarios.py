from __future__ import annotations

import pytest
import yaml

from agent.single_shot import bundle_queries
from agent.tools.base import ToolContext
from agent.tools.change_windows import ChangeWindowsParams, change_windows
from agent.tools.source_ip_history import SourceIpHistoryParams, source_ip_history
from contracts.models import Classification, EntityType, Event, Incident, Scenario
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log
from pipeline.run import INVENTORY_FILE, RULES_DIR, load_inventory
from tests.conftest import REPO

CASES = sorted(p.parent.name for p in (REPO / "lab" / "scenarios").glob("*/scenario.yml"))


def load_case(case_id: str) -> tuple[Scenario, list[Event], Incident]:
    folder = REPO / "lab" / "scenarios" / case_id
    scenario = Scenario.model_validate(
        yaml.safe_load((folder / "scenario.yml").read_text(encoding="utf-8"))
    )
    lines = (folder / "auth.log").read_text(encoding="utf-8").splitlines()
    events = parse_auth_log(lines, case_id)
    alerts = detect(events, load_rules(RULES_DIR), case_id)
    [incident] = correlate(alerts, events, load_inventory(INVENTORY_FILE), case_id)
    return scenario, events, incident


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
    scenario = Scenario.model_validate(
        yaml.safe_load((folder / "scenario.yml").read_text(encoding="utf-8"))
    )
    expected = Classification.MALICIOUS if case_id.endswith("attack") else Classification.BENIGN
    assert scenario.expected_classification is expected
    assert scenario.required_evidence


@pytest.mark.parametrize("case_id", CASES)
def test_each_log_is_in_time_order(case_id: str) -> None:
    lines = (REPO / "lab" / "scenarios" / case_id / "auth.log").read_text(encoding="utf-8")
    stamps = [line.split(" ", 1)[0] for line in lines.splitlines()]
    assert stamps == sorted(stamps)


@pytest.mark.parametrize("case_id", ["s2_benign", "s4_benign"])
def test_benign_changes_cover_the_incident(case_id: str) -> None:
    scenario, _, incident = load_case(case_id)
    [change] = scenario.changes
    assert change.start <= incident.window_start and change.end >= incident.window_end


def test_the_s4_attack_decoy_covers_the_time_and_names_the_host_but_not_the_attack() -> None:
    scenario, _, incident = load_case("s4_attack")
    [change] = scenario.changes
    assert change.change_id == "CHG-2060"
    assert change.title == "Patch web server packages on victim-web-01"
    assert change.hosts == ["victim-web-01"]
    assert change.accounts == ["svc_backup"]
    assert change.source_ips == []
    assert change.start <= incident.window_start and change.end >= incident.window_end
    named = {entity.entity_type: entity.value for entity in incident.entities}
    assert named[EntityType.ACCOUNT] == "jdoe"
    assert named[EntityType.IP_ADDRESS] == "198.51.100.77"
    assert "jdoe" not in change.accounts
    assert "198.51.100.77" not in change.source_ips


def test_the_s4_attack_decoy_reaches_the_single_call_and_an_unscoped_agent_lookup() -> None:
    scenario, events, incident = load_case("s4_attack")
    context = ToolContext(incident=incident, events=events, changes=scenario.changes)
    bundled = dict(bundle_queries(incident))["change_windows"]
    for query in (bundled, {"host": "victim-web-01"}, {}):
        found = change_windows(ChangeWindowsParams(**query), context).content["changes"]
        assert [change["change_id"] for change in found] == ["CHG-2060"], query
    by_account = change_windows(ChangeWindowsParams(account="jdoe"), context)
    assert by_account.content["changes"] == []


def test_the_s3_attack_source_logged_in_as_kpatel_within_the_last_day() -> None:
    _, events, incident = load_case("s3_attack")
    context = ToolContext(incident=incident, events=events)
    result = source_ip_history(SourceIpHistoryParams(ip="10.77.0.61", lookback_hours=24), context)
    accounts = {entry["account"]: entry for entry in result.content["accounts"]}
    assert accounts["kpatel"]["successes"] == 1
    assert accounts["kpatel"]["failures"] == 0
    assert accounts["msmith"]["failures"] == 11
    assert accounts["msmith"]["successes"] == 1
