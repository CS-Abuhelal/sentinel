from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.engine import Engine

from backend.app.findings import (
    ADVICE_FAILED,
    ADVICE_READY,
    advice_states,
    advice_unit,
    assessment,
    finding_hosts,
    last_successful_sync,
    next_finding_to_advise,
    open_findings,
    record_sync,
    related_alert_count,
    set_advice,
    unit_findings,
    upsert_findings,
)
from backend.app.store import insert_alert
from contracts.models import FindingKind, FindingStatus, Recommendation
from tests.conftest import make_finding, make_wazuh_alert

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def _advice(finding_id: str) -> Recommendation:
    return Recommendation(
        title="Update it", priority=50, steps=["Update."], finding_ids=[finding_id]
    )


def test_upsert_keeps_identity_and_resolves_what_disappeared(db: Engine) -> None:
    first = [make_finding("a", priority=70, days=5), make_finding("b", priority=40)]
    assert upsert_findings(db, "my-pc", first, NOW) == (2, 0)
    [a_before, b_before] = open_findings(db, "my-pc")
    again = [make_finding("a", priority=75, days=0)]
    assert upsert_findings(db, "my-pc", again, NOW + timedelta(hours=6)) == (1, 1)
    [a_after] = open_findings(db, "my-pc")
    assert a_after.finding_id == a_before.finding_id
    assert a_after.first_seen == a_before.first_seen
    assert a_after.priority == 75
    assert a_after.status is FindingStatus.OPEN
    assert b_before.finding_id not in {f.finding_id for f in open_findings(db, "my-pc")}
    assert upsert_findings(db, "my-pc", again, NOW + timedelta(hours=12)) == (1, 0)


def test_open_findings_are_sorted_and_filtered(db: Engine) -> None:
    upsert_findings(
        db,
        "my-pc",
        [
            make_finding("low", priority=20, package="7-Zip"),
            make_finding("check", priority=70, kind=FindingKind.CONFIGURATION, days=3),
            make_finding("vuln", priority=70, package="Google Chrome"),
            make_finding("top", priority=96, package="Google Chrome", days=1),
        ],
        NOW,
    )
    assert [f.key for f in open_findings(db, "my-pc")] == ["top", "vuln", "check", "low"]
    assert [f.key for f in open_findings(db, "my-pc", "chrome")] == ["top", "vuln"]
    assert open_findings(db, "other-pc") == []


def test_hosts_and_the_next_finding_to_advise(db: Engine) -> None:
    upsert_findings(db, "my-pc", [make_finding(f"k{n}", priority=90 - n) for n in range(12)], NOW)
    upsert_findings(db, "tiny-pc", [make_finding("only", priority=99, host="tiny-pc")], NOW)
    assert finding_hosts(db) == ["my-pc", "tiny-pc"]
    seen = []
    for _ in range(11):
        finding = next_finding_to_advise(db, top=10)
        assert finding is not None
        seen.append(finding.key)
        set_advice(db, finding.finding_id, _advice(finding.finding_id), "test", NOW)
    assert seen == [f"k{n}" for n in range(10)] + ["only"]
    assert next_finding_to_advise(db, top=10) is None


def test_units_group_the_same_package_case_insensitively(db: Engine) -> None:
    upsert_findings(
        db,
        "my-pc",
        [
            make_finding("a", priority=90, package="MongoDB", cve="CVE-2026-1"),
            make_finding("b", priority=80, package="mongodb", cve="CVE-2026-2"),
            make_finding("c", priority=70, package="Steam", cve="CVE-2026-3"),
        ],
        NOW,
    )
    [a, b, c] = open_findings(db, "my-pc")
    assert advice_unit(a) == advice_unit(b) == "package:mongodb"
    assert advice_unit(c) == "package:steam"


def test_next_finding_to_advise_returns_each_unit_lead_once(db: Engine) -> None:
    upsert_findings(
        db,
        "my-pc",
        [
            make_finding("a", priority=90, package="MongoDB", cve="CVE-2026-1"),
            make_finding("b", priority=80, package="MongoDB", cve="CVE-2026-2"),
            make_finding("c", priority=70, package="Steam", cve="CVE-2026-3"),
        ],
        NOW,
    )
    [a, _b, c] = open_findings(db, "my-pc")
    lead = next_finding_to_advise(db, top=10)
    assert lead is not None and lead.finding_id == a.finding_id
    set_advice(db, a.finding_id, _advice(a.finding_id), "test", NOW)
    lead = next_finding_to_advise(db, top=10)
    assert lead is not None and lead.finding_id == c.finding_id


def test_top_counts_units_not_findings(db: Engine) -> None:
    findings = []
    priority = 99
    for package in ("MongoDB", "Steam", "Code"):
        for n in range(4):
            findings.append(
                make_finding(
                    f"{package}-{n}", priority=priority, package=package,
                    cve=f"CVE-2026-{package}-{n}",
                )
            )
            priority -= 1
    upsert_findings(db, "my-pc", findings, NOW)
    leads = set()
    for _ in range(3):
        finding = next_finding_to_advise(db, top=2)
        if finding is None:
            break
        leads.add(finding.finding_id)
        set_advice(db, finding.finding_id, _advice(finding.finding_id), "test", NOW)
    assert len(leads) == 2
    assert next_finding_to_advise(db, top=2) is None


def test_unit_findings_returns_the_whole_unit_in_order(db: Engine) -> None:
    upsert_findings(
        db,
        "my-pc",
        [
            make_finding("a", priority=90, package="MongoDB", cve="CVE-2026-1"),
            make_finding("c", priority=70, package="Steam", cve="CVE-2026-3"),
            make_finding("b", priority=80, package="mongodb", cve="CVE-2026-2"),
        ],
        NOW,
    )
    [a, b, c] = open_findings(db, "my-pc")
    assert [f.key for f in unit_findings(db, a)] == ["a", "b"]
    assert [f.key for f in unit_findings(db, c)] == ["c"]


def test_advice_is_stored_and_failed_advice_is_retried_after_a_sync(db: Engine) -> None:
    upsert_findings(db, "my-pc", [make_finding("a", priority=80), make_finding("b")], NOW)
    [a, b] = open_findings(db, "my-pc")
    set_advice(db, a.finding_id, _advice(a.finding_id), "ollama:qwen3:14b", NOW)
    set_advice(db, b.finding_id, None, "ollama:qwen3:14b", NOW)
    assert advice_states(db, "my-pc") == {a.finding_id: ADVICE_READY, b.finding_id: ADVICE_FAILED}
    upsert_findings(db, "my-pc", [make_finding("a", priority=80), make_finding("b")], NOW)
    assert advice_states(db, "my-pc") == {a.finding_id: ADVICE_READY}


def test_assessment_combines_findings_advice_and_the_last_sync(db: Engine) -> None:
    assert assessment(db, "my-pc", NOW) is None
    upsert_findings(db, "my-pc", [make_finding("a", priority=80), make_finding("b")], NOW)
    [a, _] = open_findings(db, "my-pc")
    set_advice(db, a.finding_id, _advice(a.finding_id), "ollama:qwen3:14b", NOW)
    record_sync(db, NOW - timedelta(minutes=2), NOW - timedelta(minutes=1), True, None, 2)
    record_sync(db, NOW, NOW, False, "indexer down", 0)
    view = assessment(db, "my-pc", NOW)
    assert view is not None
    assert [f.key for f in view.findings] == ["a", "b"]
    assert all(f.raw == {} for f in view.findings)
    assert [r.finding_ids for r in view.recommendations] == [[a.finding_id]]
    assert view.synced_at == NOW - timedelta(minutes=1)
    assert view.model_name == "ollama:qwen3:14b"
    assert last_successful_sync(db) == NOW - timedelta(minutes=1)


def test_related_alerts_match_the_package_and_skip_posture(db: Engine) -> None:
    hit, payload = make_wazuh_alert("30.1", 1, process="C:\\Program Files\\7-Zip\\7z.exe")
    insert_alert(db, hit, payload)
    posture, payload = make_wazuh_alert(
        "30.2", 2, groups=["sca"], process="C:\\Program Files\\7-Zip\\7z.exe"
    )
    insert_alert(db, posture, payload)
    other, payload = make_wazuh_alert("30.3", 3)
    insert_alert(db, other, payload)
    since = datetime(2026, 9, 27, 0, 0, tzinfo=UTC)
    assert related_alert_count(db, "my-pc", "7-Zip", since) == 1
    assert related_alert_count(db, "my-pc", "7-zip", since + timedelta(days=1)) == 0
    assert related_alert_count(db, "other-pc", "7-Zip", since) == 0


def test_package_filters_match_wildcards_literally(db: Engine) -> None:
    upsert_findings(
        db,
        "my-pc",
        [
            make_finding("plain", package="7-Zip"),
            make_finding("under", package="node_modules/lodash"),
            make_finding("pct", package="100% Tool"),
        ],
        NOW,
    )
    assert [f.key for f in open_findings(db, "my-pc", "_")] == ["under"]
    assert [f.key for f in open_findings(db, "my-pc", "%")] == ["pct"]
    assert related_alert_count(db, "my-pc", "%", datetime(2026, 9, 1, tzinfo=UTC)) == 0
