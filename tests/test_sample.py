from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.engine import Engine

from backend.app.findings import open_findings, set_advice, upsert_findings
from backend.app.incidents import incident_summaries, save_run
from backend.app.store import insert_alert
from contracts.models import IncidentRun, IncidentStatus, PcSample, Recommendation
from pipeline import sample as sample_module
from pipeline.grouping import group_new_alerts
from pipeline.sample import NOTE, SampleLeak, build_sample, main, sanitize_sample
from tests.conftest import REPO, make_finding, make_wazuh_alert

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)
RUN = IncidentRun.model_validate_json(
    (REPO / "contracts" / "fixtures" / "incident_run.json").read_text(encoding="utf-8")
)
BURST = {
    "rule_id": "60204",
    "level": 10,
    "techniques": ["T1110"],
    "description": "Multiple Windows Logon Failures",
}
SCRIPT = r"powershell.exe -File C:\Users\jane.doe\x.ps1"
FIXTURE = PcSample.model_validate_json(
    (REPO / "contracts" / "fixtures" / "pc_sample.json").read_text(encoding="utf-8")
)


class Untouched:
    def learn(self, data: Any) -> None:
        return None

    def apply(self, data: Any) -> Any:
        return data


def _advice(finding_id: str, priority: int) -> Recommendation:
    return Recommendation(
        title="Update it", priority=priority, steps=["Update."], finding_ids=[finding_id]
    )


@pytest.fixture
def recorded(db: Engine) -> Engine:
    stored = [
        make_wazuh_alert("s.1", 1, user="jane.doe", command_line=SCRIPT),
        make_wazuh_alert("s.2", 2),
        make_wazuh_alert("s.3", 3, **BURST),
    ]
    for live, payload in stored:
        insert_alert(db, live, payload)
    assert group_new_alerts(db, NOW) == 3
    burst = next(s for s in incident_summaries(db) if s.max_level == 10)
    closed = burst.incident.model_copy(update={"status": IncidentStatus.CLOSED_BENIGN})
    save_run(db, RUN.model_copy(update={"incident": closed}), NOW)
    found = [
        make_finding("a", priority=70, cve="CVE-2026-0001", package="Alpha"),
        make_finding("b", priority=40, cve="CVE-2026-0002", package="Beta"),
    ]
    assert upsert_findings(db, "my-pc", found, NOW) == (2, 0)
    for finding in open_findings(db, "my-pc"):
        set_advice(db, finding.finding_id, _advice(finding.finding_id, finding.priority), "m", NOW)
    return db


def test_build_sample_reads_the_database(recorded: Engine) -> None:
    sample = build_sample(recorded, NOW)
    assert len(sample.feed.alerts) == 3
    assert [s.incident.incident_id for s in sample.feed.incidents] == [
        s.incident.incident_id for s in incident_summaries(recorded)
    ]
    assert len(sample.feed.incidents) == 2
    assert sample.assessment is not None
    assert len(sample.assessment.findings) == 2
    assert len(sample.assessment.recommendations) == 2
    [run] = sample.runs
    assert run.incident.incident_id == next(
        s.incident.incident_id
        for s in sample.feed.incidents
        if s.classification is RUN.verdict.classification
    )
    assert sample.created_at == NOW
    assert sample.note == NOTE
    assert PcSample.model_validate_json(sample.model_dump_json()) == sample


def test_status_is_fixed_text_and_counts_are_real(recorded: Engine) -> None:
    status = build_sample(recorded, NOW).feed.status
    assert status.checked_at == NOW
    for state in (status.wazuh_api, status.backfill, status.model, status.sync):
        assert state.reachable is True
        assert state.detail == "Recorded sample."
    assert status.queue_length == 0
    assert status.alert_count == 3
    assert status.last_alert_at == datetime(2026, 9, 27, 9, 3, tzinfo=UTC)


def test_limits_cut_every_part_of_the_sample(recorded: Engine) -> None:
    sample = build_sample(recorded, NOW, alerts=2, incidents=1, findings=1, runs=0)
    assert len(sample.feed.alerts) == 2
    assert len(sample.feed.incidents) == 1
    assert sample.feed.status.alert_count == 3
    assert sample.runs == []
    assert sample.assessment is not None
    assert [f.priority for f in sample.assessment.findings] == [70, 40]
    assert len(sample.assessment.recommendations) == 2


def test_investigated_incidents_are_kept_when_newer_noise_fills_the_list(db: Engine) -> None:
    stored = [
        make_wazuh_alert("n.1", 1),
        make_wazuh_alert("n.2", 2, **BURST),
        make_wazuh_alert("n.3", 30, rule_id="60106", techniques=["T1078"]),
        make_wazuh_alert("n.4", 40, rule_id="60107", techniques=["T1021"]),
    ]
    for live, payload in stored:
        insert_alert(db, live, payload)
    assert group_new_alerts(db, NOW) == 4
    summaries = incident_summaries(db)
    oldest = summaries[-1].incident
    closed = oldest.model_copy(update={"status": IncidentStatus.CLOSED_BENIGN})
    save_run(db, RUN.model_copy(update={"incident": closed}), NOW)
    sample = build_sample(db, NOW, incidents=2, runs=1)
    kept = [s.incident.incident_id for s in sample.feed.incidents]
    assert len(kept) == 2
    assert oldest.incident_id in kept
    assert kept[0] == summaries[0].incident.incident_id
    [run] = sample.runs
    assert run.incident.incident_id == oldest.incident_id


def test_every_fixed_program_keeps_its_top_weak_spot_and_fix(db: Engine) -> None:
    found = [
        make_finding("a1", priority=90, cve="CVE-2026-0011", package="Alpha"),
        make_finding("a2", priority=85, cve="CVE-2026-0012", package="Alpha"),
        make_finding("a3", priority=80, cve="CVE-2026-0013", package="Alpha"),
        make_finding("b1", priority=40, cve="CVE-2026-0021", package="Beta"),
        make_finding("b2", priority=30, cve="CVE-2026-0022", package="Beta"),
    ]
    assert upsert_findings(db, "my-pc", found, NOW) == (5, 0)
    leads = {"a1", "b1"}
    for finding in open_findings(db, "my-pc"):
        if finding.key in leads:
            advice = _advice(finding.finding_id, finding.priority)
            set_advice(db, finding.finding_id, advice, "m", NOW)
    view = build_sample(db, NOW, findings=2).assessment
    assert view is not None
    assert [f.key for f in view.findings] == ["a1", "a2", "b1"]
    assert len(view.recommendations) == 2


def test_an_empty_database_gives_an_empty_sample(db: Engine) -> None:
    sample = build_sample(db, NOW)
    assert sample.feed.alerts == []
    assert sample.feed.incidents == []
    assert sample.feed.status.alert_count == 0
    assert sample.feed.status.last_alert_at is None
    assert sample.assessment is None
    assert sample.runs == []


def test_sanitizing_removes_the_terms(recorded: Engine) -> None:
    sample = build_sample(recorded, NOW)
    assert "jane" in sample.model_dump_json()
    clean = sanitize_sample(sample, ["jane"])
    assert "jane" not in clean.model_dump_json().lower()
    [script] = [a for a in clean.feed.alerts if a.event.process.command_line]
    assert script.event.user == "user1"
    assert script.event.process.command_line == r"powershell.exe -File C:\Users\user1\x.ps1"
    assert clean.created_at == NOW
    assert clean.note == NOTE
    assert len(clean.runs) == 1


def test_sanitizing_names_the_terms_that_survive(recorded: Engine) -> None:
    sample = build_sample(recorded, NOW)
    with pytest.raises(SampleLeak, match="Logon Failure"):
        sanitize_sample(sample, ["jane", "Logon Failure"])


def test_main_needs_the_forbidden_terms(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("SENTINEL_FORBIDDEN_TERMS", raising=False)
    monkeypatch.setattr(
        sample_module, "get_engine", lambda: pytest.fail("the database must not be opened")
    )
    out = tmp_path / "pc-sample.json"
    assert main(["--out", str(out)]) == 2
    assert main([]) == 2
    assert "SENTINEL_FORBIDDEN_TERMS" in capsys.readouterr().out
    assert not out.exists()


def test_main_writes_the_sanitized_sample(
    recorded: Engine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", "jane")
    monkeypatch.setattr(sample_module, "get_engine", lambda: recorded)
    out = tmp_path / "nested" / "pc-sample.json"
    assert main(["--out", str(out)]) == 0
    written = out.read_text(encoding="utf-8")
    assert written.endswith("}\n")
    assert "\r" not in written
    assert "jane" not in written.lower()
    assert len(PcSample.model_validate_json(written).feed.alerts) == 3


def test_main_writes_nothing_when_a_term_survives(
    recorded: Engine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", "jane,Logon Failure")
    monkeypatch.setattr(sample_module, "get_engine", lambda: recorded)
    out = tmp_path / "pc-sample.json"
    assert main(["--out", str(out)]) == 3
    printed = capsys.readouterr().out
    assert "Logon Failure" in printed
    assert "Nothing was written." in printed
    assert not out.exists()


def test_sanitizing_replaces_the_real_host_in_the_weak_spots(db: Engine) -> None:
    host = "DESKTOP-9QXZ7"
    assert upsert_findings(db, host, [make_finding("a", cve="CVE-2026-0001")], NOW) == (1, 0)
    [finding] = open_findings(db, host)
    advice = Recommendation(
        title="Update Alpha",
        priority=finding.priority,
        steps=[f"Restart {host} after the update."],
        finding_ids=[finding.finding_id],
    )
    set_advice(db, finding.finding_id, advice, "m", NOW)
    sample = build_sample(db, NOW)
    assert sample.assessment is not None and sample.assessment.host == host
    clean = sanitize_sample(sample, [host])
    assert host.lower() not in clean.model_dump_json().lower()
    assert clean.assessment is not None
    assert clean.assessment.host != host
    [kept] = clean.assessment.recommendations
    assert kept.steps == [f"Restart {clean.assessment.host} after the update."]


@pytest.mark.parametrize(
    ("term", "hidden"),
    [
        ("Jane Doe", "Jane%20Doe"),
        ("Jane Doe", "jane_doe"),
        ("Jane Doe", "jane.doe"),
        ("Jane Doe", "jane+doe"),
        ("Jane Doe", "JANE%2520DOE"),
        ("Jane Doe", r"Jane Doe"),
        ("Jane Doe", r"Jane Doe"),
        ("jane.doe", "Jane Doe"),
        ("jane", "%6Aane"),
    ],
)
def test_a_term_hidden_in_another_form_still_stops_the_export(
    monkeypatch: pytest.MonkeyPatch, term: str, hidden: str
) -> None:
    monkeypatch.setattr(sample_module, "Sanitizer", Untouched)
    sample = FIXTURE.model_copy(update={"note": f"Opened {hidden} yesterday."})
    with pytest.raises(SampleLeak, match=term):
        sanitize_sample(sample, [term])


def test_a_term_hidden_in_a_dictionary_key_stops_the_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sample_module, "Sanitizer", Untouched)
    data = FIXTURE.model_dump(mode="json")
    data["feed"]["alerts"][0]["event"]["raw"] = {"Jane%20Doe": 1}
    with pytest.raises(SampleLeak, match="Jane Doe"):
        sanitize_sample(PcSample.model_validate(data), ["Jane Doe"])


def test_a_sample_without_the_term_in_any_form_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sample_module, "Sanitizer", Untouched)
    sample = FIXTURE.model_copy(update={"note": "Opened Jane yesterday, and Doe the day after."})
    assert sanitize_sample(sample, ["Jane Doe"]).note == sample.note
