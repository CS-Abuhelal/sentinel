from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from contracts.models import (
    Classification,
    FindingKind,
    IncidentRun,
    PcSample,
    Recommendation,
)
from eval.pc_accuracy import Result, label_key, load_labels, main, render, score, states_bound
from tests.conftest import REPO

BASE = PcSample.model_validate_json(
    (REPO / "contracts" / "fixtures" / "pc_sample.json").read_text(encoding="utf-8")
)

MATCHED = "Login burst on WIN-A"
MISSED = "Odd script on WIN-A"
UNLABELLED = "Disk warning on WIN-A"


def _run(
    title: str,
    hour: int,
    classification: Classification,
    confidence: float,
    tools: list[str],
) -> IncidentRun:
    run = BASE.runs[0]
    incident = run.incident.model_copy(
        update={"title": title, "window_start": datetime(2026, 9, 1, hour, tzinfo=UTC)}
    )
    verdict = run.verdict.model_copy(
        update={"classification": classification, "confidence": confidence}
    )
    evidence = [run.evidence[0].model_copy(update={"tool_name": tool}) for tool in tools]
    return run.model_copy(update={"incident": incident, "verdict": verdict, "evidence": evidence})


def _sample() -> PcSample:
    runs = [
        _run(
            MATCHED,
            9,
            Classification.MALICIOUS,
            0.9,
            ["get_auth_history", "get_entity_context", "get_auth_history"],
        ),
        _run(MISSED, 10, Classification.MALICIOUS, 0.7, ["process_activity"]),
        _run(UNLABELLED, 11, Classification.INCONCLUSIVE, 0.4, []),
    ]
    return BASE.model_copy(update={"runs": runs})


def _key(title: str, hour: int) -> str:
    return f"{title} @ 2026-09-01T{hour:02d}:00:00+00:00"


def _labels_text() -> str:
    return (
        f'"{_key(MATCHED, 9)}":\n'
        "  expected: malicious\n"
        "  why: I was away from the PC and did not type those passwords.\n"
        f'"{_key(MISSED, 10)}":\n'
        "  expected: benign\n"
        "  why: That was my own backup script.\n"
    )


@pytest.fixture
def labels_file(tmp_path: Path) -> Path:
    path = tmp_path / "labels.yml"
    path.write_text(_labels_text(), encoding="utf-8")
    return path


def test_load_labels_keys_each_label_by_incident_and_time(labels_file: Path) -> None:
    labels = load_labels(labels_file)
    assert list(labels) == [_key(MATCHED, 9), _key(MISSED, 10)]
    assert labels[_key(MISSED, 10)].expected is Classification.BENIGN
    assert labels[_key(MISSED, 10)].why == "That was my own backup script."


def test_an_empty_labels_file_means_no_labels(tmp_path: Path) -> None:
    path = tmp_path / "labels.yml"
    path.write_text("", encoding="utf-8")
    assert load_labels(path) == {}


@pytest.mark.parametrize(
    "text",
    [
        '"a @ b":\n  expected: fine\n  why: x\n',
        '"a @ b":\n  expected: benign\n',
        '"a @ b":\n  expected: benign\n  why: x\n  extra: y\n',
        '"a @ b":\n  expected: benign\n  why: ""\n',
        '"a @ b": benign\n',
    ],
)
def test_load_labels_rejects_a_label_that_is_not_usable(tmp_path: Path, text: str) -> None:
    path = tmp_path / "labels.yml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="not usable"):
        load_labels(path)


def test_load_labels_rejects_a_list(tmp_path: Path) -> None:
    path = tmp_path / "labels.yml"
    path.write_text("- expected: benign\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mapping"):
        load_labels(path)


def test_the_label_key_is_the_title_and_the_first_alert_time() -> None:
    assert label_key(_sample().runs[0]) == _key(MATCHED, 9)


def test_score_counts_matches_misses_and_unlabelled(labels_file: Path) -> None:
    report = score(_sample(), load_labels(labels_file))
    assert [row.result for row in report.rows] == [
        Result.MATCH,
        Result.MISS,
        Result.UNLABELLED,
    ]
    assert report.labelled == 2
    assert report.matched == 1
    assert report.unlabelled == 1
    assert report.unused_labels == []


def test_score_rows_carry_what_the_table_shows(labels_file: Path) -> None:
    match, miss, unlabelled = score(_sample(), load_labels(labels_file)).rows
    assert match.incident == MATCHED
    assert match.first_alert == "2026-09-01T09:00:00+00:00"
    assert match.expected is Classification.MALICIOUS
    assert match.actual is Classification.MALICIOUS
    assert match.confidence == 0.9
    assert match.tools == ("get_auth_history", "get_entity_context")
    assert miss.expected is Classification.BENIGN
    assert miss.actual is Classification.MALICIOUS
    assert unlabelled.expected is None
    assert unlabelled.why is None
    assert unlabelled.tools == ()


def test_score_reports_labels_that_match_no_incident(labels_file: Path) -> None:
    labels = load_labels(labels_file)
    sample = _sample().model_copy(update={"runs": _sample().runs[:1]})
    assert score(sample, labels).unused_labels == [_key(MISSED, 10)]


def test_render_says_how_many_labelled_incidents_matched(labels_file: Path) -> None:
    text = render(score(_sample(), load_labels(labels_file)))
    assert "1 of 2 labelled incidents matched" in text
    assert "1 incident is not labelled and is not scored" in text


def test_render_has_a_row_per_incident(labels_file: Path) -> None:
    text = render(score(_sample(), load_labels(labels_file)))
    assert (
        "| Incident | First alert | Expected | Actual | Confidence | Tools used | Result |" in text
    )
    assert (
        f"| {MATCHED} | 2026-09-01T09:00:00+00:00 | malicious | malicious | 0.90 | "
        "get_auth_history, get_entity_context | match |"
    ) in text
    assert (
        f"| {MISSED} | 2026-09-01T10:00:00+00:00 | benign | malicious | 0.70 | "
        "process_activity | miss |"
    ) in text
    assert (
        f"| {UNLABELLED} | 2026-09-01T11:00:00+00:00 | - | inconclusive | 0.40 | - | unlabelled |"
    ) in text


def test_render_shows_the_owners_reasons_for_labelled_incidents(labels_file: Path) -> None:
    text = render(score(_sample(), load_labels(labels_file)))
    assert "That was my own backup script." in text
    assert "I was away from the PC and did not type those passwords." in text


def test_render_explains_the_measurement_without_overstating(labels_file: Path) -> None:
    text = render(score(_sample(), load_labels(labels_file)))
    assert "## How this was measured" in text
    assert "set by the owner" in text
    assert "knew what happened on the PC" in text
    assert "anecdotal" in text
    assert "2 labelled incidents" in text


def test_render_names_the_model_that_wrote_the_verdicts(labels_file: Path) -> None:
    sample = _sample()
    runs = [
        run.model_copy(update={"verdict": run.verdict.model_copy(update={"model_name": "m:1b"})})
        for run in sample.runs
    ]
    report = score(sample.model_copy(update={"runs": runs}), load_labels(labels_file))
    assert "Model: m:1b" in render(report)


def test_render_keeps_a_pipe_in_a_title_from_breaking_the_table(tmp_path: Path) -> None:
    run = _run("Odd | title", 9, Classification.BENIGN, 0.5, ["a|b"])
    text = render(score(BASE.model_copy(update={"runs": [run]}), {}))
    assert "| Odd \\| title |" in text
    assert "| a\\|b |" in text


def test_render_with_no_labels_gives_no_accuracy_number() -> None:
    text = render(score(_sample(), {}))
    assert "No incidents are labelled yet" in text
    assert "labelled incidents matched" not in text
    assert "3 incidents are not labelled" in text


def test_render_lists_labels_that_match_no_incident(labels_file: Path) -> None:
    sample = _sample().model_copy(update={"runs": _sample().runs[:1]})
    text = render(score(sample, load_labels(labels_file)))
    assert "did not match any incident" in text
    assert _key(MISSED, 10) in text


def _vulnerable(sample: PcSample, finding_id: str, remediation: str | None) -> PcSample:
    assert sample.assessment is not None
    vuln = sample.assessment.findings[0].model_copy(
        update={"finding_id": finding_id, "official_remediation": remediation}
    )
    findings = [*sample.assessment.findings, vuln]
    return sample.model_copy(
        update={"assessment": sample.assessment.model_copy(update={"findings": findings})}
    )


def _recommendation(finding_ids: list[str], steps: list[str], dropped: int = 0) -> Recommendation:
    return Recommendation(
        title="Fix it",
        priority=50,
        steps=steps,
        finding_ids=finding_ids,
        dropped_steps=["Turn the firewall off."] * dropped,
    )


def _fix_sample() -> PcSample:
    sample = BASE
    sample = _vulnerable(sample, "fnd_new_node", "Package less than 8.2.13")
    sample = _vulnerable(sample, "fnd_old_node", "Package less than or equal to 24.18.0")
    assert sample.assessment is not None
    config = next(
        f.finding_id for f in sample.assessment.findings if f.kind is FindingKind.CONFIGURATION
    )
    recommendations = [
        _recommendation(
            ["fnd_new_node", config, "fnd_gone"],
            ["Download it.", "Install version 8.2.13 or newer.", "Reboot."],
        ),
        _recommendation(["fnd_old_node"], ["Update it.", "Reboot."], dropped=2),
        BASE.assessment.recommendations[0],
    ]
    assessment = sample.assessment.model_copy(update={"recommendations": recommendations})
    return sample.model_copy(update={"assessment": assessment})


def test_fix_checks_count_recommendations_steps_and_dropped_steps() -> None:
    fix = score(_fix_sample(), {}).fix
    assert fix is not None
    assert fix.recommendations == 3
    assert fix.steps == 3 + 2 + 3
    assert fix.dropped_steps == 2


def test_fix_checks_look_for_the_version_bound_in_the_steps() -> None:
    fix = score(_fix_sample(), {}).fix
    assert fix is not None
    assert fix.with_bound == 2
    assert fix.bound_stated == 1
    assert fix.without_bound == 1


def test_render_reports_the_fix_step_checks() -> None:
    text = render(score(_fix_sample(), {}))
    assert "## Fix steps" in text
    assert "Recommendations: 3" in text
    assert "Steps: 8" in text
    assert "Dropped steps: 2" in text
    assert "1 of 2 recommendations with a version bound state it in their steps" in text
    assert "1 recommendation has no version bound to check" in text


def test_render_says_so_when_no_recommendation_has_a_bound() -> None:
    text = render(score(BASE, {}))
    assert "No recommendation has a version bound to check" in text
    assert "recommendations with a version bound state it" not in text


def test_a_sample_without_an_assessment_has_no_fix_checks() -> None:
    sample = BASE.model_copy(update={"assessment": None})
    report = score(sample, {})
    assert report.fix is None
    assert "The sample has no assessment" in render(report)


@pytest.mark.parametrize(
    ("bound", "steps", "expected"),
    [
        ("version 8.2.13 or newer", ["Install 8.2.13."], True),
        ("version 8.2.13 or newer", ["Get 8.2.13 or later", "Reboot"], True),
        ("a version newer than 24.18.0", ["Pick something after v24.18.0."], True),
        ("version v1.10.0 or newer", ["Install 1.10.0"], True),
        ("version 2021-04-11 or newer", ["Install the 2021-04-11 build"], True),
        ("version 8.2.13 or newer", ["Install 18.2.13"], False),
        ("version 8.2.13 or newer", ["Install 8.2.130"], False),
        ("version 8.2.13 or newer", ["Install 1.8.2.13"], False),
        ("version 8.2.13 or newer", ["Install 8.2.13.4"], False),
        ("version 8.2.13 or newer", ["Update it.", "Reboot."], False),
        ("version 8.2.13 or newer", [], False),
        ("something else", ["8.2.13"], False),
    ],
)
def test_states_bound_needs_the_whole_version_number(
    bound: str, steps: list[str], expected: bool
) -> None:
    assert states_bound(bound, steps) is expected


def _write(tmp_path: Path, sample: PcSample) -> Path:
    path = tmp_path / "pc-sample.json"
    path.write_text(sample.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path


def test_main_writes_the_report_and_lists_what_still_needs_a_label(
    tmp_path: Path, labels_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "docs" / "pc-accuracy.md"
    code = main(
        [
            "--sample",
            str(_write(tmp_path, _sample())),
            "--labels",
            str(labels_file),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert "1 of 2 labelled incidents matched" in out.read_text(encoding="utf-8")
    shown = capsys.readouterr().out
    assert "1 of 2" in shown
    assert _key(UNLABELLED, 11) in shown


def test_main_warns_about_a_label_that_matches_no_incident(
    tmp_path: Path, labels_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sample = _sample().model_copy(update={"runs": _sample().runs[:1]})
    out = tmp_path / "out.md"
    args = ["--sample", str(_write(tmp_path, sample)), "--labels", str(labels_file)]
    assert main([*args, "--out", str(out)]) == 0
    assert _key(MISSED, 10) in capsys.readouterr().out


def test_main_stops_when_the_labels_file_is_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out.md"
    code = main(
        [
            "--sample",
            str(_write(tmp_path, _sample())),
            "--labels",
            str(tmp_path / "nope.yml"),
            "--out",
            str(out),
        ]
    )
    assert code == 2
    assert not out.exists()
    assert "nope.yml" in capsys.readouterr().out


def test_main_stops_when_a_label_is_not_usable(tmp_path: Path) -> None:
    bad = tmp_path / "labels.yml"
    bad.write_text('"a @ b":\n  expected: fine\n  why: x\n', encoding="utf-8")
    out = tmp_path / "out.md"
    args = ["--sample", str(_write(tmp_path, _sample())), "--labels", str(bad), "--out", str(out)]
    assert main(args) == 2
    assert not out.exists()
