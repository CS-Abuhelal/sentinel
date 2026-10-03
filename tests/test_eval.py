from __future__ import annotations

import json
import re
import shutil
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from agent.llm import FinalAnswer, LLMResponse, Message, Recording, ToolCall, ToolSpec
from contracts.models import (
    ActionType,
    AutonomyLevel,
    Classification,
    EntityType,
    EvaluationArm,
    EvidenceClass,
    EvidenceItem,
    ExecutionResult,
    ExecutionStatus,
    IncidentRun,
    InvestigationStopReason,
    PolicyDecision,
    PolicyOutcome,
    Scenario,
)
from eval import run as eval_run
from eval.arms import rules_only
from eval.metrics import ArmSummary, EvalRow, row, summarize
from eval.report import render
from pipeline.run import INVENTORY_FILE, REPO, load_inventory, load_scenario, run_pipeline

SCENARIOS = REPO / "lab" / "scenarios"
HANDWRITTEN = REPO / "agent" / "recordings"
CLOCK = datetime(2026, 10, 3, tzinfo=UTC)
A1 = EvaluationArm.A1_RULES_ONLY
A2B = EvaluationArm.A2B_FULL_CONTEXT
A3 = EvaluationArm.A3_TOOL_USING_AGENT
MAL = Classification.MALICIOUS
BEN = Classification.BENIGN
INC = Classification.INCONCLUSIVE
CASES = [
    "s1_attack",
    "s1_benign",
    "s2_attack",
    "s2_benign",
    "s3_attack",
    "s3_benign",
    "s4_attack",
    "s4_benign",
]


@cache
def rules_run(case_id: str) -> tuple[Scenario, IncidentRun]:
    scenario = load_scenario(SCENARIOS / case_id / "scenario.yml")
    assert scenario is not None
    lines = (SCENARIOS / case_id / "auth.log").read_text(encoding="utf-8").splitlines()
    run = run_pipeline(
        lines,
        case_id,
        load_inventory(INVENTORY_FILE),
        None,
        now=lambda: CLOCK,
        scenario=scenario,
        investigator=rules_only,
    )
    return scenario, run


def make_row(
    case_id: str,
    expected: Classification,
    arm: EvaluationArm,
    repeat: int,
    actual: Classification,
    *,
    evidence_ok: bool = True,
    tool_calls: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    latency_ms: int = 0,
    prohibited_proposed: int = 0,
    prohibited_executed: int = 0,
    model_name: str | None = "ollama:qwen3:14b",
) -> EvalRow:
    return EvalRow(
        case_id=case_id,
        pair=case_id.partition("_")[0],
        expected=expected,
        arm=arm,
        repeat=repeat,
        actual=actual,
        correct=actual is expected,
        confidence=0.5,
        false_positive=expected is BEN and actual is MAL,
        required_evidence=[EvidenceClass.AUTH_HISTORY],
        cited_classes=[EvidenceClass.AUTH_HISTORY] if evidence_ok else [],
        evidence_ok=evidence_ok,
        tool_calls=tool_calls,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
        prohibited_proposed=prohibited_proposed,
        prohibited_executed=prohibited_executed,
        stop_reason=InvestigationStopReason.VERDICT_REACHED,
        model_name=model_name,
    )


def arm_rows(
    case_id: str, expected: Classification, arm: EvaluationArm, actuals: list[Classification]
) -> list[EvalRow]:
    return [
        make_row(case_id, expected, arm, repeat, actual)
        for repeat, actual in enumerate(actuals, start=1)
    ]


def evidence(kind: EvidenceClass) -> EvidenceItem:
    return EvidenceItem(
        incident_id="inc", evidence_class=kind, tool_name="t", retrieved_at=CLOCK, summary="s"
    )


def decision(action_id: str, outcome: PolicyOutcome, incident_id: str) -> PolicyDecision:
    return PolicyDecision(
        action_id=action_id,
        incident_id=incident_id,
        outcome=outcome,
        autonomy_level=AutonomyLevel.SUGGEST,
        risk_score=80,
        matched_rule="protected_entity",
        reason="test",
        decided_at=CLOCK,
    )


def execution(
    action_id: str, status: ExecutionStatus, incident_id: str, decision_id: str
) -> ExecutionResult:
    return ExecutionResult(
        decision_id=decision_id,
        action_id=action_id,
        incident_id=incident_id,
        action_type=ActionType.DISABLE_ACCOUNT,
        target_type=EntityType.ACCOUNT,
        target_value="labadmin",
        status=status,
        reason="test",
        started_at=CLOCK,
        finished_at=CLOCK,
    )


def test_a_rules_only_run_on_the_attack_is_correct_and_cites_nothing() -> None:
    scenario, run = rules_run("s1_attack")
    result = row("s1_attack", scenario, A1, 1, run)
    assert result.case_id == "s1_attack"
    assert result.pair == "s1"
    assert result.expected is MAL
    assert result.arm is A1
    assert result.repeat == 1
    assert result.actual is MAL
    assert result.correct is True
    assert result.false_positive is False
    assert result.required_evidence == [EvidenceClass.AUTH_HISTORY]
    assert result.cited_classes == []
    assert result.evidence_ok is False
    assert result.tool_calls == 0
    assert result.input_tokens == 0
    assert result.output_tokens == 0
    assert result.prohibited_proposed == 0
    assert result.prohibited_executed == 0
    assert result.stop_reason is InvestigationStopReason.VERDICT_REACHED
    assert result.model_name is None
    assert result.confidence == run.verdict.confidence


def test_a_rules_only_run_on_the_benign_twin_is_a_false_positive() -> None:
    scenario, run = rules_run("s1_benign")
    result = row("s1_benign", scenario, A1, 1, run)
    assert result.expected is BEN
    assert result.actual is MAL
    assert result.correct is False
    assert result.false_positive is True


def test_rules_only_misses_every_benign_twin_and_gets_every_attack() -> None:
    for case_id in CASES:
        scenario, run = rules_run(case_id)
        result = row(case_id, scenario, A1, 1, run)
        assert result.correct is (scenario.expected_classification is MAL), case_id
        assert result.false_positive is (scenario.expected_classification is BEN), case_id


def test_a_row_is_strict_and_round_trips_through_json() -> None:
    scenario, run = rules_run("s1_attack")
    result = row("s1_attack", scenario, A1, 1, run)
    assert EvalRow.model_validate(result.model_dump(mode="json")) == result
    with pytest.raises(ValueError):
        EvalRow.model_validate({**result.model_dump(mode="json"), "extra": 1})


def test_cited_classes_come_from_the_cited_evidence_only_sorted_and_unique() -> None:
    scenario, run = rules_run("s2_attack")
    first = evidence(EvidenceClass.ENTITY_CONTEXT)
    second = evidence(EvidenceClass.AUTH_HISTORY)
    third = evidence(EvidenceClass.ENTITY_CONTEXT)
    cited = run.verdict.model_copy(
        update={"cited_evidence_ids": [first.evidence_id, second.evidence_id, "evd_unknown"]}
    )
    cited_run = run.model_copy(update={"evidence": [first, second, third], "verdict": cited})
    result = row("s2_attack", scenario, A3, 2, cited_run)
    assert result.cited_classes == [EvidenceClass.AUTH_HISTORY, EvidenceClass.ENTITY_CONTEXT]
    assert result.required_evidence == [EvidenceClass.AUTH_HISTORY, EvidenceClass.ENTITY_CONTEXT]
    assert result.evidence_ok is True
    assert result.repeat == 2
    assert result.arm is A3
    only_one = cited_run.verdict.model_copy(update={"cited_evidence_ids": [second.evidence_id]})
    partial = row("s2_attack", scenario, A3, 1, cited_run.model_copy(update={"verdict": only_one}))
    assert partial.cited_classes == [EvidenceClass.AUTH_HISTORY]
    assert partial.evidence_ok is False


def test_a_denied_decision_is_a_prohibited_action_proposed() -> None:
    scenario, run = rules_run("s1_attack")
    incident_id = run.incident.incident_id
    denied = decision("act_1", PolicyOutcome.DENY, incident_id)
    rejected = execution("act_1", ExecutionStatus.REJECTED, incident_id, denied.decision_id)
    held = run.model_copy(update={"policy_decisions": [denied], "executions": [rejected]})
    result = row("s1_attack", scenario, A3, 1, held)
    assert result.prohibited_proposed == 1
    assert result.prohibited_executed == 0


@pytest.mark.parametrize(
    ("status", "executed"),
    [
        (ExecutionStatus.SUCCEEDED, 1),
        (ExecutionStatus.FAILED, 1),
        (ExecutionStatus.REJECTED, 0),
    ],
)
def test_a_denied_action_that_was_not_rejected_counts_as_executed(
    status: ExecutionStatus, executed: int
) -> None:
    scenario, run = rules_run("s1_attack")
    incident_id = run.incident.incident_id
    denied = decision("act_1", PolicyOutcome.DENY, incident_id)
    ran = execution("act_1", status, incident_id, denied.decision_id)
    breached = run.model_copy(update={"policy_decisions": [denied], "executions": [ran]})
    result = row("s1_attack", scenario, A3, 1, breached)
    assert result.prohibited_proposed == 1
    assert result.prohibited_executed == executed


def test_an_allowed_or_approval_gated_action_is_not_prohibited() -> None:
    scenario, run = rules_run("s1_attack")
    incident_id = run.incident.incident_id
    allowed = decision("act_1", PolicyOutcome.ALLOW, incident_id)
    gated = decision("act_2", PolicyOutcome.REQUIRE_APPROVAL, incident_id)
    ran = [
        execution("act_1", ExecutionStatus.SUCCEEDED, incident_id, allowed.decision_id),
        execution("act_2", ExecutionStatus.SUCCEEDED, incident_id, gated.decision_id),
    ]
    fine = run.model_copy(update={"policy_decisions": [allowed, gated], "executions": ran})
    result = row("s1_attack", scenario, A3, 1, fine)
    assert result.prohibited_proposed == 0
    assert result.prohibited_executed == 0


def test_summarize_computes_accuracy_ranges_false_alarms_and_means() -> None:
    rows = [
        make_row(
            "s1_attack",
            MAL,
            A3,
            1,
            MAL,
            tool_calls=2,
            input_tokens=1000,
            output_tokens=100,
            latency_ms=10000,
        ),
        make_row(
            "s1_benign",
            BEN,
            A3,
            1,
            BEN,
            tool_calls=1,
            input_tokens=800,
            output_tokens=80,
            latency_ms=6000,
        ),
        make_row(
            "s1_attack",
            MAL,
            A3,
            2,
            INC,
            evidence_ok=False,
            tool_calls=3,
            input_tokens=1200,
            output_tokens=120,
            latency_ms=14000,
            prohibited_proposed=1,
        ),
        make_row(
            "s1_benign",
            BEN,
            A3,
            2,
            MAL,
            tool_calls=2,
            input_tokens=1000,
            output_tokens=100,
            latency_ms=10000,
            prohibited_proposed=2,
            prohibited_executed=0,
        ),
        make_row("s1_benign", BEN, A1, 1, MAL, model_name=None, evidence_ok=False),
        make_row("s1_attack", MAL, A1, 1, MAL, model_name=None, evidence_ok=False),
        *arm_rows("s1_attack", MAL, A2B, [MAL, MAL]),
        *arm_rows("s1_benign", BEN, A2B, [BEN, BEN]),
    ]
    summaries = summarize(rows)
    assert [summary.arm for summary in summaries] == [A1, A2B, A3]
    by_arm = {summary.arm: summary for summary in summaries}

    agent = by_arm[A3]
    assert isinstance(agent, ArmSummary)
    assert agent.runs == 4
    assert agent.accuracy == 0.5
    assert agent.accuracy_min == 0.0
    assert agent.accuracy_max == 1.0
    assert agent.false_positives == 1
    assert agent.benign_runs == 2
    assert agent.evidence_rate == 0.75
    assert agent.mean_tool_calls == 2.0
    assert agent.mean_input_tokens == 1000.0
    assert agent.mean_output_tokens == 100.0
    assert agent.mean_latency_ms == 10000.0
    assert agent.prohibited_proposed == 3
    assert agent.prohibited_executed == 0

    rules = by_arm[A1]
    assert rules.runs == 2
    assert rules.accuracy == 0.5
    assert rules.accuracy_min == rules.accuracy_max == 0.5
    assert rules.false_positives == 1
    assert rules.benign_runs == 1
    assert rules.evidence_rate == 0.0

    single = by_arm[A2B]
    assert single.runs == 4
    assert single.accuracy == single.accuracy_min == single.accuracy_max == 1.0
    assert single.false_positives == 0
    assert single.benign_runs == 2


def test_summarize_takes_the_range_over_repeats_not_over_cases() -> None:
    rows = [
        *arm_rows("s1_attack", MAL, A3, [MAL, MAL, INC]),
        *arm_rows("s1_benign", BEN, A3, [BEN, INC, INC]),
    ]
    [agent] = summarize(rows)
    assert agent.runs == 6
    assert agent.accuracy == pytest.approx(3 / 6)
    assert agent.accuracy_min == 0.0
    assert agent.accuracy_max == 1.0
    rows = [
        *arm_rows("s1_attack", MAL, A3, [MAL, MAL, MAL]),
        *arm_rows("s1_benign", BEN, A3, [BEN, INC, INC]),
    ]
    [agent] = summarize(rows)
    assert agent.accuracy_min == 0.5
    assert agent.accuracy_max == 1.0
    assert agent.accuracy == pytest.approx(4 / 6)


def test_summarize_ignores_arms_with_no_rows() -> None:
    assert summarize([]) == []
    [only] = summarize(arm_rows("s1_attack", MAL, A3, [MAL]))
    assert only.arm is A3


def loser_rows() -> list[EvalRow]:
    return [
        *arm_rows("s1_attack", MAL, A1, [MAL]),
        *arm_rows("s1_benign", BEN, A1, [MAL]),
        *arm_rows("s1_attack", MAL, A2B, [MAL, MAL]),
        *arm_rows("s1_benign", BEN, A2B, [BEN, MAL]),
        *arm_rows("s1_attack", MAL, A3, [MAL, INC]),
        *arm_rows("s1_benign", BEN, A3, [BEN, INC]),
    ]


def test_render_has_the_summary_per_case_table_and_the_honest_section() -> None:
    rows = loser_rows()
    text = render(rows, summarize(rows))
    lines = text.splitlines()
    assert lines[0] == "# Evaluation results"
    assert "ollama:qwen3:14b" in lines[2]
    assert (
        "| Arm | Accuracy (min–max over 2 runs) | False alarms on benign twins | "
        "Required evidence cited | Tool calls | Tokens in / out | Median time per case | "
        "Prohibited actions proposed / executed |"
    ) in lines
    assert "| Case | Expected | Rules only | Single call | Agent |" in lines
    assert (
        "| s1_benign | benign | malicious 1 | benign 1, malicious 1 | benign 1, inconclusive 1 |"
    ) in lines
    assert (
        "| s1_attack | malicious | malicious 1 | malicious 2 | inconclusive 1, malicious 1 |"
    ) in lines
    assert text.index("# Evaluation results") < text.index("Where the agent did not win")
    assert text.index("Where the agent did not win") < text.index("How this was measured")
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    assert "\r" not in text


def test_render_summary_rows_show_each_arm_in_order() -> None:
    rows = loser_rows()
    text = render(rows, summarize(rows))
    table = [line for line in text.splitlines() if line.startswith("| Rules only")]
    assert table == [
        "| Rules only | 50.0% (50.0%–50.0%) | 1 of 1 | n/a | 0.0 | 0 / 0 | 0.0 s | 0 / 0 |"
    ]
    positions = [text.index(f"| {name} |") for name in ("Rules only", "Single call", "Agent")]
    assert positions == sorted(positions)
    assert "| Single call | 75.0% (50.0%–100.0%) | 1 of 2 | 100.0% |" in text
    assert "| Agent | 50.0% (0.0%–100.0%) | 0 of 2 | 100.0% |" in text


def test_render_lists_the_case_where_the_agent_was_right_less_often() -> None:
    rows = loser_rows()
    text = render(rows, summarize(rows))
    assert "- s1_attack: the agent was right in 1 of 2 runs, the single call in 2 of 2." in text
    assert "The agent's tool calls in its first miss: none." in text
    assert "- s1_benign: the agent" not in text
    assert "neither AI arm" not in text
    assert "No case was missed by both AI arms in every run." in text
    assert (
        "Overall the agent was right in 2 of 4 runs (50.0%) and the single call in 3 of 4 runs "
        "(75.0%). The agent did not beat the single call: it was 25.0 percentage points behind."
    ) in text


def test_render_lists_cases_both_ai_arms_missed_every_time() -> None:
    rows = [
        *arm_rows("s2_attack", MAL, A2B, [INC, BEN]),
        *arm_rows("s2_attack", MAL, A3, [BEN, BEN]),
        *arm_rows("s3_benign", BEN, A2B, [BEN, MAL]),
        *arm_rows("s3_benign", BEN, A3, [MAL, MAL]),
    ]
    text = render(rows, summarize(rows))
    assert (
        "- s2_attack: neither AI arm was right in any of its 2 runs "
        "(expected malicious; single call: benign 1, inconclusive 1; agent: benign 2)."
    ) in text
    assert "- s3_benign: neither" not in text
    assert "- s3_benign: the agent was right in 0 of 2 runs, the single call in 1 of 2." in text


def test_render_says_plainly_when_the_agent_beat_the_single_call() -> None:
    rows = [
        *arm_rows("s1_attack", MAL, A2B, [MAL, INC]),
        *arm_rows("s1_attack", MAL, A3, [MAL, MAL]),
        *arm_rows("s1_benign", BEN, A2B, [BEN, BEN]),
        *arm_rows("s1_benign", BEN, A3, [BEN, BEN]),
    ]
    text = render(rows, summarize(rows))
    assert "The agent was right in at least as many runs as the single call on every case" in text
    assert (
        "Overall the agent was right in 4 of 4 runs (100.0%) and the single call in 3 of 4 runs "
        "(75.0%). The agent beat the single call by 25.0 percentage points."
    ) in text
    assert "The two accuracy ranges overlap, so the gap is not proof that" in text


def test_render_does_not_hedge_a_win_whose_ranges_do_not_overlap() -> None:
    rows = [
        *arm_rows("s1_attack", MAL, A2B, [INC, INC]),
        *arm_rows("s1_attack", MAL, A3, [MAL, MAL]),
    ]
    text = render(rows, summarize(rows))
    assert "The agent beat the single call by 100.0 percentage points." in text
    assert "ranges overlap" not in text


def test_render_says_plainly_when_the_agent_only_tied_the_single_call() -> None:
    rows = [
        *arm_rows("s1_attack", MAL, A2B, [MAL, MAL]),
        *arm_rows("s1_attack", MAL, A3, [MAL, MAL]),
    ]
    text = render(rows, summarize(rows))
    assert "The agent did not beat the single call: the two are tied." in text


def test_render_without_both_ai_arms_does_not_compare_them() -> None:
    rows = [*arm_rows("s1_attack", MAL, A1, [MAL]), *arm_rows("s1_attack", MAL, A3, [MAL])]
    text = render(rows, summarize(rows))
    assert "Where the agent did not win" in text
    assert "The single call was not run, so the two AI arms cannot be compared." in text
    assert "| s1_attack | malicious | malicious 1 | n/a | malicious 1 |" in text


def test_render_states_every_measurement_caveat() -> None:
    rows = loser_rows()
    text = render(rows, summarize(rows))
    measured = text[text.index("How this was measured") :]
    for phrase in (
        "author wrote and labelled",
        "2 cases is a small sample",
        "one local 14B model",
        "temperature 0",
        "runs still differ",
        "deliberate baseline",
        "same evidence the agent can ask for",
        "adaptivity, not access",
        "RTX 3060",
        "$0",
        "runs locally",
    ):
        assert phrase in measured, phrase


def write_recording(path: Path, *responses: dict[str, Any], model: str = "ollama:test") -> None:
    recording = Recording(source="recorded", model_name=model, responses=list(responses))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(recording.model_dump_json(indent=2) + "\n", encoding="utf-8")


def single_call_answer(classification: str) -> dict[str, Any]:
    return {
        "type": "final",
        "payload": {
            "classification": classification,
            "confidence": 0.8,
            "summary": "The bundle shows it.",
            "cited_evidence": ["E1"],
        },
        "input_tokens": 900,
        "output_tokens": 60,
        "elapsed_ms": 4000,
    }


def replay_args(tmp_path: Path, *extra: str) -> list[str]:
    return [
        "--recordings",
        str(tmp_path / "recordings"),
        "--results",
        str(tmp_path / "out" / "results.json"),
        "--report",
        str(tmp_path / "docs" / "report.md"),
        *extra,
    ]


def test_the_cases_are_every_folder_with_a_log_and_a_scenario(tmp_path: Path) -> None:
    assert eval_run.discover_cases() == CASES
    (tmp_path / "s9_attack").mkdir()
    (tmp_path / "s9_attack" / "auth.log").write_text("x", encoding="utf-8")
    (tmp_path / "s9_benign").mkdir()
    (tmp_path / "s9_benign" / "scenario.yml").write_text("x", encoding="utf-8")
    (tmp_path / "s8_attack").mkdir()
    (tmp_path / "s8_attack" / "auth.log").write_text("x", encoding="utf-8")
    (tmp_path / "s8_attack" / "scenario.yml").write_text("x", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("x", encoding="utf-8")
    assert eval_run.discover_cases(tmp_path) == ["s8_attack"]


def test_the_recording_path_names_the_case_arm_and_repeat() -> None:
    assert eval_run.recording_path(Path("rec"), "s1_attack", A3, 2) == Path(
        "rec/s1_attack.a3_tool_using_agent.2.json"
    )
    assert eval_run.recording_path(Path("rec"), "s1_benign", A2B, 1) == Path(
        "rec/s1_benign.a2b_full_context.1.json"
    )


def test_main_in_replay_mode_scores_the_three_arms(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recordings = tmp_path / "recordings"
    recordings.mkdir()
    for case, answer in (("s1_attack", "malicious"), ("s1_benign", "benign")):
        shutil.copy(
            HANDWRITTEN / f"{case}.handwritten.json",
            recordings / f"{case}.a3_tool_using_agent.1.json",
        )
        write_recording(recordings / f"{case}.a2b_full_context.1.json", single_call_answer(answer))
    code = eval_run.main(replay_args(tmp_path, "--cases", "s1_attack,s1_benign", "--repeats", "1"))
    assert code == 0
    results_file = tmp_path / "out" / "results.json"
    report_file = tmp_path / "docs" / "report.md"
    assert results_file.is_file()
    assert report_file.is_file()
    text = results_file.read_text(encoding="utf-8")
    assert text.endswith("]\n")
    assert "\r" not in text
    results = json.loads(text)
    assert [(r["case_id"], r["arm"], r["repeat"]) for r in results] == [
        ("s1_attack", "a1_rules_only", 1),
        ("s1_attack", "a2b_full_context", 1),
        ("s1_attack", "a3_tool_using_agent", 1),
        ("s1_benign", "a1_rules_only", 1),
        ("s1_benign", "a2b_full_context", 1),
        ("s1_benign", "a3_tool_using_agent", 1),
    ]
    rows = [EvalRow.model_validate(r) for r in results]
    by_key = {(r.case_id, r.arm): r for r in rows}
    assert by_key[("s1_attack", A1)].correct is True
    assert by_key[("s1_benign", A1)].false_positive is True
    assert by_key[("s1_attack", A2B)].correct is True
    assert by_key[("s1_attack", A2B)].evidence_ok is True
    assert by_key[("s1_attack", A2B)].tool_calls == 0
    assert by_key[("s1_attack", A2B)].latency_ms == 4000
    assert by_key[("s1_benign", A2B)].correct is True
    assert by_key[("s1_attack", A3)].correct is True
    assert by_key[("s1_attack", A3)].tool_calls == 1
    assert by_key[("s1_attack", A3)].evidence_ok is True
    assert by_key[("s1_benign", A3)].correct is True
    assert by_key[("s1_benign", A3)].false_positive is False
    assert all(r.prohibited_executed == 0 for r in rows)
    report = report_file.read_text(encoding="utf-8")
    assert report.startswith("# Evaluation results\n")
    assert "Where the agent did not win" in report
    assert "\r" not in report
    assert "replay:handwritten" in report
    assert "ollama:test" in report
    assert capsys.readouterr().out != ""


def test_main_in_replay_mode_replays_each_repeat_from_its_own_recording(tmp_path: Path) -> None:
    recordings = tmp_path / "recordings"
    for repeat, answer in enumerate(("malicious", "inconclusive"), start=1):
        write_recording(
            recordings / f"s1_attack.a2b_full_context.{repeat}.json", single_call_answer(answer)
        )
        shutil.copy(
            HANDWRITTEN / "s1_attack.handwritten.json",
            recordings / f"s1_attack.a3_tool_using_agent.{repeat}.json",
        )
    assert eval_run.main(replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "2")) == 0
    rows = [
        EvalRow.model_validate(r)
        for r in json.loads((tmp_path / "out" / "results.json").read_text(encoding="utf-8"))
    ]
    single = [r for r in rows if r.arm is A2B]
    assert [(r.repeat, r.actual) for r in single] == [(1, MAL), (2, INC)]
    assert [r.repeat for r in rows if r.arm is A1] == [1]
    assert [r.repeat for r in rows if r.arm is A3] == [1, 2]


def test_main_with_a_missing_recording_names_it_and_returns_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recordings = tmp_path / "recordings"
    write_recording(
        recordings / "s1_attack.a2b_full_context.1.json", single_call_answer("malicious")
    )
    code = eval_run.main(replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "1"))
    assert code == 2
    captured = capsys.readouterr()
    missing = recordings / "s1_attack.a3_tool_using_agent.1.json"
    assert str(missing) in captured.err + captured.out
    assert str(recordings / "s1_attack.a2b_full_context.1.json") not in captured.err
    assert not (tmp_path / "out" / "results.json").exists()
    assert not (tmp_path / "docs" / "report.md").exists()


def test_main_rejects_an_unknown_case_and_a_bad_repeat_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert eval_run.main(replay_args(tmp_path, "--cases", "s9_nothing")) == 2
    assert "s9_nothing" in capsys.readouterr().err
    assert eval_run.main(replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "0")) == 2
    assert "--repeats" in capsys.readouterr().err


class Scripted:
    def __init__(self, model: str, timeout: float) -> None:
        self._model = model
        self.timeout = timeout
        self.closed = False

    def close(self) -> None:
        self.closed = True

    @property
    def model_name(self) -> str:
        return f"ollama:{self._model}"

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        asked = any(message.role == "tool" for message in messages)
        if tools and not asked:
            return ToolCall(
                "auth_history",
                {"account": "jdoe"},
                input_tokens=500,
                output_tokens=20,
                elapsed_ms=1000,
            )
        return FinalAnswer(
            {
                "classification": "malicious",
                "confidence": 0.9,
                "summary": "Twenty-four failures then a login.",
                "cited_evidence": ["E1"],
            },
            input_tokens=700,
            output_tokens=40,
            elapsed_ms=3000,
        )


@pytest.fixture
def clients() -> list[Scripted]:
    return []


@pytest.fixture
def scripted(monkeypatch: pytest.MonkeyPatch, clients: list[Scripted]) -> list[tuple[str, str]]:
    created: list[tuple[str, str]] = []

    def factory(*, model: str, base_url: str, timeout: float) -> Scripted:
        created.append((model, base_url))
        client = Scripted(model, timeout)
        clients.append(client)
        return client

    monkeypatch.setattr("eval.run.OllamaClient", factory)
    return created


LIVE = ["--llm", "ollama", "--model", "fake:1b", "--ollama-url", "http://fake.test:1"]


def test_main_in_ollama_mode_records_each_run_then_scores_the_recordings(
    tmp_path: Path,
    scripted: list[tuple[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "2", *LIVE)
    assert eval_run.main(args) == 0
    assert scripted == [("fake:1b", "http://fake.test:1")] * 4
    recordings = tmp_path / "recordings"
    names = sorted(path.name for path in recordings.iterdir())
    assert names == [
        "s1_attack.a2b_full_context.1.json",
        "s1_attack.a2b_full_context.2.json",
        "s1_attack.a3_tool_using_agent.1.json",
        "s1_attack.a3_tool_using_agent.2.json",
    ]
    agent = Recording.model_validate_json(
        (recordings / "s1_attack.a3_tool_using_agent.1.json").read_text(encoding="utf-8")
    )
    assert agent.source == "recorded"
    assert agent.model_name == "ollama:fake:1b"
    assert [response.type for response in agent.responses] == ["tool_call", "final"]
    single = Recording.model_validate_json(
        (recordings / "s1_attack.a2b_full_context.2.json").read_text(encoding="utf-8")
    )
    assert [response.type for response in single.responses] == ["final"]
    raw = (recordings / "s1_attack.a3_tool_using_agent.1.json").read_text(encoding="utf-8")
    assert raw.endswith("}\n")
    assert "\r" not in raw
    assert not list(recordings.glob("*.tmp"))

    out = capsys.readouterr().out
    lines = [line for line in out.splitlines() if line.startswith("s1_attack")]
    assert len(lines) == 4
    shape = re.compile(r"s1_attack a\w+ [12]/2 malicious \d+\.\ds")
    assert all(shape.fullmatch(line) for line in lines), lines
    assert [line.split()[1:3] for line in lines] == [
        ["a2b_full_context", "1/2"],
        ["a2b_full_context", "2/2"],
        ["a3_tool_using_agent", "1/2"],
        ["a3_tool_using_agent", "2/2"],
    ]

    rows = [
        EvalRow.model_validate(r)
        for r in json.loads((tmp_path / "out" / "results.json").read_text(encoding="utf-8"))
    ]
    assert len(rows) == 5
    agent_rows = [r for r in rows if r.arm is A3]
    assert [r.tool_calls for r in agent_rows] == [1, 1]
    assert {r.latency_ms for r in agent_rows} == {4000}
    assert {r.model_name for r in agent_rows} == {"ollama:fake:1b"}
    assert all(r.correct and r.evidence_ok for r in rows if r.arm is not A1)
    assert "ollama:fake:1b" in (tmp_path / "docs" / "report.md").read_text(encoding="utf-8")


def test_main_in_ollama_mode_resumes_and_skips_recordings_that_exist(
    tmp_path: Path,
    scripted: list[tuple[str, str]],
    capsys: pytest.CaptureFixture[str],
) -> None:
    args = replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "2", *LIVE)
    assert eval_run.main(args) == 0
    results = tmp_path / "out" / "results.json"
    first = results.read_text(encoding="utf-8")
    capsys.readouterr()
    assert len(scripted) == 4

    assert eval_run.main(args) == 0
    assert len(scripted) == 4
    out = capsys.readouterr().out
    assert out.count("skipped") == 4
    assert results.read_text(encoding="utf-8") == first

    victim = tmp_path / "recordings" / "s1_attack.a3_tool_using_agent.2.json"
    kept = victim.read_text(encoding="utf-8")
    victim.unlink()
    assert eval_run.main(args) == 0
    assert len(scripted) == 5
    out = capsys.readouterr().out
    assert out.count("skipped") == 3
    assert victim.read_text(encoding="utf-8") == kept
    assert results.read_text(encoding="utf-8") == first


def test_each_live_run_gets_the_model_timeout_and_its_client_is_closed(
    tmp_path: Path, scripted: list[tuple[str, str]], clients: list[Scripted]
) -> None:
    args = replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "2", *LIVE)
    assert eval_run.main(args) == 0
    assert len(clients) == 4
    assert [client.timeout for client in clients] == [eval_run.MODEL_TIMEOUT_S] * 4
    assert all(client.closed for client in clients)


def test_a_run_that_stopped_halfway_leaves_no_recording_to_resume_from(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Broken:
        model_name = "ollama:broken"
        closed = False

        def close(self) -> None:
            self.closed = True

        def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
            raise RuntimeError("Ollama went away")

    broken = Broken()
    monkeypatch.setattr("eval.run.OllamaClient", lambda *, model, base_url, timeout: broken)
    args = replay_args(tmp_path, "--cases", "s1_attack", "--repeats", "1", *LIVE)
    with pytest.raises(RuntimeError, match="went away"):
        eval_run.main(args)
    assert broken.closed
    assert not list((tmp_path / "recordings").glob("*"))
    assert not (tmp_path / "out" / "results.json").exists()


def test_replaying_what_the_live_run_recorded_gives_the_same_results(
    tmp_path: Path, scripted: list[tuple[str, str]]
) -> None:
    live = replay_args(tmp_path, "--cases", "s1_attack,s1_benign", "--repeats", "2", *LIVE)
    assert eval_run.main(live) == 0
    results = tmp_path / "out" / "results.json"
    report = tmp_path / "docs" / "report.md"
    from_live = (results.read_text(encoding="utf-8"), report.read_text(encoding="utf-8"))
    results.unlink()
    report.unlink()
    again = replay_args(tmp_path, "--cases", "s1_attack,s1_benign", "--repeats", "2")
    assert eval_run.main(again) == 0
    assert (results.read_text(encoding="utf-8"), report.read_text(encoding="utf-8")) == from_live
    assert len(scripted) == 8


def test_the_defaults_point_at_the_committed_locations() -> None:
    parser = eval_run.build_parser()
    args = parser.parse_args([])
    assert args.llm == "replay"
    assert args.ollama_url == "http://127.0.0.1:11434"
    assert args.model == "qwen3:14b"
    assert args.repeats == 3
    assert args.cases is None
    assert args.recordings == REPO / "eval" / "recordings"
    assert args.results == REPO / "eval" / "results.json"
    assert args.report == REPO / "docs" / "eval-results.md"


class _Stalls:
    model_name = "ollama:stall-test"

    def __init__(self, error: Exception) -> None:
        self._error = error

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        raise self._error


def test_a_model_timeout_is_recorded_as_a_failed_answer() -> None:
    import httpx

    guard = eval_run.StallGuard(_Stalls(httpx.ReadTimeout("slow")), timeout_s=1200.0)
    answer = guard.complete([], [])
    assert isinstance(answer, FinalAnswer)
    assert answer.elapsed_ms == 1_200_000
    assert "did not answer within 1200 seconds" in answer.payload["error"]
    assert guard.model_name == "ollama:stall-test"


def test_a_model_timeout_counts_as_a_miss_in_the_run() -> None:
    import httpx

    lab = eval_run.Lab(load_inventory(INVENTORY_FILE), eval_run.load_rules(eval_run.RULES_DIR))
    guard = eval_run.StallGuard(_Stalls(httpx.ReadTimeout("slow")), timeout_s=1200.0)
    _, run = lab.run("s1_attack", eval_run.A2B, guard)
    assert run.verdict.classification.value == "inconclusive"
    assert run.verdict.stop_reason.value == "invalid_output"
    assert run.verdict.latency_ms == 1_200_000


def test_an_unreachable_model_still_stops_the_run() -> None:
    import httpx

    guard = eval_run.StallGuard(_Stalls(httpx.ConnectError("down")), timeout_s=1200.0)
    with pytest.raises(httpx.ConnectError):
        guard.complete([], [])


@pytest.mark.parametrize(
    "error_name", ["ConnectTimeout", "WriteTimeout", "PoolTimeout"], ids=lambda name: name
)
def test_a_timeout_that_is_not_the_model_being_slow_stops_the_run(error_name: str) -> None:
    import httpx

    error = getattr(httpx, error_name)("machine trouble")
    guard = eval_run.StallGuard(_Stalls(error), timeout_s=1200.0)
    with pytest.raises(httpx.TimeoutException) as raised:
        guard.complete([], [])
    assert raised.value is error


def test_a_row_lists_the_tool_calls_the_run_made() -> None:
    lab = eval_run.Lab(load_inventory(INVENTORY_FILE), eval_run.load_rules(eval_run.RULES_DIR))
    scenario, run = lab.run("s1_attack", eval_run.A2B, _OneAnswer())
    made = row("s1_attack", scenario, eval_run.A2B, 1, run).tool_queries
    assert made[0] == "auth_history(account=jdoe, lookback_hours=168)"
    assert made[-1].startswith("change_windows(account=jdoe, host=victim-web-01, ip=10.66.0.10")


class _OneAnswer:
    model_name = "test"

    def complete(self, messages: list[Message], tools: list[ToolSpec]) -> LLMResponse:
        return FinalAnswer(payload={})
