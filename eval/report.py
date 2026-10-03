from __future__ import annotations

from collections import Counter
from fractions import Fraction

from contracts.models import EvaluationArm
from eval.metrics import ArmSummary, EvalRow

A1 = EvaluationArm.A1_RULES_ONLY
A2B = EvaluationArm.A2B_FULL_CONTEXT
A3 = EvaluationArm.A3_TOOL_USING_AGENT
ARM_NAMES = {A1: "Rules only", A2B: "Single call", A3: "Agent"}
NOT_AVAILABLE = "n/a"
SUMMARY_COLUMNS = [
    "Arm",
    "Accuracy (min–max over {repeats} runs)",
    "False alarms on benign twins",
    "Required evidence cited",
    "Tool calls",
    "Tokens in / out",
    "Time per case",
    "Prohibited actions proposed / executed",
]
CASE_COLUMNS = ["Case", "Expected", *ARM_NAMES.values()]
NEVER_BEHIND = "On every case the agent was right in at least as many runs as the single call."
NEVER_MISSED = "On every case at least one AI arm was right at least once."
OVERLAP_NOTE = " The two accuracy ranges overlap, so the gap is not proof that the agent is better."


def render(rows: list[EvalRow], summaries: list[ArmSummary]) -> str:
    cases = sorted({r.case_id for r in rows})
    repeats = max((r.repeat for r in rows if r.arm is not A1), default=1)
    sections = [
        "# Evaluation results",
        _model_line(rows, len(cases), repeats),
        "## Summary\n\n" + _summary_table(summaries, repeats),
        "## Per case\n\n" + _case_table(rows, cases),
        "## Where the agent did not win\n\n" + "\n".join(_did_not_win(rows, summaries, cases)),
        "## How this was measured\n\n" + _measured(len(cases), repeats),
    ]
    return "\n\n".join(sections) + "\n"


def _model_line(rows: list[EvalRow], cases: int, repeats: int) -> str:
    models = sorted({r.model_name for r in rows if r.model_name is not None})
    named = ", ".join(f"`{name}`" for name in models) if models else "none (rules only)"
    return (
        f"Model: {named}. {cases} {_noun(cases, 'case')}, {repeats} {_noun(repeats, 'run')} "
        "per case for each AI arm and one run for rules only."
    )


def _summary_table(summaries: list[ArmSummary], repeats: int) -> str:
    header = [column.format(repeats=repeats) for column in SUMMARY_COLUMNS]
    body = [_summary_cells(summary) for summary in summaries]
    return _table(header, body)


def _summary_cells(summary: ArmSummary) -> list[str]:
    evidence = NOT_AVAILABLE if summary.arm is A1 else _percent(summary.evidence_rate)
    return [
        ARM_NAMES.get(summary.arm, summary.arm.value),
        (
            f"{_percent(summary.accuracy)} "
            f"({_percent(summary.accuracy_min)}–{_percent(summary.accuracy_max)})"
        ),
        f"{summary.false_positives} of {summary.benign_runs}",
        evidence,
        f"{summary.mean_tool_calls:.1f}",
        f"{round(summary.mean_input_tokens):,} / {round(summary.mean_output_tokens):,}",
        f"{summary.mean_latency_ms / 1000:.1f} s",
        f"{summary.prohibited_proposed} / {summary.prohibited_executed}",
    ]


def _case_table(rows: list[EvalRow], cases: list[str]) -> str:
    body = []
    for case_id in cases:
        in_case = [r for r in rows if r.case_id == case_id]
        cells = [case_id, in_case[0].expected.value]
        cells.extend(_counts([r for r in in_case if r.arm is arm]) for arm in ARM_NAMES)
        body.append(cells)
    return _table(CASE_COLUMNS, body)


def _counts(rows: list[EvalRow]) -> str:
    if not rows:
        return NOT_AVAILABLE
    counted = Counter(r.actual.value for r in rows)
    return ", ".join(f"{name} {counted[name]}" for name in sorted(counted))


def _did_not_win(rows: list[EvalRow], summaries: list[ArmSummary], cases: list[str]) -> list[str]:
    by_arm = {summary.arm: summary for summary in summaries}
    absent = [name for arm, name in ((A2B, "single call"), (A3, "agent")) if arm not in by_arm]
    if len(absent) == 2:
        return ["- Neither AI arm was run, so there is nothing to compare."]
    if absent:
        return [f"- The {absent[0]} was not run, so the two AI arms cannot be compared."]
    behind = []
    missed = []
    for case_id in cases:
        single = [r for r in rows if r.case_id == case_id and r.arm is A2B]
        agent = [r for r in rows if r.case_id == case_id and r.arm is A3]
        if not single or not agent:
            continue
        single_right = sum(1 for r in single if r.correct)
        agent_right = sum(1 for r in agent if r.correct)
        if Fraction(agent_right, len(agent)) < Fraction(single_right, len(single)):
            behind.append(
                f"- {case_id}: the agent was right in {agent_right} of {_runs(len(agent))}, "
                f"the single call in {single_right} of {len(single)}."
            )
        if single_right == 0 and agent_right == 0:
            missed.append(
                f"- {case_id}: neither AI arm was right in any of its {_runs(len(agent))} "
                f"(expected {agent[0].expected.value}; single call: {_counts(single)}; "
                f"agent: {_counts(agent)})."
            )
    return [
        *(behind or [f"- None. {NEVER_BEHIND}"]),
        *(missed or [f"- None. {NEVER_MISSED}"]),
        _overall(rows, by_arm),
    ]


def _overall(rows: list[EvalRow], by_arm: dict[EvaluationArm, ArmSummary]) -> str:
    single = [r for r in rows if r.arm is A2B]
    agent = [r for r in rows if r.arm is A3]
    single_right = sum(1 for r in single if r.correct)
    agent_right = sum(1 for r in agent if r.correct)
    agent_share = Fraction(agent_right, len(agent))
    single_share = Fraction(single_right, len(single))
    line = (
        f"- Overall the agent was right in {agent_right} of {_runs(len(agent))} "
        f"({_percent(float(agent_share))}) and the single call in {single_right} of "
        f"{_runs(len(single))} ({_percent(float(single_share))}). "
    )
    gap = f"{abs(float(agent_share - single_share)) * 100:.1f}"
    if agent_share > single_share:
        line += f"The agent beat the single call by {gap} percentage points."
        if _overlap(by_arm[A3], by_arm[A2B]):
            line += OVERLAP_NOTE
        return line
    if agent_share == single_share:
        return line + "The agent did not beat the single call: the two are tied."
    return line + f"The agent did not beat the single call: it was {gap} percentage points behind."


def _overlap(first: ArmSummary, second: ArmSummary) -> bool:
    return max(first.accuracy_min, second.accuracy_min) <= min(
        first.accuracy_max, second.accuracy_max
    )


def _measured(cases: int, repeats: int) -> str:
    step = f"{100 / cases:.1f}"
    definitions = [
        "- Accuracy is the share of runs whose classification matches the label. The range is "
        f"the lowest and highest accuracy over the {repeats} repeats of all {cases} cases.",
        "- A false alarm is a run on a benign twin that was called malicious.",
        "- Required evidence cited means the verdict cites evidence of every class the label "
        "requires. Rules only cites no evidence, so it is not scored on this.",
        "- Prohibited actions are actions the policy engine denied. The second number is how "
        "many of them were executed anyway, and it must be 0.",
    ]
    caveats = [
        "- The author wrote and labelled the cases. They are not an independent benchmark, "
        "and the labels are one person's judgement.",
        f"- {cases} {_noun(cases, 'case')} is a small sample. One case moves a run's accuracy by "
        f"{step} percentage points.",
        "- Only one local 14B model was used, at temperature 0, yet runs still differ from one "
        f"another. That is why each AI case was run {repeats} times and accuracy is a range. "
        "Another model could rank the arms differently.",
        "- Rules only is a deliberate baseline. It calls every alert malicious, so it gets every "
        "attack right and every benign twin wrong.",
        "- The single call gets the same evidence the agent can ask for, bundled up front, so "
        "this measures adaptivity, not access to information.",
        "- Time is the model's own time on an RTX 3060, summed over the model calls for a case. "
        "It leaves out the rest of the pipeline.",
        "- Cost is $0 because the model runs locally, so there is no cost column.",
    ]
    return (
        "What the columns mean:\n\n"
        + "\n".join(definitions)
        + "\n\nCaveats:\n\n"
        + "\n".join(caveats)
    )


def _table(header: list[str], body: list[list[str]]) -> str:
    lines = [header, ["---"] * len(header), *body]
    return "\n".join("| " + " | ".join(cells) + " |" for cells in lines)


def _percent(share: float) -> str:
    return f"{share * 100:.1f}%"


def _noun(count: int, word: str) -> str:
    return word if count == 1 else word + "s"


def _runs(count: int) -> str:
    return f"{count} {_noun(count, 'run')}"
