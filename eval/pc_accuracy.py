from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agent.fix import strictest_fix
from contracts.models import Classification, FindingKind, HostAssessment, IncidentRun, PcSample

DEFAULT_SAMPLE = Path("lab/wazuh/sample/pc-sample.json")
DEFAULT_LABELS = Path("lab/wazuh/sample/labels.yml")
DEFAULT_OUT = Path("docs/pc-accuracy.md")
BOUND = re.compile(r"^(?:version (?P<newer>\S.*) or newer|a version newer than (?P<above>\S.*))$")
DATED = re.compile(r"\d{4}-\d{2}-\d{2}")
DATED_IN_TEXT = re.compile(r"(?<![\d.-])\d{4}-\d{2}-\d{2}(?![\d-])")
VERSION_IN_TEXT = re.compile(r"(?<![\d.])\d+(?:\.\d+)*(?![\d-]|\.\d)")
NO_VALUE = "-"


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected: Classification
    why: str = Field(min_length=1)


class Result(StrEnum):
    MATCH = "match"
    MISS = "miss"
    UNLABELLED = "unlabelled"


@dataclass(frozen=True)
class Row:
    key: str
    incident: str
    first_alert: str
    expected: Classification | None
    actual: Classification
    confidence: float
    tools: tuple[str, ...]
    why: str | None
    result: Result


@dataclass(frozen=True)
class FixChecks:
    recommendations: int
    steps: int
    dropped_steps: int
    with_bound: int
    bound_stated: int

    @property
    def without_bound(self) -> int:
        return self.recommendations - self.with_bound


@dataclass(frozen=True)
class Report:
    rows: list[Row]
    models: list[str]
    unused_labels: list[str]
    fix: FixChecks | None

    @property
    def labelled(self) -> int:
        return sum(1 for row in self.rows if row.result is not Result.UNLABELLED)

    @property
    def matched(self) -> int:
        return sum(1 for row in self.rows if row.result is Result.MATCH)

    @property
    def unlabelled(self) -> int:
        return len(self.rows) - self.labelled


def load_labels(path: Path) -> dict[str, Label]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} must be a mapping from incident key to label.")
    labels: dict[str, Label] = {}
    for key, value in data.items():
        try:
            labels[str(key)] = Label.model_validate(value)
        except ValidationError as error:
            raise ValueError(
                f"The label for {str(key)!r} in {path} is not usable: {error}"
            ) from error
    return labels


def label_key(run: IncidentRun) -> str:
    return f"{run.incident.title} @ {run.incident.window_start.isoformat()}"


def states_bound(bound: str, steps: list[str]) -> bool:
    match = BOUND.match(bound)
    if match is None:
        raise ValueError(f"Unknown version bound wording: {bound}")
    number = (match.group("newer") or match.group("above")).lstrip("vV")
    dated = DATED.fullmatch(number) is not None
    needed = _parts(number)
    found = DATED_IN_TEXT if dated else VERSION_IN_TEXT
    return any(
        len(_parts(token)) >= len(needed) and _parts(token) >= needed
        for step in steps
        for token in found.findall(step)
    )


def _parts(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def fix_checks(assessment: HostAssessment) -> FixChecks:
    findings = {finding.finding_id: finding for finding in assessment.findings}
    with_bound = 0
    stated = 0
    for recommendation in assessment.recommendations:
        conditions: list[str] = []
        for finding_id in recommendation.finding_ids:
            finding = findings.get(finding_id)
            if (
                finding is not None
                and finding.kind is FindingKind.VULNERABILITY
                and finding.official_remediation
            ):
                conditions.append(finding.official_remediation)
        bound = strictest_fix(conditions)
        if bound is None:
            continue
        with_bound += 1
        if states_bound(bound, recommendation.steps):
            stated += 1
    return FixChecks(
        recommendations=len(assessment.recommendations),
        steps=sum(len(r.steps) for r in assessment.recommendations),
        dropped_steps=sum(len(r.dropped_steps) for r in assessment.recommendations),
        with_bound=with_bound,
        bound_stated=stated,
    )


def _row(run: IncidentRun, label: Label | None) -> Row:
    actual = run.verdict.classification
    if label is None:
        result = Result.UNLABELLED
    elif label.expected is actual:
        result = Result.MATCH
    else:
        result = Result.MISS
    return Row(
        key=label_key(run),
        incident=run.incident.title,
        first_alert=run.incident.window_start.isoformat(),
        expected=None if label is None else label.expected,
        actual=actual,
        confidence=run.verdict.confidence,
        tools=tuple(dict.fromkeys(item.tool_name for item in run.evidence)),
        why=None if label is None else label.why,
        result=result,
    )


def score(sample: PcSample, labels: dict[str, Label]) -> Report:
    rows = [_row(run, labels.get(label_key(run))) for run in sample.runs]
    seen = {row.key for row in rows}
    models = sorted({run.verdict.model_name for run in sample.runs if run.verdict.model_name})
    return Report(
        rows=rows,
        models=models,
        unused_labels=[key for key in labels if key not in seen],
        fix=None if sample.assessment is None else fix_checks(sample.assessment),
    )


def _count(number: int, word: str) -> str:
    return f"{number} {word}" if number == 1 else f"{number} {word}s"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def summary(report: Report) -> str:
    if report.labelled == 0:
        return "No incidents are labelled yet, so there is no accuracy number."
    return (
        f"{report.matched} of {report.labelled} labelled incidents matched. "
        "See How this was measured for what this number does and does not show."
    )


def _unlabelled_sentence(count: int) -> str:
    if count == 1:
        return "1 incident is not labelled and is not scored."
    return f"{count} incidents are not labelled and are not scored."


def _table(rows: list[Row]) -> list[str]:
    lines = [
        "| Incident | First alert | Expected | Actual | Confidence | Tools used | Result |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        expected = row.expected.value if row.expected else NO_VALUE
        tools = ", ".join(row.tools) or NO_VALUE
        lines.append(
            f"| {_cell(row.incident)} | {row.first_alert} | {expected} | {row.actual.value} | "
            f"{row.confidence:.2f} | {_cell(tools)} | {row.result.value} |"
        )
    return lines


def _measured(report: Report) -> list[str]:
    text = (
        "The expected classification of each labelled incident was set by the owner, who knew "
        "what happened on the PC. The owner is also the author of this project, so these are one "
        "person's judgements. An incident counts as a match only when the model's classification "
        "equals the label. Incidents without a label are listed but not scored."
    )
    if report.labelled:
        text += (
            f" With {_count(report.labelled, 'labelled incident')} this number is anecdotal: it "
            "shows how the model did on these cases, not how often it is right in general."
        )
    return ["## How this was measured", "", text]


def _fix_section(fix: FixChecks | None) -> list[str]:
    lines = ["## Fix steps", ""]
    if fix is None:
        return [*lines, "The sample has no assessment, so there are no fix steps to check."]
    lines += [
        f"- Recommendations: {fix.recommendations}",
        f"- Steps: {fix.steps}",
        f"- Dropped steps: {fix.dropped_steps} (removed by the checker for weakening the PC, "
        "linking to a site that is not on the allow-list, being too long, or going over the "
        "step limit)",
    ]
    if fix.with_bound == 0:
        lines.append("- No recommendation has a version bound to check.")
        return lines
    lines.append(
        f"- {fix.bound_stated} of {fix.with_bound} recommendations with a version bound name a "
        "version at least that new in their steps."
    )
    if fix.without_bound:
        lines.append(
            f"- {_count(fix.without_bound, 'recommendation')} "
            f"{'has' if fix.without_bound == 1 else 'have'} no version bound to check."
        )
    lines += [
        "",
        "The version bound is worked out again from the weak spots kept in this sample, which can "
        "be fewer than the program has, so a step passes when it names a version at least as new "
        "as that bound. The check only looks for such a version number in a step, not whether "
        "the step is right.",
    ]
    return lines


def render(report: Report) -> str:
    lines = ["# PC verdict accuracy", ""]
    if report.models:
        lines += [f"Model: {', '.join(report.models)}", ""]
    headline = summary(report)
    if report.unlabelled:
        headline += " " + _unlabelled_sentence(report.unlabelled)
    lines += [f"**{headline}**", ""]
    lines += [*_table(report.rows), ""]
    noted = [row for row in report.rows if row.why is not None]
    if noted:
        lines += ["## Why the owner expected each verdict", ""]
        lines += [f"- **{row.incident}** ({row.first_alert}): {row.why}" for row in noted]
        lines.append("")
    if report.unused_labels:
        lines += [
            "## Labels that did not match any incident",
            "",
            "No incident in the sample has this title and first alert time, so these labels "
            "were not used:",
            "",
        ]
        lines += [f"- `{key}`" for key in report.unused_labels]
        lines.append("")
    lines += [*_measured(report), ""]
    lines += [*_fix_section(report.fix), ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m eval.pc_accuracy",
        description="Score the PC sample's incident verdicts against the owner's hand labels.",
    )
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    try:
        sample = PcSample.model_validate_json(args.sample.read_text(encoding="utf-8"))
        labels = load_labels(args.labels)
        report = score(sample, labels)
    except (OSError, ValueError, yaml.YAMLError) as error:
        print(f"Could not score the sample: {error}")
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(report), encoding="utf-8", newline="\n")
    print(f"Wrote {args.out}. {summary(report)}")
    for row in report.rows:
        if row.result is Result.UNLABELLED:
            print(f"Not labelled yet: {row.key}")
    for key in report.unused_labels:
        print(f"This label matches no incident in the sample: {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
