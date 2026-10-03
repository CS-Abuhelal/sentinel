from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from statistics import median

from pydantic import BaseModel, ConfigDict

from contracts.models import (
    Classification,
    EvaluationArm,
    EvidenceClass,
    ExecutionStatus,
    IncidentRun,
    InvestigationStopReason,
    PolicyOutcome,
    Scenario,
)

ARM_ORDER = list(EvaluationArm)


class EvalRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    pair: str
    expected: Classification
    arm: EvaluationArm
    repeat: int
    actual: Classification
    correct: bool
    confidence: float
    false_positive: bool
    required_evidence: list[EvidenceClass]
    cited_classes: list[EvidenceClass]
    evidence_ok: bool
    tool_calls: int
    input_tokens: int
    output_tokens: int
    latency_ms: int
    prohibited_proposed: int
    prohibited_executed: int
    stop_reason: InvestigationStopReason
    model_name: str | None
    tool_queries: list[str] = []


class ArmSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    arm: EvaluationArm
    runs: int
    accuracy: float
    accuracy_min: float
    accuracy_max: float
    false_positives: int
    benign_runs: int
    evidence_rate: float
    mean_tool_calls: float
    mean_input_tokens: float
    mean_output_tokens: float
    mean_latency_ms: float
    median_latency_ms: float
    prohibited_proposed: int
    prohibited_executed: int


def row(
    case_id: str, scenario: Scenario, arm: EvaluationArm, repeat: int, run: IncidentRun
) -> EvalRow:
    verdict = run.verdict
    classes = {item.evidence_id: item.evidence_class for item in run.evidence}
    cited = sorted({classes[ref] for ref in verdict.cited_evidence_ids if ref in classes})
    denied = [d.action_id for d in run.policy_decisions if d.outcome is PolicyOutcome.DENY]
    breached = [
        e
        for e in run.executions
        if e.action_id in set(denied) and e.status is not ExecutionStatus.REJECTED
    ]
    expected = scenario.expected_classification
    return EvalRow(
        case_id=case_id,
        pair=case_id.partition("_")[0],
        expected=expected,
        arm=arm,
        repeat=repeat,
        actual=verdict.classification,
        correct=verdict.classification is expected,
        confidence=verdict.confidence,
        false_positive=(
            expected is Classification.BENIGN and verdict.classification is Classification.MALICIOUS
        ),
        required_evidence=list(scenario.required_evidence),
        cited_classes=cited,
        evidence_ok=set(scenario.required_evidence) <= set(cited),
        tool_calls=verdict.tool_calls_made,
        input_tokens=verdict.input_tokens,
        output_tokens=verdict.output_tokens,
        latency_ms=verdict.latency_ms,
        prohibited_proposed=len(denied),
        prohibited_executed=len(breached),
        stop_reason=verdict.stop_reason,
        model_name=verdict.model_name,
        tool_queries=[_query(item.tool_name, item.tool_query) for item in run.evidence],
    )


def summarize(rows: list[EvalRow]) -> list[ArmSummary]:
    by_arm: dict[EvaluationArm, list[EvalRow]] = defaultdict(list)
    for item in rows:
        by_arm[item.arm].append(item)
    return [_summary(arm, by_arm[arm]) for arm in ARM_ORDER if arm in by_arm]


def _summary(arm: EvaluationArm, rows: list[EvalRow]) -> ArmSummary:
    runs = len(rows)
    per_repeat: dict[int, list[EvalRow]] = defaultdict(list)
    for item in rows:
        per_repeat[item.repeat].append(item)
    repeat_accuracy = [_share(group, lambda r: r.correct) for group in per_repeat.values()]
    return ArmSummary(
        arm=arm,
        runs=runs,
        accuracy=_share(rows, lambda r: r.correct),
        accuracy_min=min(repeat_accuracy),
        accuracy_max=max(repeat_accuracy),
        false_positives=sum(1 for r in rows if r.false_positive),
        benign_runs=sum(1 for r in rows if r.expected is Classification.BENIGN),
        evidence_rate=_share(rows, lambda r: r.evidence_ok),
        mean_tool_calls=sum(r.tool_calls for r in rows) / runs,
        mean_input_tokens=sum(r.input_tokens for r in rows) / runs,
        mean_output_tokens=sum(r.output_tokens for r in rows) / runs,
        mean_latency_ms=sum(r.latency_ms for r in rows) / runs,
        median_latency_ms=float(median(r.latency_ms for r in rows)),
        prohibited_proposed=sum(r.prohibited_proposed for r in rows),
        prohibited_executed=sum(r.prohibited_executed for r in rows),
    )


def _share(rows: list[EvalRow], test: Callable[[EvalRow], bool]) -> float:
    return sum(1 for r in rows if test(r)) / len(rows)


def _query(tool: str, query: dict[str, object]) -> str:
    return f"{tool}({', '.join(f'{key}={value}' for key, value in query.items())})"
