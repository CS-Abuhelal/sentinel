from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agent.investigate import investigate
from agent.llm import LLMClient, RecordingClient, ReplayClient
from agent.ollama import DEFAULT_MODEL, DEFAULT_URL, OllamaClient
from contracts.models import (
    ActionType,
    Approval,
    AuditKind,
    AuditRecord,
    Classification,
    ExecutionResult,
    ExecutionStatus,
    Incident,
    IncidentRun,
    IncidentStatus,
    Inventory,
    PolicyDecision,
    PolicyOutcome,
    RiskScore,
    Scenario,
    Verdict,
)
from detection.correlate import correlate
from detection.sigma import RuleSet, detect, load_rules
from executor.approvals import ApprovalEntry, load_approvals, match_approval
from executor.audit import AuditLog, verify_chain
from executor.core import RunnerFor, execute
from executor.runners import DockerRunner, DryRunRunner
from ingest.linux_auth import parse_auth_log
from policy.engine import decide
from policy.risk import score_risk

REPO = Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "detection" / "rules"
INVENTORY_FILE = REPO / "lab" / "inventory.yml"
RECORDINGS_DIR = REPO / "agent" / "recordings"
APPROVALS_DIR = REPO / "approvals"
RUNS_DIR = REPO / "runs"


def utcnow() -> datetime:
    return datetime.now(UTC)


def load_inventory(path: Path) -> Inventory:
    return Inventory.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def load_scenario(path: Path) -> Scenario | None:
    if not path.is_file():
        return None
    return Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def dry_run_everywhere() -> RunnerFor:
    runner = DryRunRunner()
    return lambda host: runner


def run_pipeline(
    lines: list[str],
    case_id: str,
    inventory: Inventory,
    llm: LLMClient,
    rules: RuleSet | None = None,
    now: Callable[[], datetime] = utcnow,
    scenario: Scenario | None = None,
    approvals: list[ApprovalEntry] | None = None,
    approval_source: str = "approvals",
    runner_for: RunnerFor | None = None,
) -> IncidentRun:
    events = parse_auth_log(lines, case_id)
    alerts = detect(events, rules or load_rules(RULES_DIR), case_id)
    incidents = correlate(alerts, events, inventory, case_id)
    if len(incidents) != 1:
        raise ValueError(f"expected exactly one incident for {case_id}, found {len(incidents)}")
    [incident] = incidents
    incident_alerts = [a for a in alerts if a.alert_id in incident.alert_ids]
    incident.status = IncidentStatus.INVESTIGATING
    verdict, evidence = investigate(incident, incident_alerts, events, llm, now=now)
    risk = score_risk(incident, incident_alerts, evidence, inventory, now())
    response = _respond(
        verdict,
        incident,
        risk,
        inventory,
        approvals or [],
        approval_source,
        runner_for or dry_run_everywhere(),
        now,
    )
    incident.status = _status(verdict, response)
    incident.updated_at = now()
    return IncidentRun(
        case_id=case_id,
        created_at=now(),
        events=events,
        alerts=alerts,
        incident=incident,
        evidence=evidence,
        verdict=verdict,
        risk_score=risk,
        policy_decisions=response.decisions,
        scenario=scenario,
        approvals=response.approvals,
        executions=response.executions,
        audit=response.audit,
    )


@dataclass
class Response:
    decisions: list[PolicyDecision] = field(default_factory=list)
    approvals: list[Approval] = field(default_factory=list)
    executions: list[ExecutionResult] = field(default_factory=list)
    audit: list[AuditRecord] = field(default_factory=list)


def _respond(
    verdict: Verdict,
    incident: Incident,
    risk: RiskScore,
    inventory: Inventory,
    entries: list[ApprovalEntry],
    approval_source: str,
    runner_for: RunnerFor,
    now: Callable[[], datetime],
) -> Response:
    response = Response()
    audit = AuditLog(now)
    incident_id = incident.incident_id
    for action in verdict.proposed_actions:
        label = f"{action.action_type.value} {action.target_value}"
        audit.append(
            AuditKind.PROPOSAL,
            incident_id,
            action.action_id,
            f"Agent proposed {label}",
            {
                "action_type": action.action_type.value,
                "target_type": action.target_type.value,
                "target_value": action.target_value,
                "classification": verdict.classification.value,
                "model": verdict.model_name or "",
            },
        )
        decision = decide(action, verdict, incident, risk, inventory, now())
        response.decisions.append(decision)
        audit.append(
            AuditKind.DECISION,
            incident_id,
            decision.decision_id,
            f"Policy engine: {label} -> {decision.outcome.value} ({decision.matched_rule})",
            {
                "action_id": action.action_id,
                "outcome": decision.outcome.value,
                "matched_rule": decision.matched_rule,
                "risk_score": decision.risk_score,
            },
        )
        approval = match_approval(entries, action, decision, approval_source, now)
        if approval is not None:
            response.approvals.append(approval)
            audit.append(
                AuditKind.APPROVAL,
                incident_id,
                approval.approval_id,
                f"{approval.decided_by} {'approved' if approval.approved else 'denied'} {label}",
                {
                    "decision_id": decision.decision_id,
                    "approved": approval.approved,
                    "decided_by": approval.decided_by,
                    "source": approval.source,
                },
            )
        runnable = decision.outcome is PolicyOutcome.ALLOW or approval is not None
        if action.action_type is ActionType.NO_ACTION or not runnable:
            continue
        for execution in execute(decision, action, incident, inventory, approval, runner_for, now):
            response.executions.append(execution)
            audit.append(
                AuditKind.EXECUTION,
                incident_id,
                execution.execution_id,
                f"Executor: {_execution_line(execution)}",
                {
                    "decision_id": decision.decision_id,
                    "status": execution.status.value,
                    "host": execution.host or "",
                    "dry_run": execution.dry_run,
                    "verified": execution.verified,
                },
            )
    response.audit = audit.records
    return response


def _execution_line(execution: ExecutionResult) -> str:
    where = f" on {execution.host}" if execution.host else ""
    note = " (dry run)" if execution.dry_run else ""
    if execution.verified:
        note = ", verified"
    return (
        f"{execution.action_type.value} {execution.target_value}{where}: "
        f"{execution.status.value}{note}"
    )


def _status(verdict: Verdict, response: Response) -> IncidentStatus:
    answered = {a.decision_id for a in response.approvals}
    waiting = any(
        d.outcome is PolicyOutcome.REQUIRE_APPROVAL and d.decision_id not in answered
        for d in response.decisions
    )
    if waiting:
        return IncidentStatus.AWAITING_APPROVAL
    if verdict.classification is Classification.BENIGN:
        return IncidentStatus.CLOSED_BENIGN
    executed = response.executions
    if executed and all(
        e.status is ExecutionStatus.SUCCEEDED and e.verified is True for e in executed
    ):
        return IncidentStatus.RESOLVED
    return IncidentStatus.INVESTIGATING


def _containers(pairs: list[str]) -> dict[str, str]:
    mapping = {}
    for pair in pairs:
        host, separator, container = pair.partition("=")
        if not separator or not host or not container:
            raise SystemExit(f"--container expects HOST=CONTAINER, got {pair!r}")
        mapping[host] = container
    return mapping


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.run",
        description="Run one scenario log through every SENTINEL stage and write the run file.",
    )
    parser.add_argument("log", type=Path, help="auth.log to ingest")
    parser.add_argument("--case-id", help="defaults to the log's folder name")
    parser.add_argument(
        "--recording",
        type=Path,
        help="LLM recording to replay; defaults to agent/recordings/<case-id>.handwritten.json",
    )
    parser.add_argument("--inventory", type=Path, default=INVENTORY_FILE)
    parser.add_argument("--out", type=Path, default=RUNS_DIR)
    parser.add_argument(
        "--llm",
        choices=["replay", "ollama"],
        default="replay",
        help="replay a recording (default) or ask a live model through Ollama",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model tag")
    parser.add_argument("--ollama-url", default=DEFAULT_URL)
    parser.add_argument("--think", action="store_true", help="turn on the model's thinking mode")
    parser.add_argument("--record", type=Path, help="save the live model's responses here")
    parser.add_argument(
        "--target",
        choices=["dry-run", "docker"],
        default="dry-run",
        help="record approved commands (default) or run them in lab containers",
    )
    parser.add_argument(
        "--container",
        action="append",
        default=[],
        metavar="HOST=CONTAINER",
        help="lab container that stands in for HOST (repeatable, with --target docker)",
    )
    parser.add_argument("--docker", default="docker", help="docker executable")
    parser.add_argument("--approvals", type=Path, default=APPROVALS_DIR)
    parser.add_argument("--audit-log", type=Path, help="append the audit records to this file")
    args = parser.parse_args(argv)

    case_id = args.case_id or args.log.resolve().parent.name
    if args.llm == "ollama":
        llm: LLMClient = OllamaClient(model=args.model, base_url=args.ollama_url, think=args.think)
    else:
        llm = ReplayClient.from_file(
            args.recording or RECORDINGS_DIR / f"{case_id}.handwritten.json"
        )
    if args.target == "docker":
        containers = _containers(args.container)
        runners = {
            host: DockerRunner(name, docker=args.docker) for host, name in containers.items()
        }
        runner_for: RunnerFor = runners.get
    else:
        runner_for = dry_run_everywhere()
    approvals_path = args.approvals / f"{case_id}.yml"
    recorder = RecordingClient(llm)
    run = run_pipeline(
        args.log.read_text(encoding="utf-8").splitlines(),
        case_id,
        load_inventory(args.inventory),
        recorder,
        scenario=load_scenario(args.log.parent / "scenario.yml"),
        approvals=load_approvals(approvals_path),
        approval_source=_display_path(approvals_path),
        runner_for=runner_for,
    )
    if args.record:
        args.record.parent.mkdir(parents=True, exist_ok=True)
        args.record.write_text(
            recorder.recording().model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{case_id}.json"
    path.write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if args.audit_log and run.audit:
        args.audit_log.parent.mkdir(parents=True, exist_ok=True)
        with args.audit_log.open("a", encoding="utf-8") as handle:
            for record in run.audit:
                handle.write(record.model_dump_json() + "\n")

    _print_summary(run, path)
    return 0


def _display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO).as_posix()
    except ValueError:
        return path.as_posix()


def _print_summary(run: IncidentRun, path: Path) -> None:
    verdict = run.verdict
    print(f"events    {len(run.events)}")
    print(f"alerts    {len(run.alerts)}")
    print(f"incident  {run.incident.title} [{run.incident.status.value}]")
    print(
        f"verdict   {verdict.classification.value} ({verdict.confidence:.2f}), "
        f"{verdict.tool_calls_made} tool call{'' if verdict.tool_calls_made == 1 else 's'}, "
        f"{verdict.stop_reason.value}, "
        f"model {verdict.model_name}"
    )
    print(f"risk      {run.risk_score.score} {run.risk_score.severity.value}")
    actions = {a.action_id: a for a in verdict.proposed_actions}
    for decision in run.policy_decisions:
        action = actions[decision.action_id]
        print(
            f"policy    {action.action_type.value} {action.target_value} -> "
            f"{decision.outcome.value} ({decision.matched_rule})"
        )
    for approval in run.approvals:
        action = actions[approval.action_id]
        print(
            f"approval  {approval.decided_by} {'approved' if approval.approved else 'denied'} "
            f"{action.action_type.value} {action.target_value}"
        )
    for execution in run.executions:
        print(f"execution {_execution_line(execution)}")
        if execution.status is not ExecutionStatus.SUCCEEDED:
            print(f"          {execution.reason}")
    if run.audit:
        state = "chain intact" if verify_chain(run.audit) else "CHAIN BROKEN"
        print(f"audit     {len(run.audit)} records, {state}")
    print(f"wrote     {path}")


if __name__ == "__main__":
    sys.exit(main())
