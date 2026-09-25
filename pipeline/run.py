from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import yaml

from agent.investigate import investigate
from agent.llm import LLMClient, ReplayClient
from contracts.models import (
    Classification,
    IncidentRun,
    IncidentStatus,
    Inventory,
    PolicyDecision,
    PolicyOutcome,
    Verdict,
)
from detection.correlate import correlate
from detection.sigma import RuleSet, detect, load_rules
from ingest.linux_auth import parse_auth_log
from policy.engine import decide
from policy.risk import score_risk

REPO = Path(__file__).resolve().parents[1]
RULES_DIR = REPO / "detection" / "rules"
INVENTORY_FILE = REPO / "lab" / "inventory.yml"
RECORDINGS_DIR = REPO / "agent" / "recordings"
RUNS_DIR = REPO / "runs"


def utcnow() -> datetime:
    return datetime.now(UTC)


def load_inventory(path: Path) -> Inventory:
    return Inventory.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")) or {})


def run_pipeline(
    lines: list[str],
    case_id: str,
    inventory: Inventory,
    llm: LLMClient,
    rules: RuleSet | None = None,
    now: Callable[[], datetime] = utcnow,
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
    decisions = [
        decide(action, verdict, incident, risk, inventory, now())
        for action in verdict.proposed_actions
    ]
    incident.status = _status(verdict, decisions)
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
        policy_decisions=decisions,
    )


def _status(verdict: Verdict, decisions: list[PolicyDecision]) -> IncidentStatus:
    if any(d.outcome is PolicyOutcome.REQUIRE_APPROVAL for d in decisions):
        return IncidentStatus.AWAITING_APPROVAL
    if verdict.classification is Classification.BENIGN:
        return IncidentStatus.CLOSED_BENIGN
    return IncidentStatus.INVESTIGATING


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
    args = parser.parse_args(argv)

    case_id = args.case_id or args.log.resolve().parent.name
    recording = args.recording or RECORDINGS_DIR / f"{case_id}.handwritten.json"
    run = run_pipeline(
        args.log.read_text(encoding="utf-8").splitlines(),
        case_id,
        load_inventory(args.inventory),
        ReplayClient.from_file(recording),
    )
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"{case_id}.json"
    path.write_text(run.model_dump_json(indent=2) + "\n", encoding="utf-8")

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
    print(f"wrote     {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
