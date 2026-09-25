from __future__ import annotations

from collections.abc import Callable
from datetime import datetime

from contracts.models import (
    ActionType,
    Approval,
    CommandResult,
    EntityType,
    ExecutionResult,
    ExecutionStatus,
    Incident,
    Inventory,
    PolicyDecision,
    PolicyOutcome,
    ProposedAction,
)
from executor.catalog import CATALOG, HOST_NAME, CatalogEntry
from executor.runners import Runner

RunnerFor = Callable[[str], Runner | None]


def execute(
    decision: PolicyDecision,
    action: ProposedAction,
    incident: Incident,
    inventory: Inventory,
    approval: Approval | None,
    runner_for: RunnerFor,
    now: Callable[[], datetime],
) -> list[ExecutionResult]:
    started = now()

    def result(status: ExecutionStatus, reason: str, **fields: object) -> ExecutionResult:
        return ExecutionResult(
            decision_id=decision.decision_id,
            action_id=action.action_id,
            incident_id=incident.incident_id,
            action_type=action.action_type,
            target_type=action.target_type,
            target_value=action.target_value,
            status=status,
            reason=reason,
            started_at=started,
            finished_at=now(),
            **fields,
        )

    refusal = _refusal(decision, action, incident, inventory, approval)
    if refusal is not None:
        return [result(ExecutionStatus.REJECTED, refusal)]
    entry = CATALOG[action.action_type]
    authority = (
        f"Approved by {approval.decided_by}."
        if approval is not None
        else f"Allowed by policy rule {decision.matched_rule}."
    )
    results = []
    for host in entry.hosts(action.target_value, incident):
        results.append(_run_on_host(entry, action, host, inventory, runner_for, authority, result))
    return results or [result(ExecutionStatus.REJECTED, "There is no host to run this action on.")]


def _refusal(
    decision: PolicyDecision,
    action: ProposedAction,
    incident: Incident,
    inventory: Inventory,
    approval: Approval | None,
) -> str | None:
    entry = CATALOG.get(action.action_type)
    kind = action.action_type.value
    target = f"{action.target_type.value} {action.target_value}"
    if entry is None:
        return f"{kind} is not in the executor catalog."
    if decision.action_id != action.action_id or decision.incident_id != incident.incident_id:
        return "The policy decision does not belong to this action."
    if decision.outcome is PolicyOutcome.DENY:
        return "The policy engine denied this action."
    matches = (
        approval is not None
        and approval.decision_id == decision.decision_id
        and approval.action_id == action.action_id
    )
    if matches and approval is not None and not approval.approved:
        return f"{approval.decided_by} denied this action."
    needs_human = (
        decision.outcome is PolicyOutcome.REQUIRE_APPROVAL
        or action.action_type is ActionType.DISABLE_ACCOUNT
    )
    if needs_human and not matches:
        return "This action needs human approval before it can run."
    if action.target_type is not entry.target_type:
        return f"{kind} must target a {entry.target_type.value}, not a {action.target_type.value}."
    if inventory.is_protected(action.target_type, action.target_value):
        return f"The {target} is protected. The executor will not touch it."
    if not entry.pattern.fullmatch(action.target_value):
        return f"{action.target_value!r} is not a valid {entry.target_type.value} name."
    in_incident = any(
        e.entity_type is action.target_type and e.value == action.target_value
        for e in incident.entities
    )
    if not in_incident:
        return f"The {target} is not part of this incident."
    return None


def _run_on_host(
    entry: CatalogEntry,
    action: ProposedAction,
    host: str,
    inventory: Inventory,
    runner_for: RunnerFor,
    authority: str,
    result: Callable[..., ExecutionResult],
) -> ExecutionResult:
    if not HOST_NAME.fullmatch(host):
        return result(ExecutionStatus.REJECTED, f"{host!r} is not a valid host name.", host=host)
    if inventory.is_protected(EntityType.HOST, host):
        return result(ExecutionStatus.REJECTED, f"The host {host} is protected.", host=host)
    runner = runner_for(host)
    if runner is None:
        return result(
            ExecutionStatus.REJECTED, f"There is no execution target for host {host}.", host=host
        )
    target = action.target_value
    before = [] if runner.dry_run else [runner.run(argv) for argv in entry.checks(target)]
    commands: list[CommandResult] = []
    for step in entry.commands(target):
        outcome = runner.run(list(step.argv))
        commands.append(outcome)
        if outcome.exit_code not in step.ok:
            return result(
                ExecutionStatus.FAILED,
                f"`{' '.join(step.argv)}` exited with {outcome.exit_code} on {host}.",
                host=host,
                dry_run=runner.dry_run,
                before=before,
                commands=commands,
            )
    if runner.dry_run:
        return result(
            ExecutionStatus.SUCCEEDED,
            f"{authority} Dry run: commands recorded for {host}, not executed.",
            host=host,
            dry_run=True,
            commands=commands,
        )
    verification = [runner.run(argv) for argv in entry.checks(target)]
    verified = entry.verified(verification)
    return result(
        ExecutionStatus.SUCCEEDED if verified else ExecutionStatus.FAILED,
        f"{authority} Verified on {host}."
        if verified
        else f"{authority} The commands ran on {host} but verification failed.",
        host=host,
        before=before,
        commands=commands,
        verified=verified,
        verification=verification,
    )
