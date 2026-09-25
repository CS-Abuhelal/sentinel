# Executor and audit log — design

Date: 2026-09-25. Status: approved.

## Goal

Approved actions actually run against a real lab host and are verified. Every proposal,
decision, approval and execution is written to a tamper-evident audit log.

## Decisions

- **Target:** a real victim container (Debian slim with the lab accounts, `usermod`, `pkill`,
  `nftables`). It runs in GitHub Actions for the hosted demo, and locally with Docker. A dry-run
  target records commands without running them, for tests and machines without Docker.
- **Approvals:** a human commits `approvals/<case_id>.yml`. The build turns each entry into an
  `Approval` record. Nothing else can approve.

## Contract changes (1.3.0, D-09)

- `ExecutionStatus`: `succeeded`, `failed`, `rejected`.
- `AuditKind`: `proposal`, `decision`, `approval`, `execution`.
- `Approval(approval_id, decision_id, action_id, incident_id, approved, decided_by, decided_at,
  source, note)`.
- `CommandResult(argv, exit_code, output)`.
- `ExecutionResult(execution_id, decision_id, action_id, incident_id, action_type, target_type,
  target_value, host, status, reason, dry_run, commands, verified, verification, started_at,
  finished_at)`.
- `AuditRecord(sequence, recorded_at, kind, incident_id, subject_id, summary, payload,
  prev_hash, hash)`.
- `IncidentRun` gains `approvals`, `executions` and `audit` (empty by default).

## Executor (`executor/`)

Catalog entries, all run as argument lists with no shell:

| Action | Target | Commands on the host | Verification |
|---|---|---|---|
| `disable_account` | account | `usermod --lock --expiredate 1 <user>`, `pkill -KILL -u <user>` | `passwd --status` shows `L`, and `pgrep -u <user>` finds nothing |
| `isolate_host` | host | an `nft` table `sentinel_isolation` with input and output chains, policy drop, allowing loopback and the management network | `nft list table` shows both chains with policy drop |

`execute(decision, action, incident, inventory, approval, runner, now)` refuses (status
`rejected`, nothing run) unless all of these hold, in order:

1. The action type is in the catalog.
2. The decision belongs to this action and incident.
3. The decision allows it: `allow`, or `require_approval` with an approving `Approval` for this
   decision. `deny` never runs. `disable_account` never runs without an approval, even if a
   decision says `allow`.
4. The target type matches the catalog entry.
5. The target is not protected in the inventory.
6. The target value matches a strict pattern (account `^[a-z_][a-z0-9_-]{0,31}$`, host
   `^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$`).

A non-zero exit from any command gives `failed`. Otherwise the verification commands decide
`verified`.

`disable_account` runs on each host entity in the incident. `isolate_host` runs on the target
host. Hosts map to runners: `DockerRunner(container)` or `DryRunRunner`.

## Audit log (`executor/audit.py`)

`AuditLog.append(kind, incident_id, subject_id, summary, payload)` builds records whose `hash`
is SHA-256 over the canonical JSON of the record (without `hash`) including `prev_hash`.
`verify_chain(records)` returns whether every link and hash holds. The pipeline writes the chain
into the run and can append it to a JSONL file.

## Pipeline

After policy, for each proposed action: audit the proposal, audit the decision, attach any
approval from `approvals/<case_id>.yml` (matched on action type and target) and audit it, then
execute if allowed and audit the result. Incident status:

- `resolved` when every action that needs to run ran and verified;
- `awaiting_approval` while any decision still waits;
- `closed_benign` / `investigating` as before.

CLI: `--target dry-run|docker`, `--container host=name`, `--approvals DIR`, `--audit-log FILE`.

## Boundaries (tests)

- `agent` cannot import `executor`.
- `executor` does not import `agent`.
- Only `executor` may use `subprocess`.

## Dashboard

A stage 7, Execution (deterministic), shows each approval (who, source), each execution
(status, commands with exit codes, verification) and the audit chain with its intact or broken
state. Policy decisions with a recorded approval show it instead of the demo buttons.

## Tasks

1. Contracts 1.3.0 plus fixtures, tests and D-09.
2. Audit log and chain verification.
3. Catalog, runners, `execute()` guards.
4. Approvals file loading.
5. Pipeline and CLI integration.
6. Victim container, a Docker integration test (skipped without Docker), and the Pages workflow
   running the executor against it.
7. Dashboard stage 7 and the audit view.
8. Ask Ahmed to approve or deny, and commit his decision.
