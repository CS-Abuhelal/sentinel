# Vertical slice — design

Date: 2026-09-25. Status: approved.

## Goal

One hardcoded S1 case flows through every stage and is visible in a browser:

```
auth.log → Event → Alert → Incident → agent (one tool, replayed LLM) → Verdict
         → RiskScore → PolicyDecision → UI
```

Done means: `python -m pipeline.run lab/scenarios/s1_attack/auth.log` writes
`runs/s1_attack.json`, the API serves it, and the dashboard shows every stage of that run.
Thin pieces are fine. Later work deepens the stages instead of adding new ones next to them.

Out of scope: executor, approve/deny, audit log, Postgres, the benign twin, live LLM calls,
the prompt-injection test, more agent tools. Each one comes after the slice.

## Architecture

Approach A: an offline pipeline script, a read-only API, and a React page.

- `pipeline.run_pipeline()` runs every stage in-process and returns `IncidentRun`s. The eval
  harness will call the same function.
- The CLI writes `runs/<case_id>.json`. `case_id` defaults to the log's parent folder name, and
  the recording defaults to `agent/recordings/<case_id>.handwritten.json`. The inventory
  defaults to `lab/inventory.yml`.
- The API only reads `runs/`. It never runs the pipeline. The hosted replay dashboard is the
  same API pointed at committed run files.
- Storage is JSON run files (D-05). Postgres comes in when approvals and the audit log need a
  real database. Docker is not installed on the dev machine.

Every stage is a function from contract models to contract models, so any stage can be tested
or replaced on its own.

```
lab/scenarios/s1_attack/auth.log    hardcoded sshd log
lab/inventory.yml                   accounts and hosts: role, privileged, protected
ingest/linux_auth.py                parse_auth_log(lines, case_id) -> list[Event]
detection/rules/*.yml               Sigma rules
detection/sigma.py                  load_rules(dir), detect(events, rules, case_id) -> list[Alert]
detection/correlate.py              correlate(alerts, events, inventory, case_id) -> list[Incident]
agent/llm.py                        LLMClient protocol, ToolCall, FinalAnswer, ReplayClient
agent/tools/__init__.py             tool registry
agent/tools/auth_history.py         the single read-only tool
agent/investigate.py                investigate(...) -> (Verdict, list[EvidenceItem])
agent/prompts/system.md             system prompt
agent/recordings/s1_attack.handwritten.json
policy/risk.py                      score_risk(...) -> RiskScore
policy/engine.py                    decide(...) -> PolicyDecision
pipeline/run.py                     run_pipeline(...) and the CLI
backend/app/main.py                 GET /api/runs, GET /api/runs/{incident_id}
frontend/                           Vite + React + TypeScript
```

The empty `detection/src/` and `policy/src/` placeholders are removed. `ingest`, `detection`,
`agent`, `policy` and `pipeline` are plain Python packages.

## Contract changes (1.0.0 → 1.1.0, logged as D-06)

- `InvestigationStopReason` enum: `verdict_reached`, `tool_call_cap`, `invalid_output`.
- `Verdict.stop_reason: InvestigationStopReason`, required. The brief requires recording why
  each investigation stopped.
- `AccountRecord(role, privileged=False, protected=False)`,
  `HostRecord(role, protected=False)`,
  `Inventory(accounts: dict[str, AccountRecord], hosts: dict[str, HostRecord])` with
  `is_protected(entity_type, value) -> bool`. Correlation, risk scoring and the policy engine all
  read it, so it lives in `contracts/`. It is loaded from `lab/inventory.yml`.
- `IncidentRun(run_id, case_id, contract_version, created_at, events, alerts, incident,
  evidence, verdict, risk_score, policy_decisions)`. This is the run file and the API response.
- New `IncidentRun.schema.json` (the frontend generates its TypeScript types from it) and an
  `incident_run.json` fixture built from the existing fixture objects.

Agent-internal shapes (LLM messages, tool calls, the recording file, the LLM's draft verdict)
stay in `agent/`. They never cross a stage boundary.

## Stages

### 1. Ingest

`lab/scenarios/s1_attack/auth.log` uses the RFC 3339 timestamp format that rsyslog writes on
current Ubuntu:

```
2026-09-25T02:11:04.512031+00:00 victim-web-01 sshd[2211]: Failed password for jdoe from 10.66.0.10 port 51422 ssh2
```

The log contains, in order:
- Baseline: `jdoe` logs in successfully from `10.77.0.50` on several earlier days.
- Attack on 2026-09-25 from `10.66.0.10`:
  - a few `Failed password for invalid user <name>` lines;
  - 24 `Failed password for jdoe` lines over about 6 minutes;
  - one `Accepted password for jdoe`.
- Unrelated lines (cron, `pam_unix` sessions) that the parser skips.

`parse_auth_log` matches `Failed|Accepted <method> for [invalid user ]<user> from <ip> port
<port>` from `sshd` and produces:

| Event field | Value |
|---|---|
| `source` | `linux_auth` |
| `category` | `authentication` |
| `event_type` | `ssh_login_failed` or `ssh_login_succeeded` |
| `outcome` | `failure` or `success` |
| `network` | `src_ip`, `src_port`, `dst_port=22`, `protocol=tcp` |
| `message` | the sshd message |
| `raw` | line, pid, method, invalid_user flag |

Lines that don't match are skipped. The username is attacker-controlled and is treated as data
everywhere.

### 2. Detection (Sigma)

Two rules in `detection/rules/`:

- `ssh_failed_password.yml`: a base rule. `logsource: {product: linux, service: auth}`,
  `selection: {event_type: ssh_login_failed}`, `condition: selection`.
- `ssh_password_bruteforce.yml`: a Sigma correlation rule. `type: event_count` over
  `ssh_failed_password`, grouped by `host, user, src_ip`, `timespan: 10m`, `condition: {gte: 10}`,
  `level: medium`, tags `attack.credential_access` and `attack.t1110.001`.

The evaluator supports only what these rules use:
- Rule fields map to `Event` fields; `src_ip` maps to `network.src_ip`.
- A selection value may be a scalar or a list of alternatives.
- The condition must be a single selection name.
- Correlation supports only `event_count`.

A base rule referenced by a correlation raises no alerts of its own. Any other key or feature
makes loading fail with an error; the evaluator never silently ignores part of a rule.

Windowing: within each group, events are sorted by time. Starting from the earliest remaining
event, all events within `timespan` of it are collected. If there are at least the threshold,
they become one alert and evaluation continues after them. Otherwise it moves on by one event.

Alert fields:
- `rule_id` and `rule_name` are the correlation rule's `id` and `title`.
- `rule_severity` is mapped from Sigma `level`; `informational` becomes `info`.
- `timestamp` is the last event's time.
- `host`, `user` and `src_ip` come from the group.
- `event_ids` lists the counted events.
- `suggested_techniques` are parsed from `attack.tNNNN[.NNN]` tags, giving `T1110.001`.

### 3. Correlation

Alerts that share `host` and `user` become one incident:
- The window spans the alerts' events.
- `created_at` is the latest alert time.
- The title is `Possible account compromise: <user> on <host>`.
- The entities are the host, the account and each source IP. Each has `is_protected` from the
  inventory.
- `status` starts as `new`.

The slice's pipeline requires exactly one incident per case and raises an error otherwise.

### 4. Agent

The LLM is accessed through `LLMClient.complete(messages, tools) -> ToolCall | FinalAnswer`.
`ReplayClient` loads a recording and returns its responses in order. It raises
`ReplayExhausted` if the agent asks for more, so a recording that no longer matches the code
fails loudly.

The slice's recording is hand-written and marked `"source": "handwritten"`, with `model_name`
`replay:handwritten`, which is copied onto the `Verdict`.

**Tool registry.** Each tool is a name, a description, a Pydantic params model with
`extra="forbid"`, an evidence class, and a read-only function. The only tool is:

`auth_history(account: str, lookback_hours: int = 168, 1–720)`. It returns authentication
events for the account from `window_start − lookback_hours` through the latest event in the
store. That range includes activity after the alert, such as the successful login that follows
the brute force. The result is summarized as:
- total failures and successes;
- per-source-IP counts with first and last seen;
- `success_after_failures`: each source IP with a success at or after `window_start`, preceded
  by failures from that same IP, and the number of those failures;
- `known_source_ips`: IPs with successful logins before `window_start`.

Tools read the events the run already has (the event store). They can't write anything.

**Evidence references.** The LLM sees evidence as `E1`, `E2`, … The agent maps those to real
`evidence_id`s. Recordings don't depend on random ids, and short references are harder for a
model to garble.

**Loop.** Messages start with the system prompt and the incident and its alerts as JSON. The
tool call cap is `MAX_TOOL_CALLS = 6`. On each LLM response:
- **A tool call** past the cap stops the investigation with `tool_call_cap`.
- **An unknown tool or invalid params** stops it with `invalid_output`.
- **Any other tool call** runs the tool. The result becomes an `EvidenceItem`, and the model
  gets `{"ref": "E<n>", "data": ...}` as a tool message. Tool output is always delivered as
  JSON data, never inserted into instructions.
- **A final answer** is parsed into the agent's draft schema: classification, confidence,
  summary, techniques, attack chain, cited refs, risk factors, and proposed actions with refs.
  It's rejected as `invalid_output` if:
  - it doesn't parse;
  - it cites a ref that wasn't collected;
  - it's malicious but cites no evidence;
  - a proposed action cites an unknown ref.

  Otherwise it becomes a `Verdict` with `arm=a3_tool_using_agent` and
  `stop_reason=verdict_reached`.

If the investigation stops without a verdict, the agent produces a fallback verdict:
`inconclusive`, confidence 0, no proposed actions, and the stop reason in the summary.

The `agent` package imports nothing from `policy` or any executor, and nothing that runs
commands. A test enforces this.

The recorded S1 answer is `malicious`, techniques `T1110.001` and `T1078`, a two-step attack
chain citing E1, and one proposed action: `disable_account` on `jdoe`.

### 5. Risk scoring

`score_risk(incident, alerts, evidence, inventory, now)` uses only deterministic inputs:
alert severity, the structured content of `auth_history` evidence, and the inventory. It never
reads the LLM's verdict.

| Factor | Points |
|---|---|
| `alert_severity` (highest across alerts) | info 0, low 5, medium 15, high 25, critical 35 |
| `failed_attempts` (most failures from one IP in the window) | ≥20 → 20, ≥10 → 10 |
| `success_after_failures` | 25 |
| `new_source_ip` (the success came from an IP not in `known_source_ips`) | 20 |
| `privileged_account` (per the inventory) | 15 |

The score is the sum, capped at 100. Severity bands: ≥80 critical, ≥60 high, ≥35 medium,
≥15 low, otherwise info.

For reference, S1 scores 15 + 20 + 25 + 20 = 80 (critical). A benign twin with 6 failures
from a known IP would score 15 + 25 = 40 (medium).

### 6. Policy engine

`decide(action, verdict, incident, risk, inventory, now) -> PolicyDecision`. The first
matching rule wins. `matched_rule` holds the rule name.

1. `no_action`: `no_action` → ALLOW.
2. `not_in_executor_catalog`: not `disable_account` or `isolate_host` → DENY.
3. `target_type_mismatch`: `disable_account` must target an account and `isolate_host` a
   host → DENY.
4. `protected_target`: the inventory marks the target protected → DENY.
5. `target_not_in_incident`: the target isn't one of the incident's entities → DENY.
6. `verdict_not_malicious`: the verdict isn't malicious → DENY.
7. `disable_account_requires_approval` → REQUIRE_APPROVAL. There is no path to ALLOW.
8. `isolate_host_requires_approval` → REQUIRE_APPROVAL.

Autonomy is fixed at `act_with_approval` for the slice and recorded on each decision. No
rule depends on it yet. Other autonomy levels come in with the executor.

After policy, the pipeline sets the incident status:
- `awaiting_approval` if any decision requires approval;
- `closed_benign` if the verdict is benign;
- `investigating` otherwise.

## API

- `GET /health`: unchanged.
- `GET /api/runs`: every `IncidentRun` in `SENTINEL_RUNS_DIR` (default `runs/`), newest first.
- `GET /api/runs/{incident_id}`: one run, or 404.

Files are validated as `IncidentRun` when loaded, so a malformed file fails loudly.

## Frontend

Vite + React + TypeScript with plain CSS and no UI library. Types are generated from
`contracts/schemas/IncidentRun.schema.json` with `json-schema-to-typescript` into
`src/types/contracts.ts` (`npm run gen:types`) and committed. The Vite dev server proxies
`/api` to `localhost:8000`.

The page has a list of runs on the left. The selected run shows the stages in pipeline order:

1. **Incident:** title, status, window, entities; protected entities are marked.
2. **Detection:** alerts (rule, severity, techniques, event count), plus a collapsible table of
   normalized events.
3. **Investigation:** the evidence trail (ref, tool, parameters, summary, expandable content),
   tool calls made, stop reason, model.
4. **Verdict:** classification, confidence, summary, ATT&CK techniques, attack chain with
   evidence refs.
5. **Risk:** score, severity, factor breakdown.
6. **Response:** each proposed action with its policy decision (outcome, matched rule, reason).

A banner states that the run uses recorded LLM responses and names the recording source. The
page has no approve/deny controls until the executor exists.

## Testing

pytest, no network, no paid API:

- **Ingest:** failed, accepted and invalid-user lines parse; unrelated lines are skipped.
- **Sigma:**
  - the burst fires at the threshold but not below it;
  - grouping keeps different IPs and users apart;
  - the base rule raises no alert of its own;
  - an unsupported rule feature fails to load.
- **Correlation:** entities and protected flags come from the inventory.
- **Agent:**
  - the replay drives a tool call and then a verdict;
  - an unknown tool leads to `invalid_output`;
  - invalid params lead to `invalid_output`;
  - hitting the cap leads to `tool_call_cap`;
  - a malicious verdict without citations is rejected;
  - citing an unknown ref is rejected;
  - an exhausted replay raises;
  - the import boundary holds.
- **Risk:** the S1 factors and score are exact; without `auth_history` evidence only the
  severity and privileged-account factors apply.
- **Policy:**
  - `disable_account` is never ALLOW at any risk score or autonomy level;
  - protected targets are denied;
  - a non-malicious verdict is denied;
  - a target outside the incident is denied;
  - actions outside the catalog are denied.
- **Pipeline:** end to end on the S1 log with the hand-written recording, producing a valid
  `IncidentRun` with a malicious verdict, risk 80, and `disable_account` at `require_approval`.
- **API:** list, get, and 404, served from a temp directory.
- **Contracts:** the existing round-trip tests plus `IncidentRun` and `Inventory.is_protected`.

CI adds a frontend job: `npm ci`, regenerate the types and fail if they're stale, then
`npm run build` (which typechecks). The dashboard is checked by hand in the browser preview.

## Decisions to log

- D-05: JSON run files for slice storage; Postgres deferred.
- D-06: contract 1.1.0 (`IncidentRun`, `Inventory`, `Verdict.stop_reason`).
