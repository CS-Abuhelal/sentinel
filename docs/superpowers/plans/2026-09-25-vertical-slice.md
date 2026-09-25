# Vertical Slice Implementation Plan

> Executed inline in one session, test-first, one commit per task. Spec:
> `docs/superpowers/specs/2026-09-25-vertical-slice-design.md`.

**Goal:** One hardcoded S1 sshd log flows log → Event → Alert → Incident → agent (replayed) →
Verdict → RiskScore → PolicyDecision → run file → API → dashboard.

**Architecture:** Each stage is a pure function over contract models. `pipeline.run` chains them
and writes `runs/<case_id>.json`. FastAPI serves the run files read-only. A Vite + React page
renders them.

**Tech stack:** Python 3.11+ (dev machine has 3.14), Pydantic 2, PyYAML, FastAPI, pytest, ruff
0.16.4 · Node 24, Vite, React, TypeScript, json-schema-to-typescript.

## Global constraints

- No comments in code (including no docstrings on new code).
- Code must run on Python 3.11. That's the version CI and the Dockerfile use.
- `ruff check .` clean, `pytest -q` green, fixtures not stale, before every commit.
- No new data shape outside `contracts/` crosses a stage boundary.
- Tests never touch the network or a paid API.
- Commits use author `Ahmed Helal <abuh3lal@gmail.com>` via `git -c` (no global git identity is
  configured).

---

### Task 1: Contracts 1.1.0

**Files:** modify `contracts/models.py`, `contracts/generate_fixtures.py`,
`tests/test_contracts.py`, `DECISIONS.md`; regenerated `contracts/fixtures/*`,
`contracts/schemas/*` plus new `incident_run.json` and `IncidentRun.schema.json`.

**Produces:**
- `InvestigationStopReason` (`VERDICT_REACHED`, `TOOL_CALL_CAP`, `INVALID_OUTPUT`)
- `Verdict.stop_reason: InvestigationStopReason` (required)
- `AccountRecord(role: str, privileged: bool = False, protected: bool = False)`
- `HostRecord(role: str, protected: bool = False)`
- `Inventory(accounts: dict[str, AccountRecord], hosts: dict[str, HostRecord])`, which has
  `is_protected(entity_type: EntityType, value: str) -> bool` and
  `is_privileged(account: str) -> bool`
- `IncidentRun(run_id, case_id, contract_version, created_at, events, alerts, incident,
  evidence, verdict, risk_score, policy_decisions)`
- `CONTRACT_VERSION = "1.1.0"`, moved above the models

**Tests:**
- `incident_run` fixture round-trips.
- `Verdict` without `stop_reason` is rejected.
- `Inventory.is_protected` covers accounts, hosts, unknown values, and IP entities (always
  False).
- `Inventory.is_privileged` works.

Steps: write tests → fail → implement → regenerate with `python -m contracts.generate_fixtures`
→ pass → log D-06 → commit.

### Task 2: S1 scenario, inventory, ingest

**Files:**
- `lab/scenarios/s1_attack/auth.log`
- `lab/inventory.yml`
- `ingest/__init__.py`, `ingest/linux_auth.py`
- `tests/test_ingest.py`

**Log content:**
- Baseline: 4 × `Accepted password for jdoe from 10.77.0.50` on 2026-09-21 to 09-24.
- Attack on 2026-09-25 from 10.66.0.10:
  - 3 × `Failed password for invalid user {admin,test,oracle}` at 02:10;
  - 24 × `Failed password for jdoe`, every 15 s from 02:11:04 to 02:16:49;
  - `Accepted password for jdoe` at 02:17:03.
- Noise: `Invalid user …`, `Connection closed … [preauth]`, `pam_unix` session and CRON lines.

**Inventory:**
- `jdoe`: developer, not privileged, not protected.
- `labadmin`: lab administrator, privileged, protected.
- `victim-web-01`: web server.
- `mgmt-01`: management host, protected.

**Produces:** `parse_auth_log(lines: Iterable[str], case_id: str | None = None) -> list[Event]`

**Tests:**
- A failed line maps every field: event_type, outcome, user, `src_ip`, `src_port`,
  `dst_port=22`, and `raw.invalid_user=False`.
- An invalid-user line sets `raw.invalid_user=True` and user=`admin`.
- An accepted line gives `ssh_login_succeeded` with outcome success.
- Unrelated lines are skipped.
- The whole S1 file gives 4 + 3 + 24 + 1 = 32 events.

### Task 3: Sigma evaluator and rules

**Files:**
- `detection/__init__.py`, `detection/sigma.py`
- `detection/rules/ssh_failed_password.yml`, `detection/rules/ssh_password_bruteforce.yml`
- delete `detection/src/.gitkeep`
- `tests/test_sigma.py`

**Produces:**
- `class RuleError(ValueError)`
- `BaseRule`, `CorrelationRule`, `RuleSet(base: dict[str, BaseRule], correlations:
  list[CorrelationRule])` as frozen dataclasses
- `load_rules(directory: Path) -> RuleSet`
- `detect(events: list[Event], rules: RuleSet, case_id: str | None = None) -> list[Alert]`

**Tests** (rules written to `tmp_path` where needed):
- 10 failures in 10 minutes → one alert; 9 → none.
- 10 failures spread over 11 minutes → none.
- Two IPs with 6 failures each → none (grouping).
- The base rule referenced by a correlation raises no alert of its own.
- A standalone base rule alerts once per matching event.
- Unsupported features raise `RuleError`: an unknown condition, the `|contains` modifier, an
  unknown field, `type: temporal`.
- On the S1 events: one alert with 24 event ids, `T1110.001`, severity medium, and
  host/user/src_ip set.

### Task 4: Correlation

**Files:** `detection/correlate.py`, `tests/test_correlate.py`

**Produces:** `correlate(alerts: list[Alert], events: list[Event], inventory: Inventory,
case_id: str | None = None) -> list[Incident]`

**Tests:**
- Alerts with the same host and user merge; different users give separate incidents.
- The window spans the alerts' events, and the title is set.
- Entities are host, account and IP, with `is_protected` from the inventory (tested with a
  protected account).

### Task 5: LLM interface and auth_history tool

**Files:**
- `agent/__init__.py`, `agent/llm.py`
- `agent/tools/__init__.py`, `agent/tools/base.py`, `agent/tools/auth_history.py`
- delete `agent/tools/.gitkeep`
- `tests/test_llm.py`, `tests/test_auth_history.py`

**Produces:**
- `Message(role, content)`, `ToolSpec(name, description, parameters)`, `ToolCall(tool, args)`,
  `FinalAnswer(payload)` as frozen dataclasses; `LLMResponse = ToolCall | FinalAnswer`
- `LLMClient` Protocol with `model_name: str` and
  `complete(messages: list[Message], tools: list[ToolSpec]) -> LLMResponse`
- `Recording` (a Pydantic model), `ReplayClient(recording)`, `ReplayClient.from_file(path)`,
  `ReplayExhausted(RuntimeError)`
- `ToolContext(incident, events)`, `ToolResult(summary, content, source_event_ids)`,
  `Tool(name, description, params, evidence_class, run)` with `.spec() -> ToolSpec`
- `TOOLS: dict[str, Tool]`
- `AuthHistoryParams(account, lookback_hours=168)`
- `auth_history` content keys: `account`, `range_start`, `range_end`, `total_failures`,
  `total_successes`, `by_source_ip[{src_ip, failures, successes, first_seen, last_seen}]`,
  `success_after_failures[{src_ip, failures_before, success_at}]`, `known_source_ips`

**Tests:**
- Replay returns responses in order and raises `ReplayExhausted` after the last one.
- `from_file` parses both response types.
- On S1: total_failures 24 and total_successes 5; `success_after_failures` is
  `[{10.66.0.10, 24, 02:17:03}]`; `known_source_ips` is `[10.77.0.50]`; invalid-user events
  are excluded.
- Params reject extra fields and a `lookback_hours` out of range.

### Task 6: Investigation loop

**Files:**
- `agent/investigate.py`
- `agent/prompts/system.md`, delete `agent/prompts/.gitkeep`
- `agent/recordings/s1_attack.handwritten.json`
- `tests/test_investigate.py`

**Produces:**
- `MAX_TOOL_CALLS = 6`
- `investigate(incident, alerts, events, llm, tools=TOOLS, now=utcnow,
  max_tool_calls=MAX_TOOL_CALLS) -> tuple[Verdict, list[EvidenceItem]]`

**Tests** (using an in-test `ReplayClient` with `Recording` objects):
- Happy path: one evidence item, a malicious verdict with cited_evidence_ids = [that
  evidence_id], `verdict_reached`, 1 tool call, and the action's evidence mapped.
- Unknown tool → `invalid_output`, inconclusive, no actions.
- Bad params → `invalid_output`.
- 7 tool calls → `tool_call_cap` after 6.
- A malicious verdict with no citations → `invalid_output`.
- Citing `E9` → `invalid_output`.
- An unparseable payload → `invalid_output`.
- The tool message sent to the LLM is JSON with `ref` and `data`.
- Import boundary: the AST of every file under `agent/` imports nothing from `policy`,
  `pipeline`, `backend`, `subprocess`, `os`, `shutil` or `socket`.

### Task 7: Risk scoring and policy engine

**Files:**
- `policy/__init__.py`, `policy/risk.py`, `policy/engine.py`
- delete `policy/src/.gitkeep`
- `tests/test_risk.py`, `tests/test_policy.py`

**Produces:**
- `score_risk(incident, alerts, evidence, inventory, now) -> RiskScore`
- `EXECUTOR_CATALOG`, `decide(action, verdict, incident, risk, inventory, now) ->
  PolicyDecision`

**Risk tests:**
- S1 gives factors `{alert_severity: 15, failed_attempts: 20, success_after_failures: 25,
  new_source_ip: 20, privileged_account: 0}`, a score of 80, and severity critical.
- With no evidence, only severity (and privileged, when that applies) is counted.
- A privileged account adds 15.
- The score is capped at 100.
- The severity bands are correct.

**Policy tests:**
- Each rule in order: no_action → ALLOW; block_ip → DENY `not_in_executor_catalog`;
  disable_account on a host → DENY `target_type_mismatch`; protected `labadmin` → DENY; a
  target outside the incident → DENY; a benign verdict → DENY; disable_account on jdoe →
  REQUIRE_APPROVAL; isolate_host on victim-web-01 → REQUIRE_APPROVAL.
- `disable_account` is never ALLOW, for risk 0 to 100 and every classification (parametrized).

### Task 8: Pipeline

**Files:** `pipeline/__init__.py`, `pipeline/run.py`, `tests/test_pipeline.py`, `.gitignore`
(add `runs/`), `DECISIONS.md` (D-05)

**Produces:**
- `load_inventory(path) -> Inventory`
- `run_pipeline(lines, case_id, inventory, llm, rules=None, now=utcnow) -> IncidentRun`
- `main(argv=None) -> int`, run as `python -m pipeline.run <log> [--case-id] [--recording]
  [--inventory] [--out]`

**Tests:**
- End to end on the S1 files: a malicious verdict, risk 80, one decision with
  `require_approval` from `disable_account_requires_approval`, and incident status
  `awaiting_approval`.
- `main` writes `<out>/s1_attack.json`, which validates as `IncidentRun`.
- A log with no alerts raises `ValueError`.

### Task 9: API

**Files:** `backend/app/main.py`, `tests/test_api.py`

**Produces:** `GET /api/runs` (newest first) and `GET /api/runs/{incident_id}` (404 if
missing), with the directory taken from `SENTINEL_RUNS_DIR` (default `<repo>/runs`).

**Tests:** list, get and 404 against a temp directory, using the `incident_run.json` fixture.

### Task 10: Dashboard

**Files:**
- `frontend/package.json`, `package-lock.json`, `vite.config.ts`, `tsconfig.json`, `index.html`
- `src/main.tsx`, `src/App.tsx`, `src/api.ts`, `src/format.ts`, `src/styles.css`
- `src/types/contracts.ts` (generated)
- `src/components/*.tsx`
- delete `frontend/src/.gitkeep`
- `.github/workflows/ci.yml`: a frontend job

**Steps:**
1. Scaffold and install.
2. Run `npm run gen:types`.
3. Build the components.
4. Run `npm run build`.
5. Run the pipeline and API, open the Vite preview, and check every stage renders. Screenshot
   it at desktop and phone width.
6. Commit.

### Task 11: Docs and CI housekeeping

**Files:** `README.md` (how to run the slice), `.github/workflows/ci.yml` (bump
checkout/setup-python/setup-node to their current majors), the spec (mark it implemented).

Then push the branch and ask whether to merge.
