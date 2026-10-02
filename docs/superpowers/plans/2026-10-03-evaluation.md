# Evaluation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compare rules-only, a single AI call with full context, and the tool-using agent on 8
hand-labelled lab cases, and publish an honest results report.

**Architecture:**
- Contracts 1.8.0 add change windows and required evidence to `Scenario`.
- Three new read-only tools give the agent context it can choose to look up.
- The single-shot arm runs the same tools once up front, then makes one LLM call.
- `pipeline.run.run_incident` gains an `investigator` seam, so every arm goes through the real
  risk, policy and executor path.
- `eval/run.py` records live `qwen3:14b` runs and replays them to produce `eval/results.json` and
  `docs/eval-results.md`.

**Tech Stack:** Python 3.11+ (pydantic v2, pytest, ruff 0.16.4), Ollama `qwen3:14b`, existing
SENTINEL pipeline.

Spec: `docs/superpowers/specs/2026-10-03-evaluation-design.md`.

## Global Constraints

- Branch `feat/evaluation` (stacked on `feat/wazuh-report-sample`).
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "<plain sentence>"`.
  Stage files by path.
- No comments in code. `ruff check .` clean (ruff 0.16.4, line length 100, E F I UP B). No
  3.12-only syntax (CI runs Python 3.11).
- Python: `.venv/Scripts/python.exe`. For DB tests, set
  `SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:sentinel_dev@127.0.0.1:5432/sentinel_test`.
  Never use the `sentinel` database.
- Baseline: `954 passed, 2 skipped, 1 warning`.
- Contract change steps: edit `contracts/models.py`, bump `CONTRACT_VERSION` to `"1.8.0"`, run
  `python -m contracts.generate_fixtures`, run `npm run gen:types` in `frontend/`, add a DECISIONS
  entry (D-17).
- Lab data:
  - Made-up accounts only (`jdoe`, `svc_backup`, `labadmin`, `svc_deploy`, `msmith`, `kpatel`).
  - Internal IPs come from `10.77.0.0/16` and `10.80.0.0/16`. External IPs come from the
    documentation range `198.51.100.0/24`.
  - The cases are static log files. No attack traffic is generated or run.
- Every case must produce exactly one incident with `run_pipeline`. That means 10 or more
  `Failed password` lines for one account from one IP within 10 minutes. No failed password
  may appear for any other account.
- The agent never sees `Scenario.expected_classification` or `required_evidence`. Only
  `Scenario.changes` reaches a tool.
- Values:
  - Arms: `A1_RULES_ONLY`, `A2B_FULL_CONTEXT`, `A3_TOOL_USING_AGENT`.
  - 3 repeats for each AI arm.
  - A1 confidence by the highest alert severity: info 0.3, low 0.4, medium 0.6, high 0.8,
    critical 0.9.
  - The agent keeps `MAX_TOOL_CALLS = 6`.
- Cost is reported as $0 (local model). Do not invent API prices.

---

### Task 1: Contracts 1.8.0, inventory and S1 required evidence

**Files:** `contracts/models.py`, `contracts/fixtures/*` (generated), `contracts/schemas/*`
(generated), `frontend/src/types/*` (generated), `lab/inventory.yml`,
`lab/scenarios/s1_attack/scenario.yml`, `lab/scenarios/s1_benign/scenario.yml`, `DECISIONS.md`,
`tests/test_contracts.py`.

**Interfaces:**
- Produces: `ChangeWindow`, plus `Scenario.required_evidence: list[EvidenceClass]` and
  `Scenario.changes: list[ChangeWindow]`.

- [ ] **Step 1: Failing tests** in `tests/test_contracts.py`:

```python
def test_scenario_defaults_to_no_required_evidence_and_no_changes() -> None:
    scenario = Scenario(
        title="t", description="d", expected_classification=Classification.BENIGN
    )
    assert scenario.required_evidence == []
    assert scenario.changes == []


def test_change_window_must_not_end_before_it_starts() -> None:
    with pytest.raises(ValidationError):
        ChangeWindow(
            change_id="CHG-1",
            title="t",
            start=datetime(2026, 9, 27, 14, 0, tzinfo=UTC),
            end=datetime(2026, 9, 27, 13, 0, tzinfo=UTC),
        )


def test_scenario_files_validate() -> None:
    for path in sorted((REPO / "lab" / "scenarios").glob("*/scenario.yml")):
        scenario = Scenario.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        assert scenario.required_evidence, path
```

  Import `ChangeWindow`, `yaml` and `REPO` (`from tests.conftest import REPO`) as needed.

- [ ] **Step 2:** Run `.venv/Scripts/python.exe -m pytest tests/test_contracts.py -q`. Expect an
  ImportError for `ChangeWindow`.
- [ ] **Step 3: Implement.** In `contracts/models.py`, add this before `Scenario` and replace
  `Scenario`:

```python
class ChangeWindow(SentinelModel):
    """A documented, approved change. Lab context that can explain otherwise odd activity."""

    change_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    start: datetime
    end: datetime
    accounts: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    description: str = ""

    @model_validator(mode="after")
    def _ends_after_start(self) -> ChangeWindow:
        if self.end < self.start:
            raise ValueError("a change window cannot end before it starts")
        return self


class Scenario(SentinelModel):
    """A prepared lab case with its hand-labelled expected outcome. Never shown to the agent."""

    title: str
    description: str
    expected_classification: Classification
    required_evidence: list[EvidenceClass] = Field(default_factory=list)
    changes: list[ChangeWindow] = Field(default_factory=list)
```

  Import `model_validator` from pydantic if it is not imported yet. Set
  `CONTRACT_VERSION = "1.8.0"`.

  Add `required_evidence: [auth_history]` to both S1 `scenario.yml` files.

  Add three accounts to `lab/inventory.yml`:

```yaml
  svc_deploy:
    role: CI deploy service account
  msmith:
    role: analyst
  kpatel:
    role: developer
```

- [ ] **Step 4:** Run `.venv/Scripts/python.exe -m contracts.generate_fixtures`, then
  `npm run gen:types` in `frontend/`. Then run the full suite and ruff. Expected: all pass.
- [ ] **Step 5:** Add D-17 to the top of `DECISIONS.md`. Cover the decision (contracts 1.8.0,
  three arms, 8 cases), why, and the consequence, following the D-16 format. Commit with
  "Contracts 1.8.0: change windows and required evidence for the evaluation".

---

### Task 2: Token and latency accounting

**Files:** `agent/llm.py`, `agent/ollama.py`, `agent/investigate.py`, `tests/test_llm.py`,
`tests/test_ollama.py`, `tests/test_investigate.py`.

**Interfaces:**
- Produces:
  - `ToolCall` and `FinalAnswer` gain `input_tokens: int = 0`, `output_tokens: int = 0` and
    `elapsed_ms: int = 0` (dataclass fields with defaults, after the existing fields).
  - `RecordedToolCall` and `RecordedFinal` gain the same three fields, each defaulting to 0.
  - `investigate` fills `Verdict.input_tokens`, `output_tokens` and `latency_ms`.

- [ ] **Step 1: Failing tests**
  - `tests/test_llm.py`: a `Recording` whose responses carry `input_tokens=100`,
    `output_tokens=20` and `elapsed_ms=1500`. `ReplayClient` returns them.
    `RecordingClient(inner)` copies them into `recording()`. A recording without the fields
    still validates, with zeros.
  - `tests/test_ollama.py`: an `httpx.MockTransport` answers `/api/chat` with
    `{"message": {"content": "{\"classification\": \"benign\"}"}, "prompt_eval_count": 321, "eval_count": 45}`.
    `OllamaClient(transport=...).complete(...)` returns a `FinalAnswer` with
    `input_tokens == 321`, `output_tokens == 45` and `elapsed_ms >= 0`.
  - `tests/test_investigate.py`: a `ReplayClient` with one tool call (`input_tokens=100`,
    `output_tokens=10`, `elapsed_ms=1000`) and a valid final (`200`, `30`, `2000`). The verdict
    has `input_tokens == 300`, `output_tokens == 40` and `latency_ms == 3000`. With all zeros,
    `latency_ms` is the measured wall time (`>= 0`).
- [ ] **Step 2:** Run the three test files. Expect failures.
- [ ] **Step 3: Implement.**
  - `agent/llm.py`:
    - Add the fields.
    - `ReplayClient.complete` passes the recorded values into `ToolCall` and `FinalAnswer`.
    - `RecordingClient.complete` copies `response.input_tokens`, `output_tokens` and
      `elapsed_ms` into the recorded entries.
  - `agent/ollama.py`:
    - Wrap the POST in `time.perf_counter()`.
    - Read `data.get("prompt_eval_count", 0)` and `data.get("eval_count", 0)`.
    - Set `elapsed_ms=int((time.perf_counter() - started) * 1000)` on the returned `ToolCall` or
      `FinalAnswer`.
  - `agent/investigate.py`: after each `llm.complete`, add the response's three values to
    running totals. In `common`, set `"input_tokens"` and `"output_tokens"` to the totals, and
    set `"latency_ms"` to the elapsed total if it is above 0, else the measured wall time.
- [ ] **Step 4:** Run the three files, the full suite and ruff. Commit with "Record tokens and
  model time for every LLM answer and sum them into the verdict".

---

### Task 3: Three new read-only tools

**Files:**
- Create: `agent/tools/account_context.py`, `agent/tools/source_ip_history.py`,
  `agent/tools/change_windows.py`, `tests/test_context_tools.py`.
- Modify: `agent/tools/base.py`, `agent/tools/__init__.py`, `agent/tools/auth_history.py`,
  `agent/investigate.py`, `pipeline/run.py`, `agent/prompts/system.md`.

**Interfaces:**
- Consumes: `ChangeWindow`, `Inventory`.
- Produces:
  - `ToolContext` gains `inventory: Inventory | None = None` and
    `changes: list[ChangeWindow] = field(default_factory=list)`.
  - `agent.tools.base.source_ip(event: Event) -> str` moves here from `auth_history._src_ip`;
    `auth_history` imports it.
  - Tool constants `ACCOUNT_CONTEXT`, `SOURCE_IP_HISTORY` and `CHANGE_WINDOWS`.
  - `TOOLS` = `auth_history`, `account_context`, `source_ip_history`, `change_windows`, in that
    order. `WAZUH_TOOLS` is unchanged.
  - `investigate(..., inventory: Inventory | None = None, changes: list[ChangeWindow] | None = None)`.
  - `run_incident` passes `inventory=inventory` and
    `changes=scenario.changes if scenario else []`.

- [ ] **Step 1: Failing tests** in `tests/test_context_tools.py`. Use the `s1` fixture from
  conftest (`s1.incident`, `s1.events`, `s1.inventory`):

```python
from __future__ import annotations

from datetime import timedelta

from agent.tools import TOOLS
from agent.tools.account_context import AccountContextParams, account_context
from agent.tools.base import ToolContext
from agent.tools.change_windows import ChangeWindowsParams, change_windows
from agent.tools.source_ip_history import SourceIpHistoryParams, source_ip_history
from contracts.models import ChangeWindow, EvidenceClass


def _context(s1, changes=()) -> ToolContext:
    return ToolContext(
        incident=s1.incident, events=s1.events, inventory=s1.inventory, changes=list(changes)
    )


def test_tools_are_registered_in_order() -> None:
    assert list(TOOLS) == ["auth_history", "account_context", "source_ip_history", "change_windows"]
    assert TOOLS["account_context"].evidence_class is EvidenceClass.ENTITY_CONTEXT
    assert TOOLS["source_ip_history"].evidence_class is EvidenceClass.NETWORK_ACTIVITY
    assert TOOLS["change_windows"].evidence_class is EvidenceClass.CHANGE_WINDOW


def test_account_context_reports_the_inventory_record(s1) -> None:
    result = account_context(AccountContextParams(account="labadmin"), _context(s1))
    assert result.content == {
        "account": "labadmin",
        "known": True,
        "role": "lab administrator",
        "privileged": True,
        "protected": True,
    }
    assert "privileged" in result.summary and "protected" in result.summary
    unknown = account_context(AccountContextParams(account="nobody"), _context(s1))
    assert unknown.content["known"] is False
    assert "not in the inventory" in unknown.summary


def test_source_ip_history_lists_every_account_the_ip_tried(s1) -> None:
    result = source_ip_history(SourceIpHistoryParams(ip="10.66.0.10"), _context(s1))
    [entry] = result.content["accounts"]
    assert (entry["account"], entry["failures"], entry["successes"]) == ("jdoe", 24, 1)
    assert result.content["total_events"] == 25
    assert len(result.source_event_ids) == 25
    known = source_ip_history(SourceIpHistoryParams(ip="10.77.0.50"), _context(s1))
    assert [a["account"] for a in known.content["accounts"]] == ["jdoe"]
    none = source_ip_history(SourceIpHistoryParams(ip="192.0.2.1"), _context(s1))
    assert none.content["accounts"] == []
    assert "No authentication events" in none.summary


def test_change_windows_finds_overlapping_changes_that_mention_the_subject(s1) -> None:
    start = s1.incident.window_start
    covering = ChangeWindow(
        change_id="CHG-1",
        title="Rotate jdoe",
        start=start - timedelta(hours=1),
        end=start + timedelta(hours=1),
        accounts=["jdoe"],
    )
    elsewhere = ChangeWindow(
        change_id="CHG-2",
        title="Patch db",
        start=start - timedelta(hours=1),
        end=start + timedelta(hours=1),
        hosts=["victim-db-01"],
    )
    long_ago = ChangeWindow(
        change_id="CHG-3",
        title="Old",
        start=start - timedelta(days=10),
        end=start - timedelta(days=9),
        accounts=["jdoe"],
    )
    context = _context(s1, [covering, elsewhere, long_ago])
    found = change_windows(ChangeWindowsParams(account="jdoe"), context)
    assert [c["change_id"] for c in found.content["changes"]] == ["CHG-1"]
    everything = change_windows(ChangeWindowsParams(), context)
    assert [c["change_id"] for c in everything.content["changes"]] == ["CHG-1", "CHG-2"]
    nothing = change_windows(ChangeWindowsParams(ip="198.51.100.9"), context)
    assert nothing.content["changes"] == []
    assert "No documented change" in nothing.summary
```

  Also add to `tests/test_investigate.py` a test that `run_incident` with a `Scenario` whose
  `changes` holds one window makes the agent's `change_windows` call see it. Use a
  `ReplayClient` with a `change_windows` tool call, then a valid benign final. The evidence item
  content lists the change.

- [ ] **Step 2:** Run the tests. Expect import failures.
- [ ] **Step 3: Implement.**

  `agent/tools/base.py`: add the two `ToolContext` fields (import `field` from dataclasses, and
  `ChangeWindow` and `Inventory` from contracts) and:

```python
def source_ip(event: Event) -> str:
    if event.network is None or event.network.src_ip is None:
        return "unknown"
    return event.network.src_ip
```

  In `auth_history.py`, delete `_src_ip`, import `source_ip`, and replace its uses.

  `agent/tools/account_context.py`:

```python
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import EvidenceClass


class AccountContextParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str = Field(min_length=1, max_length=256)


def account_context(params: AccountContextParams, context: ToolContext) -> ToolResult:
    inventory = context.inventory
    record = inventory.accounts.get(params.account) if inventory else None
    content = {
        "account": params.account,
        "known": record is not None,
        "role": record.role if record else None,
        "privileged": record.privileged if record else False,
        "protected": record.protected if record else False,
    }
    if record is None:
        summary = f"{params.account} is not in the inventory."
    else:
        flags = [flag for flag in ("privileged", "protected") if content[flag]]
        summary = f"{params.account}: {record.role}" + "".join(f", {f}" for f in flags) + "."
    return ToolResult(summary=summary, content=content, source_event_ids=[])


ACCOUNT_CONTEXT = Tool(
    name="account_context",
    description=(
        "What the inventory says about one account: its role, and whether it is privileged or "
        "protected. Says so when the account is not in the inventory."
    ),
    params=AccountContextParams,
    evidence_class=EvidenceClass.ENTITY_CONTEXT,
    run=account_context,
)
```

  `agent/tools/source_ip_history.py`:

```python
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult, source_ip
from contracts.models import EventCategory, EvidenceClass


class SourceIpHistoryParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str = Field(min_length=1, max_length=64)
    lookback_hours: int = Field(default=168, ge=1, le=720)


def source_ip_history(params: SourceIpHistoryParams, context: ToolContext) -> ToolResult:
    incident = context.incident
    range_start = incident.window_start - timedelta(hours=params.lookback_hours)
    range_end = max((e.timestamp for e in context.events), default=incident.window_end)
    events = sorted(
        (
            e
            for e in context.events
            if e.category is EventCategory.AUTHENTICATION
            and source_ip(e) == params.ip
            and range_start <= e.timestamp <= range_end
        ),
        key=lambda e: e.timestamp,
    )
    accounts: dict[str, dict[str, Any]] = {}
    for event in events:
        name = event.user or "unknown"
        entry = accounts.setdefault(
            name,
            {
                "account": name,
                "failures": 0,
                "successes": 0,
                "first_seen": event.timestamp.isoformat(),
                "last_seen": event.timestamp.isoformat(),
            },
        )
        if event.outcome == "failure":
            entry["failures"] += 1
        elif event.outcome == "success":
            entry["successes"] += 1
        entry["last_seen"] = event.timestamp.isoformat()
    content = {
        "ip": params.ip,
        "range_start": range_start.isoformat(),
        "range_end": range_end.isoformat(),
        "total_events": len(events),
        "accounts": list(accounts.values()),
    }
    return ToolResult(
        summary=_summary(params.ip, content, range_start, range_end),
        content=content,
        source_event_ids=[e.event_id for e in events],
    )


def _summary(ip: str, content: dict[str, Any], start: datetime, end: datetime) -> str:
    window = f"between {start:%Y-%m-%d %H:%M} and {end:%Y-%m-%d %H:%M} UTC"
    if not content["accounts"]:
        return f"No authentication events from {ip} {window}."
    parts = ", ".join(
        f"{a['account']} ({a['failures']} failed, {a['successes']} successful)"
        for a in content["accounts"]
    )
    count = len(content["accounts"])
    return f"{ip} tried {count} account{'' if count == 1 else 's'} {window}: {parts}."


SOURCE_IP_HISTORY = Tool(
    name="source_ip_history",
    description=(
        "Every account one source IP tried to log in as, with failed and successful logins per "
        "account, from lookback_hours before the incident window up to the latest event."
    ),
    params=SourceIpHistoryParams,
    evidence_class=EvidenceClass.NETWORK_ACTIVITY,
    run=source_ip_history,
)
```

  `agent/tools/change_windows.py`:

```python
from __future__ import annotations

from datetime import timedelta

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import ChangeWindow, EvidenceClass


class ChangeWindowsParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str | None = Field(default=None, max_length=256)
    host: str | None = Field(default=None, max_length=256)
    ip: str | None = Field(default=None, max_length=64)
    hours_around: int = Field(default=24, ge=0, le=168)


def change_windows(params: ChangeWindowsParams, context: ToolContext) -> ToolResult:
    incident = context.incident
    start = incident.window_start - timedelta(hours=params.hours_around)
    end = incident.window_end + timedelta(hours=params.hours_around)
    found = [
        change
        for change in sorted(context.changes, key=lambda c: (c.start, c.change_id))
        if change.start <= end and change.end >= start and _mentions(change, params)
    ]
    content = {
        "range_start": start.isoformat(),
        "range_end": end.isoformat(),
        "account": params.account,
        "host": params.host,
        "ip": params.ip,
        "changes": [change.model_dump(mode="json") for change in found],
    }
    if found:
        listed = "; ".join(
            f"{c.change_id} {c.title} ({c.start:%Y-%m-%d %H:%M} to {c.end:%Y-%m-%d %H:%M} UTC)"
            for c in found
        )
        summary = f"{len(found)} documented change{'' if len(found) == 1 else 's'}: {listed}."
    else:
        summary = "No documented change covers this time for the given account, host or IP."
    return ToolResult(summary=summary, content=content, source_event_ids=[])


def _mentions(change: ChangeWindow, params: ChangeWindowsParams) -> bool:
    if params.account is None and params.host is None and params.ip is None:
        return True
    return (
        (params.account is not None and params.account in change.accounts)
        or (params.host is not None and params.host in change.hosts)
        or (params.ip is not None and params.ip in change.source_ips)
    )


CHANGE_WINDOWS = Tool(
    name="change_windows",
    description=(
        "Documented, approved changes (for example password rotations or network changes) that "
        "overlap the incident window, plus or minus hours_around, and mention the given "
        "account, host or IP. With none given, lists every overlapping change."
    ),
    params=ChangeWindowsParams,
    evidence_class=EvidenceClass.CHANGE_WINDOW,
    run=change_windows,
)
```

  `agent/tools/__init__.py`: import the three constants. Set
  `TOOLS = {tool.name: tool for tool in (AUTH_HISTORY, ACCOUNT_CONTEXT, SOURCE_IP_HISTORY, CHANGE_WINDOWS)}`.

  `agent/investigate.py`: add the `inventory` and `changes` parameters, and build
  `ToolContext(incident=incident, events=events, history=history, inventory=inventory, changes=list(changes or []))`.

  `pipeline/run.py` `run_incident`: pass `inventory=inventory` and
  `changes=scenario.changes if scenario else []` to the investigator.

  `agent/prompts/system.md`: in "Judging the evidence", after the sentence ending "repeated.",
  add: "Check what kind of account it is and whether a documented change, such as a password
  rotation or a network move, explains the activity. A change explains activity only when it
  names the same account, host or source and covers the time."

- [ ] **Step 4:** Run `tests/test_context_tools.py`, `tests/test_auth_history.py`,
  `tests/test_investigate.py`, `tests/test_pipeline.py`, then the full suite and ruff. The
  existing S1 replays must still pass. Commit with "Give the agent account context, source IP
  history and change windows".

---

### Task 4: Eight labelled cases

**Files:**
- Create `lab/scenarios/{s2_attack,s2_benign,s3_attack,s3_benign,s4_attack,s4_benign}/auth.log`
  and `scenario.yml`.
- Create `tests/test_scenarios.py`.

**Interfaces:**
- Consumes: Task 1's `Scenario` fields, Task 3's tools.
- Produces: 8 case folders, each with `auth.log` and `scenario.yml`, that `eval/run.py` will
  discover.

**Line formats.** Copy them exactly. `{ts}` is ISO-8601 with microseconds and `+00:00`, as in
`lab/scenarios/s1_attack/auth.log`. Every line is on host `victim-web-01`. Each failed attempt
gets its own pid, increasing:

```
{ts} victim-web-01 sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2
{ts} victim-web-01 sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid={uid}) by {user}(uid=0)
{ts} victim-web-01 sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}
{ts} victim-web-01 sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2
```

- **uids:** `labadmin` 1000, `jdoe` 1001, `svc_backup` 1002, `svc_deploy` 1003, `msmith` 1004,
  `kpatel` 1005.
- **Baseline logins:** each is three lines (accepted, session opened, session closed 8 hours
  later; 30 minutes later for service accounts).
- **Timestamps:** add a few microseconds of jitter so lines are not identical, and keep every
  file in time order.

| Case | Baseline (one login per day, 2026-09-21 to 2026-09-26) | Incident lines | `changes` |
|---|---|---|---|
| `s2_attack` | `labadmin` from `10.77.0.5` at 10:00 on 09-22 and 09-24 only; `jdoe` from `10.77.0.50` at 09:00 daily | 2026-09-27T03:40:00: 15 `Failed password for labadmin from 198.51.100.23`, every 20 s, no success | none |
| `s2_benign` | `svc_deploy` from `10.77.0.30` at 14:00 daily | 2026-09-27T14:00:05: 12 `Failed password for svc_deploy from 10.77.0.30`, every 30 s; then at 14:20:00 `Accepted password for svc_deploy from 10.77.0.30` with a session | `CHG-2041` "Rotate svc_deploy credentials", 2026-09-27T13:55:00Z to 14:30:00Z, accounts `[svc_deploy]`, hosts `[victim-web-01]`, source_ips `[10.77.0.30]`, description "Scheduled rotation. The CI runner keeps using the old password until its secret store syncs." |
| `s3_attack` | `msmith` from `10.77.0.64` at 08:30 daily; `kpatel` from `10.77.0.61` at 09:00 daily | 2026-09-27T22:15:00: 11 `Failed password for msmith from 10.77.0.61`, every 25 s; then at 22:20:30 `Accepted password for msmith from 10.77.0.61` with a session | none |
| `s3_benign` | `msmith` from `10.77.0.64` at 08:30 daily | 2026-09-27T08:31:00: 10 `Failed password for msmith from 10.77.0.64`, every 40 s; then at 08:45:00 `Accepted password for msmith from 10.77.0.64` with a session | none |
| `s4_attack` | `jdoe` from `10.77.0.50` at 09:00 daily | 2026-09-28T02:40:00: 13 `Failed password for jdoe from 198.51.100.77`, every 15 s; then at 02:44:00 `Accepted password for jdoe from 198.51.100.77` with a session | `CHG-2060` "Patch victim-db-01", 2026-09-28T01:00:00Z to 04:00:00Z, hosts `[victim-db-01]`, description "Monthly patching." |
| `s4_benign` | `jdoe` from `10.77.0.50` at 09:00 daily | 2026-09-28T09:05:00: 12 `Failed password for jdoe from 10.80.0.15`, every 20 s; then at 09:12:00 `Accepted password for jdoe from 10.80.0.15` with a session | `CHG-2070` "Move VPN egress to 10.80.0.15 and reset VPN passwords", 2026-09-28T06:00:00Z to 18:00:00Z, source_ips `[10.80.0.15]`, description "VPN users connect from 10.80.0.15 from today. Their passwords were reset, so saved passwords fail until updated." |

`scenario.yml` per case. The titles and descriptions are plain English, and the descriptions
tell the story as in the spec's table.
- `expected_classification`: `malicious` for `*_attack`, `benign` for `*_benign`.
- `required_evidence`:
  - `s2_attack`: `[auth_history, entity_context]`
  - `s2_benign`: `[auth_history, change_window]`
  - `s3_attack`: `[auth_history, network_activity]`
  - `s3_benign`: `[auth_history]`
  - `s4_attack`: `[auth_history, change_window]`
  - `s4_benign`: `[auth_history, change_window]`
- `changes`: as in the table, as YAML.

You may write the logs with a throwaway script, but do not commit it.

- [ ] **Step 1: Failing test** `tests/test_scenarios.py`:

```python
from __future__ import annotations

import pytest
import yaml

from contracts.models import Classification, Scenario
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log
from pipeline.run import INVENTORY_FILE, RULES_DIR, load_inventory
from tests.conftest import REPO

CASES = sorted(p.parent.name for p in (REPO / "lab" / "scenarios").glob("*/scenario.yml"))


def test_there_are_four_attack_benign_pairs() -> None:
    assert CASES == [f"s{n}_{kind}" for n in range(1, 5) for kind in ("attack", "benign")]


@pytest.mark.parametrize("case_id", CASES)
def test_each_case_yields_one_brute_force_incident(case_id: str) -> None:
    folder = REPO / "lab" / "scenarios" / case_id
    lines = (folder / "auth.log").read_text(encoding="utf-8").splitlines()
    events = parse_auth_log(lines, case_id)
    alerts = detect(events, load_rules(RULES_DIR), case_id)
    [incident] = correlate(alerts, events, load_inventory(INVENTORY_FILE), case_id)
    names = {a.rule_name for a in alerts if a.alert_id in incident.alert_ids}
    assert "SSH password brute force" in names
    scenario = Scenario.model_validate(yaml.safe_load((folder / "scenario.yml").read_text()))
    expected = Classification.MALICIOUS if case_id.endswith("attack") else Classification.BENIGN
    assert scenario.expected_classification is expected
    assert scenario.required_evidence


@pytest.mark.parametrize("case_id", ["s2_benign", "s4_benign"])
def test_benign_changes_cover_the_incident(case_id: str) -> None:
    folder = REPO / "lab" / "scenarios" / case_id
    scenario = Scenario.model_validate(yaml.safe_load((folder / "scenario.yml").read_text()))
    events = parse_auth_log((folder / "auth.log").read_text().splitlines(), case_id)
    alerts = detect(events, load_rules(RULES_DIR), case_id)
    [incident] = correlate(alerts, events, load_inventory(INVENTORY_FILE), case_id)
    [change] = scenario.changes
    assert change.start <= incident.window_start and change.end >= incident.window_end
```

  Check the real names: `INVENTORY_FILE` and `RULES_DIR` in `pipeline/run.py`, and the
  brute-force rule's `rule_name` (it may be the rule `name` or `title`). Adapt the test, not
  the data.

- [ ] **Step 2:** Run it. Expect failures for the missing cases.
- [ ] **Step 3:** Write the 12 files.
- [ ] **Step 4:** Run `tests/test_scenarios.py`, the full suite and ruff. Replay
  `python -m pipeline.run lab/scenarios/s2_attack/auth.log` only if a replay recording exists;
  otherwise skip it. Commit with "Add three more attack and benign twin cases for the
  evaluation".

---

### Task 5: The rules-only and single-shot arms

**Files:**
- Create: `eval/arms.py`, `agent/single_shot.py`, `tests/test_arms.py`.
- Modify: `agent/investigate.py`, `pipeline/run.py`.

**Interfaces:**
- Consumes: Tasks 2 and 3.
- Produces:
  - In `agent/investigate.py`, the private helpers become public, renamed and used by
    `investigate`:
    - `incident_message(incident, alerts) -> str`
    - `parse_draft(payload, refs) -> VerdictDraft | None`
    - `build_verdict(draft, refs, common) -> Verdict`
    - `fallback_verdict(stop, common) -> Verdict`
    - `evidence_item(tool, query, result, incident, now) -> EvidenceItem`
  - `Investigator` (a `Protocol` in `pipeline/run.py`) with the call signature of
    `investigate`.
  - `run_incident(..., investigator: Investigator = investigate)` and
    `run_pipeline(..., investigator: Investigator = investigate)`. `run_pipeline` passes it to
    `run_incident`.
  - `eval.arms.rules_only(incident, alerts, events, llm, **_) -> tuple[Verdict, list[EvidenceItem]]`
    and `eval.arms.RULES_CONFIDENCE: dict[Severity, float]`.
  - `agent.single_shot.single_shot(incident, alerts, events, llm, *, tools=TOOLS, now=utcnow, history=None, inventory=None, changes=None, **_) -> tuple[Verdict, list[EvidenceItem]]`
    and `agent.single_shot.bundle_queries(incident) -> list[tuple[str, dict[str, Any]]]`.

- [ ] **Step 1: Failing tests** `tests/test_arms.py`, using the `s1` fixture:
  - **Rules only.** `rules_only(s1.incident, s1.alerts, s1.events, None)` gives:
    - classification `malicious`, arm `A1_RULES_ONLY`;
    - confidence `RULES_CONFIDENCE[max severity of the incident's alerts]` (medium, so 0.6);
    - no evidence, no actions, `tool_calls_made == 0`, `input_tokens == 0`;
    - a summary that names the rule.
  - **Bundle.** `bundle_queries(s1.incident)` returns exactly
    `[("auth_history", {"account": "jdoe"}), ("account_context", {"account": "jdoe"}), ("source_ip_history", {"ip": "10.66.0.10"}), ("change_windows", {"account": "jdoe", "host": "victim-web-01", "ip": "10.66.0.10"})]`.
  - **Single shot, valid answer.** A `ReplayClient` with one final answer that is a valid benign
    verdict citing `E1` gives:
    - arm `A2B_FULL_CONTEXT`, 4 evidence items in the bundle order, `tool_calls_made == 0`;
    - the cited evidence is the `auth_history` item;
    - the client was called with an empty tool list (wrap the replay in a small spy that records
      the `tools` argument).
  - **Single shot, tool call instead of an answer.** If the model returns a tool call, the
    verdict is the fallback (`inconclusive`, stop reason `invalid_output`).
  - **Single shot, fake ref.** A final answer citing `E9`, which does not exist, gives the
    fallback.
  - **The seam.** `run_incident(..., investigator=rules_only)` returns an `IncidentRun` whose
    verdict arm is `A1_RULES_ONLY` and whose `policy_decisions` is empty.
- [ ] **Step 2:** Run it. Expect import failures.
- [ ] **Step 3: Implement.**

  `pipeline/run.py`:

```python
class Investigator(Protocol):
    def __call__(
        self,
        incident: Incident,
        alerts: list[Alert],
        events: list[Event],
        llm: LLMClient,
        *,
        tools: dict[str, Tool],
        now: Callable[[], datetime],
        system_prompt: str,
        history: HostHistory | None,
        inventory: Inventory | None,
        changes: list[ChangeWindow],
    ) -> tuple[Verdict, list[EvidenceItem]]: ...
```

  `run_incident` calls
  `investigator(incident, alerts, events, llm, tools=tools, now=now, system_prompt=system_prompt, history=history, inventory=inventory, changes=scenario.changes if scenario else [])`.

  `eval/arms.py`:

```python
from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from contracts.models import (
    Alert,
    Classification,
    EvaluationArm,
    Event,
    EvidenceItem,
    Incident,
    InvestigationStopReason,
    Severity,
    Verdict,
)

RULES_CONFIDENCE = {
    Severity.INFO: 0.3,
    Severity.LOW: 0.4,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 0.9,
}
ORDER = list(RULES_CONFIDENCE)


def rules_only(
    incident: Incident,
    alerts: list[Alert],
    events: list[Event],
    llm: Any,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    **_: Any,
) -> tuple[Verdict, list[EvidenceItem]]:
    top = max((alert.rule_severity for alert in alerts), key=ORDER.index)
    names = sorted({alert.rule_name for alert in alerts if alert.rule_severity is top})
    return (
        Verdict(
            incident_id=incident.incident_id,
            arm=EvaluationArm.A1_RULES_ONLY,
            classification=Classification.MALICIOUS,
            confidence=RULES_CONFIDENCE[top],
            summary=(
                f"Rule {', '.join(names)} fired. Rules alone call every alert like this "
                "malicious; they cannot look at context."
            ),
            produced_at=now(),
            stop_reason=InvestigationStopReason.VERDICT_REACHED,
        ),
        [],
    )
```

  `agent/single_shot.py`:
  - Build the bundle with `bundle_queries`. It skips any query whose subject is missing: the
    account is the first `ACCOUNT` entity, the host the first `HOST`, the IP the first
    `IP_ADDRESS`.
  - Run each tool through `tool.params.model_validate(args)` and `tool.run`, and make each
    `EvidenceItem` with `evidence_item`, with refs `E1` to `E4` in order.
  - Send one message list:
    - the system prompt
      `SYSTEM_PROMPT.replace("{max_tool_calls}", "0") + "\n\n" + SINGLE_SHOT_NOTE`, with
      `SINGLE_SHOT_NOTE = "In this run you have no tools. All the evidence is already below as refs E1 to E4, gathered for the incident's own account, host and source IP. Do not call tools. Answer once with the final JSON."`;
    - the user message: `incident_message(...)`, then
      `"\n\nEvidence:\n" + json.dumps([{"ref": ref, "tool": name, "data": {"summary": ..., "content": ...}}, ...], indent=2)`.
  - Call `llm.complete(messages, [])` once.
  - A `FinalAnswer` goes through `parse_draft`, giving `VERDICT_REACHED`, or `INVALID_OUTPUT`
    when it is `None`. A `ToolCall` gives `INVALID_OUTPUT`.
  - `common` has `arm=A2B_FULL_CONTEXT`, `tool_calls_made=0`, the tokens and latency from the one
    response (wall time when `elapsed_ms` is 0), `model_name=llm.model_name`, and
    `produced_at=now()`.
  - Return `build_verdict` or `fallback_verdict`, plus the 4 evidence items.

  Refactor `agent/investigate.py` to the public helper names. Keep `investigate`'s behaviour
  byte for byte: the S1 replay tests must not change.

- [ ] **Step 4:** Run `tests/test_arms.py`, `tests/test_investigate.py`,
  `tests/test_pipeline.py`, then the full suite and ruff. Commit with "Add the rules-only and
  single-shot arms behind an investigator seam".

---

### Task 6: The evaluation runner, metrics and report

**Files:**
- Create: `eval/run.py`, `eval/metrics.py`, `eval/report.py`, `tests/test_eval.py`.

**Interfaces:**
- Consumes: `run_pipeline(..., investigator=...)`, the arms, `ReplayClient`, `RecordingClient`
  and `OllamaClient`.
- Produces:
  - `eval.metrics.EvalRow`: a pydantic model, `extra="forbid"`, with these fields:
    - `case_id: str`, `pair: str`, `expected: Classification`, `arm: EvaluationArm`,
      `repeat: int`;
    - `actual: Classification`, `correct: bool`, `confidence: float`, `false_positive: bool`;
    - `required_evidence: list[EvidenceClass]`, `cited_classes: list[EvidenceClass]`,
      `evidence_ok: bool`;
    - `tool_calls: int`, `input_tokens: int`, `output_tokens: int`, `latency_ms: int`;
    - `prohibited_proposed: int`, `prohibited_executed: int`;
    - `stop_reason: InvestigationStopReason`, `model_name: str | None`.
  - `eval.metrics.row(case_id, scenario, arm, repeat, run) -> EvalRow`.
  - `eval.metrics.ArmSummary`: a pydantic model with these fields:
    - `arm`, `runs`;
    - `accuracy`, `accuracy_min` and `accuracy_max` (over repeats);
    - `false_positives` and `benign_runs`;
    - `evidence_rate`;
    - `mean_tool_calls`, `mean_input_tokens`, `mean_output_tokens` and `mean_latency_ms`;
    - `prohibited_proposed` and `prohibited_executed`.
  - `eval.metrics.summarize(rows) -> list[ArmSummary]`, in arm order A1, A2b, A3.
  - `eval.report.render(rows, summaries) -> str`.
  - `eval.run.main(argv) -> int` with these flags:
    - `--llm replay|ollama` (default `replay`), `--ollama-url` (default
      `http://127.0.0.1:11434`), `--model` (default `qwen3:14b`);
    - `--repeats` (default 3), `--cases` (comma-separated filter);
    - `--recordings` (default `eval/recordings`), `--results` (default `eval/results.json`),
      `--report` (default `docs/eval-results.md`).

**Metric rules:**
- `pair` is the case id up to the underscore (`s1`).
- `false_positive` is `expected == benign and actual == malicious`.
- `cited_classes` holds the evidence classes of the run's evidence items whose id is in
  `verdict.cited_evidence_ids`, sorted and unique.
- `evidence_ok` is `set(required_evidence) <= set(cited_classes)`.
- `prohibited_proposed` counts the `policy_decisions` with outcome `DENY`.
- `prohibited_executed` counts the `executions` whose `action_id` belongs to a denied decision
  and whose status is not `REJECTED`.
- `accuracy` is correct over runs for the arm. `accuracy_min` and `accuracy_max` are the lowest
  and highest per-repeat accuracy, where one repeat means all 8 cases. A1 has one repeat, so
  min = max.
- `evidence_rate` counts runs with `evidence_ok` over runs. Report it as "n/a" for A1, which
  cites no evidence.

**Runner rules:**
- Cases are every folder under `lab/scenarios` with both `auth.log` and `scenario.yml`, sorted.
- The clock is fixed, `datetime(2026, 10, 3, tzinfo=UTC)`, so results are deterministic.
- A1 runs once per case and needs no LLM. Pass any client; it is not called.
- Each AI arm runs `--repeats` times per case. The recording path is
  `{recordings}/{case_id}.{arm.value}.{n}.json`, with n from 1.
- `--llm ollama`:
  - Wrap a fresh `OllamaClient` in a `RecordingClient` per run, and write the recording with
    `model_dump_json(indent=2) + "\n"`.
  - Skip a run whose recording already exists, so the run can resume, and print one line per
    run with the case, arm, repeat, result and seconds.
  - Then build the results from the recordings exactly as replay does.
- `--llm replay`: a missing recording prints its path and exits with code 2.
- Write `results.json` as `[row.model_dump(mode="json") ...]`, indented, with a trailing
  newline. Write the report with `newline="\n"`.

**Report content** (`render`), in order:
1. `# Evaluation results`.
2. The model line.
3. The summary table, one row per arm. Columns: Arm | Accuracy (min–max over 3 runs) | False
   alarms on benign twins | Required evidence cited | Tool calls | Tokens in / out | Time per
   case | Prohibited actions proposed / executed.
4. A per-case table. Columns: Case | Expected | Rules only | Single call | Agent. Each AI cell
   counts the classifications over the repeats, for example `benign 2, inconclusive 1`.
5. "Where the agent did not win". Generated bullets for:
   - cases where A3 was correct in fewer runs than A2b;
   - cases where both AI arms missed every run;
   - one line comparing the two AI arms' overall accuracy, saying plainly whether the agent
     beat the single call.
6. "How this was measured", with these caveats:
   - the author wrote and labelled the cases;
   - 8 cases is small;
   - there is one local 14B model with temperature 0, yet runs still differ;
   - rules-only is a deliberate baseline;
   - the single call gets the same evidence the agent can ask for, so this measures adaptivity,
     not access;
   - time is the model's own time on an RTX 3060;
   - cost is $0 because the model runs locally.

- [ ] **Step 1: Failing tests** `tests/test_eval.py`:
  - `row` on an `IncidentRun` built by `run_pipeline` for `s1_attack` with `rules_only` gives
    `correct=True`, `false_positive=False`, `evidence_ok=False` and 0 prohibited actions.
  - `row` for `s1_benign` with `rules_only` gives `false_positive=True`.
  - `row` counts a DENY decision as prohibited proposed. Use a hand-built `IncidentRun` copy
    with one DENY `PolicyDecision` and one `REJECTED` execution for it: proposed 1, executed 0.
    With a `SUCCEEDED` execution for it, executed is 1.
  - `summarize` on hand-made rows (2 repeats × 2 cases) computes `accuracy`, `accuracy_min`,
    `accuracy_max`, `false_positives` and the means.
  - `render` on those rows contains the summary header, a per-case cell
    `benign 1, inconclusive 1`, and "Where the agent did not win".
  - `main` in replay mode with a temporary recordings folder: write the 2 recordings per AI arm
    for `s1_attack` and `s1_benign` (`--cases s1_attack,s1_benign --repeats 1`, so 4 files). Use
    the existing handwritten recordings in `agent/recordings` for A3. For A2b, write a single
    final answer that cites `E1`. `main` returns 0, writes both files, and the results hold 6
    rows.
  - `main` with a missing recording returns 2.
- [ ] **Step 2:** Run it. Expect import failures.
- [ ] **Step 3:** Implement the three modules to the rules above.
- [ ] **Step 4:** Run `tests/test_eval.py`, then the full suite and ruff. Commit with "Run the
  three arms over the labelled cases and write an honest report".

---

### Task 7: Record the live runs (controller, on Ahmed's PC)

- [ ] Make sure the Ollama container is up and has `qwen3:14b`. The worker must not be running
  (one GPU).
- [ ] Run
  `.venv/Scripts/python.exe -m eval.run --llm ollama --repeats 3 > eval/run.log`. That is
  48 AI runs, about 1 hour. Re-run it to resume after any interruption.
- [ ] Read every A3 and A2b result for sanity, for example invalid outputs and stalls. Do not
  edit recordings. If the model stalls, the client timeout ends the run, which is recorded as a
  miss.
- [ ] Add `tests/test_eval_replay.py`. It runs `main(["--results", tmp/"r.json",
  "--report", tmp/"r.md"])` in replay mode and asserts that `r.md` equals
  `docs/eval-results.md` and `r.json` equals `eval/results.json`, byte for byte.
- [ ] Commit `eval/recordings/*.json`, `eval/results.json`, `docs/eval-results.md` and the test
  with "Record the evaluation runs and publish the results". Do not commit `eval/run.log`;
  add it to `.gitignore`.

---

### Task 8: README, CLAUDE.md, final review and PR (controller)

- [ ] In the README, add a "Results" section after "What it does", with the summary table copied
  from `docs/eval-results.md`, a one-paragraph honest reading, and a link to the full report.
- [ ] In `CLAUDE.md`, update "What already exists" with the tools, the cases, the arms and
  `eval/run.py`.
- [ ] Run the full suite and ruff. Do a final whole-branch review (opus) and fix its findings.
  Push. Open a PR with base `feat/wazuh-report-sample` and auto-fix on.
