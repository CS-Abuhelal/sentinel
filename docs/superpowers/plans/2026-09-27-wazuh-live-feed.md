# Wazuh Live Feed (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wazuh alerts from Ahmed's Windows PC reach SENTINEL in real time, are stored in PostgreSQL, are backfilled after downtime, and show up on a live "My PC" dashboard page.

**Architecture:** A Wazuh custom integration POSTs each alert (level 3 and up) to a token-protected
FastAPI endpoint. The endpoint converts it into the existing `Event` and `Alert` contracts and
stores it idempotently in Postgres. On start, the backend backfills anything missed from the
Wazuh indexer. The React dashboard polls `GET /api/pc/feed` every 5 seconds. Wazuh runs as its
own Docker project and shares the `sentinel-wazuh` network with the SENTINEL backend.

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy 2 (Core), Alembic, psycopg 3, httpx, pydantic 2,
pytest, React 19 + TypeScript + Vite, json-schema-to-typescript, Docker Compose, Wazuh 4.14
(wazuh-docker single-node).

Spec: `docs/superpowers/specs/2026-09-27-wazuh-live-advisor-design.md`. This plan covers phase 1
only.

## Global Constraints

- Work on branch `feat/wazuh-live-feed`, created from `docs/wazuh-live-advisor-design`.
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit ...`.
  There is no global git identity on this machine.
- No comments in code (repo rule). Docstrings on contract models follow the existing style.
- `ruff check .` must stay clean (`ruff==0.16.4`, line length 100, rules E, F, I, UP, B). Use
  `Annotated[..., Depends(...)]` for FastAPI parameters, because B008 flags calls in defaults.
- Contract changes: change `contracts/models.py`, bump `CONTRACT_VERSION`, run
  `python -m contracts.generate_fixtures`, run `npm run gen:types` in `frontend/`, and log the
  change in `DECISIONS.md`. Never define a data shape outside `contracts/`.
- Values from the spec: integration level `3`; ingest body limit `1_000_000` bytes; token env var
  `SENTINEL_INGEST_TOKEN`; backfill limit `5000` alerts at `rule.level >= 3` from
  `wazuh-alerts-4.x-*`; Wazuh API probe cache `30` seconds; dashboard poll `5` seconds; Wazuh
  `4.14`.
- Level to severity: 0–3 info, 4–6 low, 7–9 medium, 10–12 high, 13–15 critical.
- Real PC data is never committed. Test data uses the placeholders `my-pc` and `user1`.
- Python commands run with the repo's virtual environment: `.venv\Scripts\python` in PowerShell,
  `.venv/Scripts/python.exe` in Git Bash. `python` below means that interpreter.
- Database tests need Postgres and are skipped unless `SENTINEL_TEST_DATABASE_URL` is set. Task 3
  shows how to set it locally. CI sets it.

## File Structure

| Path | Responsibility |
|---|---|
| `contracts/models.py` | 1.4.0: new enums, `Finding`, `Recommendation`, `HostAssessment`, `LiveAlert`, `ServiceState`, `PcStatus`, `PcFeed` |
| `contracts/generate_fixtures.py` | fixtures and schemas for the new models |
| `ingest/wazuh.py` | pure conversion from a Wazuh alert dict to `Event`, `Alert` and `LiveAlert` |
| `backend/app/db.py` | table definitions, `database_url()`, `get_engine()` |
| `backend/alembic.ini`, `backend/migrations/env.py`, `backend/migrations/versions/0001_wazuh_alerts.py` | schema migrations |
| `backend/app/store.py` | alert queries: insert, latest, count, newest time |
| `backend/app/ingest.py` | `POST /api/ingest/wazuh` |
| `backend/app/wazuh.py` | Wazuh API reachability probe with a 30-second cache |
| `backend/app/backfill.py` | fetch missed alerts from the indexer and store them |
| `backend/app/pc.py` | `GET /api/pc/feed` |
| `backend/app/main.py` | router wiring and a lifespan that starts the backfill |
| `frontend/src/components/MyPc.tsx` | live page: status bar and alert table |
| `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/styles.css` | view switch, feed client, styles |
| `lab/wazuh/` | setup README, integration script and launcher, config block, compose override |
| `docker-compose.yml`, `docker-compose.wazuh.yml`, `backend/Dockerfile`, `.env.example` | running the service |
| `tests/data/wazuh/*.json` | representative Wazuh alerts (placeholders only) |
| `tests/test_wazuh_convert.py`, `tests/test_store.py`, `tests/test_ingest_api.py`, `tests/test_wazuh_probe.py`, `tests/test_backfill.py`, `tests/test_pc_feed.py`, `tests/test_wazuh_integration_script.py` | tests |

---

### Task 0: Branch

- [ ] **Step 1: Create the feature branch**

```bash
cd <your SENTINEL checkout>
git switch docs/wazuh-live-advisor-design
git switch -c feat/wazuh-live-feed
```

Expected: `Switched to a new branch 'feat/wazuh-live-feed'`.

---

### Task 1: Contracts 1.4.0

**Files:**
- Modify: `contracts/models.py`
- Modify: `contracts/generate_fixtures.py`
- Modify: `tests/test_contracts.py`
- Modify: `frontend/package.json` (`gen:types` script)
- Modify: `frontend/src/format.ts` (`STATUS`)
- Modify: `DECISIONS.md` (D-12)
- Generated: `contracts/fixtures/*.json`, `contracts/schemas/*.schema.json`,
  `frontend/src/types/contracts.ts`, `frontend/src/types/pc.ts`

**Interfaces:**
- Produces (in `contracts.models`):
  - `TelemetrySource.WAZUH`
  - `IncidentStatus.QUEUED`, `IncidentStatus.LOW_PRIORITY`, `IncidentStatus.INVESTIGATION_FAILED`
  - `HostRecord.personal: bool = False`
  - `FindingKind`, `FindingStatus`, `Finding`, `Recommendation`, `HostAssessment`
  - `LiveAlert(wazuh_id: str, received_at: datetime, level: int, event: Event, alert: Alert)`
  - `ServiceState(reachable: bool, detail: str | None = None)`
  - `PcStatus(checked_at: datetime, wazuh_api: ServiceState, backfill: ServiceState,
    alert_count: int, last_alert_at: datetime | None = None)`
  - `PcFeed(status: PcStatus, alerts: list[LiveAlert] = [])`
  - `Verdict.recommendations: list[Recommendation] = []`
- Produces (frontend): `src/types/pc.ts`, which exports `PcFeed`, `PcStatus`, `ServiceState`,
  `LiveAlert` and the rest.

- [ ] **Step 1: Write the failing contract tests**

In `tests/test_contracts.py`, extend the `from contracts.models import (...)` list with
`Finding`, `HostAssessment`, `LiveAlert`, `PcFeed` and `Recommendation`. Add these entries to
`FIXTURE_MODEL_MAP`:

```python
    "live_alert": LiveAlert,
    "pc_feed": PcFeed,
    "finding_vulnerability": Finding,
    "finding_configuration": Finding,
    "recommendation": Recommendation,
    "host_assessment": HostAssessment,
```

Append at the end of the file:

```python
def test_recommendation_caps_steps() -> None:
    with pytest.raises(ValidationError):
        Recommendation(title="Too many steps", priority=50, steps=["Do it."] * 11)
    with pytest.raises(ValidationError):
        Recommendation(title="Step too long", priority=50, steps=["x" * 301])


def test_host_record_is_not_personal_by_default() -> None:
    assert HostRecord(role="web server").personal is False


def test_live_alert_level_stays_in_wazuh_range() -> None:
    payload = _load("live_alert")
    payload["level"] = 16
    with pytest.raises(ValidationError):
        LiveAlert.model_validate(payload)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_contracts.py -q`
Expected: collection error, `ImportError: cannot import name 'Finding' from 'contracts.models'`.

- [ ] **Step 3: Change the models**

In `contracts/models.py`:

1. Replace the imports and the version:

```python
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

CONTRACT_VERSION = "1.4.0"
```

2. Add to `TelemetrySource`, after `ZEEK_HTTP`:

```python
    WAZUH = "wazuh"
```

3. Add to `IncidentStatus`, after `CLOSED_BENIGN`:

```python
    QUEUED = "queued"
    LOW_PRIORITY = "low_priority"
    INVESTIGATION_FAILED = "investigation_failed"
```

4. After the `EvaluationArm` enum, add:

```python
class FindingKind(StrEnum):
    VULNERABILITY = "vulnerability"
    CONFIGURATION = "configuration"


class FindingStatus(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
```

5. Directly before `class Verdict`, add:

```python
FixStep = Annotated[str, StringConstraints(min_length=1, max_length=300)]


class Recommendation(SentinelModel):
    """Plain-language advice for the owner of a monitored PC. SENTINEL never carries it out."""

    recommendation_id: str = Field(default_factory=lambda: _new_id("rec"))
    title: str
    priority: int = Field(ge=0, le=100)
    steps: list[FixStep] = Field(default_factory=list, max_length=10)
    finding_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    official_remediation: str | None = None
    dropped_steps: list[str] = Field(default_factory=list)
```

6. In `Verdict`, after `proposed_actions`, add:

```python
    recommendations: list[Recommendation] = Field(default_factory=list)
```

7. In `HostRecord`, after `protected`, add:

```python
    personal: bool = False
```

8. Directly before `class IncidentRun`, add:

```python
class Finding(SentinelModel):
    """One weak spot on a monitored PC: a vulnerable package or a failed CIS check."""

    finding_id: str = Field(default_factory=lambda: _new_id("fnd"))
    kind: FindingKind
    key: str = Field(min_length=1)
    host: str
    title: str
    severity: Severity
    priority: int = Field(ge=0, le=100)
    status: FindingStatus = FindingStatus.OPEN
    cve: str | None = None
    package: str | None = None
    installed_version: str | None = None
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    policy_id: str | None = None
    check_id: str | None = None
    rationale: str | None = None
    official_remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    related_alert_count: int = Field(default=0, ge=0)
    first_seen: datetime
    last_seen: datetime
    raw: dict[str, Any] = Field(default_factory=dict)


class HostAssessment(SentinelModel):
    """The weak spots found on one PC and the advice written for them."""

    assessment_id: str = Field(default_factory=lambda: _new_id("asm"))
    host: str
    contract_version: str = CONTRACT_VERSION
    created_at: datetime
    synced_at: datetime
    findings: list[Finding] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    model_name: str | None = None


class LiveAlert(SentinelModel):
    """A Wazuh alert from the live feed, with the event and alert it was converted into."""

    wazuh_id: str = Field(min_length=1)
    received_at: datetime
    level: int = Field(ge=0, le=15)
    event: Event
    alert: Alert


class ServiceState(SentinelModel):
    reachable: bool
    detail: str | None = None


class PcStatus(SentinelModel):
    checked_at: datetime
    wazuh_api: ServiceState
    backfill: ServiceState
    alert_count: int = Field(ge=0)
    last_alert_at: datetime | None = None


class PcFeed(SentinelModel):
    """What the live My PC page polls for."""

    status: PcStatus
    alerts: list[LiveAlert] = Field(default_factory=list)
```

9. Add these names to `__all__`, keeping it alphabetical: `"Finding"`, `"FindingKind"`,
   `"FindingStatus"`, `"HostAssessment"`, `"LiveAlert"`, `"PcFeed"`, `"PcStatus"`,
   `"Recommendation"`, `"ServiceState"`.

- [ ] **Step 4: Add the fixtures**

In `contracts/generate_fixtures.py`, add `Finding`, `FindingKind`, `HostAssessment`, `LiveAlert`,
`PcFeed`, `PcStatus`, `Recommendation` and `ServiceState` to the `from contracts.models import`
list. Directly before `FIXTURES = {`, add:

```python
WZ_T0 = datetime(2026, 9, 27, 9, 30, 0, tzinfo=UTC)
PC = "my-pc"

wazuh_event = Event(
    event_id="evt_wz_1790501400_1042",
    timestamp=WZ_T0,
    source=TelemetrySource.WAZUH,
    category=EventCategory.AUTHENTICATION,
    event_type="wazuh:60122",
    host=PC,
    user="user1",
    outcome="failure",
    network=NetworkInfo(src_ip="127.0.0.1"),
    message="Logon failure - Unknown user or bad password.",
    raw={"id": "1790501400.1042", "rule": {"id": "60122", "level": 5}},
)

wazuh_alert = Alert(
    alert_id="alr_wz_1790501400_1042",
    rule_id="wazuh-60122",
    rule_name="Logon failure - Unknown user or bad password.",
    rule_severity=Severity.LOW,
    timestamp=WZ_T0,
    host=PC,
    user="user1",
    src_ip="127.0.0.1",
    description="Logon failure - Unknown user or bad password.",
    event_ids=[wazuh_event.event_id],
    suggested_techniques=["T1531"],
)

live_alert = LiveAlert(
    wazuh_id="1790501400.1042",
    received_at=WZ_T0 + timedelta(seconds=2),
    level=5,
    event=wazuh_event,
    alert=wazuh_alert,
)

pc_feed = PcFeed(
    status=PcStatus(
        checked_at=WZ_T0 + timedelta(seconds=5),
        wazuh_api=ServiceState(reachable=True, detail="Wazuh API answered HTTP 401."),
        backfill=ServiceState(reachable=True, detail="Backfilled 0 of 0 alerts at 09:29:40 UTC."),
        alert_count=1,
        last_alert_at=WZ_T0,
    ),
    alerts=[live_alert],
)

finding_vulnerability = Finding(
    finding_id="fnd_3c9a1e7b2d40",
    kind=FindingKind.VULNERABILITY,
    key="cve:CVE-2025-55130:node.js",
    host=PC,
    title="Node.js 22.11.0 is affected by CVE-2025-55130",
    severity=Severity.CRITICAL,
    priority=91,
    cve="CVE-2025-55130",
    package="node.js",
    installed_version="22.11.0",
    cvss=9.1,
    references=["https://nvd.nist.gov/vuln/detail/CVE-2025-55130"],
    first_seen=WZ_T0 - timedelta(days=3),
    last_seen=WZ_T0,
)

finding_configuration = Finding(
    finding_id="fnd_8f21c04d6e11",
    kind=FindingKind.CONFIGURATION,
    key="sca:cis_win11_enterprise:26001",
    host=PC,
    title="Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'.",
    severity=Severity.HIGH,
    priority=70,
    policy_id="cis_win11_enterprise",
    check_id="26001",
    rationale="With the public profile firewall off, the PC accepts unsolicited connections.",
    official_remediation="Set Windows Defender Firewall public profile state to On.",
    first_seen=WZ_T0 - timedelta(days=3),
    last_seen=WZ_T0,
)

recommendation = Recommendation(
    recommendation_id="rec_5b7d2e9a0c13",
    title="Update Node.js",
    priority=91,
    steps=[
        "Download the current Node.js LTS installer from nodejs.org.",
        "Run it to replace version 22.11.0.",
        "Run node --version to confirm the new version.",
    ],
    finding_ids=[finding_vulnerability.finding_id],
)

host_assessment = HostAssessment(
    assessment_id="asm_1e4f7a2c9b30",
    host=PC,
    created_at=WZ_T0,
    synced_at=WZ_T0 - timedelta(minutes=2),
    findings=[finding_vulnerability, finding_configuration],
    recommendations=[recommendation],
    model_name="qwen3:14b",
)
```

Add to the `FIXTURES` dict:

```python
    "live_alert": live_alert,
    "pc_feed": pc_feed,
    "finding_vulnerability": finding_vulnerability,
    "finding_configuration": finding_configuration,
    "recommendation": recommendation,
    "host_assessment": host_assessment,
```

Add `PcFeed` and `HostAssessment` to the end of `SCHEMA_MODELS`.

- [ ] **Step 5: Regenerate fixtures and schemas, then run the tests**

Run: `python -m contracts.generate_fixtures`
Expected: prints `fixture contracts/fixtures/live_alert.json`, `... pc_feed.json`,
`... host_assessment.json`, `schema contracts/schemas/PcFeed.schema.json` and
`schema contracts/schemas/HostAssessment.schema.json`, among the existing lines.

Run: `python -m pytest -q`
Expected: all pass. Database tests don't exist yet.

- [ ] **Step 6: Generate the frontend types and fix the status labels**

In `frontend/package.json`, replace the `gen:types` script with:

```json
    "gen:types": "json2ts -i ../contracts/schemas/IncidentRun.schema.json -o src/types/contracts.ts --bannerComment \"\" && json2ts -i ../contracts/schemas/PcFeed.schema.json -o src/types/pc.ts --bannerComment \"\""
```

In `frontend/src/format.ts`, extend `STATUS`:

```ts
export const STATUS: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  awaiting_approval: "Awaiting approval",
  resolved: "Resolved",
  closed_benign: "Closed as benign",
  queued: "Queued for the AI",
  low_priority: "Low priority",
  investigation_failed: "Investigation failed",
};
```

Run (in `frontend/`): `npm run gen:types && npm run build`
Expected: `src/types/pc.ts` is created, and the build ends with `✓ built in`.

- [ ] **Step 7: Log the decision**

In `DECISIONS.md`, insert directly after the first `---` line:

```markdown
## D-12 — Contracts 1.4.0: live alerts, findings and advice (2026-09-27)

**Decision.** Add `TelemetrySource.WAZUH`; `IncidentStatus` values `queued`, `low_priority` and
`investigation_failed`; `HostRecord.personal`; `FindingKind`, `FindingStatus`, `Finding`,
`Recommendation` and `HostAssessment`; `LiveAlert`, `ServiceState`, `PcStatus` and `PcFeed`; and
`Verdict.recommendations`.

**Why.** The live advisor (D-11) needs shapes for stored alerts, the live page, weak spots and
advice. Defining them all at once keeps a single version bump for the feature, and lets the
dashboard generate its types from them.

**Consequence.** `Recommendation` caps its steps at 10, each at most 300 characters, in the
contract itself. The dashboard gets a second generated type file, `src/types/pc.ts`, from
`PcFeed.schema.json`.

---
```

- [ ] **Step 8: Lint and commit**

Run: `python -m ruff check .`
Expected: `All checks passed!`

```bash
git add contracts tests/test_contracts.py frontend/package.json frontend/src/format.ts frontend/src/types DECISIONS.md
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Contracts 1.4.0: live alerts, findings and advice"
```

---

### Task 2: Wazuh alert converter

**Files:**
- Create: `ingest/wazuh.py`
- Create: `tests/data/wazuh/logon_failure.json`, `tests/data/wazuh/process_sysmon.json`,
  `tests/data/wazuh/fim_change.json`
- Test: `tests/test_wazuh_convert.py`

**Interfaces:**
- Consumes: the Task 1 contracts.
- Produces (in `ingest.wazuh`):
  - `class WazuhAlertError(ValueError)`
  - `severity_for_level(level: int) -> Severity`
  - `category_for_groups(groups: list[str]) -> EventCategory`
  - `parse_timestamp(value: str) -> datetime`
  - `convert(payload: dict[str, Any]) -> tuple[Event, Alert]`
  - `live_alert(payload: dict[str, Any], received_at: datetime) -> LiveAlert`
- Ids are `evt_wz_<slug>` and `alr_wz_<slug>`, where the slug is the Wazuh id with every
  non-alphanumeric character replaced by `_`.

- [ ] **Step 1: Add the test alerts**

`tests/data/wazuh/logon_failure.json`:

```json
{
  "timestamp": "2026-09-27T12:30:00.123+0300",
  "rule": {
    "level": 5,
    "description": "Logon failure - Unknown user or bad password.",
    "id": "60122",
    "mitre": {"id": ["T1531"], "tactic": ["Impact"], "technique": ["Account Access Removal"]},
    "firedtimes": 1,
    "mail": false,
    "groups": ["windows", "windows_security", "authentication_failed"]
  },
  "agent": {"id": "001", "name": "my-pc", "ip": "127.0.0.1"},
  "manager": {"name": "wazuh.manager"},
  "id": "1790501400.1042",
  "decoder": {"name": "windows_eventchannel"},
  "data": {
    "win": {
      "system": {
        "eventID": "4625",
        "providerName": "Microsoft-Windows-Security-Auditing",
        "channel": "Security"
      },
      "eventdata": {
        "targetUserName": "user1",
        "targetDomainName": "MY-PC",
        "logonType": "2",
        "ipAddress": "127.0.0.1",
        "processName": "C:\\Windows\\System32\\svchost.exe",
        "status": "0xc000006d",
        "subStatus": "0xc000006a"
      }
    }
  },
  "location": "EventChannel"
}
```

`tests/data/wazuh/process_sysmon.json`:

```json
{
  "timestamp": "2026-09-27T09:40:00.000+0000",
  "rule": {
    "level": 12,
    "description": "Powershell process spawned with an encoded command.",
    "id": "92052",
    "mitre": {"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]},
    "groups": ["windows", "sysmon", "sysmon_event1"]
  },
  "agent": {"id": "001", "name": "my-pc", "ip": "127.0.0.1"},
  "id": "1790502000.2001",
  "data": {
    "win": {
      "system": {"eventID": "1", "channel": "Microsoft-Windows-Sysmon/Operational"},
      "eventdata": {
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "commandLine": "powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwAgAGgAaQA=",
        "parentImage": "C:\\Windows\\explorer.exe",
        "user": "MY-PC\\user1"
      }
    }
  },
  "location": "EventChannel"
}
```

`tests/data/wazuh/fim_change.json`:

```json
{
  "timestamp": "2026-09-27T09:45:00.000+0000",
  "rule": {
    "level": 7,
    "description": "Integrity checksum changed.",
    "id": "550",
    "mitre": {"id": ["T1565.001"], "tactic": ["Impact"], "technique": ["Stored Data Manipulation"]},
    "groups": ["ossec", "syscheck", "syscheck_entry_modified", "syscheck_file"]
  },
  "agent": {"id": "001", "name": "my-pc", "ip": "127.0.0.1"},
  "id": "1790502300.2210",
  "syscheck": {"path": "c:\\windows\\system32\\drivers\\etc\\hosts", "event": "modified"},
  "location": "syscheck"
}
```

- [ ] **Step 2: Write the failing tests**

`tests/test_wazuh_convert.py`:

```python
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from contracts.models import EventCategory, Severity, TelemetrySource
from ingest.wazuh import (
    WazuhAlertError,
    category_for_groups,
    convert,
    live_alert,
    parse_timestamp,
    severity_for_level,
)

DATA = Path(__file__).resolve().parent / "data" / "wazuh"


def _payload(name: str) -> dict[str, Any]:
    return json.loads((DATA / f"{name}.json").read_text(encoding="utf-8"))


def test_logon_failure_becomes_an_authentication_failure() -> None:
    payload = _payload("logon_failure")
    event, alert = convert(payload)
    assert event.source is TelemetrySource.WAZUH
    assert event.category is EventCategory.AUTHENTICATION
    assert event.outcome == "failure"
    assert event.event_type == "wazuh:60122"
    assert (event.host, event.user) == ("my-pc", "user1")
    assert event.network is not None and event.network.src_ip == "127.0.0.1"
    assert event.timestamp == datetime(2026, 9, 27, 9, 30, 0, 123000, tzinfo=UTC)
    assert event.raw == payload
    assert alert.rule_id == "wazuh-60122"
    assert alert.rule_severity is Severity.LOW
    assert alert.suggested_techniques == ["T1531"]
    assert alert.event_ids == [event.event_id]
    assert (event.event_id, alert.alert_id) == (
        "evt_wz_1790501400_1042",
        "alr_wz_1790501400_1042",
    )


def test_process_alert_keeps_the_process_details() -> None:
    event, alert = convert(_payload("process_sysmon"))
    assert event.category is EventCategory.PROCESS
    assert event.process is not None
    assert event.process.name.endswith("powershell.exe")
    assert "-EncodedCommand" in event.process.command_line
    assert event.process.parent_name == "C:\\Windows\\explorer.exe"
    assert event.user is None
    assert alert.rule_severity is Severity.HIGH
    assert alert.suggested_techniques == ["T1059.001"]


def test_file_integrity_alert_keeps_the_path() -> None:
    event, alert = convert(_payload("fim_change"))
    assert event.category is EventCategory.FILE
    assert event.file_path == "c:\\windows\\system32\\drivers\\etc\\hosts"
    assert alert.rule_severity is Severity.MEDIUM


@pytest.mark.parametrize(
    "level,severity",
    [
        (0, Severity.INFO),
        (3, Severity.INFO),
        (4, Severity.LOW),
        (6, Severity.LOW),
        (7, Severity.MEDIUM),
        (9, Severity.MEDIUM),
        (10, Severity.HIGH),
        (12, Severity.HIGH),
        (13, Severity.CRITICAL),
        (15, Severity.CRITICAL),
    ],
)
def test_level_maps_to_severity(level: int, severity: Severity) -> None:
    assert severity_for_level(level) is severity


def test_unknown_groups_are_other() -> None:
    assert category_for_groups(["ossec", "rootcheck"]) is EventCategory.OTHER


def test_timestamps_accept_compact_and_z_offsets() -> None:
    expected = datetime(2026, 9, 27, 9, 30, tzinfo=UTC)
    assert parse_timestamp("2026-09-27T12:30:00+0300") == expected
    assert parse_timestamp("2026-09-27T09:30:00Z") == expected
    with pytest.raises(WazuhAlertError):
        parse_timestamp("2026-09-27T09:30:00")


def test_dash_means_empty() -> None:
    payload = _payload("logon_failure")
    payload["data"]["win"]["eventdata"]["ipAddress"] = "-"
    payload["data"]["win"]["eventdata"]["targetUserName"] = "-"
    event, alert = convert(payload)
    assert event.network is None
    assert (event.user, alert.src_ip) == (None, None)


@pytest.mark.parametrize("field", ["id", "timestamp", "rule", "agent"])
def test_missing_required_field_is_rejected(field: str) -> None:
    payload = _payload("logon_failure")
    del payload[field]
    with pytest.raises(WazuhAlertError, match=field):
        convert(payload)


@pytest.mark.parametrize("level", [-1, 16, "5", None])
def test_bad_level_is_rejected(level: object) -> None:
    payload = _payload("logon_failure")
    payload["rule"]["level"] = level
    with pytest.raises(WazuhAlertError):
        convert(payload)


def test_live_alert_wraps_the_conversion() -> None:
    received = datetime(2026, 9, 27, 9, 30, 2, tzinfo=UTC)
    live = live_alert(_payload("logon_failure"), received_at=received)
    assert (live.wazuh_id, live.level, live.received_at) == ("1790501400.1042", 5, received)
    assert live.alert.event_ids == [live.event.event_id]
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `python -m pytest tests/test_wazuh_convert.py -q`
Expected: `ModuleNotFoundError: No module named 'ingest.wazuh'`.

- [ ] **Step 4: Write the converter**

`ingest/wazuh.py`:

```python
from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from contracts.models import (
    Alert,
    Event,
    EventCategory,
    LiveAlert,
    NetworkInfo,
    ProcessInfo,
    Severity,
    TelemetrySource,
)

REQUIRED_FIELDS = ("id", "timestamp", "rule", "agent")

CATEGORY_GROUPS: tuple[tuple[EventCategory, frozenset[str]], ...] = (
    (
        EventCategory.AUTHENTICATION,
        frozenset({"authentication_failed", "authentication_success", "win_authentication"}),
    ),
    (EventCategory.PROCESS, frozenset({"sysmon_event1", "process"})),
    (EventCategory.FILE, frozenset({"syscheck"})),
    (EventCategory.ACCOUNT_MANAGEMENT, frozenset({"adduser", "group_changed", "account_changed"})),
    (EventCategory.PRIVILEGE, frozenset({"privilege"})),
)


class WazuhAlertError(ValueError):
    pass


def severity_for_level(level: int) -> Severity:
    if level <= 3:
        return Severity.INFO
    if level <= 6:
        return Severity.LOW
    if level <= 9:
        return Severity.MEDIUM
    if level <= 12:
        return Severity.HIGH
    return Severity.CRITICAL


def category_for_groups(groups: list[str]) -> EventCategory:
    present = set(groups)
    for category, names in CATEGORY_GROUPS:
        if present & names:
            return category
    return EventCategory.OTHER


def parse_timestamp(value: str) -> datetime:
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", value.strip()).replace("Z", "+00:00")
    try:
        moment = datetime.fromisoformat(text)
    except ValueError as error:
        raise WazuhAlertError(f"Unreadable timestamp: {value!r}") from error
    if moment.tzinfo is None:
        raise WazuhAlertError(f"Timestamp has no time zone: {value!r}")
    return moment


def convert(payload: dict[str, Any]) -> tuple[Event, Alert]:
    missing = [field for field in REQUIRED_FIELDS if field not in payload]
    if missing:
        raise WazuhAlertError(f"Wazuh alert is missing: {', '.join(missing)}.")
    rule = _mapping(payload, "rule")
    agent = _mapping(payload, "agent")
    rule_id = _text(rule.get("id"))
    host = _text(agent.get("name"))
    if rule_id is None or host is None:
        raise WazuhAlertError("Wazuh alert needs rule.id and agent.name.")
    level = _level(rule)
    groups = [str(group) for group in rule.get("groups") or []]
    description = _text(rule.get("description")) or f"Wazuh rule {rule_id}"
    timestamp = parse_timestamp(str(payload["timestamp"]))
    eventdata = _eventdata(payload)
    user = _text(eventdata.get("targetUserName"))
    src_ip = _text(eventdata.get("ipAddress"))
    slug = re.sub(r"[^A-Za-z0-9]", "_", str(payload["id"]))
    event = Event(
        event_id=f"evt_wz_{slug}",
        timestamp=timestamp,
        source=TelemetrySource.WAZUH,
        category=category_for_groups(groups),
        event_type=f"wazuh:{rule_id}",
        host=host,
        user=user,
        outcome=_outcome(groups),
        process=_process(eventdata),
        network=NetworkInfo(src_ip=src_ip) if src_ip else None,
        file_path=_file_path(payload),
        message=description,
        raw=payload,
    )
    alert = Alert(
        alert_id=f"alr_wz_{slug}",
        rule_id=f"wazuh-{rule_id}",
        rule_name=description,
        rule_severity=severity_for_level(level),
        timestamp=timestamp,
        host=host,
        user=user,
        src_ip=src_ip,
        description=description,
        event_ids=[event.event_id],
        suggested_techniques=_techniques(rule),
    )
    return event, alert


def live_alert(payload: dict[str, Any], received_at: datetime) -> LiveAlert:
    event, alert = convert(payload)
    return LiveAlert(
        wazuh_id=str(payload["id"]),
        received_at=received_at,
        level=_level(_mapping(payload, "rule")),
        event=event,
        alert=alert,
    )


def _mapping(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload[key]
    if not isinstance(value, dict):
        raise WazuhAlertError(f"'{key}' must be an object.")
    return value


def _level(rule: dict[str, Any]) -> int:
    level = rule.get("level")
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 15:
        raise WazuhAlertError(f"rule.level must be a whole number from 0 to 15, got {level!r}.")
    return level


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text


def _eventdata(payload: dict[str, Any]) -> dict[str, Any]:
    data = payload.get("data")
    win = data.get("win") if isinstance(data, dict) else None
    eventdata = win.get("eventdata") if isinstance(win, dict) else None
    return eventdata if isinstance(eventdata, dict) else {}


def _outcome(groups: list[str]) -> str:
    if "authentication_failed" in groups or "win_authentication_failed" in groups:
        return "failure"
    if "authentication_success" in groups:
        return "success"
    return "unknown"


def _process(eventdata: dict[str, Any]) -> ProcessInfo | None:
    name = (
        _text(eventdata.get("image"))
        or _text(eventdata.get("newProcessName"))
        or _text(eventdata.get("processName"))
    )
    command_line = _text(eventdata.get("commandLine"))
    parent = _text(eventdata.get("parentImage"))
    if name is None and command_line is None and parent is None:
        return None
    return ProcessInfo(name=name, command_line=command_line, parent_name=parent)


def _file_path(payload: dict[str, Any]) -> str | None:
    syscheck = payload.get("syscheck")
    return _text(syscheck.get("path")) if isinstance(syscheck, dict) else None


def _techniques(rule: dict[str, Any]) -> list[str]:
    mitre = rule.get("mitre")
    ids = mitre.get("id") if isinstance(mitre, dict) else None
    return [str(technique) for technique in ids] if isinstance(ids, list) else []
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest tests/test_wazuh_convert.py -q`
Expected: all pass.

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 6: Commit**

```bash
git add ingest/wazuh.py tests/data/wazuh tests/test_wazuh_convert.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Convert Wazuh alerts into events and alerts"
```

---

### Task 3: Database, migrations and alert queries

**Files:**
- Create: `backend/app/db.py`
- Create: `backend/alembic.ini`
- Create: `backend/migrations/env.py`
- Create: `backend/migrations/versions/0001_wazuh_alerts.py`
- Create: `backend/app/store.py`
- Modify: `tests/conftest.py` (database fixtures and alert helpers)
- Modify: `.github/workflows/ci.yml` (Postgres service)
- Test: `tests/test_store.py`

**Interfaces:**
- Consumes: `ingest.wazuh.live_alert`, `contracts.models.LiveAlert`.
- Produces:
  - `backend.app.db.metadata`, `backend.app.db.wazuh_alerts` (SQLAlchemy `Table`)
  - `backend.app.db.database_url() -> str` (raises `RuntimeError` when `DATABASE_URL` is unset)
  - `backend.app.db.get_engine() -> Engine` (cached, used as a FastAPI dependency)
  - `backend.app.store.insert_alert(engine: Engine, live: LiveAlert, payload: dict[str, Any]) -> bool`
  - `backend.app.store.latest_alerts(engine: Engine, limit: int) -> list[LiveAlert]`
  - `backend.app.store.alert_count(engine: Engine) -> int`
  - `backend.app.store.newest_alert_time(engine: Engine) -> datetime | None`
  - `tests.conftest`: fixtures `pg_engine` and `db`; helpers
    `wazuh_payload(name: str) -> dict[str, Any]`,
    `make_live_alert(wazuh_id: str, minute: int, level: int = 5) -> tuple[LiveAlert, dict[str, Any]]`
    and the constant `RECEIVED_AT`.

- [ ] **Step 1: Start a local test database**

```bash
docker compose up -d db
docker compose exec db createdb -U sentinel sentinel_test
```

Expected: `db` is healthy, and `createdb` prints nothing. If it says the database already exists,
that's fine.

In PowerShell, for this session:

```powershell
$env:SENTINEL_TEST_DATABASE_URL = "postgresql+psycopg://sentinel:sentinel_dev@localhost:5432/sentinel_test"
```

In Git Bash:

```bash
export SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:sentinel_dev@localhost:5432/sentinel_test
```

- [ ] **Step 2: Add the test fixtures and helpers**

In `tests/conftest.py`, extend the imports:

```python
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from contracts.models import Alert, Event, Incident, Inventory, LiveAlert
from detection.correlate import correlate
from detection.sigma import detect, load_rules
from ingest.linux_auth import parse_auth_log
from ingest.wazuh import live_alert
from pipeline.run import load_inventory
```

Append at the end of the file:

```python
WAZUH_DATA = REPO / "tests" / "data" / "wazuh"
RECEIVED_AT = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def wazuh_payload(name: str) -> dict[str, Any]:
    return json.loads((WAZUH_DATA / f"{name}.json").read_text(encoding="utf-8"))


def make_live_alert(
    wazuh_id: str, minute: int, level: int = 5
) -> tuple[LiveAlert, dict[str, Any]]:
    payload = wazuh_payload("logon_failure")
    payload["id"] = wazuh_id
    payload["timestamp"] = f"2026-09-27T09:{minute:02d}:00.000+0000"
    payload["rule"]["level"] = level
    return live_alert(payload, received_at=RECEIVED_AT), payload


@pytest.fixture(scope="session")
def pg_engine() -> Iterator[Engine]:
    url = os.environ.get("SENTINEL_TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set SENTINEL_TEST_DATABASE_URL to run the database tests.")
    config = Config(str(REPO / "backend" / "alembic.ini"))
    config.set_main_option("sqlalchemy.url", url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    yield engine
    engine.dispose()


@pytest.fixture
def db(pg_engine: Engine) -> Engine:
    with pg_engine.begin() as connection:
        connection.execute(text("TRUNCATE wazuh_alerts"))
    return pg_engine
```

- [ ] **Step 3: Write the failing store tests**

`tests/test_store.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.engine import Engine

from backend.app.store import alert_count, insert_alert, latest_alerts, newest_alert_time
from tests.conftest import make_live_alert


def test_insert_is_idempotent(db: Engine) -> None:
    live, payload = make_live_alert("1.1", minute=0)
    assert insert_alert(db, live, payload) is True
    assert insert_alert(db, live, payload) is False
    assert alert_count(db) == 1


def test_latest_alerts_are_newest_first_and_round_trip(db: Engine) -> None:
    alerts = [make_live_alert(f"1.{n}", minute=n) for n in (1, 2, 3)]
    for live, payload in alerts:
        insert_alert(db, live, payload)
    latest = latest_alerts(db, limit=2)
    assert [a.wazuh_id for a in latest] == ["1.3", "1.2"]
    assert latest[0] == alerts[2][0]


def test_newest_alert_time(db: Engine) -> None:
    assert newest_alert_time(db) is None
    live, payload = make_live_alert("1.7", minute=7)
    insert_alert(db, live, payload)
    assert newest_alert_time(db) == datetime(2026, 9, 27, 9, 7, tzinfo=UTC)
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `python -m pytest tests/test_store.py -q`
Expected: `ModuleNotFoundError: No module named 'backend.app.store'`.

- [ ] **Step 5: Write the tables, the migration and the queries**

`backend/app/db.py`:

```python
from __future__ import annotations

import os
from functools import cache

from sqlalchemy import Column, DateTime, Integer, MetaData, String, Table, create_engine
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Engine

metadata = MetaData()

wazuh_alerts = Table(
    "wazuh_alerts",
    metadata,
    Column("wazuh_id", String, primary_key=True),
    Column("alert_time", DateTime(timezone=True), nullable=False, index=True),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("agent_name", String, nullable=False),
    Column("rule_id", String, nullable=False),
    Column("level", Integer, nullable=False),
    Column("payload", JSONB, nullable=False),
    Column("event", JSONB, nullable=False),
    Column("alert", JSONB, nullable=False),
    Column("incident_id", String, nullable=True),
)


def database_url() -> str:
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError("DATABASE_URL is not set. Start the stack with docker compose.")
    return url


@cache
def get_engine() -> Engine:
    return create_engine(database_url(), pool_pre_ping=True)
```

`backend/alembic.ini`:

```ini
[alembic]
script_location = %(here)s/migrations
prepend_sys_path = %(here)s/..
path_separator = os
```

`backend/migrations/env.py`:

```python
from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine

from backend.app.db import database_url, metadata

url = context.config.get_main_option("sqlalchemy.url") or database_url()
engine = create_engine(url)
with engine.connect() as connection:
    context.configure(connection=connection, target_metadata=metadata)
    with context.begin_transaction():
        context.run_migrations()
engine.dispose()
```

`backend/migrations/versions/0001_wazuh_alerts.py`:

```python
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "wazuh_alerts",
        sa.Column("wazuh_id", sa.String(), primary_key=True),
        sa.Column("alert_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("agent_name", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("payload", JSONB(), nullable=False),
        sa.Column("event", JSONB(), nullable=False),
        sa.Column("alert", JSONB(), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=True),
    )
    op.create_index("ix_wazuh_alerts_alert_time", "wazuh_alerts", ["alert_time"])


def downgrade() -> None:
    op.drop_index("ix_wazuh_alerts_alert_time", table_name="wazuh_alerts")
    op.drop_table("wazuh_alerts")
```

`backend/app/store.py`:

```python
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine import Engine

from backend.app.db import wazuh_alerts
from contracts.models import Alert, Event, LiveAlert


def insert_alert(engine: Engine, live: LiveAlert, payload: dict[str, Any]) -> bool:
    statement = (
        insert(wazuh_alerts)
        .values(
            wazuh_id=live.wazuh_id,
            alert_time=live.event.timestamp,
            received_at=live.received_at,
            agent_name=live.event.host,
            rule_id=live.alert.rule_id,
            level=live.level,
            payload=payload,
            event=live.event.model_dump(mode="json"),
            alert=live.alert.model_dump(mode="json"),
        )
        .on_conflict_do_nothing(index_elements=[wazuh_alerts.c.wazuh_id])
    )
    with engine.begin() as connection:
        return connection.execute(statement).rowcount == 1


def latest_alerts(engine: Engine, limit: int) -> list[LiveAlert]:
    statement = (
        select(
            wazuh_alerts.c.wazuh_id,
            wazuh_alerts.c.received_at,
            wazuh_alerts.c.level,
            wazuh_alerts.c.event,
            wazuh_alerts.c.alert,
        )
        .order_by(wazuh_alerts.c.alert_time.desc(), wazuh_alerts.c.wazuh_id.desc())
        .limit(limit)
    )
    with engine.connect() as connection:
        rows = connection.execute(statement).all()
    return [
        LiveAlert(
            wazuh_id=row.wazuh_id,
            received_at=row.received_at,
            level=row.level,
            event=Event.model_validate(row.event),
            alert=Alert.model_validate(row.alert),
        )
        for row in rows
    ]


def alert_count(engine: Engine) -> int:
    with engine.connect() as connection:
        return connection.execute(select(func.count()).select_from(wazuh_alerts)).scalar_one()


def newest_alert_time(engine: Engine) -> datetime | None:
    with engine.connect() as connection:
        return connection.execute(select(func.max(wazuh_alerts.c.alert_time))).scalar_one()
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python -m pytest tests/test_store.py -v`
Expected: 3 passed. If they show as skipped, `SENTINEL_TEST_DATABASE_URL` is not set in this
shell (see step 1).

Run: `python -m pytest -q` and `python -m ruff check .`
Expected: everything passes.

- [ ] **Step 7: Give CI a Postgres service**

In `.github/workflows/ci.yml`, under `jobs.contracts`, add before `steps:`:

```yaml
    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_USER: sentinel
          POSTGRES_PASSWORD: sentinel_dev
          POSTGRES_DB: sentinel_test
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U sentinel"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
```

In the step named `Tests, including containment in real lab containers`, extend `env:`:

```yaml
        env:
          SENTINEL_DOCKER: docker
          SENTINEL_TEST_DATABASE_URL: postgresql+psycopg://sentinel:sentinel_dev@localhost:5432/sentinel_test
```

- [ ] **Step 8: Commit**

```bash
git add backend/app/db.py backend/app/store.py backend/alembic.ini backend/migrations tests/conftest.py tests/test_store.py .github/workflows/ci.yml
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Store Wazuh alerts in Postgres"
```

---

### Task 4: Ingest endpoint and running the service

**Files:**
- Create: `backend/app/ingest.py`
- Modify: `backend/app/main.py` (include the router)
- Modify: `backend/Dockerfile`
- Modify: `docker-compose.yml`
- Create: `.env.example`
- Test: `tests/test_ingest_api.py`

**Interfaces:**
- Consumes: `get_engine`, `insert_alert`, `live_alert`, `WazuhAlertError`.
- Produces: `POST /api/ingest/wazuh` returning 202 `{"stored": bool}`; 401 for a wrong or
  missing token; 503 when `SENTINEL_INGEST_TOKEN` is unset; 413 over `1_000_000` bytes; 422 for
  malformed alerts. Also `backend.app.ingest.router` and `MAX_BODY_BYTES`.

- [ ] **Step 1: Write the failing tests**

`tests/test_ingest_api.py`:

```python
from __future__ import annotations

import json
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.main import app
from backend.app.store import alert_count
from tests.conftest import wazuh_payload

URL = "/api/ingest/wazuh"
TOKEN = "test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def _clear_overrides() -> Iterator[None]:
    yield
    app.dependency_overrides.clear()


def _client(engine: object, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SENTINEL_INGEST_TOKEN", TOKEN)
    app.dependency_overrides[get_engine] = lambda: engine
    return TestClient(app)


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return _client(object(), monkeypatch)


@pytest.fixture
def online(db: Engine, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    return _client(db, monkeypatch)


def _body() -> bytes:
    return json.dumps(wazuh_payload("logon_failure")).encode()


def test_alert_is_stored_once(online: TestClient, db: Engine) -> None:
    first = online.post(URL, content=_body(), headers=AUTH)
    second = online.post(URL, content=_body(), headers=AUTH)
    assert (first.status_code, first.json()) == (202, {"stored": True})
    assert (second.status_code, second.json()) == (202, {"stored": False})
    assert alert_count(db) == 1


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}]
)
def test_wrong_or_missing_token_is_rejected(offline: TestClient, headers: dict) -> None:
    assert offline.post(URL, content=_body(), headers=headers).status_code == 401


def test_ingest_is_off_without_a_token(
    offline: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SENTINEL_INGEST_TOKEN")
    assert offline.post(URL, content=_body(), headers=AUTH).status_code == 503


def test_oversized_alert_is_rejected(offline: TestClient) -> None:
    body = b'{"padding": "' + b"a" * 1_000_001 + b'"}'
    assert offline.post(URL, content=body, headers=AUTH).status_code == 413


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"id": "1"}'])
def test_malformed_alert_is_rejected(offline: TestClient, body: bytes) -> None:
    assert offline.post(URL, content=body, headers=AUTH).status_code == 422
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_ingest_api.py -q`
Expected: the rejection tests fail with 404 (no such route). With a test database, the stored
test fails too.

- [ ] **Step 3: Write the endpoint**

`backend/app/ingest.py`:

```python
from __future__ import annotations

import hmac
import json
import os
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.engine import Engine
from starlette.concurrency import run_in_threadpool

from backend.app.db import get_engine
from backend.app.store import insert_alert
from ingest.wazuh import WazuhAlertError, live_alert

MAX_BODY_BYTES = 1_000_000

router = APIRouter()


def _check_token(request: Request) -> None:
    token = os.environ.get("SENTINEL_INGEST_TOKEN")
    if not token:
        raise HTTPException(503, "Ingest is off: SENTINEL_INGEST_TOKEN is not set.")
    supplied = request.headers.get("authorization", "")
    if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
        raise HTTPException(401, "Wrong or missing ingest token.")


async def _read_json(request: Request) -> dict[str, Any]:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, "Alert is larger than 1 MB.")
    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Alert is larger than 1 MB.")
    try:
        payload = json.loads(body)
    except ValueError as error:
        raise HTTPException(422, "Alert is not valid JSON.") from error
    if not isinstance(payload, dict):
        raise HTTPException(422, "Alert must be a JSON object.")
    return payload


@router.post("/api/ingest/wazuh", status_code=202)
async def ingest_wazuh(
    request: Request, engine: Annotated[Engine, Depends(get_engine)]
) -> dict[str, bool]:
    _check_token(request)
    payload = await _read_json(request)
    try:
        live = live_alert(payload, received_at=datetime.now(UTC))
    except WazuhAlertError as error:
        raise HTTPException(422, str(error)) from error
    stored = await run_in_threadpool(insert_alert, engine, live, payload)
    return {"stored": stored}
```

In `backend/app/main.py`, add the import after the `fastapi` import:

```python
from backend.app.ingest import router as ingest_router
```

and, directly after `app = FastAPI(title="SENTINEL API", version="0.1.0")`:

```python
app.include_router(ingest_router)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_ingest_api.py tests/test_api.py -q`
Expected: all pass. The stored test is skipped only when no test database is set.

- [ ] **Step 5: Make the container run migrations and include the converter**

`backend/Dockerfile`, full file:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY contracts/ ./contracts/
COPY ingest/ ./ingest/
COPY backend/ ./backend/

EXPOSE 8000

CMD ["sh", "-c", "alembic -c backend/alembic.ini upgrade head && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload"]
```

In `docker-compose.yml`:

- **`db`:** change `ports` to `- "127.0.0.1:5432:5432"`.
- **`backend`:**
  - add `env_file:` with `- path: .env` and `required: false`;
  - change `ports` to `- "127.0.0.1:8000:8000"`;
  - add the volume `- ./ingest:/app/ingest:ro`.
- **`frontend`:** change `ports` to `- "127.0.0.1:5173:5173"`.

The backend service becomes:

```yaml
  backend:
    build:
      context: .
      dockerfile: backend/Dockerfile
    env_file:
      - path: .env
        required: false
    environment:
      DATABASE_URL: postgresql+psycopg://sentinel:sentinel_dev@db:5432/sentinel
    ports:
      - "127.0.0.1:8000:8000"
    depends_on:
      db:
        condition: service_healthy
    volumes:
      - ./contracts:/app/contracts:ro
      - ./ingest:/app/ingest:ro
      - ./backend:/app/backend
      - ./runs:/app/runs:ro
```

`.env.example`:

```dotenv
# Copy to .env (git-ignored) and fill in the blanks.
# Generate the token with: python -c "import secrets; print(secrets.token_urlsafe(32))"
SENTINEL_INGEST_TOKEN=

# Wazuh, reached over the shared sentinel-wazuh Docker network (see lab/wazuh/README.md).
WAZUH_API_URL=https://wazuh.manager:55000
WAZUH_INDEXER_URL=https://wazuh.indexer:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=
WAZUH_CA_CERT=/run/wazuh/root-ca.pem
WAZUH_CERTS_DIR=<your wazuh-docker folder>/single-node/config/wazuh_indexer_ssl_certs
```

- [ ] **Step 6: Check the service end to end, without Wazuh**

```powershell
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Paste the printed token after `SENTINEL_INGEST_TOKEN=` in `.env`. Then:

```powershell
docker compose up -d --build db backend
docker compose logs backend --tail 20
```

Expected: the logs show `Running upgrade  -> 0001` and `Uvicorn running on http://0.0.0.0:8000`.

```powershell
$token = (Select-String -Path .env -Pattern '^SENTINEL_INGEST_TOKEN=(.+)$').Matches[0].Groups[1].Value
curl.exe -s -X POST http://127.0.0.1:8000/api/ingest/wazuh -H "Authorization: Bearer $token" -H "Content-Type: application/json" --data-binary "@tests/data/wazuh/logon_failure.json"
```

Expected: `{"stored":true}`. Running the same command again gives `{"stored":false}`.

- [ ] **Step 7: Commit**

```bash
git add backend/app/ingest.py backend/app/main.py backend/Dockerfile docker-compose.yml .env.example tests/test_ingest_api.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Accept Wazuh alerts on a token-protected endpoint"
```

---

### Task 5: Wazuh API probe, backfill and startup

**Files:**
- Create: `backend/app/wazuh.py`
- Create: `backend/app/backfill.py`
- Modify: `backend/app/main.py` (lifespan)
- Test: `tests/test_wazuh_probe.py`, `tests/test_backfill.py`

**Interfaces:**
- Consumes: `insert_alert`, `newest_alert_time`, `live_alert`, `WazuhAlertError`, `ServiceState`.
- Produces:
  - `backend.app.wazuh.WazuhApiProbe(url: str | None, ttl_seconds: float = 30.0,
    clock: Callable[[], float] = time.monotonic, transport: httpx.BaseTransport | None = None)`
    with `.state() -> ServiceState`
  - `backend.app.wazuh.get_wazuh_probe() -> WazuhApiProbe` (cached, reads `WAZUH_API_URL`)
  - `backend.app.backfill.IndexerSettings(url, user, password, ca_cert)` with
    `.from_env() -> IndexerSettings | None` and `.client() -> httpx.Client`
  - `backend.app.backfill.search_body(since: datetime | None, limit: int = 5000) -> dict`
  - `backend.app.backfill.fetch_alerts(client: httpx.Client, since: datetime | None,
    limit: int = 5000) -> list[dict]`
  - `backend.app.backfill.backfill(engine: Engine, client: httpx.Client, now: datetime) -> ServiceState`
  - `app.state.backfill: ServiceState`, set at startup

- [ ] **Step 1: Write the failing probe tests**

`tests/test_wazuh_probe.py`:

```python
from __future__ import annotations

from collections.abc import Callable

import httpx

from backend.app.wazuh import WazuhApiProbe


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _probe(
    handler: Callable[[httpx.Request], httpx.Response], clock: Clock | None = None
) -> tuple[WazuhApiProbe, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    probe = WazuhApiProbe(
        url="https://wazuh.manager:55000",
        transport=httpx.MockTransport(record),
        clock=clock or Clock(),
    )
    return probe, seen


def test_no_url_means_offline() -> None:
    state = WazuhApiProbe(url=None).state()
    assert state.reachable is False
    assert state.detail is not None and "WAZUH_API_URL" in state.detail


def test_any_http_answer_means_online() -> None:
    probe, _ = _probe(lambda request: httpx.Response(401))
    state = probe.state()
    assert state.reachable is True
    assert state.detail == "Wazuh API answered HTTP 401."


def test_connection_error_means_offline() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    probe, _ = _probe(refuse)
    state = probe.state()
    assert state.reachable is False
    assert state.detail is not None and "connection refused" in state.detail


def test_answer_is_cached_for_30_seconds() -> None:
    clock = Clock()
    probe, seen = _probe(lambda request: httpx.Response(401), clock)
    probe.state()
    clock.now = 29.9
    probe.state()
    assert len(seen) == 1
    clock.now = 30.0
    probe.state()
    assert len(seen) == 2
```

- [ ] **Step 2: Write the failing backfill tests**

`tests/test_backfill.py`:

```python
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.backfill import backfill, fetch_alerts, search_body
from backend.app.main import app
from backend.app.store import alert_count, insert_alert
from contracts.models import ServiceState
from tests.conftest import make_live_alert

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    return httpx.Client(
        base_url="https://wazuh.indexer:9200", transport=httpx.MockTransport(handler)
    )


def _hits(payloads: list[dict[str, Any]]) -> httpx.Response:
    return httpx.Response(200, json={"hits": {"hits": [{"_source": p} for p in payloads]}})


def test_search_body_without_since() -> None:
    body = search_body(None)
    assert body["size"] == 5000
    assert body["sort"] == [{"timestamp": {"order": "asc"}}]
    assert body["query"]["bool"]["filter"] == [{"range": {"rule.level": {"gte": 3}}}]


def test_search_body_with_since() -> None:
    since = datetime(2026, 9, 27, 9, 5, tzinfo=UTC)
    filters = search_body(since)["query"]["bool"]["filter"]
    assert filters[1] == {"range": {"timestamp": {"gte": since.isoformat()}}}


def test_fetch_alerts_searches_the_alerts_index() -> None:
    _, payload = make_live_alert("2.1", minute=1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/wazuh-alerts-4.x-*/_search"
        assert json.loads(request.content)["size"] == 5000
        return _hits([payload])

    assert fetch_alerts(_client(handler), since=None) == [payload]


def test_backfill_stores_valid_alerts_once(db: Engine) -> None:
    payloads = [make_live_alert(f"2.{n}", minute=n)[1] for n in (1, 2)] + [{"id": "broken"}]
    client = _client(lambda request: _hits(payloads))
    first = backfill(db, client, NOW)
    second = backfill(db, client, NOW)
    assert first.reachable is True
    assert first.detail is not None and first.detail.startswith("Backfilled 2 of 3 alerts")
    assert second.detail is not None and second.detail.startswith("Backfilled 0 of 3 alerts")
    assert alert_count(db) == 2


def test_backfill_starts_from_the_newest_stored_alert(db: Engine) -> None:
    live, payload = make_live_alert("2.5", minute=5)
    insert_alert(db, live, payload)
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return _hits([])

    backfill(db, _client(handler), NOW)
    since = seen[0]["query"]["bool"]["filter"][1]["range"]["timestamp"]["gte"]
    assert datetime.fromisoformat(since) == datetime(2026, 9, 27, 9, 5, tzinfo=UTC)


def test_backfill_reports_an_unreachable_indexer(db: Engine) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    state = backfill(db, _client(refuse), NOW)
    assert state.reachable is False
    assert state.detail is not None and state.detail.startswith("Backfill failed")


def test_startup_without_an_indexer_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WAZUH_INDEXER_URL", raising=False)
    try:
        with TestClient(app):
            assert app.state.backfill == ServiceState(
                reachable=False, detail="WAZUH_INDEXER_URL is not set."
            )
    finally:
        del app.state.backfill
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `python -m pytest tests/test_wazuh_probe.py tests/test_backfill.py -q`
Expected: `ModuleNotFoundError: No module named 'backend.app.wazuh'` and `'backend.app.backfill'`.

- [ ] **Step 4: Write the probe**

`backend/app/wazuh.py`:

```python
from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache

import httpx

from contracts.models import ServiceState


@dataclass
class WazuhApiProbe:
    url: str | None
    ttl_seconds: float = 30.0
    clock: Callable[[], float] = time.monotonic
    transport: httpx.BaseTransport | None = None
    _state: ServiceState | None = field(default=None, init=False)
    _checked_at: float = field(default=0.0, init=False)

    def state(self) -> ServiceState:
        if self.url is None:
            return ServiceState(reachable=False, detail="WAZUH_API_URL is not set.")
        now = self.clock()
        if self._state is None or now - self._checked_at >= self.ttl_seconds:
            self._state = self._check(self.url)
            self._checked_at = now
        return self._state

    def _check(self, url: str) -> ServiceState:
        try:
            with httpx.Client(verify=False, timeout=2.0, transport=self.transport) as client:
                response = client.get(url)
        except httpx.HTTPError as error:
            return ServiceState(reachable=False, detail=f"Wazuh API unreachable: {error}")
        return ServiceState(
            reachable=True, detail=f"Wazuh API answered HTTP {response.status_code}."
        )


@cache
def get_wazuh_probe() -> WazuhApiProbe:
    return WazuhApiProbe(url=os.environ.get("WAZUH_API_URL") or None)
```

- [ ] **Step 5: Write the backfill**

`backend/app/backfill.py`:

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy.engine import Engine

from backend.app.store import insert_alert, newest_alert_time
from contracts.models import ServiceState
from ingest.wazuh import WazuhAlertError, live_alert

ALERTS_INDEX = "wazuh-alerts-4.x-*"
MIN_LEVEL = 3
LIMIT = 5000


@dataclass(frozen=True)
class IndexerSettings:
    url: str
    user: str
    password: str
    ca_cert: str | None = None

    @classmethod
    def from_env(cls) -> IndexerSettings | None:
        url = os.environ.get("WAZUH_INDEXER_URL")
        if not url:
            return None
        return cls(
            url=url.rstrip("/"),
            user=os.environ.get("WAZUH_INDEXER_USER", ""),
            password=os.environ.get("WAZUH_INDEXER_PASSWORD", ""),
            ca_cert=os.environ.get("WAZUH_CA_CERT") or None,
        )

    def client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.url,
            auth=(self.user, self.password),
            verify=self.ca_cert or True,
            timeout=10.0,
        )


def search_body(since: datetime | None, limit: int = LIMIT) -> dict[str, Any]:
    filters: list[dict[str, Any]] = [{"range": {"rule.level": {"gte": MIN_LEVEL}}}]
    if since is not None:
        filters.append({"range": {"timestamp": {"gte": since.isoformat()}}})
    return {
        "size": limit,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": filters}},
    }


def fetch_alerts(
    client: httpx.Client, since: datetime | None, limit: int = LIMIT
) -> list[dict[str, Any]]:
    response = client.post(f"/{ALERTS_INDEX}/_search", json=search_body(since, limit))
    response.raise_for_status()
    return [hit["_source"] for hit in response.json()["hits"]["hits"]]


def backfill(engine: Engine, client: httpx.Client, now: datetime) -> ServiceState:
    try:
        payloads = fetch_alerts(client, newest_alert_time(engine))
    except (httpx.HTTPError, KeyError, ValueError) as error:
        return ServiceState(reachable=False, detail=f"Backfill failed: {error}")
    stored = 0
    for payload in payloads:
        try:
            live = live_alert(payload, received_at=now)
        except WazuhAlertError:
            continue
        stored += insert_alert(engine, live, payload)
    return ServiceState(
        reachable=True,
        detail=f"Backfilled {stored} of {len(payloads)} alerts at {now:%H:%M:%S} UTC.",
    )
```

- [ ] **Step 6: Start the backfill when the app starts**

`backend/app/main.py`: replace everything above `def runs_dir()` with:

```python
from __future__ import annotations

import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException

from backend.app.backfill import IndexerSettings, backfill
from backend.app.db import get_engine
from backend.app.ingest import router as ingest_router
from contracts.models import CONTRACT_VERSION, IncidentRun, ServiceState

REPO = Path(__file__).resolve().parents[2]


def _backfill_in_background(app: FastAPI, settings: IndexerSettings) -> None:
    try:
        with settings.client() as client:
            app.state.backfill = backfill(get_engine(), client, datetime.now(UTC))
    except Exception as error:
        app.state.backfill = ServiceState(reachable=False, detail=f"Backfill failed: {error}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = IndexerSettings.from_env()
    if settings is None:
        app.state.backfill = ServiceState(reachable=False, detail="WAZUH_INDEXER_URL is not set.")
    else:
        app.state.backfill = ServiceState(reachable=False, detail="Backfill is running.")
        threading.Thread(
            target=_backfill_in_background, args=(app, settings), daemon=True
        ).start()
    yield


app = FastAPI(title="SENTINEL API", version="0.1.0", lifespan=lifespan)
app.include_router(ingest_router)
```

Keep `runs_dir`, `load_runs` and the existing routes unchanged below it.

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python -m pytest tests/test_wazuh_probe.py tests/test_backfill.py tests/test_api.py -q`
Expected: all pass. The database tests are skipped only without a test database.

Run: `python -m ruff check .`
Expected: `All checks passed!`

- [ ] **Step 8: Commit**

```bash
git add backend/app/wazuh.py backend/app/backfill.py backend/app/main.py tests/test_wazuh_probe.py tests/test_backfill.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Backfill missed Wazuh alerts on start and probe the Wazuh API"
```

---

### Task 6: Live feed endpoint

**Files:**
- Create: `backend/app/pc.py`
- Modify: `backend/app/main.py` (include the router)
- Test: `tests/test_pc_feed.py`

**Interfaces:**
- Consumes: `get_engine`, `latest_alerts`, `alert_count`, `newest_alert_time`,
  `get_wazuh_probe`, `WazuhApiProbe`, `app.state.backfill`.
- Produces: `GET /api/pc/feed?limit=200` (1 ≤ limit ≤ 1000) returning `PcFeed`.
  `backend.app.pc.router`, `backend.app.pc.get_backfill_state(request) -> ServiceState`, and
  `NOT_RUN = ServiceState(reachable=False, detail="Backfill has not run.")`.

- [ ] **Step 1: Write the failing tests**

`tests/test_pc_feed.py`:

```python
from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.main import app
from backend.app.pc import NOT_RUN, get_backfill_state
from backend.app.store import insert_alert
from backend.app.wazuh import WazuhApiProbe, get_wazuh_probe
from contracts.models import PcFeed, ServiceState
from tests.conftest import make_live_alert

BACKFILLED = ServiceState(reachable=True, detail="Backfilled 0 of 0 alerts at 10:00:00 UTC.")


@pytest.fixture
def client(db: Engine) -> Iterator[TestClient]:
    probe = WazuhApiProbe(url=None)
    app.dependency_overrides[get_engine] = lambda: db
    app.dependency_overrides[get_wazuh_probe] = lambda: probe
    app.dependency_overrides[get_backfill_state] = lambda: BACKFILLED
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_empty_feed(client: TestClient) -> None:
    response = client.get("/api/pc/feed")
    assert response.status_code == 200
    feed = PcFeed.model_validate(response.json())
    assert feed.alerts == []
    assert feed.status.alert_count == 0
    assert feed.status.last_alert_at is None
    assert feed.status.wazuh_api.reachable is False
    assert feed.status.backfill == BACKFILLED


def test_backfill_state_defaults_to_not_run() -> None:
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))
    assert get_backfill_state(request) == NOT_RUN


def test_feed_is_newest_first_and_limited(client: TestClient, db: Engine) -> None:
    for n in (1, 2, 3):
        live, payload = make_live_alert(f"3.{n}", minute=n)
        insert_alert(db, live, payload)
    feed = PcFeed.model_validate(client.get("/api/pc/feed?limit=2").json())
    assert [a.wazuh_id for a in feed.alerts] == ["3.3", "3.2"]
    assert feed.status.alert_count == 3
    assert feed.status.last_alert_at == datetime(2026, 9, 27, 9, 3, tzinfo=UTC)


@pytest.mark.parametrize("limit", [0, 1001])
def test_limit_is_bounded(client: TestClient, limit: int) -> None:
    assert client.get(f"/api/pc/feed?limit={limit}").status_code == 422
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_pc_feed.py -q`
Expected: 404 on `/api/pc/feed` (or skipped without a test database).

- [ ] **Step 3: Write the endpoint**

`backend/app/pc.py`:

```python
from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from backend.app.wazuh import WazuhApiProbe, get_wazuh_probe
from contracts.models import PcFeed, PcStatus, ServiceState

NOT_RUN = ServiceState(reachable=False, detail="Backfill has not run.")

router = APIRouter(prefix="/api/pc")


def get_backfill_state(request: Request) -> ServiceState:
    return getattr(request.app.state, "backfill", NOT_RUN)


@router.get("/feed", response_model=PcFeed)
def feed(
    engine: Annotated[Engine, Depends(get_engine)],
    probe: Annotated[WazuhApiProbe, Depends(get_wazuh_probe)],
    backfill_state: Annotated[ServiceState, Depends(get_backfill_state)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> PcFeed:
    status = PcStatus(
        checked_at=datetime.now(UTC),
        wazuh_api=probe.state(),
        backfill=backfill_state,
        alert_count=alert_count(engine),
        last_alert_at=newest_alert_time(engine),
    )
    return PcFeed(status=status, alerts=latest_alerts(engine, limit))
```

In `backend/app/main.py`, add `from backend.app.pc import router as pc_router` after the ingest
import, and `app.include_router(pc_router)` after `app.include_router(ingest_router)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest -q` and `python -m ruff check .`
Expected: everything passes.

- [ ] **Step 5: Commit**

```bash
git add backend/app/pc.py backend/app/main.py tests/test_pc_feed.py
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Serve the live My PC feed"
```

---

### Task 7: "My PC" dashboard page

**Files:**
- Create: `frontend/src/components/MyPc.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`

**Interfaces:**
- Consumes: `GET /api/pc/feed` and the `PcFeed` and `ServiceState` types from
  `src/types/pc.ts` (Task 1).
- Produces:
  - `PC_FEED_URL: string | null`. It is `null` on the static public build, where
    `VITE_RUNS_URL` is set.
  - `fetchPcFeed(url: string): Promise<PcFeed>`.
  - The page `?view=pc`.

- [ ] **Step 1: Add the feed client**

`frontend/src/api.ts`, full file:

```ts
import type { IncidentRun } from "./types/contracts";
import type { PcFeed } from "./types/pc";

const RUNS_URL: string = import.meta.env.VITE_RUNS_URL ?? "/api/runs";

export const PC_FEED_URL: string | null =
  import.meta.env.VITE_PC_FEED_URL ?? (import.meta.env.VITE_RUNS_URL ? null : "/api/pc/feed");

export async function fetchRuns(): Promise<IncidentRun[]> {
  const response = await fetch(RUNS_URL);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${RUNS_URL}.`);
  }
  return response.json();
}

export async function fetchPcFeed(url: string): Promise<PcFeed> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${url}.`);
  }
  return response.json();
}
```

- [ ] **Step 2: Write the page**

`frontend/src/components/MyPc.tsx`:

```tsx
import { useEffect, useState } from "react";

import { fetchPcFeed } from "../api";
import { utc } from "../format";
import type { PcFeed, ServiceState } from "../types/pc";

const POLL_MS = 5000;

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string; last: PcFeed | null }
  | { state: "ready"; feed: PcFeed };

export function MyPc({ url }: { url: string }) {
  const [load, setLoad] = useState<Load>({ state: "loading" });

  useEffect(() => {
    let cancelled = false;
    let last: PcFeed | null = null;
    const poll = () => {
      fetchPcFeed(url)
        .then((feed) => {
          last = feed;
          if (!cancelled) setLoad({ state: "ready", feed });
        })
        .catch((error: Error) => {
          if (!cancelled) setLoad({ state: "failed", message: error.message, last });
        });
    };
    poll();
    const timer = window.setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [url]);

  const feed = load.state === "ready" ? load.feed : load.state === "failed" ? load.last : null;

  return (
    <section className="pc">
      <header className="pc-head">
        <p className="eyebrow">Live · refreshes every 5 seconds</p>
        <h1>My PC</h1>
      </header>
      {load.state === "loading" && <p className="notice">Connecting to the SENTINEL service…</p>}
      {load.state === "failed" && (
        <div className="notice">
          <p>
            <strong>Can’t reach the SENTINEL service.</strong> {load.message}
          </p>
          <p>
            Start it from the repo root with <code>docker compose up -d</code>.
          </p>
        </div>
      )}
      {feed && <StatusBar feed={feed} />}
      {feed && <AlertTable feed={feed} />}
    </section>
  );
}

function StatusBar({ feed }: { feed: PcFeed }) {
  const { status } = feed;
  return (
    <dl className="pc-status">
      <Service label="Wazuh API" state={status.wazuh_api} />
      <Service label="Backfill" state={status.backfill} />
      <div>
        <dt>Alerts stored</dt>
        <dd className="mono">{status.alert_count}</dd>
      </div>
      <div>
        <dt>Last alert (UTC)</dt>
        <dd className="mono">{status.last_alert_at ? utc(status.last_alert_at) : "none yet"}</dd>
      </div>
    </dl>
  );
}

function Service({ label, state }: { label: string; state: ServiceState }) {
  return (
    <div>
      <dt>{label}</dt>
      <dd className={state.reachable ? "pc-ok" : "pc-down"}>
        {state.reachable ? "Online" : "Offline"}
      </dd>
      {state.detail && <dd className="small muted">{state.detail}</dd>}
    </div>
  );
}

function AlertTable({ feed }: { feed: PcFeed }) {
  if (feed.alerts.length === 0) {
    return (
      <p className="notice">
        No alerts yet. Follow <code>lab/wazuh/README.md</code> to connect Wazuh, then trigger a
        failed logon.
      </p>
    );
  }
  return (
    <table className="pc-alerts">
      <thead>
        <tr>
          <th>Time (UTC)</th>
          <th>Severity</th>
          <th>Rule</th>
          <th>What happened</th>
          <th>User</th>
          <th>Process</th>
        </tr>
      </thead>
      <tbody>
        {feed.alerts.map(({ wazuh_id, level, alert, event }) => (
          <tr key={wazuh_id}>
            <td className="mono">{utc(alert.timestamp)}</td>
            <td>
              <span className={`sev sev--${alert.rule_severity}`}>{alert.rule_severity}</span>{" "}
              <span className="small muted">L{level}</span>
            </td>
            <td className="mono">{alert.rule_id}</td>
            <td>{alert.description}</td>
            <td className="mono">{event.user ?? "—"}</td>
            <td className="mono">{event.process?.name ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
```

- [ ] **Step 3: Add the view switch**

`frontend/src/App.tsx`, full file:

```tsx
import { useEffect, useState } from "react";

import { PC_FEED_URL, fetchRuns } from "./api";
import { MyPc } from "./components/MyPc";
import { RunDetail } from "./components/RunDetail";
import { RunList } from "./components/RunList";
import type { IncidentRun } from "./types/contracts";

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "ready"; runs: IncidentRun[] };

const PC_VIEW =
  PC_FEED_URL !== null && new URLSearchParams(window.location.search).get("view") === "pc";

export function App() {
  return (
    <div className="app">
      <header className="masthead">
        <span className="wordmark">SENTINEL</span>
        <span className="masthead-tag">The AI proposes. Deterministic policy decides.</span>
        {PC_FEED_URL && (
          <nav className="views" aria-label="Views">
            <a href="?" aria-current={PC_VIEW ? undefined : "page"}>
              Incidents
            </a>
            <a href="?view=pc" aria-current={PC_VIEW ? "page" : undefined}>
              My PC
            </a>
          </nav>
        )}
        <a className="masthead-link" href="https://github.com/CS-Abuhelal/sentinel">
          Source on GitHub
        </a>
      </header>
      {PC_VIEW && PC_FEED_URL ? (
        <div className="layout">
          <main className="main">
            <MyPc url={PC_FEED_URL} />
          </main>
        </div>
      ) : (
        <Runs />
      )}
    </div>
  );
}

function Runs() {
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    fetchRuns()
      .then((runs) => {
        setLoad({ state: "ready", runs });
        const wanted = new URLSearchParams(window.location.search).get("case");
        const initial = runs.find((run) => run.case_id === wanted) ?? runs[0];
        setSelectedId(initial?.incident.incident_id ?? null);
      })
      .catch((error: Error) => setLoad({ state: "failed", message: error.message }));
  }, []);

  const runs = load.state === "ready" ? load.runs : [];
  const selected = runs.find((run) => run.incident.incident_id === selectedId) ?? null;

  const select = (incidentId: string) => {
    const run = runs.find((candidate) => candidate.incident.incident_id === incidentId);
    if (run) window.history.replaceState(null, "", `?case=${encodeURIComponent(run.case_id)}`);
    setSelectedId(incidentId);
  };

  return (
    <div className="layout">
      {runs.length > 0 && (
        <nav className="runs" aria-label="Incident runs">
          <RunList runs={runs} selectedId={selectedId} onSelect={select} />
        </nav>
      )}
      <main className="main">
        {load.state === "loading" && <p className="notice">Loading runs…</p>}
        {load.state === "failed" && (
          <div className="notice">
            <p>
              <strong>Can’t load runs.</strong> {load.message}
            </p>
            <p>
              Start the API from the repo root with{" "}
              <code>uvicorn backend.app.main:app --reload</code>, then reload this page.
            </p>
          </div>
        )}
        {load.state === "ready" && runs.length === 0 && (
          <div className="notice">
            <p>
              <strong>No runs yet.</strong> Run a scenario from the repo root, then reload:
            </p>
            <pre>python -m pipeline.run lab/scenarios/s1_attack/auth.log</pre>
          </div>
        )}
        {selected && <RunDetail key={selected.run_id} run={selected} />}
      </main>
    </div>
  );
}
```

- [ ] **Step 4: Add the styles**

Append to `frontend/src/styles.css`:

```css
.views {
  display: flex;
  gap: 16px;
  font-size: 13px;
}

.views a {
  color: var(--ink-2);
  text-decoration: none;
  padding-bottom: 2px;
}

.views a[aria-current="page"] {
  color: var(--ink);
  font-weight: 600;
  border-bottom: 2px solid var(--agent);
}

.pc {
  display: grid;
  gap: 20px;
}

.pc-head h1 {
  margin: 2px 0 0;
  font-family: var(--font-display);
  font-weight: 600;
  font-size: 30px;
  letter-spacing: 0.02em;
}

.pc-status {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 12px;
  margin: 0;
}

.pc-status > div {
  background: var(--panel);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  padding: 10px 14px;
}

.pc-status dt {
  font-size: 12px;
  color: var(--ink-3);
}

.pc-status dd {
  margin: 2px 0 0;
}

.pc-ok {
  color: var(--allow);
  font-weight: 600;
}

.pc-down {
  color: var(--deny);
  font-weight: 600;
}

.pc-alerts {
  width: 100%;
  border-collapse: collapse;
  background: var(--panel);
  border: 1px solid var(--rule);
  font-size: 13px;
}

.pc-alerts th {
  text-align: left;
  font-weight: 600;
  font-size: 12px;
  color: var(--ink-3);
  padding: 8px 10px;
  border-bottom: 1px solid var(--rule);
}

.pc-alerts td {
  padding: 8px 10px;
  border-bottom: 1px solid var(--rule-soft);
  vertical-align: top;
}

.pc-alerts tr:last-child td {
  border-bottom: 0;
}
```

- [ ] **Step 5: Build**

Run (in `frontend/`): `npm run build`
Expected: `tsc --noEmit` passes and Vite prints `✓ built in`.

- [ ] **Step 6: Check it in the browser**

With `db` and `backend` still running from Task 4:

```powershell
cd frontend
npm run dev
```

Open `http://localhost:5173/?view=pc`. Expected:
- **Status bar:** Wazuh API "Offline" with "WAZUH_API_URL is not set." (or unreachable),
  Backfill "Offline" with "WAZUH_INDEXER_URL is not set.", and the Task 4 test alert counted.
- **Alert table:** one row, `wazuh-60122`, severity `low L5`, user `user1`.

POST a second alert with a new id, from the repo root:

```powershell
$token = (Select-String -Path .env -Pattern '^SENTINEL_INGEST_TOKEN=(.+)$').Matches[0].Groups[1].Value
(Get-Content tests/data/wazuh/process_sysmon.json -Raw) | curl.exe -s -X POST http://127.0.0.1:8000/api/ingest/wazuh -H "Authorization: Bearer $token" -H "Content-Type: application/json" --data-binary "@-"
```

Expected: within 5 seconds, a `high L12` PowerShell row appears on top without reloading. The
"Incidents" tab still shows the recorded runs. Take a screenshot for the PR.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/api.ts frontend/src/App.tsx frontend/src/components/MyPc.tsx frontend/src/styles.css
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the live My PC page"
```

---

### Task 8: Wazuh setup kit and integration script

**Files:**
- Create: `lab/wazuh/integrations/custom-sentinel.py`
- Create: `lab/wazuh/integrations/custom-sentinel` (launcher, executable)
- Create: `lab/wazuh/ossec-integration.xml`
- Create: `lab/wazuh/docker-compose.override.yml`
- Create: `lab/wazuh/README.md`
- Create: `docker-compose.wazuh.yml`
- Modify: `DECISIONS.md` (D-11), `CLAUDE.md`
- Test: `tests/test_wazuh_integration_script.py`

**Interfaces:**
- Consumes: `POST /api/ingest/wazuh` (Task 4).
- Produces: `custom-sentinel.py main(argv: list[str]) -> int`. It returns 0 when SENTINEL answers
  202, 1 on any failure or invalid JSON, and 2 on bad usage. Wazuh calls it as
  `custom-sentinel <alert_file> <api_key> <hook_url>`.

- [ ] **Step 1: Write the failing tests**

`tests/test_wazuh_integration_script.py`:

```python
from __future__ import annotations

import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType

import pytest

from tests.conftest import REPO, wazuh_payload

SCRIPT = REPO / "lab" / "wazuh" / "integrations" / "custom-sentinel.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("custom_sentinel", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Receiver:
    def __init__(self, status: int) -> None:
        self.requests: list[tuple[str | None, bytes]] = []
        received = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers["Content-Length"])
                received.append((self.headers.get("Authorization"), self.rfile.read(length)))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/ingest/wazuh"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Receiver:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def alert_file(tmp_path: Path) -> Path:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(wazuh_payload("logon_failure")), encoding="utf-8")
    return path


def test_posts_the_alert_with_the_token(alert_file: Path) -> None:
    with Receiver(202) as receiver:
        code = _script().main(["custom-sentinel", str(alert_file), "tok", receiver.url])
    assert code == 0
    [(authorization, body)] = receiver.requests
    assert authorization == "Bearer tok"
    assert json.loads(body) == wazuh_payload("logon_failure")


def test_a_rejected_alert_is_a_failure(alert_file: Path) -> None:
    with Receiver(401) as receiver:
        code = _script().main(["custom-sentinel", str(alert_file), "tok", receiver.url])
    assert code == 1


def test_an_unreachable_sentinel_is_a_failure(alert_file: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}/api/ingest/wazuh"
    assert _script().main(["custom-sentinel", str(alert_file), "tok", url]) == 1


def test_invalid_json_is_never_sent(tmp_path: Path) -> None:
    path = tmp_path / "alert.json"
    path.write_text("not json", encoding="utf-8")
    with Receiver(202) as receiver:
        code = _script().main(["custom-sentinel", str(path), "tok", receiver.url])
    assert code == 1
    assert receiver.requests == []


def test_bad_usage() -> None:
    assert _script().main(["custom-sentinel"]) == 2
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest tests/test_wazuh_integration_script.py -q`
Expected: `FileNotFoundError` for `custom-sentinel.py`.

- [ ] **Step 3: Write the integration script and launcher**

`lab/wazuh/integrations/custom-sentinel.py`:

```python
import json
import sys
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 5


def send(alert_file: str, api_key: str, hook_url: str) -> int:
    with open(alert_file, encoding="utf-8") as handle:
        body = handle.read().encode("utf-8")
    try:
        json.loads(body)
    except ValueError:
        return 1
    request = urllib.request.Request(
        hook_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return 0 if response.status == 202 else 1
    except (urllib.error.URLError, TimeoutError):
        return 1


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("usage: custom-sentinel <alert_file> <api_key> <hook_url>", file=sys.stderr)
        return 2
    return send(argv[1], argv[2], argv[3])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
```

`lab/wazuh/integrations/custom-sentinel`:

```sh
#!/bin/sh
WAZUH_PATH="$(cd "$(dirname "$0")/.." && pwd -P)"
exec "${WAZUH_PATH}/framework/python/bin/python3" "${WAZUH_PATH}/integrations/custom-sentinel.py" "$@"
```

Mark the launcher as executable in git:

```bash
git add lab/wazuh/integrations/custom-sentinel
git update-index --chmod=+x lab/wazuh/integrations/custom-sentinel
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest tests/test_wazuh_integration_script.py -q` and `python -m ruff check .`
Expected: 5 passed, and ruff is clean.

- [ ] **Step 5: Write the configuration files**

`lab/wazuh/ossec-integration.xml`:

```xml
<integration>
  <name>custom-sentinel</name>
  <hook_url>http://sentinel-backend:8000/api/ingest/wazuh</hook_url>
  <api_key>REPLACE_WITH_SENTINEL_INGEST_TOKEN</api_key>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

`lab/wazuh/docker-compose.override.yml`, which gets copied into `wazuh-docker/single-node/`:

```yaml
services:
  wazuh.manager:
    networks:
      - default
      - sentinel-wazuh
    volumes:
      - ${SENTINEL_REPO:?Set SENTINEL_REPO in .env}/lab/wazuh/integrations/custom-sentinel:/var/ossec/integrations/custom-sentinel:ro
      - ${SENTINEL_REPO}/lab/wazuh/integrations/custom-sentinel.py:/var/ossec/integrations/custom-sentinel.py:ro

  wazuh.indexer:
    networks:
      - default
      - sentinel-wazuh
    environment:
      - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"

networks:
  sentinel-wazuh:
    external: true
```

`docker-compose.wazuh.yml`, at the SENTINEL repo root:

```yaml
services:
  backend:
    networks:
      default: {}
      sentinel-wazuh:
        aliases:
          - sentinel-backend
    volumes:
      - ${WAZUH_CERTS_DIR:?Set WAZUH_CERTS_DIR in .env}/root-ca.pem:/run/wazuh/root-ca.pem:ro

networks:
  sentinel-wazuh:
    external: true
```

- [ ] **Step 6: Write the setup guide**

`lab/wazuh/README.md`:

````markdown
# Watching your own PC with Wazuh

This connects Wazuh 4.14 (in Docker) to SENTINEL's live feed. Your Windows PC runs the Wazuh
agent. Wazuh sends every alert of level 3 or higher to SENTINEL, which stores it and shows it at
`http://localhost:5173/?view=pc`. Everything stays on this PC: Wazuh and SENTINEL talk over a
private Docker network, and SENTINEL's ports listen on `127.0.0.1` only.

SENTINEL never changes anything on your PC. It only reads and advises.

## Before you start

- Docker Desktop with the WSL 2 backend.
- About 5 GB of free RAM while Wazuh runs. Close heavy apps.
- Allow the Wazuh indexer's memory mapping, once. Create or edit `%UserProfile%\.wslconfig`:

  ```ini
  [wsl2]
  kernelCommandLine = "sysctl.vm.max_map_count=262144"
  ```

  Then run `wsl --shutdown` and restart Docker Desktop.

## 1. The shared network

```powershell
docker network create sentinel-wazuh
```

## 2. Wazuh in Docker

```powershell
cd <the folder that holds your checkouts>
git ls-remote --tags https://github.com/wazuh/wazuh-docker "v4.14.*"
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker\single-node
```

Use the newest `v4.14.x` tag that `ls-remote` lists, in place of `v4.14.0`.

1. Copy `lab\wazuh\docker-compose.override.yml` from the SENTINEL repo into this folder.
2. Create `.env` in this folder containing:

   ```dotenv
   SENTINEL_REPO=<your SENTINEL checkout>
   ```

3. Open `config\wazuh_cluster\wazuh_manager.conf` and paste the block from
   `lab\wazuh\ossec-integration.xml` just before the last `</ossec_config>`. Replace
   `REPLACE_WITH_SENTINEL_INGEST_TOKEN` with `SENTINEL_INGEST_TOKEN` from SENTINEL's `.env`.
4. Generate the certificates and start Wazuh:

   ```powershell
   docker compose -f generate-indexer-certs.yml run --rm generator
   docker compose up -d
   ```

The Wazuh dashboard is at `https://localhost`, with user `admin` and password `SecretPassword`.
These are the wazuh-docker defaults, and they're only reachable from this PC.

## 3. SENTINEL

In SENTINEL's `.env` (copied from `.env.example`), set `WAZUH_INDEXER_PASSWORD=SecretPassword`.
Check that `WAZUH_CERTS_DIR` points to `wazuh-docker\single-node\config\wazuh_indexer_ssl_certs`.
Then, from the SENTINEL repo:

```powershell
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --build
```

## 4. The agent on this PC

In an **administrator** PowerShell, using the same version as the Wazuh tag:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_AGENT_NAME="my-pc"
NET START Wazuh
```

The agent is named `my-pc`, so your real computer name never shows up in SENTINEL's data.

## 5. Check it works

Trigger five harmless failed logons with a user that doesn't exist, so no real account gets
locked. Type any password when asked:

```powershell
1..5 | ForEach-Object { runas /user:$env:COMPUTERNAME\sentinel-test-nobody cmd }
```

Within about 10 seconds, `http://localhost:5173/?view=pc` shows `wazuh-60122` "Logon failure"
alerts.

## Stopping and starting

- **Stop Wazuh:** `docker compose down` in `wazuh-docker\single-node`. Your data is kept in
  Docker volumes.
- **Stop SENTINEL:** `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml down`.
- **Missed alerts:** alerts that Wazuh raised while SENTINEL was stopped are fetched from the
  Wazuh indexer the next time SENTINEL starts.

## Troubleshooting

- **No alerts arrive.** Run
  `docker compose exec wazuh.manager grep -i integrat /var/ossec/logs/ossec.log`.
  If the integration isn't executable, copy both files in and fix their permissions:

  ```powershell
  docker compose cp ..\..\SENTINEL\lab\wazuh\integrations\. wazuh.manager:/var/ossec/integrations/
  docker compose exec wazuh.manager chmod 750 /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
  docker compose exec wazuh.manager chown root:wazuh /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
  docker compose restart wazuh.manager
  ```

- **The page says the backfill failed.** Read the detail line. A TLS error means
  `WAZUH_CERTS_DIR` is wrong. A 401 means the indexer password in `.env` is wrong.
````

- [ ] **Step 7: Log the decision and update the project brief**

In `DECISIONS.md`, insert directly after the first `---` line (above D-12):

```markdown
## D-11 — A live advisor mode that reads from Wazuh (2026-09-27)

**Decision.** SENTINEL gets a live mode for Ahmed's own Windows PC. Wazuh 4.14 (single-node
Docker) watches the PC and pushes every alert of level 3 or higher to SENTINEL through a custom
integration. SENTINEL stores the alerts in PostgreSQL, backfills missed ones from the Wazuh
indexer, and shows them on a live "My PC" page. Later phases investigate the alerts and rank weak
spots. Wazuh is an external source: SENTINEL reads from it and never needs it to build or test.

**Why.** A system that watches a real machine and explains what to do is a stronger result than
two recorded cases, and it reuses SENTINEL's core: evidence-cited AI behind a deterministic
boundary. D-00 keeps Wazuh out of SENTINEL's own stack, and that still holds.

**Consequence.** PostgreSQL arrives, as D-05 planned, because the live feed needs durable writes.
Everything on the PC is advice only. Real PC data stays local, and the public site only ever
shows a sanitized sample. Design: `docs/superpowers/specs/2026-09-27-wazuh-live-advisor-design.md`.

---
```

In `CLAUDE.md`, under "What already exists in this repo", after the pipeline bullet, add:

```markdown
- Live advisor, phase 1 (`docs/superpowers/specs/2026-09-27-wazuh-live-advisor-design.md`):
  Wazuh alerts arrive at `POST /api/ingest/wazuh` (token in `.env`), are converted by
  `ingest/wazuh.py`, stored in PostgreSQL (`backend/app/db.py`, Alembic in `backend/migrations/`),
  backfilled from the Wazuh indexer on start, and shown live at `?view=pc`. Wazuh setup:
  `lab/wazuh/README.md`. Database tests run when `SENTINEL_TEST_DATABASE_URL` is set (CI sets it).
```

- [ ] **Step 8: Commit**

```bash
git add lab/wazuh docker-compose.wazuh.yml tests/test_wazuh_integration_script.py DECISIONS.md CLAUDE.md
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -m "Add the Wazuh setup kit and the SENTINEL integration"
```

---

### Task 9: End-to-end check on the real PC

This task needs Ahmed. Installing the agent needs an administrator shell. Nothing is committed
except fixes found along the way.

- [ ] **Step 1: Run the setup** in `lab/wazuh/README.md` sections 1–4. Record the exact
  wazuh-docker tag used.

- [ ] **Step 2: Live check.** Run the `runas` loop from section 5.
  Expected: five `wazuh-60122` rows appear on `?view=pc` within 10 seconds, with severity `low`
  and user `sentinel-test-nobody`. The status bar shows Wazuh API "Online" and Backfill "Online".

- [ ] **Step 3: Backfill check.**

```powershell
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml stop backend
1..3 | ForEach-Object { runas /user:$env:COMPUTERNAME\sentinel-test-nobody cmd }
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml start backend
```

Expected: within a minute, the three new alerts appear, and Backfill reads "Backfilled 3 of N
alerts". N can be larger than 3, because the newest stored alert is included again (the insert is
idempotent).

- [ ] **Step 4: Check the converter against real alerts.** In a real 60122 alert, compare the
  fields shown on the page with the raw alert:

```powershell
docker compose exec db psql -U sentinel -c "SELECT payload->'data'->'win'->'eventdata' FROM wazuh_alerts ORDER BY alert_time DESC LIMIT 1;"
```

If `user`, the process or the IP is empty while the raw alert has it under a different key, add
that key to `ingest/wazuh.py`. Add a test using a copy of the alert with every personal value
replaced by `my-pc` or `user1`, then commit:

```bash
git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit -am "Map <field> from real Wazuh alerts"
```

- [ ] **Step 5: Push and open the pull request**, once Ahmed agrees. Include the Task 7 screenshot,
  and one from this task with any personal detail cropped out.

```bash
git push -u origin feat/wazuh-live-feed
gh pr create --title "Live feed from Wazuh (advisor phase 1)" --body "Phase 1 of docs/superpowers/specs/2026-09-27-wazuh-live-advisor-design.md: Wazuh alerts reach SENTINEL in real time, are stored in Postgres, backfilled after downtime, and shown on the live My PC page."
```
