# Wazuh Report, Public Sample and Accuracy (Phase 4) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Phase 4 finishes the live advisor with four pieces:
- **Report.** A printable report of what SENTINEL found on the owner's PC.
- **Sanitizer.** It removes every personal identifier from a sample of real data.
- **Public page.** A "My PC (sample)" page on GitHub Pages, built from that sanitized sample.
- **Accuracy.** An honest accuracy page comparing the model's verdicts with hand labels.

**Architecture:**
- `pipeline/sanitize.py` learns identifiers from the data and replaces them everywhere with stable
  placeholders: computer and host names, user names, profile-path users, IPv4, IPv6 and MAC
  addresses, agent ids.
- `pipeline/sample.py` exports a `PcSample` from the live database: a feed, the assessment and
  the investigated runs. It sanitizes the sample and refuses to write it if any term in
  `SENTINEL_FORBIDDEN_TERMS` survives. That variable holds the owner's real names and is set at
  run time, never committed.
- The sample is committed to `lab/wazuh/sample/pc-sample.json`. The Pages build copies it and
  serves it through `VITE_PC_SAMPLE_URL`.
- The dashboard's My PC page gains a sample mode: it loads once, shows a banner and hides the
  controls. It also gains a Report tab that prints cleanly to PDF.
- `eval/pc_accuracy.py` compares the sample's verdicts with `lab/wazuh/sample/labels.yml` and
  writes `docs/pc-accuracy.md`.

**Tech Stack:** Python 3.11, pydantic 2, SQLAlchemy Core, PyYAML, pytest, React 19 + TypeScript + Vite, GitHub Actions.

Spec: `docs/superpowers/specs/2026-09-27-wazuh-live-advisor-design.md` (phase 4 row, "Safety"
sanitizer bullet, "Dashboard" Report tab and public sample).

## Global Constraints

- Work on branch `feat/wazuh-report-sample`, created from `feat/wazuh-weak-spots`.
- Commit with `git -c user.name="Ahmed Helal" -c user.email="abuh3lal@gmail.com" commit ...`.
- No comments in code. `ruff check .` clean (ruff 0.16.4, line length 100, E F I UP B).
- Contract changes follow the usual steps: models, version bump, `python -m contracts.generate_fixtures`,
  `npm run gen:types`, DECISIONS entry.
- Python is `.venv/Scripts/python.exe`. DB tests need
  `SENTINEL_TEST_DATABASE_URL=postgresql+psycopg://sentinel:sentinel_dev@127.0.0.1:5432/sentinel_test`
  in the same command.
- Baseline at the start: `749 passed, 2 skipped, 1 warning`.
- **Privacy is the point of this phase.**
  - Nothing personal may be committed. Placeholders are `my-pc`, `MY-PC`, `user1`, `user2`, …,
    `sentinel-test-nobody`, `203.0.113.N` (TEST-NET-3, RFC 5737), `2001:db8::N` (the IPv6
    documentation range, RFC 3849), `00:00:5e:00:53:NN` (the documentation MAC range) and
    agent ids `001`, `002`, ….
  - The owner's real names are only ever passed at run time in `SENTINEL_FORBIDDEN_TERMS`,
    separated by commas, semicolons or newlines. They never appear in code, tests, docs, commit
    messages or CI.
  - The owner reviews the exported sample before it is committed.
- Values:
  - The sample holds at most 50 alerts, 30 incident summaries, the top 25 findings with their
    recommendations, and at most 10 investigated runs.
  - Loopback (`127.0.0.1`, `::1`), the unspecified addresses (`0.0.0.0`, `::`) and
    already-placeholder values are kept.
  - Built-in Windows accounts are kept: `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`,
    `ANONYMOUS LOGON`, `Administrator`, `Guest`, `DefaultAccount`, `WDAGUtilityAccount`, `-`.
  - Profile folders `Public`, `Default`, `Default User` and `All Users` are kept.
- The sample page is read-only: no Rescan, no Retry, no polling. Its banner reads "Recorded
  sample from the author's own PC, with names and addresses replaced. Nothing here is live."

## File Structure

| Path | Responsibility |
|---|---|
| `contracts/models.py` | 1.7.0: `PcSample` |
| `pipeline/sanitize.py` | learn identifiers, replace them everywhere, find leftovers |
| `pipeline/sample.py` | export a sanitized `PcSample` from the database (CLI) |
| `eval/pc_accuracy.py`, `lab/wazuh/sample/labels.yml` | verdict accuracy against hand labels |
| `lab/wazuh/sample/pc-sample.json`, `docs/pc-accuracy.md` | committed outputs, after owner review |
| `frontend/src/api.ts`, `App.tsx`, `components/MyPc.tsx`, `FixPanel.tsx`, `ReportPanel.tsx`, `styles.css` | sample mode, Report tab, print styles |
| `.github/workflows/pages.yml` | copy the sample into the Pages build |

---

### Task 1: Contracts 1.7.0 — `PcSample`

**Files:** `contracts/models.py`, `contracts/generate_fixtures.py`, `tests/test_contracts.py`, `DECISIONS.md`, `frontend/package.json`, generated fixtures/schemas/types.

**Interfaces:**
- Produces: `PcSample(created_at: datetime, note: str, feed: PcFeed, assessment: HostAssessment | None = None, runs: list[IncidentRun] = [])`, and the frontend type in `frontend/src/types/sample.ts`.

- [ ] **Step 1: Failing test.** In `tests/test_contracts.py`, import `PcSample` and add
  `"pc_sample": PcSample,` to `FIXTURE_MODEL_MAP`. Append:

```python
def test_pc_sample_defaults() -> None:
    feed = PcFeed(
        status=PcStatus(
            checked_at=datetime(2026, 9, 29, tzinfo=UTC),
            wazuh_api=ServiceState(reachable=True),
            backfill=ServiceState(reachable=True),
            alert_count=0,
        )
    )
    sample = PcSample(created_at=datetime(2026, 9, 29, tzinfo=UTC), note="n", feed=feed)
    assert sample.assessment is None
    assert sample.runs == []
```

(import `PcFeed` if needed).

- [ ] **Step 2: Model.**
  - Set `CONTRACT_VERSION = "1.7.0"`.
  - Add after `PcFeed`:

```python
class PcSample(SentinelModel):
    """A sanitized, recorded snapshot of the live My PC page, for the public demo."""

    created_at: datetime
    note: str
    feed: PcFeed
    assessment: HostAssessment | None = None
    runs: list[IncidentRun] = Field(default_factory=list)
```

  Put it after `IncidentRun` if `IncidentRun` is defined later in the file. Add it to
  `__all__`.
- [ ] **Step 3: Fixture and types.**
  - In `generate_fixtures.py`, add
    `pc_sample = PcSample(created_at=WZ_T0, note="Recorded sample.", feed=pc_feed, assessment=host_assessment, runs=[incident_run])`.
    Use the existing `incident_run` fixture variable; check its name. Add it to `FIXTURES` and
    add `PcSample` to `SCHEMA_MODELS`.
  - Append ` && json2ts -i ../contracts/schemas/PcSample.schema.json -o src/types/sample.ts --bannerComment \"\"`
    to the `gen:types` script.
  - Regenerate the fixtures, then run `npm run gen:types && npm run build`.
- [ ] **Step 4: D-16** in `DECISIONS.md`, after the first `---`:

```markdown
## D-16 — Contracts 1.7.0 and a sanitized public sample (2026-09-29)

**Decision.** Add `PcSample`, a recorded snapshot of the My PC page (feed, assessment, runs).
`pipeline.sample` exports it from the live database, and `pipeline.sanitize` replaces every
host name, user name, profile-path user, IPv4 and MAC address and agent id with a stable
placeholder. The export refuses to write if any term in `SENTINEL_FORBIDDEN_TERMS` survives. The
owner reviews the file before it is committed to `lab/wazuh/sample/`, and GitHub Pages serves it
read-only.

**Why.** Recruiters should see the live advisor working on real data without the owner's PC
being exposed. Learning identifiers from the data catches the names that occur in free text,
not only those in known fields. The runtime deny-list is the last check, and it never lives in
the repo.

**Consequence.** The public page is a snapshot, so it does not update. Regenerating it means
running the export again and reviewing it again.

---
```

- [ ] **Step 5:** Run the full suite and ruff, then commit with the message "Contracts 1.7.0: a recorded My PC sample".

---

### Task 2: The sanitizer

**Files:** Create `pipeline/sanitize.py`, `tests/test_sanitize.py`.

**Interfaces:**
- Produces: `Sanitizer()` with `.learn(doc)`, `.apply(doc)` (returns a new JSON-like value) and
  `.mapping` (dict of original → placeholder); `leftovers(doc, terms) -> list[str]`; and
  `forbidden_terms() -> list[str]`, which reads `SENTINEL_FORBIDDEN_TERMS`.

- [ ] **Step 1: Failing tests.** Create `tests/test_sanitize.py`:

```python
from __future__ import annotations

import pytest

from pipeline.sanitize import Sanitizer, forbidden_terms, leftovers

DOC = {
    "event": {"host": "DESKTOP-9QXZ7", "user": "jane.doe", "network": {"src_ip": "192.168.1.23"}},
    "raw": {
        "agent": {"id": "007", "name": "my-pc"},
        "data": {
            "win": {
                "system": {"computer": "DESKTOP-9QXZ7"},
                "eventdata": {
                    "subjectUserName": "jane.doe",
                    "targetUserName": "SYSTEM",
                    "workstationName": "DESKTOP-9QXZ7",
                    "processName": "C:\\\\Users\\\\jane.doe\\\\AppData\\\\app.exe",
                },
            }
        },
        "full_log": "Login by jane.doe from 192.168.1.23 on DESKTOP-9QXZ7 (mac 3C:52:82:AA:BB:CC)",
        "message": "C:\\Users\\Jane.Doe\\Documents and C:\\Users\\Public\\x",
    },
    "loopback": "127.0.0.1 and ::1",
    "keep": "sentinel-test-nobody on my-pc",
}


def _clean() -> tuple[Sanitizer, object]:
    sanitizer = Sanitizer()
    sanitizer.learn(DOC)
    return sanitizer, sanitizer.apply(DOC)


def test_identifiers_are_replaced_everywhere() -> None:
    _, clean = _clean()
    text = repr(clean)
    for secret in ("DESKTOP-9QXZ7", "jane.doe", "Jane.Doe", "192.168.1.23", "3C:52:82:AA:BB:CC", "007"):
        assert secret.lower() not in text.lower()


def test_placeholders_are_stable_and_sensible() -> None:
    sanitizer, clean = _clean()
    assert clean["event"]["host"] == "MY-PC"
    assert clean["event"]["user"] == "user1"
    assert clean["event"]["network"]["src_ip"] == "203.0.113.1"
    assert clean["raw"]["agent"] == {"id": "001", "name": "my-pc"}
    assert clean["raw"]["data"]["win"]["eventdata"]["targetUserName"] == "SYSTEM"
    assert "\\\\Users\\\\user1\\\\AppData" in clean["raw"]["data"]["win"]["eventdata"]["processName"]
    assert "C:\\Users\\user1\\Documents" in clean["raw"]["message"]
    assert "C:\\Users\\Public\\x" in clean["raw"]["message"]
    assert "00:00:5e:00:53:01" in clean["raw"]["full_log"]
    assert clean["loopback"] == "127.0.0.1 and ::1"
    assert clean["keep"] == "sentinel-test-nobody on my-pc"
    again = Sanitizer()
    again.learn(DOC)
    assert again.apply(DOC) == clean


def test_sanitizing_twice_changes_nothing() -> None:
    _, clean = _clean()
    second = Sanitizer()
    second.learn(clean)
    assert second.apply(clean) == clean


def test_machine_accounts_map_to_the_host() -> None:
    doc = {"event": {"host": "DESKTOP-9QXZ7"}, "raw": {"user": "DESKTOP-9QXZ7$"}}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc)["raw"]["user"] == "MY-PC$"


def test_leftovers_and_forbidden_terms(monkeypatch: pytest.MonkeyPatch) -> None:
    _, clean = _clean()
    assert leftovers(clean, ["jane", "desktop-9qxz7"]) == []
    assert leftovers(DOC, ["JANE"]) == ["JANE"]
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", " jane , ,DESKTOP ")
    assert forbidden_terms() == ["jane", "DESKTOP"]
    monkeypatch.delenv("SENTINEL_FORBIDDEN_TERMS")
    assert forbidden_terms() == []
```

- [ ] **Step 2: Run it.** It fails with ModuleNotFoundError.
- [ ] **Step 3: Implement.** Create `pipeline/sanitize.py`:

```python
from __future__ import annotations

import os
import re
from typing import Any

HOST_KEYS = frozenset({"host", "agent_name", "computer", "workstationName", "hostname", "hostName"})
USER_KEYS = frozenset(
    {"user", "targetUserName", "subjectUserName", "userName", "accountName", "samAccountName"}
)
KEEP = frozenset(
    {
        "my-pc",
        "MY-PC",
        "sentinel-test-nobody",
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "ANONYMOUS LOGON",
        "Administrator",
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "-",
        "Public",
        "Default",
        "Default User",
        "All Users",
        "wazuh.manager",
    }
)
KEEP_LOWER = frozenset(value.lower() for value in KEEP)
PLACEHOLDER = re.compile(r"^(user\d+|HOST-\d+|MY-PC)\$?$", re.IGNORECASE)
PROFILE = re.compile(r"(?i)\b[A-Z]:(?:\\+|/)Users(?:\\+|/)([^\\/\s\"'<>|:*?]+)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC = re.compile(r"(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b")
KEEP_IPS = frozenset({"127.0.0.1", "0.0.0.0"})


class Sanitizer:
    def __init__(self) -> None:
        self._hosts: set[str] = set()
        self._users: set[str] = set()
        self._agents: set[str] = set()
        self._ips: set[str] = set()
        self._macs: set[str] = set()
        self.mapping: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def learn(self, doc: Any) -> None:
        self._walk(doc, None, None)
        self._build()

    def apply(self, doc: Any) -> Any:
        if isinstance(doc, dict):
            return {key: self.apply(value) for key, value in doc.items()}
        if isinstance(doc, list):
            return [self.apply(value) for value in doc]
        if isinstance(doc, str):
            return self._replace(doc)
        return doc

    def _walk(self, value: Any, key: str | None, parent: str | None) -> None:
        if isinstance(value, dict):
            for child_key, child in value.items():
                self._walk(child, child_key, key)
            return
        if isinstance(value, list):
            for child in value:
                self._walk(child, key, parent)
            return
        if not isinstance(value, str):
            return
        text = value.strip()
        if key == "id" and parent == "agent" and text and text != "000":
            self._agents.add(text)
        if key in HOST_KEYS and text:
            self._add_host(text)
        if key in USER_KEYS and text:
            self._add_user(text)
        for match in PROFILE.finditer(value):
            self._add_user(match.group(1))
        for match in IPV4.finditer(value):
            if match.group(0) not in KEEP_IPS and not match.group(0).startswith("203.0.113."):
                self._ips.add(match.group(0))
        for match in MAC.finditer(value):
            if not match.group(0).lower().startswith("00:00:5e:00:53"):
                self._macs.add(match.group(0).upper())

    def _add_host(self, text: str) -> None:
        name = text.rstrip("$")
        if name and name.lower() not in KEEP_LOWER and not PLACEHOLDER.match(name):
            self._hosts.add(name.upper())

    def _add_user(self, text: str) -> None:
        if text.endswith("$"):
            self._add_host(text)
            return
        if text and text.lower() not in KEEP_LOWER and not PLACEHOLDER.match(text):
            self._users.add(text.lower())

    def _build(self) -> None:
        mapping: dict[str, str] = {}
        for index, host in enumerate(sorted(self._hosts)):
            mapping[host] = "MY-PC" if index == 0 else f"HOST-{index + 1}"
        for index, user in enumerate(sorted(self._users)):
            mapping[user] = f"user{index + 1}"
        for index, ip in enumerate(sorted(self._ips)):
            mapping[ip] = f"203.0.113.{index + 1}"
        for index, mac in enumerate(sorted(self._macs)):
            mapping[mac] = f"00:00:5e:00:53:{index + 1:02x}"
        for index, agent in enumerate(sorted(self._agents)):
            mapping[agent] = f"{index + 1:03d}"
        self.mapping = mapping
        words = sorted((k for k in mapping if k not in self._agents), key=len, reverse=True)
        self._pattern = (
            re.compile("|".join(re.escape(word) for word in words), re.IGNORECASE)
            if words
            else None
        )
        self._lookup = {key.lower(): value for key, value in mapping.items()}

    def _replace(self, text: str) -> str:
        if text in self._agents:
            return self.mapping[text]
        if self._pattern is None:
            return text
        return self._pattern.sub(lambda m: self._lookup[m.group(0).lower()], text)


def leftovers(doc: Any, terms: list[str]) -> list[str]:
    text = repr(doc).lower()
    return [term for term in terms if term.lower() in text]


def forbidden_terms() -> list[str]:
    value = os.environ.get("SENTINEL_FORBIDDEN_TERMS", "")
    return [term.strip() for term in value.split(",") if term.strip()]
```

  Notes for the implementer:
  - `agent.id` values are replaced only as whole strings, so short numbers inside other text
    stay as they are.
  - Words that are too short to be safe to replace should not appear here: host and user names
    come from known fields and profile paths.
  - If a learned user name is shorter than 3 characters, skip it (add that rule in `_add_user`)
    and add a test.
  - Adjust the tests' expected values only if your implementation's placeholder order differs,
    and keep them deterministic.
- [ ] **Step 4:** Run the tests, the full suite and ruff. Commit with the message "Sanitize real PC data before it can leave the machine".

---

### Task 3: The sample exporter

**Files:** Create `pipeline/sample.py`, `tests/test_sample.py`.

**Interfaces:**
- Consumes: `backend.app.store.latest_alerts`, `alert_count`, `newest_alert_time`;
  `backend.app.incidents.incident_summaries`, `get_run`; `backend.app.findings.finding_hosts`,
  `assessment`; `pipeline.sanitize`.
- Produces: `build_sample(engine, now, *, alerts=50, incidents=30, findings=25, runs=10) -> PcSample`
  (not sanitized), `sanitize_sample(sample, terms) -> PcSample` (raises `SampleLeak` naming the
  surviving terms), and `main(argv)` (`--out`, default `lab/wazuh/sample/pc-sample.json`).

- [ ] **Step 1: Failing tests** (`tests/test_sample.py`, DB):
  - Store three alerts with `make_wazuh_alert`. One has `user="jane.doe"` and a
    `command_line` containing `C:\Users\jane.doe\x.ps1`. Group them with
    `pipeline.grouping.group_new_alerts`, save a run for one incident with `save_run`, and
    upsert two findings.
  - `build_sample(db, NOW)` has 3 alerts, the summaries, a non-empty assessment and 1 run.
  - `sanitize_sample(sample, ["jane"])` has no "jane" anywhere (check `model_dump_json()`), and
    its user placeholder is `user1`.
  - `sanitize_sample` raises `SampleLeak` when a term survives. Test this by passing a term
    that is not an identifier, e.g. "Logon Failure".
  - The status in the sample has fixed text: the `wazuh_api`, `model` and `sync` details say
    "Recorded sample.", and `queue_length` is 0.
- [ ] **Step 2: Implement** `pipeline/sample.py`:

```python
from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.findings import assessment, finding_hosts
from backend.app.incidents import get_run, incident_summaries
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from contracts.models import PcFeed, PcSample, PcStatus, ServiceState
from pipeline.sanitize import Sanitizer, forbidden_terms, leftovers

DEFAULT_OUT = Path("lab/wazuh/sample/pc-sample.json")
NOTE = (
    "Recorded sample from the author's own PC, with names and addresses replaced. "
    "Nothing here is live."
)
RECORDED = ServiceState(reachable=True, detail="Recorded sample.")


class SampleLeak(ValueError):
    pass


def build_sample(
    engine: Engine,
    now: datetime,
    *,
    alerts: int = 50,
    incidents: int = 30,
    findings: int = 25,
    runs: int = 10,
) -> PcSample:
    summaries = incident_summaries(engine, limit=incidents)
    status = PcStatus(
        checked_at=now,
        wazuh_api=RECORDED,
        backfill=RECORDED,
        alert_count=alert_count(engine),
        last_alert_at=newest_alert_time(engine),
        queue_length=0,
        model=RECORDED,
        sync=RECORDED,
    )
    feed = PcFeed(status=status, alerts=latest_alerts(engine, alerts), incidents=summaries)
    hosts = finding_hosts(engine)
    view = assessment(engine, hosts[0], now) if hosts else None
    if view is not None:
        kept = view.findings[:findings]
        ids = {finding.finding_id for finding in kept}
        view = view.model_copy(
            update={
                "findings": kept,
                "recommendations": [
                    r for r in view.recommendations if any(f in ids for f in r.finding_ids)
                ],
            }
        )
    investigated = [s for s in summaries if s.classification is not None][:runs]
    recorded = [get_run(engine, s.incident.incident_id) for s in investigated]
    return PcSample(
        created_at=now,
        note=NOTE,
        feed=feed,
        assessment=view,
        runs=[run for run in recorded if run is not None],
    )


def sanitize_sample(sample: PcSample, terms: list[str]) -> PcSample:
    data = sample.model_dump(mode="json")
    sanitizer = Sanitizer()
    sanitizer.learn(data)
    clean = sanitizer.apply(data)
    left = leftovers(clean, terms)
    if left:
        raise SampleLeak(f"These terms survived sanitizing: {', '.join(left)}")
    return PcSample.model_validate(clean)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.sample",
        description="Export a sanitized sample of the live My PC page for the public demo.",
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    terms = forbidden_terms()
    if not terms:
        print("Set SENTINEL_FORBIDDEN_TERMS to your real user and computer names first.")
        return 2
    sample = sanitize_sample(build_sample(get_engine(), datetime.now(UTC)), terms)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(sample.model_dump_json(indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Wrote {args.out}. Review it before committing.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

  Check the real signatures: `incident_summaries(engine, limit=...)`, `latest_alerts(engine,
  limit)`, `assessment(engine, host, now)`. Adapt the calls, not the behaviour. Also add a test
  that `main([])` returns 2 without the environment variable.
- [ ] **Step 3:** Run the tests, the full suite and ruff. Commit with the message "Export a sanitized sample of the My PC page".

---

### Task 4: Sample mode on the dashboard

**Files:** `frontend/src/api.ts`, `frontend/src/App.tsx`, `frontend/src/components/MyPc.tsx`, `frontend/src/components/FixPanel.tsx`, `frontend/src/styles.css`.

**Behaviour:**
- **Config.** `api.ts` exports `PC_SAMPLE_URL = import.meta.env.VITE_PC_SAMPLE_URL ?? null` and
  `fetchPcSample(url): Promise<PcSample>`, with types from `./types/sample`.
- **Navigation.** `App.tsx` shows the My PC link when `PC_FEED_URL` or `PC_SAMPLE_URL` is set.
  The label is "My PC (sample)" when only the sample is available. The view renders
  `<MyPc source={{ kind: "live", url }} />` or `<MyPc source={{ kind: "sample", url }} />`.
- **Loading in sample mode.**
  - `MyPc` loads the sample once and never polls.
  - The feed comes from `sample.feed`.
  - `fetchPcRun` is replaced by looking up `sample.runs` by incident id. An incident without a
    run shows "Not investigated in this sample."
  - The Retry button is hidden.
  - The header shows the banner (`sample.note`) in a `notice` above the status bar, and the
    eyebrow reads "Recorded sample" instead of "Live · refreshes every 5 seconds".
- **FixPanel.** It takes an optional `sample?: HostAssessment | null` prop. With it, it doesn't
  fetch, hides Rescan, and shows "No weak spots in this sample." when the prop is null.
- **Live mode.** Live mode is unchanged.
- **Build.** `npm run gen:types && git diff --exit-code src/types && npm run build`.
- **Verify.** Build with `VITE_PC_SAMPLE_URL=pc-sample.json VITE_RUNS_URL=runs.json`, with
  `contracts/fixtures/pc_sample.json` copied to `frontend/public/pc-sample.json` temporarily
  and not committed. The controller then checks it in a browser.
- **Commit** with the message "Show a recorded My PC sample read-only".

---

### Task 5: The printable report

**Files:** Create `frontend/src/components/ReportPanel.tsx`; modify `MyPc.tsx`, `styles.css`.

**Behaviour:**
- **Tab.** A fourth tab, "Report" (`?view=pc&tab=report`), available in both live and sample
  mode.
- **Header.** "SENTINEL report for {host}", generated {UTC time}, then a line about the data:
  - live: "Live data from Wazuh on this PC.";
  - sample: `sample.note`.

  A `control` button, "Print or save as PDF", calls `window.print()`.
- **Sections:**
  1. **Status.** Wazuh, AI model and weak-spot sync, as `name: detail` lines.
  2. **Fix these first.**
     - Take the assessment's recommendations in finding order, at most 10.
     - For each: the title, the covered finding count ("covers N weak spots"), the numbered
       steps, and the finding's `official_remediation` as "Wazuh says:".
     - Live mode fetches the assessment with `fetchAssessment()`; sample mode uses
       `sample.assessment`.
     - When there is no assessment: "No weak spots synced yet."
  3. **Recent incidents.**
     - The investigated incidents from `feed.incidents`, at most 10.
     - For each: the title, the status label (the same "Advice ready" rule as the table), the
       classification, and the recommendation titles.
     - The runs come from `fetchPcRun` (live, at most 10 requests, in parallel) or
       `sample.runs`.
  4. **Totals.** Open weak spots by severity; incidents by status.
- **Print CSS** in `styles.css`, under `@media print`:
  - hide `.masthead`, `.pc-head`, `.pc-tabs`, `.pc-status`, `.fix-head` and every `button`;
  - white background and black text;
  - `a` shows its URL after the text;
  - no page break inside a recommendation block (`.report-item { break-inside: avoid }`);
  - A4 margins through `@page { margin: 16mm }`.
- **Rendering.** Render all text as text.
- **Build.** Run the build, then commit with the message "Add a printable My PC report".

---

### Task 6: Publish the sample on GitHub Pages

**Files:** `.github/workflows/pages.yml`, `README.md`.

- In the "Build the static dashboard" step, before `npm run build`, copy
  `lab/wazuh/sample/pc-sample.json` to `frontend/public/pc-sample.json` when it exists, and set
  `VITE_PC_SAMPLE_URL: pc-sample.json` in that step's `env`.
- The README's "Watching a real PC" section gets a link to the public sample page:
  `https://cs-abuhelal.github.io/sentinel/?view=pc`.
- Commit with the message "Serve the recorded My PC sample on GitHub Pages".

---

### Task 7: Accuracy against hand labels

**Files:** Create `eval/__init__.py` (empty) if `eval/` has none, `eval/pc_accuracy.py`,
`tests/test_pc_accuracy.py`, `lab/wazuh/sample/labels.yml` (Task 8), `docs/pc-accuracy.md`
(generated, Task 8).

**Interfaces:**
- `load_labels(path) -> dict[str, Label]`. `Label` is a small pydantic model in the script
  (`expected: Classification`, `why: str`), keyed by incident title plus first alert time. The
  key is the run's `incident.title` + " @ " + `incident.window_start` isoformat, because
  sanitized sample ids are stable but opaque.
- `score(sample, labels) -> Report`: rows with the incident, the expected and actual
  classification, the confidence, the tools used, match/miss, and "unlabelled".
- `render(report) -> str`: Markdown. It contains a summary line, "N of M labelled incidents
  matched", a table and a short "How this was measured" paragraph, which says that labels were
  set by the owner, who knew what happened on the PC. It also reports fix-step checks from the
  sample assessment: recommendations, total steps, dropped steps, and whether every
  recommendation's `fixed_when` bound appears in its steps.
- `main(argv)`: `--sample lab/wazuh/sample/pc-sample.json --labels lab/wazuh/sample/labels.yml --out docs/pc-accuracy.md`.

- [ ] Tests: a small in-memory `PcSample` built from `contracts/fixtures/pc_sample.json` with
  two labelled runs (one match, one miss) and one unlabelled. Check the counts, the table rows
  and that `render` contains "1 of 2 labelled incidents matched".
- [ ] Implement it, run it, then commit with the message "Score the PC verdicts against hand labels".

---

### Task 8: Export, owner review, labels, screenshots and PR (controller, with Ahmed)

1. With the live stack running, export the sample:

   ```bash
   SENTINEL_FORBIDDEN_TERMS="<set by the controller from the owner's names, never written to a file>" DATABASE_URL=... python -m pipeline.sample
   ```

   Then grep the output with the same terms. It must print 0.
2. **Ahmed reviews** `lab/wazuh/sample/pc-sample.json`. The controller shows the list of
   incidents, the top fixes and a sample of alert text, and asks for a yes before committing.
3. **Labels.**
   - The controller drafts `labels.yml` for every investigated incident in the sample, each with
     a reason: the failed-logon burst was his own test; the rootcheck `C:\WINDOWS\tracing`
     alternate data stream is a known Windows false positive; and so on.
   - Ahmed confirms or corrects each label. Aim for about 10 labelled incidents. If fewer
     exist, say so honestly in `docs/pc-accuracy.md`, and optionally trigger one more benign
     burst.
   - Run `eval/pc_accuracy.py` and commit the sample, the labels and the report.
4. **Screenshots.**
   - `15-my-pc-report.png`: the Report tab, cropped.
   - `16-my-pc-sample.png`: the Pages build locally with the sample banner.
   - Add a README paragraph linking the accuracy page.
5. Push and open the PR (base `feat/wazuh-weak-spots`). After the PR chain (#11 → #12 → phase 3
   → phase 4) is merged, the Pages deploy on `main` publishes the sample.
