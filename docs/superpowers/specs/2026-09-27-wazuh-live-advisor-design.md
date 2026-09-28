# Wazuh live advisor — design

Date: 2026-09-27. Status: approved in conversation, awaiting review of this document.

## Goal

SENTINEL watches Ahmed's own Windows PC through Wazuh in real time and tells him what to do:
which alerts are real threats and which are normal, and which weak spots (vulnerable software,
failed CIS settings) to fix first, in plain language with evidence. It never acts on the PC.

## Decisions

- **Scope:** both suspicious activity (Wazuh alerts) and weak spots (vulnerabilities and failed
  CIS checks).
- **Feed:** real time. Wazuh pushes every alert to a SENTINEL service. Weak spots are pulled from
  Wazuh on start, every 6 hours and on demand.
- **Wazuh:** the official single-node Docker deployment, version 4.14, on the same PC. The
  Windows PC runs the Wazuh agent.
- **Output:** a live "My PC" dashboard page and a printable report. The public demo shows a
  recorded, sanitized sample.
- **Advice only:** SENTINEL never executes anything on the PC.
- **Storage:** PostgreSQL, the store already planned under D-00 and D-05.
- **Model:** local `qwen3:14b` through Ollama, as today. Investigations are queued and run one at
  a time.

## Phases

Each phase gets its own implementation plan and ends with something that works.

| Phase | Delivers | Done when |
|---|---|---|
| 1. Live feed | Wazuh in Docker, the PC enrolled, the SENTINEL service with Postgres, the ingest endpoint, backfill, and a "My PC → Alerts" page | Five failed logons show up as alerts on the page within 10 seconds. They come from `runas` with a user that does not exist, so no real account is locked out. Alerts sent while SENTINEL was stopped appear after it restarts. CI is green. |
| 2. Alert investigations | Grouping alerts into incidents, the queue worker, three new read-only tools, AI recommendations with the step checker, the advice-only policy rule, and the incidents view | Enough failed logons within a few minutes to trigger Wazuh's multiple-logon-failure rule (60204, level 10) produce an incident. The model investigates it using at least one new tool, and every proposed action is denied with `personal_host_advice_only`. The new prompt-injection test passes. |
| 3. Weak spots | Sync of vulnerabilities and failed CIS checks, the priority score, AI fix steps with the checker, and the "Fix these first" view | A rescan lists open findings sorted by priority, and the top 10 have checked fix steps. |
| 4. Report, demo, accuracy | The report page, the sanitizer, the public sample page, and the accuracy script | The report prints to PDF, the sample is live on GitHub Pages, and `docs/pc-accuracy.md` reports results against about 10 hand labels. |

## Architecture

```
Windows PC ── Wazuh agent ──► Wazuh manager (Docker) ── custom-sentinel integration ──┐
                                   ▲                                                   │ POST, token
                                   │ Server API :55000, Indexer :9200 (read only)      ▼
                                   └──────────── SENTINEL service (FastAPI) ◄──── /api/ingest/wazuh
                                                      │  backfill, sync
                                                      ▼
                                                 PostgreSQL
                                                      ▲
                     pipeline.worker ─────────────────┘  groups → investigates (Ollama) → advice
                     dashboard "My PC" ◄── /api/pc/* (polls every 5 s)
```

Wazuh is an external data source. SENTINEL reads from it and never depends on it at build or
test time (D-11).

The Wazuh manager, the Wazuh indexer and the SENTINEL backend share an external Docker network,
`sentinel-wazuh`. There the backend has the alias `sentinel-backend`, and Wazuh is reached at
`wazuh.manager` and `wazuh.indexer`. SENTINEL publishes its ports on `127.0.0.1` only. The
network is added through `docker-compose.wazuh.yml`, so plain `docker compose up` still works
without Wazuh.

## Wazuh side (`lab/wazuh/`)

- `README.md`: setup steps for the wazuh-docker single-node deployment (tag `v4.14.x`):
  `vm.max_map_count=262144` in the `docker-desktop` WSL distribution, certificate generation,
  `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g` for the indexer, and the Windows agent installed with the
  manager at `127.0.0.1`.
- `docker-compose.override.yml` overrides upstream wazuh-docker's port publishing, which
  otherwise binds to all interfaces: only the dashboard and the agent ports are published, and
  only on `127.0.0.1`. The indexer (9200), the API (55000) and the syslog port (514) are not
  published at all; SENTINEL reaches the manager and the indexer over the `sentinel-wazuh`
  network instead.
- `custom-sentinel` and `custom-sentinel.py`: a Wazuh custom integration mounted into
  `/var/ossec/integrations/`. It reads the alert file path, API key and hook URL that Wazuh passes
  as arguments, and POSTs the alert JSON with `Authorization: Bearer <key>`. It sets a 5-second
  timeout and never retries. The backfill on start covers downtime and the last 10 minutes.
- `ossec-integration.xml`: the block added to the manager configuration:

```xml
<integration>
  <name>custom-sentinel</name>
  <hook_url>http://sentinel-backend:8000/api/ingest/wazuh</hook_url>
  <api_key>REPLACE_WITH_SENTINEL_INGEST_TOKEN</api_key>
  <level>3</level>
  <alert_format>json</alert_format>
</integration>
```

At setup, the `api_key` value is replaced with the token from SENTINEL's `.env`. The committed
file keeps the placeholder.

## Contracts 1.4.0 (D-12)

- `TelemetrySource.WAZUH = "wazuh"`.
- `IncidentStatus` gains `queued`, `low_priority` and `investigation_failed`.
- `HostRecord` gains `personal: bool = False`.
- `FindingKind`: `vulnerability`, `configuration`. `FindingStatus`: `open`, `resolved`.
- `Finding(finding_id, kind, key, host, title, severity, priority, status, cve, package,
  installed_version, cvss, policy_id, check_id, rationale, official_remediation, references,
  related_alert_count, first_seen, last_seen, raw)`. `key` is `cve:<CVE>:<package>` or
  `sca:<policy_id>:<check_id>` and is unique per host.
- `Recommendation(recommendation_id, title, priority, steps, finding_ids, evidence_ids,
  official_remediation, dropped_steps)`.
- `HostAssessment(assessment_id, host, contract_version, created_at, synced_at, findings,
  recommendations, model_name)`.
- `Verdict` gains `recommendations: list[Recommendation] = []`.
- `LiveAlert(wazuh_id, received_at, level, event, alert)` is one stored alert as the live page
  shows it.
- `ServiceState(reachable, detail)`.
- `PcStatus(checked_at, wazuh_api, backfill, alert_count, last_alert_at)`. Later phases add the
  queue length and whether Ollama is reachable.
- `PcFeed(status, alerts)` is what the live page polls.

Fixtures, JSON Schemas and frontend types are regenerated as usual.

## SENTINEL components

### Ingest (`backend/app/ingest.py`)

`POST /api/ingest/wazuh` compares the bearer token with `SENTINEL_INGEST_TOKEN` in constant time
and returns 401 on a mismatch. It rejects bodies over 1 MB (413) and anything that is not a JSON
object with `id`, `timestamp`, `rule` and `agent` (422). It stores the raw alert keyed by the
Wazuh alert `id` (`ON CONFLICT DO NOTHING`) and returns 202 `{"stored": true|false}`. No model
call happens in the request path.

### Converter (`ingest/wazuh.py`)

`convert(alert) -> (Event, Alert)`, deterministic:

- `Event.source = wazuh`, `host = agent.name`, `timestamp = alert.timestamp`,
  `event_type = "wazuh:<rule.id>"`, `message = rule.description`, and `raw` is the full alert.
- Fields come from `data.win.eventdata` when present: `targetUserName` → `user`; `image`,
  `newProcessName` or `processName` (the program that tried to log on, in logon events) →
  `process.name`; `commandLine` → `process.command_line`; `parentImage` →
  `process.parent_name`; `ipAddress` → `network.src_ip`. `syscheck.path` → `file_path`.
- Category from `rule.groups`: `authentication_failed`, `authentication_success`,
  `authentication_failures` or `win_authentication_failed` → authentication; `sysmon_event1` or
  `process` → process; `syscheck` → file; `adduser`, `group_changed` or `account_changed` →
  account_management; `privilege` → privilege; anything else → other. The outcome is `failure`
  for `authentication_failed`, `authentication_failures` or `win_authentication_failed`, and
  `success` for `authentication_success`.
- `Alert.rule_id = "wazuh-<rule.id>"`, `rule_name = rule.description`,
  `suggested_techniques = rule.mitre.id`. Severity comes from `rule.level`: 0–3 info, 4–6 low,
  7–9 medium, 10–12 high, 13–15 critical.
- Wazuh doubles every backslash in `data.win.eventdata` values; the converter turns them back
  into single backslashes (the event's `raw` keeps the original). Verified against Wazuh 4.14.8,
  whose rule 60122 carries the group `authentication_failed`.

### Backfill

The cursor is computed at startup, before live alerts are accepted, so a live alert stored during
backfill can never move it past a downtime gap: 10 minutes before the newest stored alert (or the
start of time, if nothing is stored yet). The backend then asks the Wazuh indexer
(`wazuh-alerts-4.x-*`) for alerts with `rule.level >= 3` and `timestamp` at or after that cursor,
in pages of up to 5,000, advancing the cursor to the last page's newest timestamp and stopping
when a page comes back short, for up to 20 pages. Alerts already stored are skipped by the
idempotent insert, so pages can safely overlap. If the indexer cannot be reached, it logs the
reason and the status endpoint reports it.

### Storage (`backend/app/db.py`, Alembic in `backend/migrations/`)

SQLAlchemy 2 with psycopg 3 (`DATABASE_URL`). Contract documents are stored as JSONB, with a few
indexed columns for queries:

| Table | Columns |
|---|---|
| `wazuh_alerts` | `wazuh_id` PK, `alert_time`, `received_at`, `agent_name`, `rule_id`, `level`, `payload` JSONB, `event` JSONB, `alert` JSONB, `incident_id` |
| `incidents` | `incident_id` PK, `host`, `group_key`, `status`, `first_alert_at`, `last_alert_at`, `max_level`, `run` JSONB (the `IncidentRun`, once investigated) |
| `findings` | `finding_id` PK, `host`, `key`, `kind`, `status`, `priority`, `first_seen`, `last_seen`, `finding` JSONB; unique (`host`, `key`) |
| `assessments` | `assessment_id` PK, `created_at`, `assessment` JSONB |
| `sync_runs` | `id` PK, `started_at`, `finished_at`, `ok`, `error` |

### Read API (`/api/pc/*`)

`GET /feed?limit=200` returns a `PcFeed`: the status (Wazuh API reachable, cached for 30 s;
backfill result; alert count; last alert) and the newest alerts. Later phases add
`GET /incidents`, `GET /incidents/{id}`,
`POST /incidents/{id}/retry`, `GET /assessment` (latest), `POST /rescan`, and `GET /report`
(printable HTML). Each endpoint arrives in the phase that needs it. The existing `/api/runs`
endpoints stay as they are.

### Worker (`pipeline/worker.py`, phase 2)

It runs in a loop every 10 seconds:

1. **Group.** Each new alert joins the open incident with the same key if it came within 60
   minutes of that incident's alerts (a late, older alert widens the window backwards) and the
   incident would still span at most 24 hours. Otherwise it starts a new incident. The key is the
   host plus the first MITRE technique, or the Wazuh rule id when there is none. Alerts in the `sca`
   or `vulnerability-detector` groups are weak spots, not incidents: they are marked as grouped
   without an incident and handled by phase 3.
2. **Triage.** An incident whose highest alert level is below 7 gets `low_priority` and is not
   investigated. It stays visible. Anything else is `queued`.
3. **Investigate.** If Ollama is reachable, the oldest queued incident is investigated with the
   existing agent loop. The worker builds the inventory at runtime from the Wazuh agent list, and
   every Wazuh host is `personal: true`. Nothing about the PC is committed.
4. **Save.** The `IncidentRun`, including the audit chain, goes to `incidents.run`. On
   `invalid_output` or `tool_call_cap` without a verdict, the status becomes
   `investigation_failed`. `POST /api/pc/incidents/{id}/retry` puts it back in the queue.

The worker runs as the `worker` service in `docker-compose.yml` and reaches Ollama at
`OLLAMA_URL` (default `http://host.docker.internal:11434`). Investigations of the PC use their
own system prompt (`agent/prompts/pc.md`): the model writes `recommendations` (advice the owner
carries out) and leaves `proposed_actions` empty. Every recommendation must cite evidence, and the
step checker (`policy/advice.py`, the deny-list under "Fix steps") drops any step that would weaken
the PC's security before the run is saved. A recommendation whose title would weaken it is removed
whole.

### New read-only tools (phase 2)

All tools read Postgres through a `HostHistory` on the tool context. They never call Wazuh or
the network. `host_posture` and `finding_details` arrive in phase 3 with the findings table.

| Tool | Parameters | Returns | Evidence class |
|---|---|---|---|
| `related_alerts` | `hours` (1–72), optional `rule_group` | other alerts on the host around the incident window, grouped by rule, with counts | `related_alerts` |
| `process_activity` | `process` (image name or path), `hours` | alerts and events for the same process or parent, with command lines | `process_lineage` |
| `rule_context` | `rule_id` | rule description, groups, MITRE mapping, and how often it fired on this host over the last 30 days | `baseline_comparison` |
| `host_posture` (phase 3) | optional `package` | open findings on the host, filtered by package when given | `entity_context` |
| `finding_details` (phase 3, fix steps only) | `finding_id` | the full finding, including Wazuh's rationale, remediation and references | `entity_context` |

`auth_history` also works for Windows logon events, because the converter maps them to the
authentication category.

### Policy (`policy/engine.py`)

A new rule, `personal_host_advice_only`, applies whenever any host entity of the incident is
`personal` in the inventory. Its outcome is `deny`, with the reason "Advice only: SENTINEL never
acts on your own PC." It runs right after `no_action` and before every other rule. `runner_for`
returns no runner for personal hosts, so the executor cannot run either way.

### Weak spots (phase 3)

**Sync.** The server API is used with the JWT from `POST /security/user/authenticate`:
`GET /sca/{agent_id}` and `GET /sca/{agent_id}/checks/{policy_id}?result=failed`. The indexer
provides `wazuh-states-vulnerabilities-*`, filtered by `agent.id`. The first phase 3 task checks
these endpoints and field names against the running 4.14 instance. Findings that are no longer
reported become `resolved`.

**Priority** (deterministic, `policy/priority.py`):

- A vulnerability starts at `round(cvss * 10)`. Without CVSS, severity decides: critical 90,
  high 70, medium 45, low 20.
- A failed CIS check starts at its category weight, matched by keywords in the title and
  compliance fields:

| Category | Weight |
|---|---|
| firewall | 70 |
| antivirus / Defender | 70 |
| account and password policy | 60 |
| remote access (RDP, SMB) | 60 |
| audit policy | 55 |
| other | 35 |

- Either kind gets +10 when a related alert appeared in the last 7 days. The score is capped at
  100.
- Severity bands: 80+ critical, 60+ high, 40+ medium, 20+ low, otherwise info.
- Ties go to vulnerabilities before configuration findings, then to the oldest `first_seen`.

**Fix steps.** For the top 10 open findings, the model writes one `Recommendation` each, using
`host_posture`, `related_alerts` and a `finding_details` tool. Every recommendation passes the
checker (`policy/advice.py`) before it is stored:

- It must cite at least one existing finding, and every evidence id must exist.
- Every `CVE-\d{4}-\d+` it mentions must belong to a cited finding. If not, the recommendation is
  dropped.
- Any step that matches the weakening deny-list is removed and recorded in `dropped_steps`. The
  list is `WEAKENING` in `policy/advice.py`: turning off, pausing or removing Defender, the
  firewall, antivirus, UAC, SmartScreen, real-time or tamper protection; UAC "never notify";
  download-and-run commands (`iex`, `DownloadString`, `-EncodedCommand`, `certutil -urlcache`,
  `bitsadmin /transfer`, piping into a shell); Defender exclusions; `Set-ExecutionPolicy
  Unrestricted`; and `bcdedit`. Matching is case-insensitive. A recommendation whose title
  matches is dropped whole.
- At most 10 steps, each at most 300 characters.
- For CIS findings, Wazuh's own remediation text is kept in `official_remediation` and shown
  beside the model's steps.

### Dashboard

A new route, "My PC", polls every 5 seconds. It has a status bar (Wazuh, last sync, queue,
model) and these tabs:

- **Alerts** (phase 1).
- **Incidents** (phase 2), reusing the existing stage view.
- **Fix these first** (phase 3), with a **Rescan** button.
- **Report** (phase 4).

The public build shows "My PC (sample)", read from a static sanitized file, with a "recorded
sample" banner.

## Safety

- Nothing runs on the PC: the policy rule, no runner, and a test that an approval file changes
  nothing.
- The ingest endpoint is bound to the host and the Docker network only. It needs a token and has
  a size limit.
- Secrets live in `.env`, which is git-ignored: `SENTINEL_INGEST_TOKEN`, `WAZUH_API_URL`,
  `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER` and
  `WAZUH_INDEXER_PASSWORD`. A blank `.env.example` is committed.
- The Wazuh API liveness check in the status bar does not verify TLS. It sends no credentials
  and reads no data, and the manager's API certificate is self-signed rather than issued by the
  indexer CA. Every call that sends credentials (the backfill now, the sync in phase 3) verifies
  TLS against `WAZUH_CA_CERT`.
- Alert text is data, never instructions. A new injection test puts instructions in
  `data.win.eventdata.commandLine`, and the classification, policy outcome and executions must not
  change.
- Real PC data stays in the local Postgres database.
- `pipeline.sanitize` maps the host name, usernames, IPv4 addresses, MAC addresses, user-profile
  paths (`C:\Users\<name>`) and agent ids to stable placeholders, in every string field including
  `raw`. A test checks that no original identifier is left. Ahmed reviews the sample before it is
  committed to `lab/wazuh/sample/`.

## Failure handling

| Failure | Behaviour |
|---|---|
| Wazuh down | The status shows the Wazuh API as offline with the last error. The sync records the error. |
| SENTINEL down | Missed alerts are backfilled from the indexer on start. |
| Ollama down | Incidents stay `queued`. |
| Model gives bad output | `investigation_failed`, with a retry endpoint. |
| Duplicate alert | Ignored by the primary key. |

## Testing

- **Unit tests** for the converter and backfill mapping, using sanitized real alert fixtures in
  `tests/data/wazuh/`. Also unit tests for grouping and triage, the priority formula, the policy
  rule, the advice checker and the sanitizer.
- **API tests** with FastAPI's TestClient against a real Postgres. CI adds a `postgres:16`
  service, and the tests are skipped locally when `SENTINEL_TEST_DATABASE_URL` is not set.
- **Agent tests** replay recorded `qwen3:14b` responses for one incident and one fix-step run.
- **A manual end-to-end check** for each phase, following the "done when" column.

## Contracts 1.5.0 (D-13, phase 2)

- `PcIncidentSummary(incident, alert_count, max_level, classification, recommendation_count)`.
- `PcStatus` gains `queue_length` (default 0) and `model: ServiceState` (Ollama reachability).
- `PcFeed` gains `incidents: list[PcIncidentSummary]`.
- `Inventory.is_personal(host)`.

## Decision log entries

- **D-11:** SENTINEL gets a live advisor mode that reads from Wazuh as an external source. D-00
  still keeps Wazuh out of SENTINEL's own stack. PostgreSQL arrives, as D-05 planned, because the
  feed needs durable writes.
- **D-12:** Contracts 1.4.0, as listed above.

## Out of scope

- More than one PC.
- Any automatic remediation or Wazuh active response.
- Push updates (server-sent events or WebSockets).
- External threat-intelligence feeds.
- Alert levels below 3.
- Sysmon installation. Sysmon is optional: if it is installed, its events flow through the same
  converter.
