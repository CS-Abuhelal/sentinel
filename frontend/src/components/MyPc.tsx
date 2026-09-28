import { useEffect, useState } from "react";

import { fetchPcFeed, fetchPcRun, retryIncident } from "../api";
import { STATUS, utc } from "../format";
import type { IncidentRun } from "../types/contracts";
import type { PcFeed, PcIncidentSummary, ServiceState } from "../types/pc";
import { RunDetail } from "./RunDetail";

const POLL_MS = 5000;

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string; last: PcFeed | null }
  | { state: "ready"; feed: PcFeed };

type Tab = "alerts" | "incidents";

type RunLoad =
  | { state: "idle" }
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "ready"; run: IncidentRun };

function initialTab(): Tab {
  return new URLSearchParams(window.location.search).get("tab") === "incidents" ? "incidents" : "alerts";
}

function initialIncidentId(): string | null {
  return new URLSearchParams(window.location.search).get("incident");
}

export function MyPc({ url }: { url: string }) {
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [tab, setTab] = useState<Tab>(initialTab);
  const [incidentId, setIncidentId] = useState<string | null>(initialIncidentId);
  const [runLoad, setRunLoad] = useState<RunLoad>({ state: "idle" });

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

  useEffect(() => {
    const params = new URLSearchParams();
    params.set("view", "pc");
    if (tab === "incidents") params.set("tab", "incidents");
    if (incidentId) params.set("incident", incidentId);
    window.history.replaceState(null, "", `?${params.toString()}`);
  }, [tab, incidentId]);

  useEffect(() => {
    if (!incidentId) {
      setRunLoad({ state: "idle" });
      return;
    }
    let cancelled = false;
    setRunLoad({ state: "loading" });
    fetchPcRun(incidentId)
      .then((run) => {
        if (!cancelled) setRunLoad({ state: "ready", run });
      })
      .catch((error: Error) => {
        if (!cancelled) setRunLoad({ state: "failed", message: error.message });
      });
    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const feed = load.state === "ready" ? load.feed : load.state === "failed" ? load.last : null;

  const selectTab = (next: Tab) => {
    setTab(next);
    setIncidentId(null);
  };

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
      <nav className="pc-tabs" aria-label="My PC views">
        <button type="button" aria-pressed={tab === "alerts"} onClick={() => selectTab("alerts")}>
          Alerts
        </button>
        <button type="button" aria-pressed={tab === "incidents"} onClick={() => selectTab("incidents")}>
          Incidents
        </button>
      </nav>
      {feed && tab === "alerts" && <AlertTable feed={feed} />}
      {feed && tab === "incidents" && (
        <IncidentsPanel
          feed={feed}
          incidentId={incidentId}
          runLoad={runLoad}
          onSelect={setIncidentId}
          onBack={() => setIncidentId(null)}
        />
      )}
    </section>
  );
}

function StatusBar({ feed }: { feed: PcFeed }) {
  const { status } = feed;
  return (
    <dl className="pc-status">
      <Service label="Wazuh API" state={status.wazuh_api} />
      <Service label="Backfill" state={status.backfill} />
      <Service label="AI model" state={status.model} />
      <div>
        <dt>Alerts stored</dt>
        <dd className="mono">{status.alert_count}</dd>
      </div>
      <div>
        <dt>Last alert (UTC)</dt>
        <dd className="mono">{status.last_alert_at ? utc(status.last_alert_at) : "none yet"}</dd>
      </div>
      <div>
        <dt>Queue</dt>
        <dd className="mono">{status.queue_length}</dd>
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

function IncidentsPanel({
  feed,
  incidentId,
  runLoad,
  onSelect,
  onBack,
}: {
  feed: PcFeed;
  incidentId: string | null;
  runLoad: RunLoad;
  onSelect: (incidentId: string) => void;
  onBack: () => void;
}) {
  if (incidentId) {
    return (
      <div>
        <button type="button" className="control control--quiet" onClick={onBack}>
          ← All incidents
        </button>
        {runLoad.state === "loading" && <p className="notice">Loading the investigation…</p>}
        {runLoad.state === "failed" && (
          <p className="notice">
            <strong>Can’t load this incident.</strong> {runLoad.message}
          </p>
        )}
        {runLoad.state === "ready" && <RunDetail key={runLoad.run.run_id} run={runLoad.run} />}
      </div>
    );
  }

  if (feed.incidents.length === 0) {
    return (
      <p className="notice">
        No incidents yet. Alerts become incidents within 10 seconds; those at level 7 or higher
        are investigated by the AI when the model is running.
      </p>
    );
  }

  return (
    <table className="pc-alerts pc-incidents">
      <thead>
        <tr>
          <th>Last alert (UTC)</th>
          <th>Status</th>
          <th>Verdict</th>
          <th>Level</th>
          <th>Alerts</th>
          <th>What happened</th>
          <th>Advice</th>
        </tr>
      </thead>
      <tbody>
        {feed.incidents.map((item) => (
          <IncidentRow key={item.incident.incident_id} item={item} onSelect={onSelect} />
        ))}
      </tbody>
    </table>
  );
}

function IncidentRow({
  item,
  onSelect,
}: {
  item: PcIncidentSummary;
  onSelect: (incidentId: string) => void;
}) {
  const { incident, classification, max_level, alert_count, recommendation_count } = item;
  const openable = classification !== null;
  const label =
    classification !== null && incident.status === "investigating"
      ? "Advice ready"
      : STATUS[incident.status];

  return (
    <tr
      data-open={openable ? "true" : undefined}
      onClick={openable ? () => onSelect(incident.incident_id) : undefined}
    >
      <td className="mono">{utc(incident.window_end)}</td>
      <td>
        <span className={`status status--${incident.status}`}>{label}</span>
        {incident.status === "investigation_failed" && (
          <>
            {" "}
            <button
              type="button"
              className="control control--quiet small"
              onClick={(event) => {
                event.stopPropagation();
                retryIncident(incident.incident_id).catch(() => {});
              }}
            >
              Retry
            </button>
          </>
        )}
      </td>
      <td>
        {classification !== null ? (
          <span className={`cls cls--${classification}`}>{classification}</span>
        ) : (
          "—"
        )}
      </td>
      <td className="mono">{max_level}</td>
      <td className="mono">{alert_count}</td>
      <td>{incident.title}</td>
      <td className="mono">{recommendation_count}</td>
    </tr>
  );
}
