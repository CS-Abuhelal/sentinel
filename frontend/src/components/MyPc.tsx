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
