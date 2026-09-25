import { useEffect, useState } from "react";

import { fetchRuns } from "./api";
import { RunDetail } from "./components/RunDetail";
import { RunList } from "./components/RunList";
import type { IncidentRun } from "./types/contracts";

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "ready"; runs: IncidentRun[] };

export function App() {
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [selectedId, setSelectedId] = useState<string | null>(null);

  useEffect(() => {
    fetchRuns()
      .then((runs) => {
        setLoad({ state: "ready", runs });
        setSelectedId(runs[0]?.incident.incident_id ?? null);
      })
      .catch((error: Error) => setLoad({ state: "failed", message: error.message }));
  }, []);

  const runs = load.state === "ready" ? load.runs : [];
  const selected = runs.find((run) => run.incident.incident_id === selectedId) ?? null;

  return (
    <div className="app">
      <header className="masthead">
        <span className="wordmark">SENTINEL</span>
        <span className="masthead-tag">The AI proposes. Deterministic policy decides.</span>
        <a className="masthead-link" href="https://github.com/CS-Abuhelal/sentinel">
          Source on GitHub
        </a>
      </header>
      <div className="layout">
        {runs.length > 0 && (
          <nav className="runs" aria-label="Incident runs">
            <RunList runs={runs} selectedId={selectedId} onSelect={setSelectedId} />
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
    </div>
  );
}
