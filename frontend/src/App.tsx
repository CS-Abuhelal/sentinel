import { useEffect, useState } from "react";

import { PC_FEED_URL, PC_SAMPLE_URL, fetchRuns } from "./api";
import type { PcSource } from "./api";
import { MyPc } from "./components/MyPc";
import { RunDetail } from "./components/RunDetail";
import { RunList } from "./components/RunList";
import type { IncidentRun } from "./types/contracts";

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "ready"; runs: IncidentRun[] };

const PC_SOURCE: PcSource | null = PC_FEED_URL
  ? { kind: "live", url: PC_FEED_URL }
  : PC_SAMPLE_URL
    ? { kind: "sample", url: PC_SAMPLE_URL }
    : null;

const PC_VIEW =
  PC_SOURCE !== null && new URLSearchParams(window.location.search).get("view") === "pc";

export function App() {
  return (
    <div className="app">
      <header className="masthead">
        <span className="wordmark">SENTINEL</span>
        <span className="masthead-tag">The AI proposes. Deterministic policy decides.</span>
        {PC_SOURCE && (
          <nav className="views" aria-label="Views">
            <a href="?" aria-current={PC_VIEW ? undefined : "page"}>
              Incidents
            </a>
            <a href="?view=pc" aria-current={PC_VIEW ? "page" : undefined}>
              {PC_SOURCE.kind === "live" ? "My PC" : "My PC (sample)"}
            </a>
          </nav>
        )}
        <a className="masthead-link" href="https://github.com/CS-Abuhelal/sentinel">
          Source on GitHub
        </a>
      </header>
      {PC_VIEW && PC_SOURCE ? (
        <div className="layout">
          <main className="main">
            <MyPc source={PC_SOURCE} />
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
