import { useEffect, useState } from "react";

import { STATUS, evidenceRefs, utc } from "../format";
import { usePlayback, type Playback } from "../playback";
import type { IncidentRun } from "../types/contracts";
import { ExpectedBadge } from "./Expected";
import { Stage, stageState } from "./Stage";
import { Correlation } from "./stages/Correlation";
import { Detection } from "./stages/Detection";
import { Execution } from "./stages/Execution";
import { Investigation } from "./stages/Investigation";
import { Policy } from "./stages/Policy";
import { Risk } from "./stages/Risk";
import { Telemetry } from "./stages/Telemetry";

const DURATIONS = [1400, 1400, 1400, 2400, 1800, 2200, 1500, 1500, 1800];
const START = { telemetry: 0, detection: 1, correlation: 2, investigation: 3, risk: 6, policy: 7, execution: 8 };
const STEP_LABELS = [
  "Parsing the log",
  "Running detection rules",
  "Opening an incident",
  "Agent is choosing a tool",
  "Evidence is back",
  "Agent is writing its verdict",
  "Scoring risk",
  "Policy engine is deciding",
  "Executor is acting",
];

export function RunDetail({ run }: { run: IncidentRun }) {
  const { incident, verdict, risk_score: risk } = run;
  const refs = evidenceRefs(run.evidence);
  const agent = `Agent · ${verdict.model_name ?? "unknown model"}`;
  const [anchor] = useState(() => window.location.hash.slice(1));
  const playback = usePlayback(DURATIONS, anchor !== "");

  useEffect(() => {
    if (anchor) document.getElementById(anchor)?.scrollIntoView({ block: "start" });
  }, [anchor]);
  const { step, finished } = playback;
  const state = (start: number, end: number) => stageState(step, finished, start, end);

  return (
    <article className="run">
      <header className="run-head">
        <p className="eyebrow mono">
          {run.case_id} · {utc(incident.created_at)} UTC
        </p>
        <h1>{incident.title}</h1>
        {finished ? (
          <p className="run-state reveal">
            <span className={`status status--${incident.status}`}>{STATUS[incident.status]}</span>
            <span>
              Verdict <strong className={`cls cls--${verdict.classification}`}>{verdict.classification}</strong>
            </span>
            <ExpectedBadge run={run} />
            <span>
              Risk <strong>{risk.score}</strong> <span className={`sev sev--${risk.severity}`}>{risk.severity}</span>
            </span>
          </p>
        ) : (
          <p className="run-state">
            <span className="status">In progress</span>
          </p>
        )}
        <ReplayNote modelName={verdict.model_name} />
        <Controls playback={playback} />
      </header>

      <ol className="spine">
        <Stage n={1} title="Telemetry" producer="Deterministic" state={state(START.telemetry, START.telemetry)}>
          <Telemetry run={run} counting={step === START.telemetry && !finished} />
        </Stage>
        <Stage n={2} title="Detection" producer="Deterministic" state={state(START.detection, START.detection)}>
          <Detection run={run} />
        </Stage>
        <Stage n={3} title="Correlation" producer="Deterministic" state={state(START.correlation, START.correlation)}>
          <Correlation run={run} />
        </Stage>
        <Stage
          n={4}
          title="Investigation"
          producer={agent}
          agent
          state={state(START.investigation, START.risk - 1)}
        >
          <Investigation run={run} refs={refs} phase={finished ? 2 : step - START.investigation} />
        </Stage>
        <li className="boundary">
          <div className="boundary-band" aria-hidden="true" />
          <p className="boundary-text">
            <strong>Policy boundary.</strong> The agent’s work ends here: it can only propose.
            Below this line, deterministic code scores the risk and decides what may run.
          </p>
        </li>
        <Stage n={5} title="Risk" producer="Deterministic" state={state(START.risk, START.risk)}>
          <Risk risk={risk} />
        </Stage>
        <Stage n={6} title="Policy" producer="Deterministic" state={state(START.policy, START.policy)}>
          <Policy run={run} />
        </Stage>
        <Stage n={7} title="Execution" producer="Deterministic" state={state(START.execution, START.execution)}>
          <Execution run={run} />
        </Stage>
      </ol>
    </article>
  );
}

function Controls({ playback }: { playback: Playback }) {
  const { step, total, playing, finished, toggle, restart, skip } = playback;
  return (
    <div className="controls">
      {finished ? (
        <button type="button" className="control" onClick={restart}>
          Replay the incident
        </button>
      ) : (
        <>
          <button type="button" className="control" onClick={toggle}>
            {playing ? "Pause" : "Resume"}
          </button>
          <button type="button" className="control control--quiet" onClick={skip}>
            Skip to result
          </button>
        </>
      )}
      <span className="controls-status" aria-live="polite">
        {finished ? "Showing the full run" : `Step ${step + 1} of ${total}: ${STEP_LABELS[step]}`}
      </span>
      <span className="controls-bar" aria-hidden="true">
        <span style={{ width: `${(Math.min(step, total) / total) * 100}%` }} />
      </span>
    </div>
  );
}

function ReplayNote({ modelName }: { modelName: string | null }) {
  if (modelName?.startsWith("ollama:")) {
    return (
      <p className="replay replay--live">
        Live AI: this investigation came from <span className="mono">{modelName.slice("ollama:".length)}</span>,
        an open-weight model that ran inside GitHub Actions when this site was built. Nothing in it was
        written by hand. The log it investigated is a prepared lab scenario.
      </p>
    );
  }
  if (!modelName?.startsWith("replay:")) return null;
  const source = modelName.slice("replay:".length);
  return (
    <p className="replay">
      {source === "handwritten"
        ? "Replay: the agent’s responses in this run were written by hand for the demo, not produced by a live model. Every other stage ran for real."
        : `Replay: the agent’s responses were recorded from ${source} and played back.`}
    </p>
  );
}
