import { STATUS, evidenceRefs, utc } from "../format";
import type { IncidentRun } from "../types/contracts";
import { Stage } from "./Stage";
import { Correlation } from "./stages/Correlation";
import { Detection } from "./stages/Detection";
import { Investigation } from "./stages/Investigation";
import { Policy } from "./stages/Policy";
import { Risk } from "./stages/Risk";
import { Telemetry } from "./stages/Telemetry";

export function RunDetail({ run }: { run: IncidentRun }) {
  const { incident, verdict, risk_score: risk } = run;
  const refs = evidenceRefs(run.evidence);
  const agent = `Agent · ${verdict.model_name ?? "unknown model"}`;

  return (
    <article className="run">
      <header className="run-head">
        <p className="eyebrow mono">
          {run.case_id} · {utc(incident.created_at)} UTC
        </p>
        <h1>{incident.title}</h1>
        <p className="run-state">
          <span className={`status status--${incident.status}`}>{STATUS[incident.status]}</span>
          <span>
            Verdict <strong className={`cls cls--${verdict.classification}`}>{verdict.classification}</strong>
          </span>
          <span>
            Risk <strong>{risk.score}</strong> <span className={`sev sev--${risk.severity}`}>{risk.severity}</span>
          </span>
        </p>
        <ReplayNote modelName={verdict.model_name} />
      </header>

      <ol className="spine">
        <Stage n={1} title="Telemetry" producer="Deterministic">
          <Telemetry run={run} />
        </Stage>
        <Stage n={2} title="Detection" producer="Deterministic">
          <Detection run={run} />
        </Stage>
        <Stage n={3} title="Correlation" producer="Deterministic">
          <Correlation run={run} />
        </Stage>
        <Stage n={4} title="Investigation" producer={agent} agent>
          <Investigation run={run} refs={refs} />
        </Stage>
        <li className="boundary">
          <div className="boundary-band" aria-hidden="true" />
          <p className="boundary-text">
            <strong>Policy boundary.</strong> The agent’s work ends here: it can only propose.
            Below this line, deterministic code scores the risk and decides what may run.
          </p>
        </li>
        <Stage n={5} title="Risk" producer="Deterministic">
          <Risk risk={risk} />
        </Stage>
        <Stage n={6} title="Policy" producer="Deterministic">
          <Policy run={run} />
        </Stage>
      </ol>
    </article>
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
