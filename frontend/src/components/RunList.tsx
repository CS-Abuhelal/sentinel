import { STATUS } from "../format";
import { isCorrect } from "./Expected";
import type { IncidentRun } from "../types/contracts";

type Props = {
  runs: IncidentRun[];
  selectedId: string | null;
  onSelect: (incidentId: string) => void;
};

export function RunList({ runs, selectedId, onSelect }: Props) {
  return (
    <ul className="run-list">
      {runs.map((run) => {
        const id = run.incident.incident_id;
        return (
          <li key={run.run_id}>
            <button
              type="button"
              className="run-item"
              aria-current={id === selectedId ? "true" : undefined}
              onClick={() => onSelect(id)}
            >
              <span className="run-case mono">{run.case_id}</span>
              <span className="run-title">{run.incident.title}</span>
              <span className="run-meta">
                <span className={`cls cls--${run.verdict.classification}`}>
                  {run.verdict.classification}
                </span>
                <span>Risk {run.risk_score.score}</span>
                {isCorrect(run) === false && <span className="check check--wrong">Wrong</span>}
                <span>{STATUS[run.incident.status]}</span>
              </span>
            </button>
          </li>
        );
      })}
    </ul>
  );
}
