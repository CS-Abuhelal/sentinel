import { ACTION, ENTITY, STOP_REASON } from "../../format";
import type { IncidentRun } from "../../types/contracts";
import { Cites } from "../Cites";
import { ExpectedNote } from "../Expected";

type EvidenceProps = { run: IncidentRun; refs: Map<string, string>; calling: boolean };

function EvidenceList({ run, refs, calling }: EvidenceProps) {
  if (run.evidence.length === 0) {
    return <p className="muted">{calling ? "The agent is deciding what to check." : "No evidence was collected."}</p>;
  }
  return (
    <ol className="evidence">
      {run.evidence.map((item) => {
        const ref = refs.get(item.evidence_id) ?? "?";
        const args = Object.entries(item.tool_query)
          .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
          .join(", ");
        return (
          <li key={item.evidence_id} id={`evidence-${ref}`} className="evidence-item">
            <span className="tag">{ref}</span>
            <div>
              <code className="call">
                {item.tool_name}({args})
              </code>
              {calling ? (
                <p className="pending">
                  <span className="spinner" aria-hidden="true" /> Running the tool.
                </p>
              ) : (
                <>
                  <p>{item.summary}</p>
                  <details className="disclosure">
                    <summary>Raw tool output</summary>
                    <pre className="raw">{JSON.stringify(item.content, null, 2)}</pre>
                  </details>
                </>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

type Props = { run: IncidentRun; refs: Map<string, string>; phase: number };

export function Investigation({ run, refs, phase }: Props) {
  const { verdict } = run;
  const calls = verdict.tool_calls_made;
  const calling = phase === 0;
  if (phase < 2) {
    return (
      <>
        <p className="lede">The agent is investigating with read-only tools.</p>
        <h3 className="sub">Evidence</h3>
        <EvidenceList run={run} refs={refs} calling={calling} />
        {!calling && (
          <p className="pending">
            <span className="spinner" aria-hidden="true" /> The agent is writing its verdict.
          </p>
        )}
      </>
    );
  }
  return (
    <>
      <p className="lede">
        The agent chose {calls} read-only tool call{calls === 1 ? "" : "s"}, then stopped:{" "}
        {STOP_REASON[verdict.stop_reason].toLowerCase()}.
      </p>

      <h3 className="sub">Evidence</h3>
      <EvidenceList run={run} refs={refs} calling={false} />

      <h3 className="sub">Verdict</h3>
      <div className="proposal verdict">
        <p className="verdict-line">
          <span className={`cls cls--${verdict.classification} cls--large`}>{verdict.classification}</span>
          <span>{Math.round(verdict.confidence * 100)}% confidence</span>
          <Cites ids={verdict.cited_evidence_ids} refs={refs} />
        </p>
        <p>{verdict.summary}</p>
        <ExpectedNote run={run} />
        {verdict.attack_chain.length > 0 && (
          <ol className="chain" aria-label="Attack chain">
            {verdict.attack_chain.map((step) => (
              <li key={step.order}>
                <p className="chain-head">
                  <span className="chip mono">{step.technique_id}</span>
                  <strong>{step.technique_name}</strong>
                  <span className="muted">{step.tactic}</span>
                  <Cites ids={step.evidence_ids} refs={refs} />
                </p>
                <p>{step.description}</p>
              </li>
            ))}
          </ol>
        )}
        {verdict.risk_factors.length > 0 && (
          <>
            <h4>Agent’s risk notes</h4>
            <ul className="notes">
              {verdict.risk_factors.map((factor) => (
                <li key={factor}>{factor}</li>
              ))}
            </ul>
          </>
        )}
      </div>

      <h3 className="sub">Proposed actions</h3>
      {verdict.proposed_actions.length === 0 && <p className="muted">The agent proposed no actions.</p>}
      {verdict.proposed_actions.map((action) => (
        <div key={action.action_id} className="proposal">
          <p className="proposal-head">
            <strong>{ACTION[action.action_type]}</strong>
            <span className="muted">{ENTITY[action.target_type]}</span>
            <span className="mono">{action.target_value}</span>
            <Cites ids={action.evidence_ids} refs={refs} />
          </p>
          <p>{action.justification}</p>
        </div>
      ))}
    </>
  );
}
