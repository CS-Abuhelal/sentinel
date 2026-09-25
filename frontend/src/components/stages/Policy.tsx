import { ACTION, OUTCOME } from "../../format";
import type { IncidentRun } from "../../types/contracts";

export function Policy({ run }: { run: IncidentRun }) {
  const actions = new Map(run.verdict.proposed_actions.map((action) => [action.action_id, action]));
  if (run.policy_decisions.length === 0) {
    return <p className="lede">The agent proposed no actions, so nothing reached the policy engine.</p>;
  }
  return (
    <>
      <p className="lede">Each proposal checked against fixed rules. The first matching rule decides.</p>
      {run.policy_decisions.map((decision) => {
        const action = actions.get(decision.action_id);
        return (
          <div key={decision.decision_id} className="decision">
            <div className="proposal decision-proposal">
              <span className="kicker">Agent proposed</span>
              <p className="proposal-head">
                <strong>{action ? ACTION[action.action_type] : decision.action_id}</strong>
                {action && <span className="mono">{action.target_value}</span>}
              </p>
            </div>
            <span className="decision-arrow" aria-hidden="true" />
            <div className={`ruling ruling--${decision.outcome}`}>
              <span className="kicker">Policy engine</span>
              <p className="ruling-head">
                <strong>{OUTCOME[decision.outcome]}</strong>
                <span className="mono small">{decision.matched_rule}</span>
              </p>
              <p>{decision.reason}</p>
              <dl className="facts facts--tight">
                <div>
                  <dt>Autonomy</dt>
                  <dd className="mono small">{decision.autonomy_level}</dd>
                </div>
                <div>
                  <dt>Risk</dt>
                  <dd>{decision.risk_score}</dd>
                </div>
                <div>
                  <dt>Protected target</dt>
                  <dd>{decision.target_is_protected ? "Yes" : "No"}</dd>
                </div>
              </dl>
            </div>
          </div>
        );
      })}
      <p className="executed">Nothing has been executed. Actions that need approval wait for an analyst.</p>
    </>
  );
}
