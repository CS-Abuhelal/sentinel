import { utc } from "../../format";
import type { IncidentRun } from "../../types/contracts";

export function Detection({ run }: { run: IncidentRun }) {
  return (
    <>
      <p className="lede">Sigma rules evaluated over the events. {run.alerts.length} fired.</p>
      {run.alerts.map((alert) => (
        <div key={alert.alert_id} className="card">
          <div className="card-top">
            <h3>{alert.rule_name}</h3>
            <span className={`sev sev--${alert.rule_severity}`}>{alert.rule_severity}</span>
          </div>
          <p>{alert.description}</p>
          <dl className="facts">
            <div>
              <dt>Events</dt>
              <dd>{alert.event_ids.length}</dd>
            </div>
            <div>
              <dt>ATT&CK</dt>
              <dd>
                {alert.suggested_techniques.map((technique) => (
                  <span key={technique} className="chip mono">
                    {technique}
                  </span>
                ))}
              </dd>
            </div>
            <div>
              <dt>Fired</dt>
              <dd className="mono">{utc(alert.timestamp)}</dd>
            </div>
            <div>
              <dt>Rule</dt>
              <dd className="mono small">{alert.rule_id}</dd>
            </div>
          </dl>
        </div>
      ))}
    </>
  );
}
