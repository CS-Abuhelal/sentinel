import { ENTITY, clock, duration } from "../../format";
import type { IncidentRun } from "../../types/contracts";

export function Correlation({ run }: { run: IncidentRun }) {
  const { incident } = run;
  const alerts = incident.alert_ids.length;
  return (
    <>
      <p className="lede">
        {alerts} alert{alerts === 1 ? "" : "s"} grouped by host and account into one incident.
      </p>
      <dl className="facts">
        <div>
          <dt>Window</dt>
          <dd className="mono">
            {clock(incident.window_start)}–{clock(incident.window_end)} UTC
          </dd>
        </div>
        <div>
          <dt>Span</dt>
          <dd>{duration(incident.window_start, incident.window_end)}</dd>
        </div>
      </dl>
      <ul className="entities" aria-label="Entities">
        {incident.entities.map((entity) => (
          <li key={`${entity.entity_type}:${entity.value}`} className="entity">
            <span className="entity-type">{ENTITY[entity.entity_type]}</span>
            <span className="mono">{entity.value}</span>
            {entity.is_protected && <span className="protected">Protected</span>}
          </li>
        ))}
      </ul>
    </>
  );
}
