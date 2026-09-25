import { utc } from "../../format";
import { useCountUp } from "../../playback";
import type { IncidentRun } from "../../types/contracts";

export function Telemetry({ run, counting }: { run: IncidentRun; counting: boolean }) {
  const alerted = new Set(run.alerts.flatMap((alert) => alert.event_ids));
  const hosts = [...new Set(run.events.map((event) => event.host))].join(", ");
  const sources = [...new Set(run.events.map((event) => event.source))].join(", ");
  const shown = useCountUp(run.events.length, counting);

  return (
    <>
      <p className="lede">
        <strong className="count">{shown}</strong> sshd login events parsed from{" "}
        <span className="mono">{hosts}</span> ({sources}). {alerted.size} of them fed the alert and
        are marked below.
      </p>
      <details className="disclosure">
        <summary>Show all {run.events.length} normalized events</summary>
        <div className="table-scroll">
          <table className="events">
            <thead>
              <tr>
                <th scope="col">Time (UTC)</th>
                <th scope="col">Outcome</th>
                <th scope="col">User</th>
                <th scope="col">Source</th>
                <th scope="col">Message</th>
              </tr>
            </thead>
            <tbody>
              {run.events.map((event) => (
                <tr key={event.event_id} className={alerted.has(event.event_id) ? "in-alert" : undefined}>
                  <td className="mono">{utc(event.timestamp)}</td>
                  <td>
                    <span className={`outcome-dot outcome-dot--${event.outcome}`}>{event.outcome}</span>
                  </td>
                  <td className="mono">{event.user}</td>
                  <td className="mono">{event.network?.src_ip}</td>
                  <td className="mono message">{event.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}
