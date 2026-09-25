import { useEffect, useState } from "react";

import { verifyChain, type ChainCheck } from "../../audit";
import { ACTION, utc } from "../../format";
import type { AuditRecord, CommandResult, ExecutionResult, IncidentRun } from "../../types/contracts";

export function Execution({ run }: { run: IncidentRun }) {
  const actions = new Map(run.verdict.proposed_actions.map((action) => [action.action_id, action]));
  const approvals = new Map(run.approvals.map((approval) => [approval.decision_id, approval]));

  return (
    <>
      <p className="lede">
        Only the executor can change a system, and only for actions the policy engine allowed or a
        person approved. It runs fixed commands from its catalog in the lab and checks the result.
      </p>
      {run.policy_decisions.length === 0 && <p className="muted">Nothing was proposed, so nothing ran.</p>}
      {run.policy_decisions.map((decision) => {
        const action = actions.get(decision.action_id);
        const approval = approvals.get(decision.decision_id);
        const executions = run.executions.filter((e) => e.decision_id === decision.decision_id);
        const label = action ? `${ACTION[action.action_type]} ${action.target_value}` : decision.action_id;
        return (
          <div key={decision.decision_id} className="card execution">
            <div className="card-top">
              <h3>{label}</h3>
            </div>
            {approval ? (
              <p className={approval.approved ? "approval approval--yes" : "approval approval--no"}>
                <strong>
                  {approval.approved ? "Approved" : "Denied"} by {approval.decided_by}
                </strong>{" "}
                in <span className="mono small">{approval.source}</span>
                {approval.note && <> · “{approval.note}”</>}
              </p>
            ) : decision.outcome === "require_approval" ? (
              <p className="approval approval--waiting">
                <strong>Waiting for a person.</strong> No approval is recorded for this action, so
                the executor has not touched anything.
              </p>
            ) : null}
            {executions.map((execution) => (
              <ExecutionDetail key={execution.execution_id} execution={execution} />
            ))}
          </div>
        );
      })}
      {run.audit.length > 0 && <AuditTrail records={run.audit} />}
    </>
  );
}

function ExecutionDetail({ execution }: { execution: ExecutionResult }) {
  const proof = execution.before.length > 0 && execution.verification.length > 0;
  return (
    <div className={`result result--${execution.status}`}>
      <p className="result-head">
        <span className={`result-status result-status--${execution.status}`}>{execution.status}</span>
        {execution.host && <span className="mono">{execution.host}</span>}
        {execution.dry_run && <span className="muted">dry run</span>}
        {execution.verified && <span className="check check--right">Verified</span>}
      </p>
      <p>{execution.reason}</p>
      {execution.commands.length > 0 && (
        <>
          <h4 className="mini">Commands run</h4>
          <Commands results={execution.commands} />
        </>
      )}
      {proof && (
        <div className="proof">
          <div>
            <h4 className="mini">Before</h4>
            <Commands results={execution.before} />
          </div>
          <div>
            <h4 className="mini">After</h4>
            <Commands results={execution.verification} />
          </div>
        </div>
      )}
    </div>
  );
}

function Commands({ results }: { results: CommandResult[] }) {
  return (
    <ul className="commands">
      {results.map((result, index) => (
        <li key={index}>
          <code className="mono">$ {result.argv.join(" ")}</code>
          <span className={result.exit_code === 0 ? "exit" : "exit exit--nonzero"}>exit {result.exit_code}</span>
          {result.output && <pre className="output">{result.output}</pre>}
        </li>
      ))}
    </ul>
  );
}

function AuditTrail({ records }: { records: AuditRecord[] }) {
  const [shown, setShown] = useState(records);
  const [check, setCheck] = useState<ChainCheck | null>(null);
  const tampered = shown !== records;

  useEffect(() => {
    let current = true;
    setCheck(null);
    verifyChain(shown).then((result) => {
      if (current) setCheck(result);
    });
    return () => {
      current = false;
    };
  }, [shown]);

  const tamper = () => {
    const index = Math.min(1, records.length - 1);
    setShown(records.map((record, i) => (i === index ? { ...record, summary: `${record.summary} (edited)` } : record)));
  };

  return (
    <div className="audit">
      <h3 className="sub">Audit log</h3>
      <p className={check === null ? "chain-status" : check.intact ? "chain-status chain-status--intact" : "chain-status chain-status--broken"} role="status">
        {check === null
          ? "Checking the chain…"
          : check.intact
            ? `Chain intact: your browser recomputed all ${shown.length} SHA-256 hashes and every link matches.`
            : `Chain broken at record ${check.brokenAt}: its hash no longer matches its contents.`}
      </p>
      <ol className="audit-list">
        {shown.map((record) => (
          <li key={record.sequence}>
            <span className="audit-kind">{record.kind}</span>
            <span className="audit-summary">{record.summary}</span>
            <span className="audit-meta mono">
              #{record.sequence} · {utc(record.recorded_at)} · {record.hash.slice(0, 12)}…
            </span>
          </li>
        ))}
      </ol>
      <button type="button" className="control control--quiet" onClick={tampered ? () => setShown(records) : tamper}>
        {tampered ? "Restore the original record" : "Edit a record to see the chain break"}
      </button>
    </div>
  );
}
