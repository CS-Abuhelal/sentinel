import { useEffect, useRef, useState } from "react";

import { fetchAssessment, rescan } from "../api";
import type { Finding, HostAssessment, Recommendation } from "../types/assessment";
import type { ServiceState } from "../types/pc";

const POLL_MS = 30000;
const RESCAN_REFRESH_MS = 3000;
const VISIBLE_ROWS = 20;
const ADVICE_TOP = 10;

type Load =
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "empty" }
  | { state: "ready"; assessment: HostAssessment };

type RescanState = { state: "idle" } | { state: "busy" } | { state: "failed"; message: string };

function toLoad(assessment: HostAssessment | null): Load {
  return assessment ? { state: "ready", assessment } : { state: "empty" };
}

function adviceUnit(finding: Finding): string {
  if (finding.kind === "vulnerability" && finding.package) {
    return `package:${finding.package.toLowerCase()}`;
  }
  return `finding:${finding.finding_id}`;
}

function firstUnits(findings: Finding[], limit: number): Set<string> {
  const units = new Set<string>();
  for (const finding of findings) {
    const unit = adviceUnit(finding);
    if (units.has(unit) || units.size < limit) {
      units.add(unit);
    }
  }
  return units;
}

function subtitle(finding: Finding): string {
  if (finding.kind === "vulnerability") {
    const parts: string[] = [];
    if (finding.cvss != null) parts.push(`CVSS ${finding.cvss}`);
    if (finding.official_remediation) parts.push(`Wazuh: ${finding.official_remediation}`);
    if (parts.length > 0) return parts.join(" · ");
    return `${finding.package ?? "—"} ${finding.installed_version ?? "—"}`;
  }
  return `CIS check ${finding.check_id ?? "—"}`;
}

export function FixPanel({ sync }: { sync: ServiceState }) {
  const [load, setLoad] = useState<Load>({ state: "loading" });
  const [rescanState, setRescanState] = useState<RescanState>({ state: "idle" });
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    const poll = () => {
      fetchAssessment()
        .then((assessment) => {
          if (!cancelled) setLoad(toLoad(assessment));
        })
        .catch((error: Error) => {
          if (!cancelled) setLoad({ state: "failed", message: error.message });
        });
    };
    poll();
    const timer = window.setInterval(poll, POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const handleRescan = () => {
    setRescanState({ state: "busy" });
    rescan()
      .then(() => {
        if (mountedRef.current) setRescanState({ state: "idle" });
        window.setTimeout(() => {
          fetchAssessment()
            .then((assessment) => {
              if (mountedRef.current) setLoad(toLoad(assessment));
            })
            .catch((error: Error) => {
              if (mountedRef.current) setLoad({ state: "failed", message: error.message });
            });
        }, RESCAN_REFRESH_MS);
      })
      .catch((error: Error) => {
        if (mountedRef.current) setRescanState({ state: "failed", message: error.message });
      });
  };

  return (
    <div>
      <p className="lede">
        Weak spots Wazuh found on this PC, most important first. The AI writes fix steps for the
        top 10; SENTINEL never changes anything itself.
      </p>
      <div className="fix-head">
        {sync.detail && <span className="small muted">{sync.detail}</span>}
        <button
          type="button"
          className="control"
          disabled={rescanState.state === "busy"}
          onClick={handleRescan}
        >
          {rescanState.state === "busy"
            ? "Rescanning…"
            : rescanState.state === "failed"
              ? "Rescan again"
              : "Rescan"}
        </button>
        {rescanState.state === "failed" && (
          <span className="small muted">{rescanState.message}</span>
        )}
      </div>
      {load.state === "loading" && <p className="notice">Loading weak spots…</p>}
      {load.state === "failed" && (
        <p className="notice">
          <strong>Can’t load weak spots.</strong> {load.message}
        </p>
      )}
      {load.state === "empty" && (
        <p className="notice">No weak spots yet. Press Rescan to pull them from Wazuh.</p>
      )}
      {load.state === "ready" && (
        <FixTable
          assessment={load.assessment}
          expanded={expanded}
          onToggle={setExpanded}
          showAll={showAll}
          onShowAll={() => setShowAll(true)}
        />
      )}
    </div>
  );
}

function FixTable({
  assessment,
  expanded,
  onToggle,
  showAll,
  onShowAll,
}: {
  assessment: HostAssessment;
  expanded: string | null;
  onToggle: (findingId: string | null) => void;
  showAll: boolean;
  onShowAll: () => void;
}) {
  const total = assessment.findings.length;
  const visible = showAll ? assessment.findings : assessment.findings.slice(0, VISIBLE_ROWS);
  const recommendedFindingIds = new Set(
    assessment.recommendations.flatMap((recommendation) => recommendation.finding_ids),
  );
  const beingWrittenUnits = firstUnits(assessment.findings, ADVICE_TOP);

  return (
    <>
      <table className="pc-alerts pc-fixes">
        <thead>
          <tr>
            <th>#</th>
            <th>Priority</th>
            <th>Weak spot</th>
            <th>Fix steps</th>
          </tr>
        </thead>
        <tbody>
          {visible.map((finding, index) => {
            const rank = index + 1;
            const recommendation = assessment.recommendations.find((item) =>
              item.finding_ids.includes(finding.finding_id),
            );
            const fixStatus = recommendedFindingIds.has(finding.finding_id)
              ? "Ready"
              : beingWrittenUnits.has(adviceUnit(finding))
                ? "Being written"
                : "—";
            return (
              <FindingRow
                key={finding.finding_id}
                finding={finding}
                rank={rank}
                recommendation={recommendation}
                fixStatus={fixStatus}
                expanded={expanded === finding.finding_id}
                onToggle={onToggle}
              />
            );
          })}
        </tbody>
      </table>
      {!showAll && total > VISIBLE_ROWS && (
        <button type="button" className="control control--quiet" onClick={onShowAll}>
          Show all {total}
        </button>
      )}
    </>
  );
}

function FindingRow({
  finding,
  rank,
  recommendation,
  fixStatus,
  expanded,
  onToggle,
}: {
  finding: Finding;
  rank: number;
  recommendation: Recommendation | undefined;
  fixStatus: string;
  expanded: boolean;
  onToggle: (findingId: string | null) => void;
}) {
  const toggle = () => onToggle(expanded ? null : finding.finding_id);

  return (
    <>
      <tr
        data-open="true"
        tabIndex={0}
        aria-expanded={expanded}
        aria-label={`Show details for ${finding.title}`}
        onClick={toggle}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            if (event.key === " ") event.preventDefault();
            toggle();
          }
        }}
      >
        <td>{rank}</td>
        <td>
          <strong>{finding.priority}</strong>{" "}
          <span className={`sev sev--${finding.severity}`}>{finding.severity}</span>
        </td>
        <td>
          <div>{finding.title}</div>
          <div className="small muted">{subtitle(finding)}</div>
        </td>
        <td>{fixStatus}</td>
      </tr>
      {expanded && <FixDetail finding={finding} recommendation={recommendation} />}
    </>
  );
}

function FixDetail({
  finding,
  recommendation,
}: {
  finding: Finding;
  recommendation: Recommendation | undefined;
}) {
  const references = finding.references.filter((ref) => ref.startsWith("https://")).slice(0, 3);

  return (
    <tr className="fix-detail">
      <td colSpan={4}>
        <p className="eyebrow">What to do</p>
        {recommendation && recommendation.steps.length > 0 && (
          <ol>
            {recommendation.steps.map((step, index) => (
              <li key={`${index}-${step}`}>{step}</li>
            ))}
          </ol>
        )}
        {recommendation && recommendation.dropped_steps.length > 0 && (
          <p className="small muted">
            {recommendation.dropped_steps.length} step(s) removed by the checker.
          </p>
        )}
        <p className="eyebrow">Wazuh says</p>
        <p>{finding.official_remediation ?? "—"}</p>
        <p className="eyebrow">Why it matters</p>
        <p>{finding.rationale ?? "—"}</p>
        {references.length > 0 && (
          <p>
            {references.map((ref, index) => (
              <span key={ref}>
                {index > 0 && " "}
                <a href={ref} target="_blank" rel="noreferrer">
                  {ref}
                </a>
              </span>
            ))}
          </p>
        )}
      </td>
    </tr>
  );
}
