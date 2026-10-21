import { useEffect, useState } from "react";

import { fetchAssessment, fetchPcRun } from "../api";
import { incidentLabel, utc } from "../format";
import type { Finding, HostAssessment, Recommendation, Severity } from "../types/assessment";
import type { PcFeed, PcIncidentSummary, ServiceState } from "../types/pc";
import type { PcSample } from "../types/sample";

const MAX_ITEMS = 10;
const FEED_INCIDENTS = 100;
const LAST_RANK = Number.MAX_SAFE_INTEGER;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const RECORDED_DETAIL = "Recorded";

type AssessmentLoad =
  | { state: "loading" }
  | { state: "failed"; message: string }
  | { state: "ready"; assessment: HostAssessment | null };

type Advice =
  | { state: "loading" }
  | { state: "missing" }
  | { state: "ready"; titles: string[] };

type FetchedAdvice = { key: string; titles: Record<string, string[]> };

function adviceTitles(run: { verdict: { recommendations: { title: string }[] } }): string[] {
  return run.verdict.recommendations.map((recommendation) => recommendation.title);
}

function inFindingOrder(assessment: HostAssessment): Recommendation[] {
  const rank = new Map(assessment.findings.map((finding, index) => [finding.finding_id, index]));
  return assessment.recommendations
    .map((recommendation) => ({
      recommendation,
      first: Math.min(
        LAST_RANK,
        ...recommendation.finding_ids.map((findingId) => rank.get(findingId) ?? LAST_RANK),
      ),
    }))
    .sort((a, b) => a.first - b.first)
    .map(({ recommendation }) => recommendation);
}

function wazuhSays(recommendation: Recommendation, findings: Map<string, Finding>): string | null {
  for (const findingId of recommendation.finding_ids) {
    const text = findings.get(findingId)?.official_remediation;
    if (text) return text;
  }
  return recommendation.official_remediation;
}

function plural(count: number, one: string, many: string): string {
  return `${count} ${count === 1 ? one : many}`;
}

function serviceLine(name: string, state: ServiceState, recorded: boolean): string {
  if (recorded) return `${name}: ${state.detail ?? RECORDED_DETAIL}`;
  const online = state.reachable ? "Online" : "Offline";
  return `${name}: ${state.detail ? `${online} · ${state.detail}` : online}`;
}

function countBy<T>(items: T[], key: (item: T) => string): [string, number][] {
  const counts = new Map<string, number>();
  for (const item of items) {
    const name = key(item);
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  return [...counts];
}

function weakSpotTotals(load: AssessmentLoad): string {
  if (load.state === "loading") return "loading…";
  if (load.state === "failed") return "unavailable.";
  if (load.assessment === null) return "none synced yet.";
  const open = load.assessment.findings.filter((finding) => finding.status === "open");
  if (open.length === 0) return "none.";
  const parts = SEVERITIES.map(
    (severity) => [severity, open.filter((finding) => finding.severity === severity).length] as const,
  )
    .filter(([, count]) => count > 0)
    .map(([severity, count]) => `${severity} ${count}`);
  return `${open.length} (${parts.join(", ")})`;
}

function incidentTotals(incidents: PcIncidentSummary[], recorded: boolean): string {
  if (incidents.length === 0) return "none.";
  const counts = countBy(incidents, ({ incident, classification }) =>
    incidentLabel(incident.status, classification),
  );
  const parts = counts.map(([label, count]) => `${label} ${count}`).join(", ");
  const total = `${incidents.length} (${parts})`;
  if (recorded || incidents.length < FEED_INCIDENTS) return total;
  return `${total}, counting only the newest ${FEED_INCIDENTS}`;
}

export function ReportPanel({ feed, sample }: { feed: PcFeed; sample: PcSample | null }) {
  const recorded = sample !== null;
  const [generated] = useState(() => utc(new Date().toISOString()));
  const [fetchedAssessment, setFetchedAssessment] = useState<AssessmentLoad>({
    state: "loading",
  });
  const [fetchedAdvice, setFetchedAdvice] = useState<FetchedAdvice | null>(null);

  const assessmentLoad: AssessmentLoad = sample
    ? { state: "ready", assessment: sample.assessment }
    : fetchedAssessment;
  const assessment = assessmentLoad.state === "ready" ? assessmentLoad.assessment : null;

  const allInvestigated = feed.incidents.filter((item) => item.classification !== null);
  const investigated = allInvestigated.slice(0, MAX_ITEMS);
  const idsKey = investigated.map((item) => item.incident.incident_id).join("\n");

  useEffect(() => {
    if (sample) return;
    let cancelled = false;
    fetchAssessment()
      .then((loaded) => {
        if (!cancelled) setFetchedAssessment({ state: "ready", assessment: loaded });
      })
      .catch((error: Error) => {
        if (!cancelled) setFetchedAssessment({ state: "failed", message: error.message });
      });
    return () => {
      cancelled = true;
    };
  }, [sample]);

  useEffect(() => {
    if (sample) return;
    const ids = idsKey === "" ? [] : idsKey.split("\n");
    let cancelled = false;
    Promise.allSettled(ids.map((id) => fetchPcRun(id))).then((results) => {
      if (cancelled) return;
      const titles: Record<string, string[]> = {};
      results.forEach((result, index) => {
        if (result.status === "fulfilled") titles[ids[index]] = adviceTitles(result.value);
      });
      setFetchedAdvice({ key: idsKey, titles });
    });
    return () => {
      cancelled = true;
    };
  }, [sample, idsKey]);

  const adviceFor = (incidentId: string): Advice => {
    if (sample) {
      const run = sample.runs.find((candidate) => candidate.incident.incident_id === incidentId);
      return run ? { state: "ready", titles: adviceTitles(run) } : { state: "missing" };
    }
    if (fetchedAdvice === null || fetchedAdvice.key !== idsKey) return { state: "loading" };
    const titles = fetchedAdvice.titles[incidentId];
    return titles ? { state: "ready", titles } : { state: "missing" };
  };

  const host = assessment?.host || feed.alerts[0]?.event.host || "this PC";
  const { status } = feed;

  return (
    <article className="report">
      <header className="report-head">
        <div>
          <h2>SENTINEL report for {host}</h2>
          <p className="report-meta">
            {sample ? `Recorded ${utc(sample.created_at)} UTC` : `Generated ${generated} UTC`}
          </p>
          <p className="report-meta">
            {sample ? sample.note : "Live data from Wazuh on this PC."}
          </p>
        </div>
        <button type="button" className="control" onClick={() => window.print()}>
          Print or save as PDF
        </button>
      </header>

      <section className="report-section">
        <h3>Status</h3>
        <ul className="report-lines">
          <li>{serviceLine("Wazuh", status.wazuh_api, recorded)}</li>
          <li>{serviceLine("AI model", status.model, recorded)}</li>
          <li>{serviceLine("Weak-spot sync", status.sync, recorded)}</li>
        </ul>
      </section>

      <section className="report-section">
        <h3>Fix these first</h3>
        <FixSection load={assessmentLoad} recorded={recorded} />
      </section>

      <section className="report-section">
        <h3>Recent incidents</h3>
        {investigated.length === 0 ? (
          <p className="muted">
            {recorded
              ? "No investigated incidents in this sample."
              : "No investigated incidents yet."}
          </p>
        ) : (
          <ul className="report-items">
            {investigated.map(({ incident, classification }) => {
              const advice = adviceFor(incident.incident_id);
              return (
                <li key={incident.incident_id} className="report-item">
                  <p className="report-title">{incident.title}</p>
                  <p className="report-meta">
                    Status: {incidentLabel(incident.status, classification)} · Classification:{" "}
                    {classification}
                  </p>
                  {advice.state === "loading" && <p className="small muted">Loading advice…</p>}
                  {advice.state === "missing" && (
                    <p className="small muted">Advice details are not available.</p>
                  )}
                  {advice.state === "ready" && advice.titles.length === 0 && (
                    <p className="small muted">No recommendations.</p>
                  )}
                  {advice.state === "ready" && advice.titles.length > 0 && (
                    <>
                      <p className="report-meta">Recommendations:</p>
                      <ul>
                        {advice.titles.map((title, index) => (
                          <li key={`${index}-${title}`}>{title}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        )}
        {allInvestigated.length > investigated.length && (
          <p className="small muted">
            And{" "}
            {plural(
              allInvestigated.length - investigated.length,
              "more investigated incident",
              "more investigated incidents",
            )}{" "}
            not listed here.
          </p>
        )}
      </section>

      <section className="report-section">
        <h3>{recorded ? "Totals in this sample" : "Totals"}</h3>
        {recorded && (
          <p className="small muted">
            The sample keeps only part of the PC’s data, so these counts are for the sample, not
            for the whole PC.
          </p>
        )}
        <ul className="report-lines">
          <li>Open weak spots: {weakSpotTotals(assessmentLoad)}</li>
          <li>Incidents: {incidentTotals(feed.incidents, recorded)}</li>
        </ul>
      </section>
    </article>
  );
}

function FixSection({ load, recorded }: { load: AssessmentLoad; recorded: boolean }) {
  if (load.state === "loading") return <p className="muted">Loading weak spots…</p>;
  if (load.state === "failed") {
    return (
      <p className="notice">
        <strong>Can’t load weak spots.</strong> {load.message}
      </p>
    );
  }
  if (load.assessment === null) return <p className="muted">No weak spots synced yet.</p>;

  const findings = new Map(
    load.assessment.findings.map((finding) => [finding.finding_id, finding]),
  );
  const ordered = inFindingOrder(load.assessment);
  const top = ordered.slice(0, MAX_ITEMS);

  if (top.length === 0) {
    return (
      <p className="muted">
        {recorded ? "No fix steps in this sample." : "No fix steps written yet."}
      </p>
    );
  }

  return (
    <ul className="report-items">
      {top.map((recommendation, index) => {
        const says = wazuhSays(recommendation, findings);
        return (
          <li key={recommendation.recommendation_id} className="report-item">
            <p className="report-title">
              {index + 1}. {recommendation.title}
            </p>
            <p className="report-meta">
              This fix covers {plural(recommendation.finding_ids.length, "weak spot", "weak spots")}
            </p>
            {recommendation.steps.length > 0 && (
              <ol>
                {recommendation.steps.map((step, stepIndex) => (
                  <li key={`${stepIndex}-${step}`}>{step}</li>
                ))}
              </ol>
            )}
            {says && <p>Wazuh says (top weak spot): {says}</p>}
          </li>
        );
      })}
      {ordered.length > top.length && (
        <li className="small muted">
          And {plural(ordered.length - top.length, "more fix", "more fixes")} not listed here.
        </li>
      )}
    </ul>
  );
}
