import type { HostAssessment } from "./types/assessment";
import type { IncidentRun } from "./types/contracts";
import type { PcFeed } from "./types/pc";

const RUNS_URL: string = import.meta.env.VITE_RUNS_URL ?? "/api/runs";

export const PC_FEED_URL: string | null =
  import.meta.env.VITE_PC_FEED_URL ?? (import.meta.env.VITE_RUNS_URL ? null : "/api/pc/feed");

export async function fetchRuns(): Promise<IncidentRun[]> {
  const response = await fetch(RUNS_URL);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${RUNS_URL}.`);
  }
  return response.json();
}

export async function fetchPcFeed(url: string): Promise<PcFeed> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${url}.`);
  }
  return response.json();
}

export async function fetchPcRun(incidentId: string): Promise<IncidentRun> {
  const url = `/api/pc/incidents/${encodeURIComponent(incidentId)}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${url}.`);
  }
  return response.json();
}

export async function retryIncident(incidentId: string): Promise<void> {
  const url = `/api/pc/incidents/${encodeURIComponent(incidentId)}/retry`;
  const response = await fetch(url, { method: "POST" });
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${url}.`);
  }
}

export async function fetchAssessment(): Promise<HostAssessment | null> {
  const url = "/api/pc/assessment";
  const response = await fetch(url);
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${url}.`);
  }
  return response.json();
}

export async function rescan(): Promise<void> {
  const url = "/api/pc/rescan";
  const response = await fetch(url, { method: "POST" });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(typeof body.detail === "string" ? body.detail : `Got ${response.status}.`);
  }
}
