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
