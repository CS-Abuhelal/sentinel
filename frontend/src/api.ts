import type { IncidentRun } from "./types/contracts";

const RUNS_URL: string = import.meta.env.VITE_RUNS_URL ?? "/api/runs";

export async function fetchRuns(): Promise<IncidentRun[]> {
  const response = await fetch(RUNS_URL);
  if (!response.ok) {
    throw new Error(`Got ${response.status} from ${RUNS_URL}.`);
  }
  return response.json();
}
