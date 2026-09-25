import type { IncidentRun } from "./types/contracts";

export async function fetchRuns(): Promise<IncidentRun[]> {
  const response = await fetch("/api/runs");
  if (!response.ok) {
    throw new Error(`The API answered ${response.status} for /api/runs.`);
  }
  return response.json();
}
