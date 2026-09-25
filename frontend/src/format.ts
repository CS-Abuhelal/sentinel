import type {
  ActionType,
  EntityType,
  EvidenceItem,
  IncidentStatus,
  InvestigationStopReason,
  PolicyOutcome,
} from "./types/contracts";

export function utc(iso: string): string {
  return new Date(iso).toISOString().slice(0, 19).replace("T", " ");
}

export function clock(iso: string): string {
  return new Date(iso).toISOString().slice(11, 19);
}

export function duration(startIso: string, endIso: string): string {
  const seconds = Math.round((Date.parse(endIso) - Date.parse(startIso)) / 1000);
  const minutes = Math.floor(seconds / 60);
  if (minutes === 0) return `${seconds} s`;
  return `${minutes} min ${seconds % 60} s`;
}

export function evidenceRefs(evidence: EvidenceItem[]): Map<string, string> {
  return new Map(evidence.map((item, index) => [item.evidence_id, `E${index + 1}`]));
}

export const STATUS: Record<IncidentStatus, string> = {
  new: "New",
  investigating: "Investigating",
  awaiting_approval: "Awaiting approval",
  resolved: "Resolved",
  closed_benign: "Closed as benign",
};

export const STOP_REASON: Record<InvestigationStopReason, string> = {
  verdict_reached: "Reached a verdict",
  tool_call_cap: "Hit the tool-call limit",
  invalid_output: "Model output failed validation",
};

export const OUTCOME: Record<PolicyOutcome, string> = {
  allow: "Allowed",
  require_approval: "Needs approval",
  deny: "Denied",
};

export const ACTION: Record<ActionType, string> = {
  block_ip: "Block IP",
  disable_account: "Disable account",
  isolate_host: "Isolate host",
  kill_process: "Kill process",
  force_password_reset: "Force password reset",
  no_action: "No action",
};

export const ENTITY: Record<EntityType, string> = {
  host: "Host",
  account: "Account",
  ip_address: "IP",
  process: "Process",
  file: "File",
};

export const FACTOR: Record<string, string> = {
  alert_severity: "Alert severity",
  failed_attempts: "Failed attempts",
  success_after_failures: "Success after failures",
  new_source_ip: "New source IP",
  privileged_account: "Privileged account",
};
