export type CheckedAt = string;
export type Reachable = boolean;
export type Detail = string | null;
export type AlertCount = number;
export type LastAlertAt = string | null;
export type QueueLength = number;
export type WazuhId = string;
export type ReceivedAt = string;
export type Level = number;
export type EventId = string;
export type Timestamp = string;
export type IngestedAt = string | null;
export type TelemetrySource =
  | "windows_security"
  | "windows_sysmon"
  | "linux_auth"
  | "linux_syslog"
  | "linux_auditd"
  | "zeek_conn"
  | "zeek_dns"
  | "zeek_http"
  | "wazuh";
export type EventCategory =
  "authentication" | "process" | "network" | "file" | "account_management" | "privilege" | "persistence" | "other";
export type EventType = string;
export type Host = string;
export type User = string | null;
export type Outcome = "success" | "failure" | "unknown";
export type Pid = number | null;
export type Name = string | null;
export type CommandLine = string | null;
export type ParentPid = number | null;
export type ParentName = string | null;
export type User1 = string | null;
export type HashSha256 = string | null;
export type SrcIp = string | null;
export type SrcPort = number | null;
export type DstIp = string | null;
export type DstPort = number | null;
export type Protocol = string | null;
export type BytesSent = number | null;
export type BytesReceived = number | null;
export type Domain = string | null;
export type FilePath = string | null;
export type Message = string | null;
export type CaseId = string | null;
export type AlertId = string;
export type RuleId = string;
export type RuleName = string;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Timestamp1 = string;
export type Host1 = string;
export type User2 = string | null;
export type SrcIp1 = string | null;
export type Description = string;
/**
 * @minItems 1
 */
export type EventIds = [string, ...string[]];
export type SuggestedTechniques = string[];
export type CaseId1 = string | null;
export type Alerts = LiveAlert[];
export type IncidentId = string;
export type Title = string;
export type IncidentStatus =
  | "new"
  | "investigating"
  | "awaiting_approval"
  | "resolved"
  | "closed_benign"
  | "queued"
  | "low_priority"
  | "investigation_failed";
export type CreatedAt = string;
export type UpdatedAt = string | null;
export type WindowStart = string;
export type WindowEnd = string;
/**
 * @minItems 1
 */
export type AlertIds = [string, ...string[]];
export type EntityType = "host" | "account" | "ip_address" | "process" | "file";
export type Value = string;
export type IsProtected = boolean;
export type Entities = Entity[];
export type CaseId2 = string | null;
export type AlertCount1 = number;
export type MaxLevel = number;
export type Classification = "malicious" | "benign" | "inconclusive";
export type RecommendationCount = number;
export type Incidents = PcIncidentSummary[];

/**
 * What the live My PC page polls for.
 */
export interface PcFeed {
  status: PcStatus;
  alerts: Alerts;
  incidents: Incidents;
}
export interface PcStatus {
  checked_at: CheckedAt;
  wazuh_api: ServiceState;
  backfill: ServiceState;
  alert_count: AlertCount;
  last_alert_at: LastAlertAt;
  queue_length: QueueLength;
  model: ServiceState;
  sync: ServiceState;
}
export interface ServiceState {
  reachable: Reachable;
  detail: Detail;
}
/**
 * A Wazuh alert from the live feed, with the event and alert it was converted into.
 */
export interface LiveAlert {
  wazuh_id: WazuhId;
  received_at: ReceivedAt;
  level: Level;
  event: Event;
  alert: Alert;
}
/**
 * One normalized telemetry record. The atomic unit of evidence.
 */
export interface Event {
  event_id: EventId;
  timestamp: Timestamp;
  ingested_at: IngestedAt;
  source: TelemetrySource;
  category: EventCategory;
  event_type: EventType;
  host: Host;
  user: User;
  outcome: Outcome;
  process: ProcessInfo | null;
  network: NetworkInfo | null;
  file_path: FilePath;
  message: Message;
  raw: Raw;
  case_id: CaseId;
}
export interface ProcessInfo {
  pid: Pid;
  name: Name;
  command_line: CommandLine;
  parent_pid: ParentPid;
  parent_name: ParentName;
  user: User1;
  hash_sha256: HashSha256;
}
export interface NetworkInfo {
  src_ip: SrcIp;
  src_port: SrcPort;
  dst_ip: DstIp;
  dst_port: DstPort;
  protocol: Protocol;
  bytes_sent: BytesSent;
  bytes_received: BytesReceived;
  domain: Domain;
}
export interface Raw {
  [k: string]: unknown;
}
/**
 * A detection rule fired. High recall by design; severity here is rule-declared,
 * not the final risk score.
 */
export interface Alert {
  alert_id: AlertId;
  rule_id: RuleId;
  rule_name: RuleName;
  rule_severity: Severity;
  timestamp: Timestamp1;
  host: Host1;
  user: User2;
  src_ip: SrcIp1;
  description: Description;
  event_ids: EventIds;
  suggested_techniques: SuggestedTechniques;
  case_id: CaseId1;
}
/**
 * One incident on a monitored PC, as the live page lists it.
 */
export interface PcIncidentSummary {
  incident: Incident;
  alert_count: AlertCount1;
  max_level: MaxLevel;
  classification: Classification | null;
  recommendation_count: RecommendationCount;
}
/**
 * Correlated group of alerts. The unit the agent investigates.
 */
export interface Incident {
  incident_id: IncidentId;
  title: Title;
  status: IncidentStatus;
  created_at: CreatedAt;
  updated_at: UpdatedAt;
  window_start: WindowStart;
  window_end: WindowEnd;
  alert_ids: AlertIds;
  entities: Entities;
  case_id: CaseId2;
}
export interface Entity {
  entity_type: EntityType;
  value: Value;
  is_protected: IsProtected;
}
