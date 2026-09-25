export type RunId = string;
export type CaseId = string;
export type ContractVersion = string;
export type CreatedAt = string;
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
  | "zeek_http";
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
export type CaseId1 = string | null;
export type Events = Event[];
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
export type CaseId2 = string | null;
export type Alerts = Alert[];
export type IncidentId = string;
export type Title = string;
export type IncidentStatus = "new" | "investigating" | "awaiting_approval" | "resolved" | "closed_benign";
export type CreatedAt1 = string;
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
export type CaseId3 = string | null;
export type EvidenceId = string;
export type IncidentId1 = string;
/**
 * Ground-truth evidence categories. Drives Evidence Coverage and Utilization metrics.
 */
export type EvidenceClass =
  | "auth_history"
  | "entity_context"
  | "process_lineage"
  | "network_activity"
  | "file_activity"
  | "change_window"
  | "related_alerts"
  | "threat_intel"
  | "baseline_comparison";
export type ToolName = string;
export type RetrievedAt = string;
export type Summary = string;
export type SourceEventIds = string[];
export type WasProductive = boolean | null;
export type Evidence = EvidenceItem[];
export type VerdictId = string;
export type IncidentId2 = string;
export type EvaluationArm =
  "a1_rules_only" | "a2a_raw_single_shot" | "a2b_full_context" | "a2c_oracle_bundle" | "a3_tool_using_agent";
export type Classification = "malicious" | "benign" | "inconclusive";
export type Confidence = number;
export type Summary1 = string;
export type Order = number;
export type Tactic = string;
export type TechniqueId = string | null;
export type TechniqueName = string | null;
export type Description1 = string;
export type EvidenceIds = string[];
export type AttackChain = AttackChainStep[];
export type Techniques = string[];
export type CitedEvidenceIds = string[];
export type RiskFactors = string[];
export type ActionId = string;
/**
 * The complete response catalog. The executor runs nothing outside this list.
 */
export type ActionType =
  "block_ip" | "disable_account" | "isolate_host" | "kill_process" | "force_password_reset" | "no_action";
export type TargetValue = string;
export type Justification = string;
export type Reversible = boolean;
export type EvidenceIds1 = string[];
export type ProposedActions = ProposedAction[];
export type ProducedAt = string;
export type ModelName = string | null;
export type ToolCallsMade = number;
export type InputTokens = number;
export type OutputTokens = number;
export type LatencyMs = number;
export type InvestigationStopReason = "verdict_reached" | "tool_call_cap" | "invalid_output";
export type IncidentId3 = string;
export type Score = number;
export type ComputedAt = string;
export type DecisionId = string;
export type ActionId1 = string;
export type IncidentId4 = string;
export type PolicyOutcome = "allow" | "require_approval" | "deny";
export type AutonomyLevel = "observe_only" | "suggest" | "act_with_approval" | "act_autonomously";
export type RiskScore1 = number;
export type MatchedRule = string;
export type Reason = string;
export type TargetIsProtected = boolean;
export type DecidedAt = string;
export type ApprovedBy = string | null;
export type ApprovedAt = string | null;
export type PolicyDecisions = PolicyDecision[];

/**
 * One incident taken through every pipeline stage. The run file and the API response.
 */
export interface IncidentRun {
  run_id: RunId;
  case_id: CaseId;
  contract_version: ContractVersion;
  created_at: CreatedAt;
  events: Events;
  alerts: Alerts;
  incident: Incident;
  evidence: Evidence;
  verdict: Verdict;
  risk_score: RiskScore;
  policy_decisions: PolicyDecisions;
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
  case_id: CaseId1;
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
  case_id: CaseId2;
}
/**
 * Correlated group of alerts. The unit the agent investigates.
 */
export interface Incident {
  incident_id: IncidentId;
  title: Title;
  status: IncidentStatus;
  created_at: CreatedAt1;
  updated_at: UpdatedAt;
  window_start: WindowStart;
  window_end: WindowEnd;
  alert_ids: AlertIds;
  entities: Entities;
  case_id: CaseId3;
}
export interface Entity {
  entity_type: EntityType;
  value: Value;
  is_protected: IsProtected;
}
/**
 * One piece of evidence a tool retrieved. Carries provenance so an analyst can verify it.
 */
export interface EvidenceItem {
  evidence_id: EvidenceId;
  incident_id: IncidentId1;
  evidence_class: EvidenceClass;
  tool_name: ToolName;
  tool_query: ToolQuery;
  retrieved_at: RetrievedAt;
  summary: Summary;
  content: Content;
  source_event_ids: SourceEventIds;
  was_productive: WasProductive;
}
export interface ToolQuery {
  [k: string]: unknown;
}
export interface Content {
  [k: string]: unknown;
}
/**
 * The agent's structured conclusion about an incident.
 */
export interface Verdict {
  verdict_id: VerdictId;
  incident_id: IncidentId2;
  arm: EvaluationArm;
  classification: Classification;
  confidence: Confidence;
  summary: Summary1;
  attack_chain: AttackChain;
  techniques: Techniques;
  cited_evidence_ids: CitedEvidenceIds;
  risk_factors: RiskFactors;
  proposed_actions: ProposedActions;
  produced_at: ProducedAt;
  model_name: ModelName;
  tool_calls_made: ToolCallsMade;
  input_tokens: InputTokens;
  output_tokens: OutputTokens;
  latency_ms: LatencyMs;
  stop_reason: InvestigationStopReason;
}
export interface AttackChainStep {
  order: Order;
  tactic: Tactic;
  technique_id: TechniqueId;
  technique_name: TechniqueName;
  description: Description1;
  evidence_ids: EvidenceIds;
}
/**
 * An action the agent recommends. The agent NEVER executes this itself.
 */
export interface ProposedAction {
  action_id: ActionId;
  action_type: ActionType;
  target_type: EntityType;
  target_value: TargetValue;
  justification: Justification;
  reversible: Reversible;
  evidence_ids: EvidenceIds1;
}
/**
 * Deterministic. Computed in Python from evidence-derived factors. Never by an LLM.
 */
export interface RiskScore {
  incident_id: IncidentId3;
  score: Score;
  severity: Severity;
  factors: Factors;
  computed_at: ComputedAt;
}
export interface Factors {
  [k: string]: number;
}
/**
 * Deterministic authorization result. This, not the agent, decides what may run.
 */
export interface PolicyDecision {
  decision_id: DecisionId;
  action_id: ActionId1;
  incident_id: IncidentId4;
  outcome: PolicyOutcome;
  autonomy_level: AutonomyLevel;
  risk_score: RiskScore1;
  matched_rule: MatchedRule;
  reason: Reason;
  target_is_protected: TargetIsProtected;
  decided_at: DecidedAt;
  approved_by: ApprovedBy;
  approved_at: ApprovedAt;
}
