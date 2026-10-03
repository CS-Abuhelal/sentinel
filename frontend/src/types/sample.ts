export type CreatedAt = string;
export type Note = string;
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
export type CaseId2 = string | null;
export type AlertCount1 = number;
export type MaxLevel = number;
export type Classification = "malicious" | "benign" | "inconclusive";
export type RecommendationCount = number;
export type Incidents = PcIncidentSummary[];
export type AssessmentId = string;
export type Host2 = string;
export type ContractVersion = string;
export type CreatedAt2 = string;
export type SyncedAt = string;
export type FindingId = string;
export type FindingKind = "vulnerability" | "configuration";
export type Key = string;
export type Host3 = string;
export type Title1 = string;
export type Priority = number;
export type FindingStatus = "open" | "resolved";
export type Cve = string | null;
export type Package = string | null;
export type InstalledVersion = string | null;
export type Cvss = number | null;
export type PolicyId = string | null;
export type CheckId = string | null;
export type Rationale = string | null;
export type OfficialRemediation = string | null;
export type References = string[];
export type RelatedAlertCount = number;
export type FirstSeen = string;
export type LastSeen = string;
export type Findings = Finding[];
export type RecommendationId = string;
export type Title2 = string;
export type Priority1 = number;
/**
 * @maxItems 10
 */
export type Steps =
  | []
  | [string]
  | [string, string]
  | [string, string, string]
  | [string, string, string, string]
  | [string, string, string, string, string]
  | [string, string, string, string, string, string]
  | [string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string, string]
  | [string, string, string, string, string, string, string, string, string, string];
export type FindingIds = string[];
export type EvidenceIds = string[];
export type OfficialRemediation1 = string | null;
export type DroppedSteps = string[];
export type Recommendations = Recommendation[];
export type ModelName = string | null;
export type RunId = string;
export type CaseId3 = string;
export type ContractVersion1 = string;
export type CreatedAt3 = string;
export type Events = Event[];
export type Alerts1 = Alert[];
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
export type Confidence = number;
export type Summary1 = string;
export type Order = number;
export type Tactic = string;
export type TechniqueId = string | null;
export type TechniqueName = string | null;
export type Description1 = string;
export type EvidenceIds1 = string[];
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
export type EvidenceIds2 = string[];
export type ProposedActions = ProposedAction[];
export type Recommendations1 = Recommendation[];
export type ProducedAt = string;
export type ModelName1 = string | null;
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
export type Title3 = string;
export type Description2 = string;
export type RequiredEvidence = EvidenceClass[];
export type ChangeId = string;
export type Title4 = string;
export type Start = string;
export type End = string;
export type Accounts = string[];
export type Hosts = string[];
export type SourceIps = string[];
export type Description3 = string;
export type Changes = ChangeWindow[];
export type ApprovalId = string;
export type DecisionId1 = string;
export type ActionId2 = string;
export type IncidentId5 = string;
export type Approved = boolean;
export type DecidedBy = string;
export type DecidedAt1 = string;
export type Source = string;
export type Note1 = string | null;
export type Approvals = Approval[];
export type ExecutionId = string;
export type DecisionId2 = string;
export type ActionId3 = string;
export type IncidentId6 = string;
export type TargetValue1 = string;
export type Host4 = string | null;
export type ExecutionStatus = "succeeded" | "failed" | "rejected";
export type Reason1 = string;
export type DryRun = boolean;
/**
 * @minItems 1
 */
export type Argv = [string, ...string[]];
export type ExitCode = number;
export type Output = string;
export type Before = CommandResult[];
export type Commands = CommandResult[];
export type Verified = boolean | null;
export type Verification = CommandResult[];
export type StartedAt = string;
export type FinishedAt = string;
export type Executions = ExecutionResult[];
export type Sequence = number;
export type RecordedAt = string;
export type AuditKind = "proposal" | "decision" | "approval" | "execution";
export type IncidentId7 = string;
export type SubjectId = string;
export type Summary2 = string;
export type PrevHash = string;
export type Hash = string;
export type Audit = AuditRecord[];
export type Runs = IncidentRun[];

/**
 * A sanitized, recorded snapshot of the live My PC page, for the public demo.
 */
export interface PcSample {
  created_at: CreatedAt;
  note: Note;
  feed: PcFeed;
  assessment: HostAssessment | null;
  runs: Runs;
}
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
  created_at: CreatedAt1;
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
/**
 * The weak spots found on one PC and the advice written for them.
 */
export interface HostAssessment {
  assessment_id: AssessmentId;
  host: Host2;
  contract_version: ContractVersion;
  created_at: CreatedAt2;
  synced_at: SyncedAt;
  findings: Findings;
  recommendations: Recommendations;
  model_name: ModelName;
}
/**
 * One weak spot on a monitored PC: a vulnerable package or a failed CIS check.
 */
export interface Finding {
  finding_id: FindingId;
  kind: FindingKind;
  key: Key;
  host: Host3;
  title: Title1;
  severity: Severity;
  priority: Priority;
  status: FindingStatus;
  cve: Cve;
  package: Package;
  installed_version: InstalledVersion;
  cvss: Cvss;
  policy_id: PolicyId;
  check_id: CheckId;
  rationale: Rationale;
  official_remediation: OfficialRemediation;
  references: References;
  related_alert_count: RelatedAlertCount;
  first_seen: FirstSeen;
  last_seen: LastSeen;
  raw: Raw1;
}
export interface Raw1 {
  [k: string]: unknown;
}
/**
 * Plain-language advice for the owner of a monitored PC. SENTINEL never carries it out.
 */
export interface Recommendation {
  recommendation_id: RecommendationId;
  title: Title2;
  priority: Priority1;
  steps: Steps;
  finding_ids: FindingIds;
  evidence_ids: EvidenceIds;
  official_remediation: OfficialRemediation1;
  dropped_steps: DroppedSteps;
}
/**
 * One incident taken through every pipeline stage. The run file and the API response.
 */
export interface IncidentRun {
  run_id: RunId;
  case_id: CaseId3;
  contract_version: ContractVersion1;
  created_at: CreatedAt3;
  events: Events;
  alerts: Alerts1;
  incident: Incident;
  evidence: Evidence;
  verdict: Verdict;
  risk_score: RiskScore;
  policy_decisions: PolicyDecisions;
  scenario: Scenario | null;
  approvals: Approvals;
  executions: Executions;
  audit: Audit;
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
  recommendations: Recommendations1;
  produced_at: ProducedAt;
  model_name: ModelName1;
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
  evidence_ids: EvidenceIds1;
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
  evidence_ids: EvidenceIds2;
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
/**
 * A prepared lab case with its hand-labelled expected outcome. Never shown to the agent.
 */
export interface Scenario {
  title: Title3;
  description: Description2;
  expected_classification: Classification;
  required_evidence: RequiredEvidence;
  changes: Changes;
}
/**
 * A documented, approved change. Lab context that can explain otherwise odd activity.
 */
export interface ChangeWindow {
  change_id: ChangeId;
  title: Title4;
  start: Start;
  end: End;
  accounts: Accounts;
  hosts: Hosts;
  source_ips: SourceIps;
  description: Description3;
}
/**
 * A human's answer to a decision that required approval. Nothing else can unlock one.
 */
export interface Approval {
  approval_id: ApprovalId;
  decision_id: DecisionId1;
  action_id: ActionId2;
  incident_id: IncidentId5;
  approved: Approved;
  decided_by: DecidedBy;
  decided_at: DecidedAt1;
  source: Source;
  note: Note1;
}
/**
 * What the executor did with one decision on one host. Rejected means nothing ran.
 */
export interface ExecutionResult {
  execution_id: ExecutionId;
  decision_id: DecisionId2;
  action_id: ActionId3;
  incident_id: IncidentId6;
  action_type: ActionType;
  target_type: EntityType;
  target_value: TargetValue1;
  host: Host4;
  status: ExecutionStatus;
  reason: Reason1;
  dry_run: DryRun;
  before: Before;
  commands: Commands;
  verified: Verified;
  verification: Verification;
  started_at: StartedAt;
  finished_at: FinishedAt;
}
export interface CommandResult {
  argv: Argv;
  exit_code: ExitCode;
  output: Output;
}
/**
 * One append-only audit entry. Each hash covers the previous one, so edits break the chain.
 */
export interface AuditRecord {
  sequence: Sequence;
  recorded_at: RecordedAt;
  kind: AuditKind;
  incident_id: IncidentId7;
  subject_id: SubjectId;
  summary: Summary2;
  payload: Payload;
  prev_hash: PrevHash;
  hash: Hash;
}
export interface Payload {
  [k: string]: unknown;
}
