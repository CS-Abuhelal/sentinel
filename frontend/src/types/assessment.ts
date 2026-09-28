export type AssessmentId = string;
export type Host = string;
export type ContractVersion = string;
export type CreatedAt = string;
export type SyncedAt = string;
export type FindingId = string;
export type FindingKind = "vulnerability" | "configuration";
export type Key = string;
export type Host1 = string;
export type Title = string;
export type Severity = "info" | "low" | "medium" | "high" | "critical";
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
export type Title1 = string;
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

/**
 * The weak spots found on one PC and the advice written for them.
 */
export interface HostAssessment {
  assessment_id: AssessmentId;
  host: Host;
  contract_version: ContractVersion;
  created_at: CreatedAt;
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
  host: Host1;
  title: Title;
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
  raw: Raw;
}
export interface Raw {
  [k: string]: unknown;
}
/**
 * Plain-language advice for the owner of a monitored PC. SENTINEL never carries it out.
 */
export interface Recommendation {
  recommendation_id: RecommendationId;
  title: Title1;
  priority: Priority1;
  steps: Steps;
  finding_ids: FindingIds;
  evidence_ids: EvidenceIds;
  official_remediation: OfficialRemediation1;
  dropped_steps: DroppedSteps;
}
