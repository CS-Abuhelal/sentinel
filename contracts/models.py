"""SENTINEL shared data contracts.

Every component imports these models. No component defines its own version of any shape
declared here. Changes bump the contract version, regenerate fixtures and schemas, and are
logged in DECISIONS.md.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

CONTRACT_VERSION = "1.3.0"


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class SentinelModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        use_enum_values=False,
        validate_assignment=True,
        protected_namespaces=(),
        json_schema_serialization_defaults_required=True,
    )


class TelemetrySource(StrEnum):
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUTH = "linux_auth"
    LINUX_SYSLOG = "linux_syslog"
    LINUX_AUDITD = "linux_auditd"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    ZEEK_HTTP = "zeek_http"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    ACCOUNT_MANAGEMENT = "account_management"
    PRIVILEGE = "privilege"
    PERSISTENCE = "persistence"
    OTHER = "other"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESOLVED = "resolved"
    CLOSED_BENIGN = "closed_benign"


class EntityType(StrEnum):
    HOST = "host"
    ACCOUNT = "account"
    IP_ADDRESS = "ip_address"
    PROCESS = "process"
    FILE = "file"


class EvidenceClass(StrEnum):
    """Ground-truth evidence categories. Drives Evidence Coverage and Utilization metrics."""

    AUTH_HISTORY = "auth_history"
    ENTITY_CONTEXT = "entity_context"
    PROCESS_LINEAGE = "process_lineage"
    NETWORK_ACTIVITY = "network_activity"
    FILE_ACTIVITY = "file_activity"
    CHANGE_WINDOW = "change_window"
    RELATED_ALERTS = "related_alerts"
    THREAT_INTEL = "threat_intel"
    BASELINE_COMPARISON = "baseline_comparison"


class Classification(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class ActionType(StrEnum):
    """The complete response catalog. The executor runs nothing outside this list."""

    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    FORCE_PASSWORD_RESET = "force_password_reset"
    NO_ACTION = "no_action"


class InvestigationStopReason(StrEnum):
    VERDICT_REACHED = "verdict_reached"
    TOOL_CALL_CAP = "tool_call_cap"
    INVALID_OUTPUT = "invalid_output"


class ExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"


class AuditKind(StrEnum):
    PROPOSAL = "proposal"
    DECISION = "decision"
    APPROVAL = "approval"
    EXECUTION = "execution"


class PolicyOutcome(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class AutonomyLevel(StrEnum):
    OBSERVE_ONLY = "observe_only"
    SUGGEST = "suggest"
    ACT_WITH_APPROVAL = "act_with_approval"
    ACT_AUTONOMOUSLY = "act_autonomously"


class EvaluationArm(StrEnum):
    A1_RULES_ONLY = "a1_rules_only"
    A2A_RAW_SINGLE_SHOT = "a2a_raw_single_shot"
    A2B_FULL_CONTEXT = "a2b_full_context"
    A2C_ORACLE_BUNDLE = "a2c_oracle_bundle"
    A3_TOOL_USING_AGENT = "a3_tool_using_agent"


class ProcessInfo(SentinelModel):
    pid: int | None = None
    name: str | None = None
    command_line: str | None = None
    parent_pid: int | None = None
    parent_name: str | None = None
    user: str | None = None
    hash_sha256: str | None = None


class NetworkInfo(SentinelModel):
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    domain: str | None = None


class Entity(SentinelModel):
    entity_type: EntityType
    value: str
    is_protected: bool = False


class Event(SentinelModel):
    """One normalized telemetry record. The atomic unit of evidence."""

    event_id: str = Field(default_factory=lambda: _new_id("evt"))
    timestamp: datetime
    ingested_at: datetime | None = None
    source: TelemetrySource
    category: EventCategory
    event_type: str
    host: str
    user: str | None = None
    outcome: Literal["success", "failure", "unknown"] = "unknown"
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file_path: str | None = None
    message: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    case_id: str | None = None


class Alert(SentinelModel):
    """A detection rule fired. High recall by design; severity here is rule-declared,
    not the final risk score."""

    alert_id: str = Field(default_factory=lambda: _new_id("alr"))
    rule_id: str
    rule_name: str
    rule_severity: Severity
    timestamp: datetime
    host: str
    user: str | None = None
    src_ip: str | None = None
    description: str
    event_ids: list[str] = Field(default_factory=list, min_length=1)
    suggested_techniques: list[str] = Field(default_factory=list)
    case_id: str | None = None


class Incident(SentinelModel):
    """Correlated group of alerts. The unit the agent investigates."""

    incident_id: str = Field(default_factory=lambda: _new_id("inc"))
    title: str
    status: IncidentStatus = IncidentStatus.NEW
    created_at: datetime
    updated_at: datetime | None = None
    window_start: datetime
    window_end: datetime
    alert_ids: list[str] = Field(default_factory=list, min_length=1)
    entities: list[Entity] = Field(default_factory=list)
    case_id: str | None = None


class EvidenceItem(SentinelModel):
    """One piece of evidence a tool retrieved. Carries provenance so an analyst can verify it."""

    evidence_id: str = Field(default_factory=lambda: _new_id("evd"))
    incident_id: str
    evidence_class: EvidenceClass
    tool_name: str
    tool_query: dict[str, Any] = Field(default_factory=dict)
    retrieved_at: datetime
    summary: str
    content: dict[str, Any] = Field(default_factory=dict)
    source_event_ids: list[str] = Field(default_factory=list)
    was_productive: bool | None = None


class AttackChainStep(SentinelModel):
    order: int
    tactic: str
    technique_id: str | None = None
    technique_name: str | None = None
    description: str
    evidence_ids: list[str] = Field(default_factory=list)


class ProposedAction(SentinelModel):
    """An action the agent recommends. The agent NEVER executes this itself."""

    action_id: str = Field(default_factory=lambda: _new_id("act"))
    action_type: ActionType
    target_type: EntityType
    target_value: str
    justification: str
    reversible: bool = True
    evidence_ids: list[str] = Field(default_factory=list)


class Verdict(SentinelModel):
    """The agent's structured conclusion about an incident."""

    verdict_id: str = Field(default_factory=lambda: _new_id("vrd"))
    incident_id: str
    arm: EvaluationArm
    classification: Classification
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    risk_factors: list[str] = Field(default_factory=list)
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    produced_at: datetime
    model_name: str | None = None
    tool_calls_made: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    stop_reason: InvestigationStopReason


class RiskScore(SentinelModel):
    """Deterministic. Computed in Python from evidence-derived factors. Never by an LLM."""

    incident_id: str
    score: int = Field(ge=0, le=100)
    severity: Severity
    factors: dict[str, int] = Field(default_factory=dict)
    computed_at: datetime


class PolicyDecision(SentinelModel):
    """Deterministic authorization result. This, not the agent, decides what may run."""

    decision_id: str = Field(default_factory=lambda: _new_id("pol"))
    action_id: str
    incident_id: str
    outcome: PolicyOutcome
    autonomy_level: AutonomyLevel
    risk_score: int = Field(ge=0, le=100)
    matched_rule: str
    reason: str
    target_is_protected: bool = False
    decided_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None


class Approval(SentinelModel):
    """A human's answer to a decision that required approval. Nothing else can unlock one."""

    approval_id: str = Field(default_factory=lambda: _new_id("apr"))
    decision_id: str
    action_id: str
    incident_id: str
    approved: bool
    decided_by: str = Field(min_length=1)
    decided_at: datetime
    source: str
    note: str | None = None


class CommandResult(SentinelModel):
    argv: list[str] = Field(min_length=1)
    exit_code: int
    output: str = ""


class ExecutionResult(SentinelModel):
    """What the executor did with one decision on one host. Rejected means nothing ran."""

    execution_id: str = Field(default_factory=lambda: _new_id("exe"))
    decision_id: str
    action_id: str
    incident_id: str
    action_type: ActionType
    target_type: EntityType
    target_value: str
    host: str | None = None
    status: ExecutionStatus
    reason: str
    dry_run: bool = False
    commands: list[CommandResult] = Field(default_factory=list)
    verified: bool | None = None
    verification: list[CommandResult] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime


class AuditRecord(SentinelModel):
    """One append-only audit entry. Each hash covers the previous one, so edits break the chain."""

    sequence: int = Field(ge=0)
    recorded_at: datetime
    kind: AuditKind
    incident_id: str
    subject_id: str
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str


class AccountRecord(SentinelModel):
    role: str
    privileged: bool = False
    protected: bool = False


class HostRecord(SentinelModel):
    role: str
    protected: bool = False


class Inventory(SentinelModel):
    """Lab asset inventory. Protected entities are denied at the policy level."""

    accounts: dict[str, AccountRecord] = Field(default_factory=dict)
    hosts: dict[str, HostRecord] = Field(default_factory=dict)

    def is_protected(self, entity_type: EntityType, value: str) -> bool:
        if entity_type is EntityType.ACCOUNT:
            record: AccountRecord | HostRecord | None = self.accounts.get(value)
        elif entity_type is EntityType.HOST:
            record = self.hosts.get(value)
        else:
            return False
        return record is not None and record.protected

    def is_privileged(self, account: str) -> bool:
        record = self.accounts.get(account)
        return record is not None and record.privileged


class Scenario(SentinelModel):
    """A prepared lab case with its hand-labelled expected outcome. Never shown to the agent."""

    title: str
    description: str
    expected_classification: Classification


class IncidentRun(SentinelModel):
    """One incident taken through every pipeline stage. The run file and the API response."""

    run_id: str = Field(default_factory=lambda: _new_id("run"))
    case_id: str
    contract_version: str = CONTRACT_VERSION
    created_at: datetime
    events: list[Event]
    alerts: list[Alert]
    incident: Incident
    evidence: list[EvidenceItem]
    verdict: Verdict
    risk_score: RiskScore
    policy_decisions: list[PolicyDecision]
    scenario: Scenario | None = None
    approvals: list[Approval] = Field(default_factory=list)
    executions: list[ExecutionResult] = Field(default_factory=list)
    audit: list[AuditRecord] = Field(default_factory=list)


__all__ = [
    "CONTRACT_VERSION",
    "AccountRecord",
    "ActionType",
    "Alert",
    "Approval",
    "AuditKind",
    "AuditRecord",
    "AttackChainStep",
    "AutonomyLevel",
    "Classification",
    "CommandResult",
    "Entity",
    "EntityType",
    "EvaluationArm",
    "Event",
    "EventCategory",
    "EvidenceClass",
    "EvidenceItem",
    "ExecutionResult",
    "ExecutionStatus",
    "HostRecord",
    "Incident",
    "IncidentRun",
    "IncidentStatus",
    "InvestigationStopReason",
    "Inventory",
    "NetworkInfo",
    "PolicyDecision",
    "PolicyOutcome",
    "ProcessInfo",
    "ProposedAction",
    "RiskScore",
    "Scenario",
    "Severity",
    "TelemetrySource",
    "Verdict",
]
