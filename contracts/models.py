"""SENTINEL shared data contracts.

FROZEN. Every component imports these models. No component defines its own version
of any shape declared here. Changes require a team decision logged in docs/decisions.md.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:12]}"


class SentinelModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        use_enum_values=False,
        validate_assignment=True,
        protected_namespaces=(),
    )


class TelemetrySource(str, Enum):
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUTH = "linux_auth"
    LINUX_SYSLOG = "linux_syslog"
    LINUX_AUDITD = "linux_auditd"
    ZEEK_CONN = "zeek_conn"
    ZEEK_DNS = "zeek_dns"
    ZEEK_HTTP = "zeek_http"


class EventCategory(str, Enum):
    AUTHENTICATION = "authentication"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    ACCOUNT_MANAGEMENT = "account_management"
    PRIVILEGE = "privilege"
    PERSISTENCE = "persistence"
    OTHER = "other"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    NEW = "new"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    RESOLVED = "resolved"
    CLOSED_BENIGN = "closed_benign"


class EntityType(str, Enum):
    HOST = "host"
    ACCOUNT = "account"
    IP_ADDRESS = "ip_address"
    PROCESS = "process"
    FILE = "file"


class EvidenceClass(str, Enum):
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


class Classification(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    INCONCLUSIVE = "inconclusive"


class ActionType(str, Enum):
    """The complete response catalog. The executor runs nothing outside this list."""

    BLOCK_IP = "block_ip"
    DISABLE_ACCOUNT = "disable_account"
    ISOLATE_HOST = "isolate_host"
    KILL_PROCESS = "kill_process"
    FORCE_PASSWORD_RESET = "force_password_reset"
    NO_ACTION = "no_action"


class PolicyOutcome(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class AutonomyLevel(str, Enum):
    OBSERVE_ONLY = "observe_only"
    SUGGEST = "suggest"
    ACT_WITH_APPROVAL = "act_with_approval"
    ACT_AUTONOMOUSLY = "act_autonomously"


class EvaluationArm(str, Enum):
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


CONTRACT_VERSION = "1.0.0"

__all__ = [
    "CONTRACT_VERSION",
    "ActionType",
    "Alert",
    "AttackChainStep",
    "AutonomyLevel",
    "Classification",
    "Entity",
    "EntityType",
    "EvaluationArm",
    "Event",
    "EventCategory",
    "EvidenceClass",
    "EvidenceItem",
    "Incident",
    "IncidentStatus",
    "NetworkInfo",
    "PolicyDecision",
    "PolicyOutcome",
    "ProcessInfo",
    "ProposedAction",
    "RiskScore",
    "Severity",
    "TelemetrySource",
    "Verdict",
]
