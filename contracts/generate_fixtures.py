"""Generate sample JSON for every contract model, plus JSON Schema.

Run from the repo root:  python contracts/generate_fixtures.py

The fixtures describe one coherent S1 case (credential attack leading to account
compromise) flowing through every stage of the pipeline. Build against these instead of
waiting for another team member's component.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from contracts.models import (
    Alert,
    AttackChainStep,
    Classification,
    Entity,
    EntityType,
    EvaluationArm,
    Event,
    EventCategory,
    EvidenceClass,
    EvidenceItem,
    Incident,
    IncidentStatus,
    NetworkInfo,
    PolicyDecision,
    PolicyOutcome,
    ProcessInfo,
    ProposedAction,
    ActionType,
    AutonomyLevel,
    RiskScore,
    Severity,
    TelemetrySource,
    Verdict,
)

OUT = Path(__file__).parent
T0 = datetime(2026, 3, 14, 2, 11, 0, tzinfo=timezone.utc)
CASE = "S1_dev_004"

HOST = "WIN-FIN-07"
USER = "m.alharbi"
ATTACKER_IP = "10.13.37.24"

failed_login = Event(
    event_id="evt_a1b2c3d4e5f6",
    timestamp=T0,
    ingested_at=T0 + timedelta(seconds=3),
    source=TelemetrySource.WINDOWS_SECURITY,
    category=EventCategory.AUTHENTICATION,
    event_type="4625_failed_logon",
    host=HOST,
    user=USER,
    outcome="failure",
    network=NetworkInfo(src_ip=ATTACKER_IP, dst_ip="10.20.0.7", dst_port=445, protocol="tcp"),
    message="An account failed to log on. Logon type 3. Status 0xC000006A (bad password).",
    raw={"EventID": 4625, "LogonType": 3, "SubStatus": "0xC000006A"},
    case_id=CASE,
)

successful_login = Event(
    event_id="evt_f6e5d4c3b2a1",
    timestamp=T0 + timedelta(minutes=6, seconds=42),
    ingested_at=T0 + timedelta(minutes=6, seconds=45),
    source=TelemetrySource.WINDOWS_SECURITY,
    category=EventCategory.AUTHENTICATION,
    event_type="4624_successful_logon",
    host=HOST,
    user=USER,
    outcome="success",
    network=NetworkInfo(src_ip=ATTACKER_IP, dst_ip="10.20.0.7", dst_port=445, protocol="tcp"),
    message="An account was successfully logged on. Logon type 3.",
    raw={"EventID": 4624, "LogonType": 3},
    case_id=CASE,
)

post_login_process = Event(
    event_id="evt_9988776655aa",
    timestamp=T0 + timedelta(minutes=8, seconds=15),
    source=TelemetrySource.WINDOWS_SYSMON,
    category=EventCategory.PROCESS,
    event_type="sysmon_1_process_create",
    host=HOST,
    user=USER,
    outcome="success",
    process=ProcessInfo(
        pid=6612,
        name="powershell.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi",
        parent_pid=884,
        parent_name="services.exe",
        user=USER,
        hash_sha256="9f2b1c0e4a7d8e3f5b6c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
    ),
    message="Process created with encoded command line.",
    case_id=CASE,
)

alert_bruteforce = Alert(
    alert_id="alr_11aa22bb33cc",
    rule_id="SIG-AUTH-0007",
    rule_name="Multiple Failed Logons Followed By Success",
    rule_severity=Severity.MEDIUM,
    timestamp=T0 + timedelta(minutes=6, seconds=50),
    host=HOST,
    user=USER,
    src_ip=ATTACKER_IP,
    description="23 failed logons for m.alharbi from 10.13.37.24 followed by a successful logon within 7 minutes.",
    event_ids=[failed_login.event_id, successful_login.event_id],
    suggested_techniques=["T1110.001"],
    case_id=CASE,
)

alert_encoded_ps = Alert(
    alert_id="alr_44dd55ee66ff",
    rule_id="SIG-PROC-0021",
    rule_name="Encoded PowerShell Command Line",
    rule_severity=Severity.HIGH,
    timestamp=T0 + timedelta(minutes=8, seconds=20),
    host=HOST,
    user=USER,
    src_ip=None,
    description="powershell.exe launched with -enc and hidden window from an interactive session.",
    event_ids=[post_login_process.event_id],
    suggested_techniques=["T1059.001", "T1027"],
    case_id=CASE,
)

incident = Incident(
    incident_id="inc_7c3e9f1a2b4d",
    title=f"Possible account compromise on {HOST} ({USER})",
    status=IncidentStatus.INVESTIGATING,
    created_at=T0 + timedelta(minutes=7),
    updated_at=T0 + timedelta(minutes=9),
    window_start=T0,
    window_end=T0 + timedelta(minutes=10),
    alert_ids=[alert_bruteforce.alert_id, alert_encoded_ps.alert_id],
    entities=[
        Entity(entity_type=EntityType.HOST, value=HOST, is_protected=False),
        Entity(entity_type=EntityType.ACCOUNT, value=USER, is_protected=False),
        Entity(entity_type=EntityType.IP_ADDRESS, value=ATTACKER_IP, is_protected=False),
    ],
    case_id=CASE,
)

evidence_auth_history = EvidenceItem(
    evidence_id="evd_aa11bb22cc33",
    incident_id=incident.incident_id,
    evidence_class=EvidenceClass.AUTH_HISTORY,
    tool_name="get_auth_history",
    tool_query={"user": USER, "window_hours": 720},
    retrieved_at=T0 + timedelta(minutes=9, seconds=30),
    summary=f"{USER} has never authenticated from 10.13.37.0/24 in the previous 30 days; all prior logons came from 10.20.4.0/24.",
    content={
        "total_logons_30d": 412,
        "distinct_source_subnets": ["10.20.4.0/24"],
        "first_seen_from_source": None,
        "failed_logons_30d_baseline": 3,
    },
    source_event_ids=[failed_login.event_id, successful_login.event_id],
    was_productive=True,
)

evidence_entity_context = EvidenceItem(
    evidence_id="evd_dd44ee55ff66",
    incident_id=incident.incident_id,
    evidence_class=EvidenceClass.ENTITY_CONTEXT,
    tool_name="get_entity_context",
    tool_query={"entity_type": "account", "value": USER},
    retrieved_at=T0 + timedelta(minutes=9, seconds=45),
    summary="m.alharbi is a standard finance user, not a service account and not a member of any administrative group.",
    content={
        "account_type": "user",
        "department": "Finance",
        "groups": ["Domain Users", "Finance-RW"],
        "is_service_account": False,
        "privileged": False,
    },
    source_event_ids=[],
    was_productive=True,
)

evidence_change_window = EvidenceItem(
    evidence_id="evd_77aa88bb99cc",
    incident_id=incident.incident_id,
    evidence_class=EvidenceClass.CHANGE_WINDOW,
    tool_name="get_change_window",
    tool_query={"host": HOST, "at": (T0 + timedelta(minutes=6)).isoformat()},
    retrieved_at=T0 + timedelta(minutes=10),
    summary="No scheduled maintenance or approved change covered this host at the time of the activity.",
    content={"in_change_window": False, "nearest_window": None},
    source_event_ids=[],
    was_productive=True,
)

risk = RiskScore(
    incident_id=incident.incident_id,
    score=82,
    severity=Severity.HIGH,
    factors={
        "credential_attack_confirmed": 25,
        "novel_source_subnet": 20,
        "post_compromise_execution": 25,
        "outside_change_window": 7,
        "non_privileged_target": 5,
    },
    computed_at=T0 + timedelta(minutes=10, seconds=5),
)

action_block = ProposedAction(
    action_id="act_bb11cc22dd33",
    action_type=ActionType.BLOCK_IP,
    target_type=EntityType.IP_ADDRESS,
    target_value=ATTACKER_IP,
    justification="Source of a successful credential attack with no legitimate history for this account.",
    reversible=True,
    evidence_ids=[evidence_auth_history.evidence_id],
)

action_disable = ProposedAction(
    action_id="act_ee44ff55aa66",
    action_type=ActionType.DISABLE_ACCOUNT,
    target_type=EntityType.ACCOUNT,
    target_value=USER,
    justification="Account credentials are presumed compromised; encoded PowerShell ran under this session.",
    reversible=True,
    evidence_ids=[evidence_auth_history.evidence_id, evidence_entity_context.evidence_id],
)

verdict = Verdict(
    verdict_id="vrd_5f6a7b8c9d0e",
    incident_id=incident.incident_id,
    arm=EvaluationArm.A3_TOOL_USING_AGENT,
    classification=Classification.MALICIOUS,
    confidence=0.88,
    summary=(
        "A password-guessing attack from 10.13.37.24 succeeded against m.alharbi at 02:17 UTC. "
        "The source subnet has no authentication history for this account across 30 days, the activity "
        "falls outside any approved change window, and an encoded PowerShell process launched under the "
        "session 90 seconds after logon. This is a genuine account compromise with post-access execution."
    ),
    attack_chain=[
        AttackChainStep(
            order=1,
            tactic="Credential Access",
            technique_id="T1110.001",
            technique_name="Password Guessing",
            description="23 failed logons against m.alharbi from a previously unseen subnet.",
            evidence_ids=[evidence_auth_history.evidence_id],
        ),
        AttackChainStep(
            order=2,
            tactic="Initial Access",
            technique_id="T1078",
            technique_name="Valid Accounts",
            description="Successful network logon using the guessed credentials.",
            evidence_ids=[evidence_auth_history.evidence_id],
        ),
        AttackChainStep(
            order=3,
            tactic="Execution",
            technique_id="T1059.001",
            technique_name="PowerShell",
            description="Encoded, hidden-window PowerShell launched under the compromised session.",
            evidence_ids=[evidence_change_window.evidence_id],
        ),
    ],
    techniques=["T1110.001", "T1078", "T1059.001", "T1027"],
    cited_evidence_ids=[
        evidence_auth_history.evidence_id,
        evidence_entity_context.evidence_id,
        evidence_change_window.evidence_id,
    ],
    risk_factors=[
        "Source subnet never seen for this account in 30 days",
        "Successful logon directly after sustained failures",
        "Encoded PowerShell execution post-logon",
        "Activity outside any approved change window",
    ],
    proposed_actions=[action_block, action_disable],
    produced_at=T0 + timedelta(minutes=10, seconds=30),
    model_name="frontier-llm-v1",
    tool_calls_made=4,
    input_tokens=11420,
    output_tokens=903,
    latency_ms=18734,
)

policy_allow = PolicyDecision(
    decision_id="pol_1a2b3c4d5e6f",
    action_id=action_block.action_id,
    incident_id=incident.incident_id,
    outcome=PolicyOutcome.ALLOW,
    autonomy_level=AutonomyLevel.ACT_WITH_APPROVAL,
    risk_score=risk.score,
    matched_rule="POL-007: reversible network block on unprotected external IP above risk 70",
    reason="Target is not a protected entity, the action is reversible, and risk exceeds the autonomous threshold.",
    target_is_protected=False,
    decided_at=T0 + timedelta(minutes=10, seconds=40),
)

policy_approval = PolicyDecision(
    decision_id="pol_6f5e4d3c2b1a",
    action_id=action_disable.action_id,
    incident_id=incident.incident_id,
    outcome=PolicyOutcome.REQUIRE_APPROVAL,
    autonomy_level=AutonomyLevel.ACT_WITH_APPROVAL,
    risk_score=risk.score,
    matched_rule="POL-012: account disable always requires human approval",
    reason="Disabling a user account is disruptive to a real person and is never taken autonomously.",
    target_is_protected=False,
    decided_at=T0 + timedelta(minutes=10, seconds=41),
)

FIXTURES = {
    "event_failed_login": failed_login,
    "event_successful_login": successful_login,
    "event_process_create": post_login_process,
    "alert_bruteforce": alert_bruteforce,
    "alert_encoded_powershell": alert_encoded_ps,
    "incident": incident,
    "evidence_auth_history": evidence_auth_history,
    "evidence_entity_context": evidence_entity_context,
    "evidence_change_window": evidence_change_window,
    "risk_score": risk,
    "proposed_action_block_ip": action_block,
    "proposed_action_disable_account": action_disable,
    "verdict": verdict,
    "policy_decision_allow": policy_allow,
    "policy_decision_require_approval": policy_approval,
}

SCHEMA_MODELS = [
    Event,
    Alert,
    Incident,
    EvidenceItem,
    Verdict,
    ProposedAction,
    PolicyDecision,
    RiskScore,
]


def main() -> None:
    fixtures_dir = OUT / "fixtures"
    schemas_dir = OUT / "schemas"
    fixtures_dir.mkdir(exist_ok=True)
    schemas_dir.mkdir(exist_ok=True)

    for name, obj in FIXTURES.items():
        path = fixtures_dir / f"{name}.json"
        path.write_text(obj.model_dump_json(indent=2) + "\n", encoding="utf-8")
        print(f"fixture  {path.relative_to(OUT.parent)}")

    for model in SCHEMA_MODELS:
        path = schemas_dir / f"{model.__name__}.schema.json"
        path.write_text(
            json.dumps(model.model_json_schema(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(f"schema   {path.relative_to(OUT.parent)}")

    bundle = fixtures_dir / "s1_full_case.json"
    bundle.write_text(
        json.dumps(
            {
                "case_id": CASE,
                "scenario": "S1 — credential attack leading to account compromise",
                "ground_truth_classification": "malicious",
                "events": [
                    json.loads(e.model_dump_json())
                    for e in (failed_login, successful_login, post_login_process)
                ],
                "alerts": [
                    json.loads(a.model_dump_json())
                    for a in (alert_bruteforce, alert_encoded_ps)
                ],
                "incident": json.loads(incident.model_dump_json()),
                "evidence": [
                    json.loads(e.model_dump_json())
                    for e in (
                        evidence_auth_history,
                        evidence_entity_context,
                        evidence_change_window,
                    )
                ],
                "risk_score": json.loads(risk.model_dump_json()),
                "verdict": json.loads(verdict.model_dump_json()),
                "policy_decisions": [
                    json.loads(p.model_dump_json()) for p in (policy_allow, policy_approval)
                ],
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"bundle   {bundle.relative_to(OUT.parent)}")


if __name__ == "__main__":
    main()
