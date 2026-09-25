from __future__ import annotations

from datetime import datetime

from contracts.models import (
    Alert,
    EntityType,
    EvidenceClass,
    EvidenceItem,
    Incident,
    Inventory,
    RiskScore,
    Severity,
)

SEVERITY_POINTS = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 25,
    Severity.CRITICAL: 35,
}

SEVERITY_BANDS = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (35, Severity.MEDIUM),
    (15, Severity.LOW),
)


def score_risk(
    incident: Incident,
    alerts: list[Alert],
    evidence: list[EvidenceItem],
    inventory: Inventory,
    now: datetime,
) -> RiskScore:
    accounts = [e.value for e in incident.entities if e.entity_type is EntityType.ACCOUNT]
    history = [
        item.content
        for item in evidence
        if item.evidence_class is EvidenceClass.AUTH_HISTORY
        and item.tool_name == "auth_history"
        and item.tool_query.get("account") in accounts
    ]
    most_failures = max(
        (entry["failures"] for content in history for entry in content["by_source_ip"]),
        default=0,
    )
    after_failures = [entry for content in history for entry in content["success_after_failures"]]
    known = {src_ip for content in history for src_ip in content["known_source_ips"]}
    factors = {
        "alert_severity": max((SEVERITY_POINTS[a.rule_severity] for a in alerts), default=0),
        "failed_attempts": 20 if most_failures >= 20 else 10 if most_failures >= 10 else 0,
        "success_after_failures": 25 if after_failures else 0,
        "new_source_ip": 20 if any(e["src_ip"] not in known for e in after_failures) else 0,
        "privileged_account": 15 if any(inventory.is_privileged(a) for a in accounts) else 0,
    }
    score = min(100, sum(factors.values()))
    return RiskScore(
        incident_id=incident.incident_id,
        score=score,
        severity=severity_for(score),
        factors=factors,
        computed_at=now,
    )


def severity_for(score: int) -> Severity:
    for threshold, severity in SEVERITY_BANDS:
        if score >= threshold:
            return severity
    return Severity.INFO
