from __future__ import annotations

import json
import re
from datetime import datetime

from contracts.models import Finding, FindingKind, Severity

RELATED_BONUS = 10
SEVERITY_START = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 45,
    Severity.LOW: 20,
    Severity.INFO: 20,
}
CATEGORIES: tuple[tuple[int, re.Pattern[str]], ...] = (
    (35, re.compile(r"notification")),
    (55, re.compile(r"\blog(s|ging|ged)?\b")),
    (70, re.compile(r"firewall")),
    (70, re.compile(r"antivirus|defender|malware")),
    (60, re.compile(r"password|account|lockout")),
    (60, re.compile(r"remote desktop|rdp|smb|remote assistance|winrm")),
    (55, re.compile(r"audit")),
)
OTHER = 35
BANDS = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
)


def base_score(finding: Finding) -> int:
    if finding.kind is FindingKind.VULNERABILITY:
        if finding.cvss is not None:
            return round(finding.cvss * 10)
        return SEVERITY_START[finding.severity]
    text = f"{finding.title} {_compliance(finding)}".lower()
    for weight, pattern in CATEGORIES:
        if pattern.search(text):
            return weight
    return OTHER


def band(score: int) -> Severity:
    for floor, severity in BANDS:
        if score >= floor:
            return severity
    return Severity.INFO


def prioritize(finding: Finding, related_alerts: int) -> Finding:
    score = min(100, base_score(finding) + (RELATED_BONUS if related_alerts > 0 else 0))
    return finding.model_copy(
        update={"priority": score, "severity": band(score), "related_alert_count": related_alerts}
    )


def sort_key(finding: Finding) -> tuple[int, int, datetime, str]:
    kind = 0 if finding.kind is FindingKind.VULNERABILITY else 1
    return (-finding.priority, kind, finding.first_seen, finding.key)


def _compliance(finding: Finding) -> str:
    data = finding.raw.get("data")
    sca = data.get("sca") if isinstance(data, dict) else None
    check = sca.get("check") if isinstance(sca, dict) else None
    compliance = check.get("compliance") if isinstance(check, dict) else None
    return json.dumps(compliance) if compliance else ""
