from __future__ import annotations

import re
from collections.abc import Mapping

from contracts.models import Finding, Recommendation

PROTECTIONS = (
    r"defender|firewall|anti-?virus|uac|user\s+account\s+control|smartscreen"
    r"|real-?time\s+protection|tamper\s+protection|windows\s+security"
)
SWITCHED_OFF = (
    r"defender|firewall|anti-?virus|uac|smartscreen|real-?time\s+protection|tamper\s+protection"
)

NEGATED = r"(?<!not\s)(?<!never\s)(?<!n't\s)"
DENIAL = r"\b(?:not|never)\b|n't\b"
BETWEEN_VERB_AND_TARGET = r"\b(?:at|in|with|using|keep|not|never)\b|[;:]"

WEAKENING = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        NEGATED
        + r"\b(disable|turn\s+off|switch\s+off|stop|kill|uninstall|pause|deactivate)\b"
        rf"(?:(?!{BETWEEN_VERB_AND_TARGET})[^.\n]){{0,40}}\b({PROTECTIONS})\b",
        rf"\b({SWITCHED_OFF})\b(?:(?!{DENIAL})[^.\n]){{0,30}}\b(off|disabled)\b",
        r"never\s+notify",
        r"\b(iex|invoke-expression)\b",
        r"downloadstring",
        r"-enc(odedcommand)?\b",
        r"certutil\b[^\n]*-urlcache",
        r"bitsadmin\b[^\n]*/transfer",
        r"\|\s*(iex|sh|bash|cmd)\b",
        r"Set-MpPreference\s+-Disable",
        r"DisableRealtimeMonitoring",
        r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off",
        r"Set-ExecutionPolicy\s+(Unrestricted|Bypass)",
        r"bcdedit",
        r"Add-MpPreference\s+-Exclusion",
        r"(add|create)\s+(an?\s+)?(defender\s+|antivirus\s+)?exclusion",
        r"(Stop-Service|sc(\.exe)?\s+(stop|delete))\b.*\bWinDefend\b",
        r"start=\s*disabled",
    )
)


CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def weakens_security(text: str) -> bool:
    return any(pattern.search(text) for pattern in WEAKENING)


def vet(recommendation: Recommendation) -> Recommendation | None:
    if weakens_security(recommendation.title):
        return None
    kept = [step for step in recommendation.steps if not weakens_security(step)]
    dropped = [step for step in recommendation.steps if weakens_security(step)]
    return recommendation.model_copy(
        update={"steps": kept, "dropped_steps": [*recommendation.dropped_steps, *dropped]}
    )


def check_fix(
    recommendation: Recommendation, findings: Mapping[str, Finding]
) -> Recommendation | None:
    cited = recommendation.finding_ids
    if not cited or any(finding_id not in findings for finding_id in cited):
        return None
    allowed = {findings[f].cve.upper() for f in cited if findings[f].cve}
    text = " ".join([recommendation.title, *recommendation.steps])
    if any(match.upper() not in allowed for match in CVE_ID.findall(text)):
        return None
    return vet(recommendation)
