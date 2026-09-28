from __future__ import annotations

import re

from contracts.models import Recommendation

PROTECTIONS = (
    r"defender|firewall|anti-?virus|uac|user\s+account\s+control|smartscreen"
    r"|real-?time\s+protection|tamper\s+protection|windows\s+security"
)
SWITCHED_OFF = (
    r"defender|firewall|anti-?virus|uac|smartscreen|real-?time\s+protection|tamper\s+protection"
)

WEAKENING = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\b(disable|turn\s+off|switch\s+off|stop|kill|uninstall|pause|deactivate)\b"
        rf"[^.\n]{{0,40}}\b({PROTECTIONS})\b",
        rf"\b({SWITCHED_OFF})\b[^.\n]{{0,30}}\b(off|disabled)\b",
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
