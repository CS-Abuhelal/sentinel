from __future__ import annotations

import re

from contracts.models import Recommendation

WEAKENING = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"Set-MpPreference\s+-Disable",
        r"DisableRealtimeMonitoring",
        r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off",
        r"(turn|switch)\s+off\s+(the\s+)?(windows\s+)?(defender|firewall|antivirus)",
        r"disable\s+(the\s+)?(windows\s+)?(defender|firewall|uac|antivirus)",
        r"Set-ExecutionPolicy\s+(Unrestricted|Bypass)",
        r"bcdedit",
        r"Add-MpPreference\s+-Exclusion",
        r"(add|create)\s+(an?\s+)?(defender\s+|antivirus\s+)?exclusion",
        r"uninstall\s+(the\s+)?(windows\s+)?(defender|antivirus|firewall)",
        r"(stop|kill)\s+(the\s+)?(windows\s+)?(defender|antivirus|firewall)",
        r"(Stop-Service|sc(\.exe)?\s+(stop|delete))\b.*\bWinDefend\b",
        r"start=\s*disabled",
    )
)


def weakens_security(step: str) -> bool:
    return any(pattern.search(step) for pattern in WEAKENING)


def vet(recommendation: Recommendation) -> Recommendation:
    kept = [step for step in recommendation.steps if not weakens_security(step)]
    dropped = [step for step in recommendation.steps if weakens_security(step)]
    return recommendation.model_copy(
        update={"steps": kept, "dropped_steps": [*recommendation.dropped_steps, *dropped]}
    )
