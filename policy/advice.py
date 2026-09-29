from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from contracts.models import Finding, FindingKind, Recommendation

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
ONLY_NOTIFICATIONS = r"(?!\s+notifications?\b)"

WEAKENING = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        NEGATED
        + r"\b(disable|turn\s+off|switch\s+off|stop|kill|uninstall|pause|deactivate)\b"
        rf"(?:(?!{BETWEEN_VERB_AND_TARGET})[^.\n]){{0,40}}\b({PROTECTIONS})\b"
        + ONLY_NOTIFICATIONS,
        rf"\b({SWITCHED_OFF})\b{ONLY_NOTIFICATIONS}(?:(?!{DENIAL})[^.\n]){{0,30}}"
        r"\b(off|disabled)\b",
        r"never\s+notify",
        r"\b(iex|invoke-expression)\b",
        r"downloadstring",
        r"-enc(odedcommand)?\b",
        r"certutil\b[^\n]*-urlcache",
        r"bitsadmin\b[^\n]*/transfer",
        r"\|\s*(iex|sh|bash|cmd)\b",
        r"Set-MpPreference\s+-Disable",
        r"DisableRealtimeMonitoring",
        r"\b(DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring"
        r"|DisableBehaviorMonitoring|DisableIOAVProtection)\b[^\n]*\b(1|true)\b",
        r"Set-NetFirewallProfile\b[^\n]*-Enabled\s+(False|0|\$false)",
        r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off",
        r"netsh\s+firewall\b[^\n]*\bdisable\b",
        r"\bEnableLUA\b[^\n]*\b0\b",
        r"\bConsentPromptBehaviorAdmin\b[^\n]*\b0\b",
        r"Set-ExecutionPolicy\s+(Unrestricted|Bypass)",
        r"bcdedit",
        r"Add-MpPreference\s+-Exclusion",
        r"Set-MpPreference\s+-Exclusion",
        r"(add|create)\s+(an?\s+)?(defender\s+|antivirus\s+)?exclusion",
        r"\b(Stop-Service|Set-Service|sc(\.exe)?\s+(stop|config|delete))\b[^\n]*"
        r"\b(mpssvc|WinDefend|wscsvc|SecurityHealthService)\b",
        r"start=\s*disabled",
    )
)


CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
DASHES = str.maketrans(dict.fromkeys([*map(chr, range(0x2010, 0x2016)), chr(0x2212)], "-"))
URL = re.compile(r"https?://\S+", re.IGNORECASE)
URL_END = ".,;:!?)]}>'\""
VENDOR_HOSTS = frozenset(
    {
        "learn.microsoft.com",
        "support.microsoft.com",
        "www.microsoft.com",
        "code.visualstudio.com",
        "nodejs.org",
        "www.python.org",
        "python.org",
        "www.mongodb.com",
        "store.steampowered.com",
        "www.npmjs.com",
        "pypi.org",
    }
)
UNVERIFIED_LINK = "Unverified link: "


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


def link_host(url: str) -> str | None:
    try:
        parts = urlsplit(url.rstrip(URL_END))
        host = parts.hostname
    except ValueError:
        return None
    if "@" in parts.netloc or "\\" in parts.netloc:
        return None
    return host


def trusted_host(host: str | None, allowed: frozenset[str]) -> bool:
    return host is not None and any(
        host == name or host.endswith("." + name) for name in allowed
    )


def has_unverified_link(step: str, allowed: frozenset[str]) -> bool:
    return any(not trusted_host(link_host(url), allowed) for url in URL.findall(step))


def check_fix(
    recommendation: Recommendation, findings: Mapping[str, Finding]
) -> Recommendation | None:
    cited = recommendation.finding_ids
    if not cited or any(finding_id not in findings for finding_id in cited):
        return None
    allowed = {findings[f].cve.upper() for f in cited if findings[f].cve}
    text = " ".join([recommendation.title, *recommendation.steps]).translate(DASHES)
    if any(match.upper() not in allowed for match in CVE_ID.findall(text)):
        return None
    hosts = VENDOR_HOSTS | {
        host
        for f in cited
        if findings[f].kind is FindingKind.VULNERABILITY
        for reference in findings[f].references
        if (host := link_host(reference)) is not None
    }
    steps = recommendation.steps
    linked = recommendation.model_copy(
        update={
            "steps": [s for s in steps if not has_unverified_link(s, hosts)],
            "dropped_steps": [
                *recommendation.dropped_steps,
                *(UNVERIFIED_LINK + s for s in steps if has_unverified_link(s, hosts)),
            ],
        }
    )
    vetted = vet(linked)
    return vetted if vetted is not None and vetted.steps else None
