from __future__ import annotations

import re
import unicodedata
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
ONLY_NOTIFICATIONS = r"(?!(?:\s+firewall)?\s+notifications?\b)"
SERVICES = r"(?:mpssvc|WinDefend|wscsvc|SecurityHealthService)"
SWITCHED_ON = r"(?:0*1|true|0x0*1|dword:0*1)"
SWITCHED_TO_ZERO = r"(?:0+|0x0+|dword:0+)"
VERBS = r"(?:disable|turn\s+off|switch\s+off|stop|kill|uninstall|pause|deactivate)"
CHAIN_FILLER = r"(?:,?\s+(?:and|then|also|plus|the|your|its|all|windows|microsoft|built-in))*"

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
        r"(?<![\w-])[-/]enc(odedcommand)?\b",
        r"(?<![\w-])[-/]e(c|n\w*)?\s+['\"]?[A-Za-z0-9+/]{16,}={0,2}",
        rf"\b{VERBS}\b[^.\n]*\b(and|then|also|plus)\b{CHAIN_FILLER},?\s+({SWITCHED_OFF})\b"
        + ONLY_NOTIFICATIONS,
        r"\b(?:keep|leave)\s+(?:it\s+|them\s+)?(?:off|disabled)\b[^.\n]{0,30}\b("
        + PROTECTIONS
        + r")\b",
        rf"\b({PROTECTIONS})\b{ONLY_NOTIFICATIONS}[^.\n]{{0,60}}\b{VERBS}\s+(it|them)\b",
        r"certutil\b[^\n]*-urlcache",
        r"bitsadmin\b[^\n]*/transfer",
        r"\|\s*(?:&\s*)?(iex|sh|bash|cmd|powershell|pwsh)\b",
        r"\bSet-MpPreference\b[^\n]*-(Disable\w*(?![\s:=]+['\"]?(\$false|false|0)\b)"
        r"|MAPSReporting\s+0|SubmitSamplesConsent\s+2"
        r"|PUAProtection\s+(0|Disabled)|Enable\w+\s+(0|Disabled|\$false))\b",
        r"-ExecutionPolicy\s+(Unrestricted|Bypass)\b",
        r"-DefaultInboundAction\s+Allow\b",
        r"firewallpolicy\s+allowinbound",
        r"\\Services\\" + SERVICES + r"\b[^\n]*\bStart\b[^\n]*\b(0*4|0x0*4|dword:0*4)\b",
        r"\bSmartScreenEnabled\b[^\n]*\bOff\b",
        r"\b(EnableSmartScreen|PromptOnSecureDesktop)\b[^\n]*\b" + SWITCHED_TO_ZERO + r"\b",
        r"DisableRealtimeMonitoring\b(?![\s:=]+['\"]?(\$false|false|0)\b)",
        r"\b(DisableAntiSpyware|DisableAntiVirus|DisableRealtimeMonitoring"
        r"|DisableBehaviorMonitoring|DisableIOAVProtection)\b[^\n]*\b" + SWITCHED_ON + r"\b",
        r"Set-NetFirewallProfile\b[^\n]*-Enabled[\s:]+['\"]?(False|0|\$false)\b",
        r"netsh\s+advfirewall\s+set\s+\S+\s+state\s+off",
        r"netsh\s+firewall\b[^\n]*\bdisable\b",
        r"\bEnableLUA\b[^\n]*\b" + SWITCHED_TO_ZERO + r"\b",
        r"\bConsentPromptBehaviorAdmin\b[^\n]*\b" + SWITCHED_TO_ZERO + r"\b",
        r"Set-ExecutionPolicy\s+(Unrestricted|Bypass)",
        r"bcdedit",
        r"\b(Set|Add)-MpPreference\b[^\n]*-Exclusion",
        r"(add|create)\s+(an?\s+)?(defender\s+|antivirus\s+)?exclusion",
        r"\b(Stop-Service|Set-Service|sc(\.exe)?\s+(stop|config|delete))\b[^\n]*\b"
        + SERVICES
        + r"\b",
        r"\bnet1?(\.exe)?\s+stop\s+['\"]?" + SERVICES + r"\b",
        r"\b" + SERVICES + r"\b[^\n]*\|\s*(Stop-Service|Set-Service)\b",
        r"start=\s*disabled",
    )
)


CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
DASHES = str.maketrans(dict.fromkeys([*map(chr, range(0x2010, 0x2016)), chr(0x2212)], "-"))
URL = re.compile(r"(?=(https?:[/\\]+[^\s/\\]\S*))", re.IGNORECASE)
WWW = re.compile(r"(?<![\w./\\-])(?=(www\.[\w-]\S*))", re.IGNORECASE)
UNC = re.compile(r"(?<![\w:\\])\\\\[^\s\\]")
URL_END = ".,;:!?)]}>'\"`*"
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
        "go.microsoft.com",
        "aka.ms",
    }
)
UNVERIFIED_LINK = "Unverified link: "


def normalize(text: str) -> str:
    folded = unicodedata.normalize("NFKC", text).translate(DASHES)
    return "".join(char for char in folded if unicodedata.category(char) != "Cf")


def weakens_security(text: str) -> bool:
    text = normalize(text)
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


def has_unverified_link(text: str, allowed: frozenset[str]) -> bool:
    text = normalize(text)
    if UNC.search(text):
        return True
    links = [*URL.findall(text), *("https://" + match for match in WWW.findall(text))]
    return any(not trusted_host(link_host(url), allowed) for url in links)


def check_fix(
    recommendation: Recommendation, findings: Mapping[str, Finding]
) -> Recommendation | None:
    cited = recommendation.finding_ids
    if not cited or any(finding_id not in findings for finding_id in cited):
        return None
    allowed = {findings[f].cve.upper() for f in cited if findings[f].cve}
    text = normalize(" ".join([recommendation.title, *recommendation.steps]))
    if any(match.upper() not in allowed for match in CVE_ID.findall(text)):
        return None
    hosts = VENDOR_HOSTS | {
        host
        for f in cited
        if findings[f].kind is FindingKind.VULNERABILITY
        for reference in findings[f].references
        if (host := link_host(reference)) is not None
    }
    linked = drop_unverified_links(recommendation, hosts)
    vetted = vet(linked) if linked is not None else None
    return vetted if vetted is not None and vetted.steps else None


def check_advice(recommendation: Recommendation) -> Recommendation | None:
    linked = drop_unverified_links(recommendation, VENDOR_HOSTS)
    return vet(linked) if linked is not None else None


def drop_unverified_links(
    recommendation: Recommendation, hosts: frozenset[str]
) -> Recommendation | None:
    if has_unverified_link(recommendation.title, hosts):
        return None
    steps = recommendation.steps
    return recommendation.model_copy(
        update={
            "steps": [s for s in steps if not has_unverified_link(s, hosts)],
            "dropped_steps": [
                *recommendation.dropped_steps,
                *(UNVERIFIED_LINK + s for s in steps if has_unverified_link(s, hosts)),
            ],
        }
    )
