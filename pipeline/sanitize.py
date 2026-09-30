from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterable, Iterator
from itertools import count
from typing import Any
from urllib.parse import quote, unquote

OWN_HOST_KEYS = frozenset({"host", "agent_name", "computer"})
OTHER_HOST_KEYS = frozenset(
    {
        "workstationName",
        "hostname",
        "hostName",
        "subjectDomainName",
        "targetDomainName",
        "workstation",
        "targetServerName",
        "sourceHostname",
        "destinationHostname",
        "clientName",
    }
)
LOCAL_HOST_KEYS = frozenset({"queryName"})
USER_KEYS = frozenset(
    {
        "user",
        "targetUserName",
        "subjectUserName",
        "userName",
        "accountName",
        "samAccountName",
        "dstuser",
        "srcuser",
        "uname_after",
        "uname_before",
        "oldTargetUserName",
        "newTargetUserName",
        "targetOutboundUserName",
        "account",
        "sourceUser",
        "targetUser",
        "parentUser",
        "userPrincipalName",
    }
)
FULL_NAME_KEYS = frozenset({"displayName", "decided_by", "approved_by"})
ACCOUNT_NAME_PARENTS = frozenset({"user", "win_perm_before", "win_perm_after"})
ACCOUNT_CONTAINER_KEYS = frozenset({"accounts", "by_account", "by_user"})
HOST_CONTAINER_KEYS = frozenset({"by_host", "hosts"})
SERVICE_DOMAINS = frozenset(
    {
        "nt authority",
        "nt service",
        "iis apppool",
        "window manager",
        "font driver host",
        "builtin",
        "nt virtual machine",
    }
)
KEEP = frozenset(
    {
        "my-pc",
        "MY-PC",
        "sentinel-test-nobody",
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "LocalSystem",
        "LocalService",
        "NetworkService",
        "ANONYMOUS LOGON",
        "Administrator",
        "Guest",
        "DefaultAccount",
        "WDAGUtilityAccount",
        "-",
        "Public",
        "Default",
        "Default User",
        "All Users",
        "wazuh.manager",
        "NT AUTHORITY",
        "NT SERVICE",
        "WORKGROUP",
        "MicrosoftAccount",
        "AzureAD",
        "BUILTIN",
        "IIS APPPOOL",
        "Window Manager",
        "Font Driver Host",
        "TrustedInstaller",
        "NT VIRTUAL MACHINE",
        "Administrators",
        "Guests",
        "Power Users",
        "Remote Desktop Users",
        "Remote Management Users",
        "Backup Operators",
        "Network Configuration Operators",
        "Cryptographic Operators",
        "Access Control Assistance Operators",
        "Performance Log Users",
        "Performance Monitor Users",
        "Distributed COM Users",
        "Event Log Readers",
        "Hyper-V Administrators",
        "Device Owners",
        "Replicator",
        "IIS_IUSRS",
        "OpenSSH Users",
        "docker-users",
        "Authenticated Users",
        "Everyone",
        "INTERACTIVE",
        "NETWORK",
        "SERVICE",
        "BATCH",
        "CREATOR OWNER",
        "CREATOR GROUP",
        "OWNER RIGHTS",
        "ALL APPLICATION PACKAGES",
        "ALL RESTRICTED APPLICATION PACKAGES",
    }
)
KEEP_FOLDED = frozenset(value.casefold() for value in KEEP)
GENERIC = frozenset(
    {
        "user",
        "users",
        "admin",
        "owner",
        "test",
        "temp",
        "windows",
        "unknown",
        "localhost",
        "none",
        "null",
        "n/a",
        "git",
        "noreply",
        "no-reply",
        "support",
        "info",
        "security",
        "secure",
        "help",
        "contact",
        "abuse",
        "postmaster",
        "webmaster",
        "hostmaster",
        "root",
        "mail",
        "wsl",
        "wsl.localhost",
        "tsclient",
        "wpad",
        "isatap",
    }
)
LOCAL_SUFFIXES = frozenset(
    {
        "lan",
        "local",
        "localdomain",
        "home",
        "internal",
        "intranet",
        "corp",
        "private",
        "arpa",
        "home.arpa",
        "fritz.box",
        "mshome.net",
        "attlocal.net",
        "router",
        "gateway",
    }
)
MIN_NAME_LENGTH = 3
NETBIOS_LENGTH = 15
PLACEHOLDER = re.compile(r"^(user\d+|HOST-\d+|MY-PC)\$?$", re.IGNORECASE)
BUILTIN_ACCOUNT = re.compile(r"^(DWM|UMFD)-\d+$", re.IGNORECASE)
INSERTION_STRING = re.compile(r"^%%\d+$")
_ESCAPED = r"(?<=\\[nrt])|(?<=\\u[0-9A-Fa-f]{4})|(?<=%[0-9A-Fa-f]{2})"
_PROFILE_ROOT = r"(?i)(?:\\+|/+)(?:Users|Documents and Settings)(?:\\+|/+)"
PROFILE_FOLDER = re.compile(_PROFILE_ROOT + r"([^\\/:*?\x22<>|\r\n\t%]{1,64}?)(?=[\\/])")
PROFILE = re.compile(_PROFILE_ROOT + r"(All Users|Default User|[^\\/\s\x22\x27<>|:*?%,;(){}\[\]]+)")
UNC = re.compile(r"(?:(?<![\w.$:\\-])|(?<=\\[nrt]))(\\{2,})([^\\\s]{3,})(\\+)")
LONG_UNC = re.compile(r"(?i)(?<!\\)(\\+)(?:\1\?\1UNC|Device\1Mup)\1([^\\\s;]{3,})\1")
HOME_FOLDER = re.compile(
    r"(?:(?<![\w.%-])|(?<=\\[nrt]))/home/([^/\s\x22\x27<>|:*?%,;(){}\[\]\\]+)/"
)
DOMAIN_ACCOUNT = re.compile(
    r"(?:(?<![\w.$\\-])|(?<=\\[nrt]))([^\W_][\w.-]*)"
    r"(?:(?:\\\\){1,2}|\\(?![nrt\x22]|u[0-9A-Fa-f]{4}))([^\W_][\w.$-]*)"
)
LABEL = re.compile(
    r"(Account Name|Account Domain|Workstation Name|Source Workstation|Client Name"
    r"|Target Server Name):((?:[ \t]|\\t)*)"
)
LABEL_VALUE = re.compile(r"[^\t\r\n\\\x22]+(?:\\[^\s\\\x22]+)?")
ESCAPED_LABEL_VALUE = re.compile(r"[^\t\r\n\\\x22]+(?:\\\\[^\s\\\x22]+)?")
_LABEL_WORD = (
    r"(?:Account|Additional|Authentication|Caller|Client|Detailed|Elevated|Error|Failure"
    r"|Impersonation|Key|Linked|Logon|Network|New|Old|Package|Process|Restricted|Security"
    r"|Source|Status|Sub|Subject|Target|Transited|Virtual|Workstation)\b"
)
LABEL_START = re.compile(_LABEL_WORD + r"(?: [A-Z][\w()/-]*){0,2}:|[^\s:]+:")
LABEL_END = re.compile(r"\s+" + _LABEL_WORD + r"[\w ()/-]{0,40}:")
MAIL_KEY = re.compile(r"(?i)mail")
EMAIL = re.compile(
    r"(?:(?<![\w.+\\-])|(?<=\\)(?![nrt]|u[0-9A-Fa-f]{4})|" + _ESCAPED + r")"
    r"[\w+-][\w.+-]*@(?:[^\W_][\w-]*\.)+[^\W\d_]{2,}(?![\w-])"
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|0?[1-9]\d|0{0,2}\d)"
IPV4 = re.compile(
    rf"(?<!(?i:CIS) )(?:(?<!\d)(?<!\d\.)|(?<=\\u[0-9A-Fa-f]{{4}}))"
    rf"{_OCTET}(?:\.{_OCTET}){{3}}(?!\d)(?!\.\d)"
)
IPV6 = re.compile(
    r"(?:(?<![\w.\]])|" + _ESCAPED + r")(?=[0-9A-Fa-f]|::)"
    r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_-]+)?(?![\w:])(?!\.\d)"
)
MAC = re.compile(
    r"(?i)(?:(?<![0-9a-f])(?<!\W[0-9a-f][:-])(?<!\W[0-9a-f]{2}[:-])(?<!^[0-9a-f][:-])"
    r"(?<!^[0-9a-f]{2}[:-])|(?<=\\u[0-9a-f]{4}))"
    r"[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}(?![0-9a-f])(?![:-][0-9a-f])"
    r"|(?:(?<![\w.-])|(?<=\\[nrt])|(?<=\\u[0-9a-f]{4}))"
    r"(?:0x[0-9a-f]{12}|(?=[\d.]*[a-f])[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}"
    r"|(?=\d*[a-f])[0-9a-f]{12})(?![\w-])(?!\.[0-9a-f])"
)
SID = re.compile(r"(?i)S-1-5-21-\d+-\d+-\d+")
SID_PREFIX = "S-1-5-21-"
SID_BASE = "1000000000-1000000000-"
PLACEHOLDER_SID = re.compile(r"1000000000-1000000000-1000000\d{3}")
AZURE_SID = re.compile(r"(?i)S-1-12-1-\d+-\d+-\d+-\d+")
AZURE_SID_PREFIX = "S-1-12-1-"
AZURE_SID_BASE = "1000000000-1000000000-1000000000-"
PLACEHOLDER_AZURE_SID = re.compile(r"1000000000-1000000000-1000000000-1000000\d{3}")
ANY_SID = re.compile(r"(?i)S-1-\d+(?:-\d+)+")
FIRST_SID_NUMBER = 1000000000
DOMAIN_SEPARATOR = re.compile(r"\\+")
NAME_PARTS = re.compile(r"[\s,]+")
FORBIDDEN_SEPARATOR = re.compile(r"[,;\r\n]+")
BENCHMARK_KEY = re.compile(
    r"(?i)(?:compliance|cis|cis_csc|pci_dss|gdpr|hipaa|nist_800_53|nist_sp_800-53|nist_800_171"
    r"|tsc|gpg13|soc_2|cmmc|iso_27001)(?:[_-]v?\d[\w.-]*)?"
)
VERSION_KEY = re.compile(r"(?:^|[_-])(?i:version)$|Version$")
_NAME_START = r"(?:(?<![^\W_])|" + _ESCAPED + r")"
KEEP_MACS = frozenset({"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"})
PLACEHOLDER_MAC_PREFIX = "00:00:5E:00:53:"
PLACEHOLDER_IP_PREFIX = "203.0.113."
PLACEHOLDER_IPV6_NETWORK = ipaddress.IPv6Network("2001:db8::/32")
MAX_IPS = 254
MAX_MACS = 255
MAX_SIDS = 1000


def _numbers_only_key(key: str | None) -> bool:
    return key is not None and bool(BENCHMARK_KEY.fullmatch(key) or VERSION_KEY.search(key))


def _agent_id_key(key: str | None, parent: str | None) -> bool:
    return (key == "id" and parent == "agent") or key == "agent_id"


def _mail_key(key: str | None) -> bool:
    return key is not None and bool(MAIL_KEY.search(key))


def _local_suffix(rest: str) -> bool:
    folded = rest.casefold()
    return any(folded == suffix or folded.endswith("." + suffix) for suffix in LOCAL_SUFFIXES)


def _canonical_ipv4(text: str) -> str:
    return ".".join(str(int(part)) for part in text.split("."))


def _keep_ipv4(address: str) -> bool:
    first = int(address.split(".")[0])
    return (
        first in {0, 127, 255} or 224 <= first <= 239 or address.startswith(PLACEHOLDER_IP_PREFIX)
    )


def _ipv4_order(address: str) -> tuple[int, ...]:
    return tuple(int(part) for part in address.split("."))


def _ipv6(text: str) -> ipaddress.IPv6Address | None:
    try:
        return ipaddress.IPv6Address(text.split("%", 1)[0])
    except ValueError:
        return None


def _keep_ipv6(address: ipaddress.IPv6Address) -> bool:
    return address.is_loopback or address.is_unspecified or address in PLACEHOLDER_IPV6_NETWORK


def _holds_identifier(text: str) -> bool:
    return bool(IPV4.search(text) or MAC.search(text) or ANY_SID.search(text)) or any(
        _ipv6(match.group(0)) is not None for match in IPV6.finditer(text)
    )


def _canonical_mac(text: str) -> str:
    digits = re.sub(r"[^0-9A-Fa-f]", "", text[2:] if text[:2].lower() == "0x" else text).upper()
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def _sid_parts(text: str) -> str:
    return "-".join(str(int(part)) for part in text.split("-")[4:])


def _sid_order(parts: str) -> tuple[int, ...]:
    return tuple(int(part) for part in parts.split("-"))


def _number_sids(sids: set[str], taken: set[str], base: str) -> dict[str, str]:
    numbers = (number for number in count(FIRST_SID_NUMBER) if f"{base}{number}" not in taken)
    return {parts: f"{base}{next(numbers)}" for parts in sorted(sids, key=_sid_order)}


def _renumber_sid(text: str, known: dict[str, str], placeholder: re.Pattern[str], base: str) -> str:
    parts = _sid_parts(text)
    if placeholder.fullmatch(parts):
        return parts
    return known.get(parts, f"{base}{FIRST_SID_NUMBER}")


def _learnable(name: str) -> bool:
    folded = name.casefold()
    return (
        len(name) >= MIN_NAME_LENGTH
        and not name.isdigit()
        and folded not in KEEP_FOLDED
        and folded not in GENERIC
        and not PLACEHOLDER.match(name)
        and not BUILTIN_ACCOUNT.match(name)
        and not INSERTION_STRING.match(name)
        and not _holds_identifier(name)
    )


def _groups(names: Iterable[str]) -> dict[str, set[str]]:
    groups: dict[str, set[str]] = {}
    for name in names:
        groups.setdefault(name.casefold(), set()).add(name)
    return groups


def _forms(key: str, variants: Iterable[str]) -> set[str]:
    forms = {key} | {variant.lower() for variant in variants}
    for form in list(forms):
        forms.add(quote(form, safe="").lower())
        forms.add(form.replace(" ", "+"))
    return forms


class Sanitizer:
    def __init__(self) -> None:
        self._own_hosts: set[str] = set()
        self._other_hosts: set[str] = set()
        self._users: set[str] = set()
        self._emails: set[str] = set()
        self._agents: set[str] = set()
        self._ips: set[str] = set()
        self._ipv6s: set[str] = set()
        self._macs: set[str] = set()
        self._sids: set[str] = set()
        self._sid_taken: set[str] = set()
        self._azure_sids: set[str] = set()
        self._azure_sid_taken: set[str] = set()
        self._domain_accounts: set[tuple[str, str]] = set()
        self.mapping: dict[str, str] = {}
        self._ip_map: dict[str, str] = {}
        self._ipv6_map: dict[str, str] = {}
        self._mac_map: dict[str, str] = {}
        self._sid_map: dict[str, str] = {}
        self._azure_sid_map: dict[str, str] = {}
        self._agent_map: dict[str, str] = {}
        self._group_placeholders: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def learn(self, doc: Any) -> None:
        self._walk(doc, None, None, False)
        self._learn_domain_accounts()
        self._build()

    def apply(self, doc: Any) -> Any:
        return self._apply(doc, None, None, False)

    def _apply(self, doc: Any, key: str | None, parent: str | None, numbers_only: bool) -> Any:
        numbers_only = numbers_only or _numbers_only_key(key)
        if isinstance(doc, dict):
            result: dict[Any, Any] = {}
            for child_key, value in doc.items():
                new_key = child_key
                if isinstance(child_key, str):
                    new_key = self._replace(child_key, not numbers_only)
                if new_key in result:
                    raise ValueError("Two dict keys would become the same key after sanitizing.")
                result[new_key] = self._apply(value, str(child_key), key, numbers_only)
            return result
        if isinstance(doc, (list, tuple)):
            return [self._apply(value, key, parent, numbers_only) for value in doc]
        if isinstance(doc, str):
            stripped = doc.strip()
            if _agent_id_key(key, parent) and stripped in self._agent_map:
                return doc.replace(stripped, self._agent_map[stripped])
            return self._replace(doc, not numbers_only)
        return doc

    def _walk(self, value: Any, key: str | None, parent: str | None, numbers_only: bool) -> None:
        numbers_only = numbers_only or _numbers_only_key(key)
        if isinstance(value, dict):
            self._learn_entity(value)
            for child_key, child in value.items():
                if isinstance(child_key, str):
                    self._learn_text(child_key, numbers_only)
                    if key in ACCOUNT_CONTAINER_KEYS:
                        self._add_account(child_key)
                    elif key in HOST_CONTAINER_KEYS:
                        self._add_host(child_key, own=False)
                    elif _mail_key(key):
                        self._learn_account_emails(child_key)
                self._walk(child, str(child_key), key, numbers_only)
            return
        if isinstance(value, (list, tuple)):
            for child in value:
                self._walk(child, key, parent, numbers_only)
            return
        if not isinstance(value, str):
            return
        text = value.strip()
        if _agent_id_key(key, parent) and text and text != "000":
            self._agents.add(text)
        if key in OWN_HOST_KEYS or (key == "name" and parent == "agent"):
            self._add_host(text, own=True)
        elif key in OTHER_HOST_KEYS or (key == "name" and parent == "manager"):
            self._add_host(text, own=False)
        elif key in LOCAL_HOST_KEYS:
            self._add_host(text, own=False, local_only=True)
        if key in USER_KEYS or (key == "name" and parent in ACCOUNT_NAME_PARENTS):
            self._add_account(text)
        elif key in FULL_NAME_KEYS:
            self._add_account(text, parts=True)
        if _mail_key(key):
            self._learn_account_emails(value)
        self._learn_text(value, numbers_only)

    def _learn_text(self, value: str, numbers_only: bool) -> None:
        decoded = unquote(value) if "%" in value else value
        for text in dict.fromkeys((value, decoded)):
            self._learn_paths(text)
            for match in LABEL.finditer(text):
                escaped = "\\t" in match.group(2)
                found = (ESCAPED_LABEL_VALUE if escaped else LABEL_VALUE).match(text, match.end())
                if found is not None:
                    self._learn_label(match.group(1), found.group(0))
            for match in EMAIL.finditer(text):
                self._add_email(match.group(0))
            for match in DOMAIN_ACCOUNT.finditer(text):
                self._domain_accounts.add((match.group(1), match.group(2)))
            self._learn_addresses(text, numbers_only)

    def _learn_addresses(self, text: str, numbers_only: bool) -> None:
        for regex, placeholder, found, taken in (
            (SID, PLACEHOLDER_SID, self._sids, self._sid_taken),
            (AZURE_SID, PLACEHOLDER_AZURE_SID, self._azure_sids, self._azure_sid_taken),
        ):
            for match in regex.finditer(text):
                parts = _sid_parts(match.group(0))
                (taken if placeholder.fullmatch(parts) else found).add(parts)
        spans: list[tuple[int, int]] = []
        for match in IPV6.finditer(text):
            address = _ipv6(match.group(0))
            if address is None:
                continue
            spans.append(match.span())
            if not _keep_ipv6(address):
                self._ipv6s.add(address.compressed)
        for match in MAC.finditer(text):
            if any(start <= match.start() < end for start, end in spans):
                continue
            mac = _canonical_mac(match.group(0))
            if mac not in KEEP_MACS and not mac.startswith(PLACEHOLDER_MAC_PREFIX):
                self._macs.add(mac)
        if not numbers_only:
            for match in IPV4.finditer(text):
                address = _canonical_ipv4(match.group(0))
                if not _keep_ipv4(address):
                    self._ips.add(address)

    def _learn_paths(self, text: str) -> None:
        for match in PROFILE_FOLDER.finditer(text):
            folder = match.group(1)
            if folder == folder.strip() and not folder.endswith("."):
                self._add_account(folder)
        for match in PROFILE.finditer(text):
            self._add_account(match.group(1).rstrip("."))
        for match in HOME_FOLDER.finditer(text):
            self._add_account(match.group(1))
        for match in UNC.finditer(text):
            lead, host, trail = match.groups()
            if len(lead) == 2 * len(trail):
                self._add_host(host, own=False)
        for match in LONG_UNC.finditer(text):
            self._add_host(match.group(2), own=False)

    def _learn_label(self, label: str, value: str) -> None:
        if LABEL_START.match(value):
            return
        end = LABEL_END.search(value)
        if end is not None:
            value = value[: end.start()]
        value = value.strip()
        if ":" in value:
            value = value.split()[0]
        if label == "Account Name":
            self._add_account(value)
        else:
            self._add_host(value, own=False)

    def _learn_account_emails(self, text: str) -> None:
        for match in EMAIL.finditer(text):
            self._add_user(match.group(0))

    def _learn_domain_accounts(self) -> None:
        hosts = {name.casefold() for name in self._own_hosts | self._other_hosts}
        for domain, name in self._domain_accounts:
            if domain.casefold() in hosts:
                self._add_user(name.rstrip("."))

    def _learn_entity(self, value: dict[Any, Any]) -> None:
        for type_key, value_key in (("entity_type", "value"), ("target_type", "target_value")):
            name = value.get(value_key)
            if not isinstance(name, str):
                continue
            if value.get(type_key) == "host":
                self._add_host(name, own=True)
            elif value.get(type_key) == "account":
                self._add_account(name)

    def _add_host(self, text: str, own: bool, local_only: bool = False) -> None:
        name = text.strip().lstrip("\\").rstrip("$").rstrip(".")
        first, _, rest = name.partition(".")
        local = _local_suffix(rest)
        if not _learnable(name) or (local_only and rest and not local):
            return
        hosts = self._own_hosts if own else self._other_hosts
        hosts.add(name)
        if rest and (own or local) and _learnable(first):
            hosts.add(first)

    def _add_account(self, text: str, parts: bool = False) -> None:
        pieces = [piece for piece in DOMAIN_SEPARATOR.split(text.strip()) if piece] or [""]
        *domains, name = pieces
        for domain in domains:
            self._add_host(domain, own=False)
        if domains and domains[-1].strip().casefold() in SERVICE_DOMAINS:
            return
        self._add_user(name.strip(), parts)

    def _add_user(self, name: str, parts: bool = False) -> None:
        if name.endswith("$"):
            self._add_host(name, own=False)
            return
        local, at, domain = name.rpartition("@")
        if at and local and domain:
            if _learnable(name):
                self._emails.add(name)
            if _learnable(local):
                self._users.add(local)
            return
        if not _learnable(name):
            return
        self._users.add(name)
        if parts:
            for part in NAME_PARTS.split(name):
                if part != name and _learnable(part):
                    self._users.add(part)

    def _add_email(self, address: str) -> None:
        if _learnable(address):
            self._emails.add(address)

    def _build(self) -> None:
        if (
            len(self._ips) > MAX_IPS
            or len(self._macs) > MAX_MACS
            or len(self._sids) + len(self._sid_taken) > MAX_SIDS
            or len(self._azure_sids) + len(self._azure_sid_taken) > MAX_SIDS
        ):
            raise ValueError("Too many distinct addresses to give each a placeholder.")
        own = _groups(self._own_hosts)
        other = {key: names for key, names in _groups(self._other_hosts).items() if key not in own}
        hosts = {**own, **other}
        aliases = {key: target for key in hosts if (target := self._alias(key, hosts))}
        numbered = sorted((key for key in own if key not in aliases), key=str.upper)
        numbered += sorted((key for key in other if key not in aliases), key=str.upper)
        placeholders: dict[str, str] = {}
        first_number = 1 if any(key in own for key in numbered) else 2
        for offset, key in enumerate(numbered):
            number = first_number + offset
            placeholders[key] = "MY-PC" if number == 1 else f"HOST-{number}"
        for key in aliases:
            target = aliases[key]
            while target in aliases:
                target = aliases[target]
            placeholders[key] = placeholders[target]
        mapping = {key.upper(): placeholders[key] for key in hosts}
        users = {key: names for key, names in _groups(self._users).items() if key not in hosts}
        emails = _groups(self._emails)
        for key in emails:
            local = key.rpartition("@")[0]
            if local in placeholders or local in users:
                continue
            users.setdefault(key, set())
        for index, key in enumerate(sorted(users)):
            placeholders[key] = f"user{index + 1}"
        for key in emails:
            placeholders.setdefault(key, placeholders.get(key.rpartition("@")[0], ""))
        mapping.update({key: placeholders[key] for key in {**users, **emails}})
        self._ip_map = {
            ip: f"{PLACEHOLDER_IP_PREFIX}{index + 1}"
            for index, ip in enumerate(sorted(self._ips, key=_ipv4_order))
        }
        self._ipv6_map = {
            address: f"2001:db8::{index + 1:x}"
            for index, address in enumerate(
                sorted(self._ipv6s, key=lambda text: int(ipaddress.IPv6Address(text)))
            )
        }
        self._mac_map = {
            mac: f"{PLACEHOLDER_MAC_PREFIX.lower()}{index + 1:02x}"
            for index, mac in enumerate(sorted(self._macs))
        }
        self._agent_map = {
            agent: f"{index + 1:03d}" for index, agent in enumerate(sorted(self._agents))
        }
        self._sid_map = _number_sids(self._sids, self._sid_taken, SID_BASE)
        self._azure_sid_map = _number_sids(self._azure_sids, self._azure_sid_taken, AZURE_SID_BASE)
        mapping.update(self._ip_map)
        mapping.update(self._ipv6_map)
        mapping.update(self._mac_map)
        mapping.update(self._agent_map)
        for prefix, sids in ((SID_PREFIX, self._sid_map), (AZURE_SID_PREFIX, self._azure_sid_map)):
            mapping.update({prefix + parts: prefix + new for parts, new in sids.items()})
        self.mapping = mapping
        ordered = [(key, group[key]) for group in (hosts, users, emails) for key in sorted(group)]
        alternatives: dict[str, str] = {}
        for key, names in ordered:
            for form in {key} | {name.lower() for name in names}:
                alternatives.setdefault(form, placeholders[key])
        for key, names in ordered:
            for form in _forms(key, names):
                alternatives.setdefault(form, placeholders[key])
        words = sorted(alternatives, key=lambda word: (-len(word), word))
        self._group_placeholders = {
            f"n{index}": alternatives[word] for index, word in enumerate(words)
        }
        if words:
            body = "|".join(f"(?P<n{index}>{re.escape(word)})" for index, word in enumerate(words))
            self._pattern = re.compile(rf"{_NAME_START}(?:{body})(?![^\W_])", re.IGNORECASE)
        else:
            self._pattern = None

    @staticmethod
    def _alias(key: str, hosts: dict[str, set[str]]) -> str | None:
        first = key.partition(".")[0]
        if first != key and first in hosts:
            return first
        if len(key) == NETBIOS_LENGTH and "." not in key:
            longer = sorted(
                other
                for other in hosts
                if len(other) > NETBIOS_LENGTH and "." not in other and other.startswith(key)
            )
            if longer:
                return longer[0]
        return None

    def _name_placeholder(self, match: re.Match[str]) -> str:
        return self._group_placeholders[match.lastgroup or ""]

    def _mac_placeholder(self, match: re.Match[str]) -> str:
        return self._mac_map.get(_canonical_mac(match.group(0)), match.group(0))

    def _ipv4_placeholder(self, match: re.Match[str]) -> str:
        return self._ip_map.get(_canonical_ipv4(match.group(0)), match.group(0))

    def _ipv6_placeholder(self, match: re.Match[str]) -> str:
        address = _ipv6(match.group(0))
        if address is None:
            return match.group(0)
        return self._ipv6_map.get(address.compressed, match.group(0))

    def _sid_placeholder(self, match: re.Match[str]) -> str:
        parts = _renumber_sid(match.group(0), self._sid_map, PLACEHOLDER_SID, SID_BASE)
        return SID_PREFIX + parts

    def _azure_sid_placeholder(self, match: re.Match[str]) -> str:
        known = self._azure_sid_map
        parts = _renumber_sid(match.group(0), known, PLACEHOLDER_AZURE_SID, AZURE_SID_BASE)
        return AZURE_SID_PREFIX + parts

    def _replace(self, text: str, addresses: bool) -> str:
        text = SID.sub(self._sid_placeholder, text)
        text = AZURE_SID.sub(self._azure_sid_placeholder, text)
        if self._ipv6_map:
            text = IPV6.sub(self._ipv6_placeholder, text)
        if self._mac_map:
            text = MAC.sub(self._mac_placeholder, text)
        if self._ip_map and addresses:
            text = IPV4.sub(self._ipv4_placeholder, text)
        if self._pattern is not None:
            text = self._pattern.sub(self._name_placeholder, text)
        return text


def _strings(doc: Any) -> Iterator[str]:
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(doc, (list, tuple)):
        for value in doc:
            yield from _strings(value)
    elif doc is not None:
        yield str(doc)


def leftovers(doc: Any, terms: list[str]) -> list[str]:
    haystack = "\n".join(_strings(doc)).casefold()
    return [term for term in terms if term.strip() and term.casefold() in haystack]


def forbidden_terms() -> list[str]:
    value = os.environ.get("SENTINEL_FORBIDDEN_TERMS", "")
    return [term.strip() for term in FORBIDDEN_SEPARATOR.split(value) if term.strip()]
