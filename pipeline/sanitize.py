from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Iterator
from typing import Any

OWN_HOST_KEYS = frozenset({"host", "agent_name", "computer"})
OTHER_HOST_KEYS = frozenset({"workstationName", "hostname", "hostName"})
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
    }
)
KEEP_LOWER = frozenset(value.lower() for value in KEEP)
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
    }
)
MIN_NAME_LENGTH = 3
PLACEHOLDER = re.compile(r"^(user\d+|HOST-\d+|MY-PC)\$?$", re.IGNORECASE)
BUILTIN_ACCOUNT = re.compile(r"^(DWM|UMFD)-\d+$", re.IGNORECASE)
PROFILE = re.compile(
    r"(?i)[A-Z]:(?:\\+|/)Users(?:\\+|/)"
    r"(All Users|Default User|[^\\/\s\x22\x27<>|:*?%,;(){}\[\]]+)"
)
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|0?[1-9]\d|0{0,2}\d)"
IPV4 = re.compile(rf"(?<!\d)(?<!\d\.){_OCTET}(?:\.{_OCTET}){{3}}(?!\d)(?!\.\d)")
IPV6 = re.compile(
    r"(?:(?<![\w.])|(?<=\\[nrt]))(?=[0-9A-Fa-f]|::)"
    r"[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_-]+)?(?![\w:])(?!\.\d)"
)
MAC = re.compile(
    r"(?i)(?<![0-9a-f])(?<![0-9a-f][:-])[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}"
    r"(?![0-9a-f])(?![:-][0-9a-f])"
)
SID = re.compile(r"(?i)S-1-5-21-\d+-\d+-\d+")
SID_PLACEHOLDER = "S-1-5-21-1000000000-1000000000-1000000000"
DOMAIN_SEPARATOR = re.compile(r"\\+")
NUMBERS_ONLY_KEYS = frozenset(
    {"compliance", "pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "gpg13"}
)
KEEP_MACS = frozenset({"00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"})
PLACEHOLDER_MAC_PREFIX = "00:00:5E:00:53:"
PLACEHOLDER_IP_PREFIX = "203.0.113."
PLACEHOLDER_IPV6_NETWORK = ipaddress.IPv6Network("2001:db8::/32")
MAX_IPS = 254
MAX_MACS = 255


def _numbers_only_key(key: str | None) -> bool:
    return key in NUMBERS_ONLY_KEYS or "version" in (key or "").lower()


def _canonical_ipv4(text: str) -> str:
    return ".".join(str(int(part)) for part in text.split("."))


def _keep_ipv4(address: str) -> bool:
    first = int(address.split(".")[0])
    return (
        address == "0.0.0.0"
        or first in {127, 255}
        or 224 <= first <= 239
        or address.startswith(PLACEHOLDER_IP_PREFIX)
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


def _is_address(text: str) -> bool:
    return bool(IPV4.fullmatch(text)) or _ipv6(text.strip("[]")) is not None


def _canonical_mac(text: str) -> str:
    return text.upper().replace("-", ":")


def _learnable(name: str) -> bool:
    lowered = name.lower()
    return (
        len(name) >= MIN_NAME_LENGTH
        and not name.isdigit()
        and lowered not in KEEP_LOWER
        and lowered not in GENERIC
        and not PLACEHOLDER.match(name)
        and not BUILTIN_ACCOUNT.match(name)
        and not _is_address(name)
    )


class Sanitizer:
    def __init__(self) -> None:
        self._own_hosts: set[str] = set()
        self._other_hosts: set[str] = set()
        self._users: set[str] = set()
        self._agents: set[str] = set()
        self._ips: set[str] = set()
        self._ipv6s: set[str] = set()
        self._macs: set[str] = set()
        self.mapping: dict[str, str] = {}
        self._names: dict[str, str] = {}
        self._ip_map: dict[str, str] = {}
        self._ipv6_map: dict[str, str] = {}
        self._mac_map: dict[str, str] = {}
        self._agent_map: dict[str, str] = {}
        self._pattern: re.Pattern[str] | None = None

    def learn(self, doc: Any) -> None:
        self._walk(doc, None, None, False)
        self._build()

    def apply(self, doc: Any) -> Any:
        return self._apply(doc, None, False)

    def _apply(self, doc: Any, key: str | None, numbers_only: bool) -> Any:
        numbers_only = numbers_only or _numbers_only_key(key)
        if isinstance(doc, dict):
            result: dict[Any, Any] = {}
            for child_key, value in doc.items():
                new_key = child_key
                if isinstance(child_key, str):
                    new_key = self._replace(child_key, True)
                result[new_key] = self._apply(value, str(child_key), numbers_only)
            return result
        if isinstance(doc, (list, tuple)):
            return [self._apply(value, key, numbers_only) for value in doc]
        if isinstance(doc, str):
            return self._replace(doc, not numbers_only)
        return doc

    def _walk(self, value: Any, key: str | None, parent: str | None, numbers_only: bool) -> None:
        numbers_only = numbers_only or _numbers_only_key(key)
        if isinstance(value, dict):
            self._learn_entity(value)
            for child_key, child in value.items():
                self._walk(child, str(child_key), key, numbers_only)
            return
        if isinstance(value, (list, tuple)):
            for child in value:
                self._walk(child, key, parent, numbers_only)
            return
        if not isinstance(value, str):
            return
        text = value.strip()
        if key == "id" and parent == "agent" and text and text != "000":
            self._agents.add(text)
        if key in OWN_HOST_KEYS or (key == "name" and parent == "agent"):
            self._add_host(text, own=True)
        elif key in OTHER_HOST_KEYS:
            self._add_host(text, own=False)
        if key in USER_KEYS:
            self._add_account(text)
        for match in PROFILE.finditer(value):
            self._add_account(match.group(1).rstrip("."))
        if not numbers_only:
            for match in IPV4.finditer(value):
                address = _canonical_ipv4(match.group(0))
                if not _keep_ipv4(address):
                    self._ips.add(address)
        for match in IPV6.finditer(value):
            ipv6 = _ipv6(match.group(0))
            if ipv6 is not None and not _keep_ipv6(ipv6):
                self._ipv6s.add(ipv6.compressed)
        for match in MAC.finditer(value):
            mac = _canonical_mac(match.group(0))
            if mac not in KEEP_MACS and not mac.startswith(PLACEHOLDER_MAC_PREFIX):
                self._macs.add(mac)

    def _learn_entity(self, value: dict[Any, Any]) -> None:
        for type_key, value_key in (("entity_type", "value"), ("target_type", "target_value")):
            name = value.get(value_key)
            if not isinstance(name, str):
                continue
            if value.get(type_key) == "host":
                self._add_host(name, own=True)
            elif value.get(type_key) == "account":
                self._add_account(name)

    def _add_host(self, text: str, own: bool) -> None:
        name = text.strip().rstrip("$")
        if _learnable(name):
            (self._own_hosts if own else self._other_hosts).add(name.upper())

    def _add_account(self, text: str) -> None:
        parts = [part for part in DOMAIN_SEPARATOR.split(text.strip()) if part] or [""]
        *domains, name = parts
        if name.endswith("$"):
            self._add_host(name, own=False)
            return
        if not _learnable(name):
            return
        self._users.add(name.lower())
        for domain in domains:
            self._add_host(domain, own=False)

    def _build(self) -> None:
        if len(self._ips) > MAX_IPS or len(self._macs) > MAX_MACS:
            raise ValueError("Too many distinct addresses to give each a placeholder.")
        mapping: dict[str, str] = {}
        names: dict[str, str] = {}
        hosts = sorted(self._own_hosts) + sorted(self._other_hosts - self._own_hosts)
        first_number = 1 if self._own_hosts else 2
        for offset, host in enumerate(hosts):
            number = first_number + offset
            placeholder = "MY-PC" if number == 1 else f"HOST-{number}"
            mapping[host] = names[host.lower()] = placeholder
        users = sorted(user for user in self._users if user not in names)
        for index, user in enumerate(users):
            mapping[user] = names[user] = f"user{index + 1}"
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
        mapping.update(self._ip_map)
        mapping.update(self._ipv6_map)
        mapping.update(self._mac_map)
        mapping.update(self._agent_map)
        self.mapping = mapping
        self._names = names
        if names:
            words = sorted(names, key=lambda word: (-len(word), word))
            alternatives = "|".join(re.escape(word) for word in words)
            self._pattern = re.compile(
                rf"(?:(?<![^\W_])|(?<=\\[nrt]))(?:{alternatives})(?![^\W_])", re.IGNORECASE
            )
        else:
            self._pattern = None

    def _mac_placeholder(self, match: re.Match[str]) -> str:
        return self._mac_map.get(_canonical_mac(match.group(0)), match.group(0))

    def _ipv4_placeholder(self, match: re.Match[str]) -> str:
        return self._ip_map.get(_canonical_ipv4(match.group(0)), match.group(0))

    def _ipv6_placeholder(self, match: re.Match[str]) -> str:
        address = _ipv6(match.group(0))
        if address is None:
            return match.group(0)
        return self._ipv6_map.get(address.compressed, match.group(0))

    def _replace(self, text: str, addresses: bool) -> str:
        stripped = text.strip()
        if stripped in self._agent_map:
            return text.replace(stripped, self._agent_map[stripped])
        text = SID.sub(SID_PLACEHOLDER, text)
        if self._ipv6_map:
            text = IPV6.sub(self._ipv6_placeholder, text)
        if self._mac_map:
            text = MAC.sub(self._mac_placeholder, text)
        if self._ip_map and addresses:
            text = IPV4.sub(self._ipv4_placeholder, text)
        if self._pattern is not None:
            text = self._pattern.sub(lambda m: self._names[m.group(0).lower()], text)
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
    haystack = "\n".join(_strings(doc)).lower()
    return [term for term in terms if term.strip() and term.lower() in haystack]


def forbidden_terms() -> list[str]:
    value = os.environ.get("SENTINEL_FORBIDDEN_TERMS", "")
    return [term.strip() for term in value.split(",") if term.strip()]
