from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from contracts.models import ActionType, CommandResult, EntityType, Incident

ACCOUNT_NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
HOST_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}")
MANAGEMENT_NETWORK = "10.99.0.0/24"
ISOLATION_TABLE = "sentinel_isolation"


@dataclass(frozen=True)
class Step:
    argv: tuple[str, ...]
    ok: frozenset[int] = field(default_factory=lambda: frozenset({0}))


@dataclass(frozen=True)
class CatalogEntry:
    target_type: EntityType
    pattern: re.Pattern[str]
    commands: Callable[[str], list[Step]]
    checks: Callable[[str], list[list[str]]]
    verified: Callable[[list[CommandResult]], bool]
    hosts: Callable[[str, Incident], list[str]]


def _disable_account_commands(user: str) -> list[Step]:
    return [
        Step(("usermod", "--lock", "--expiredate", "1", user)),
        Step(("pkill", "-KILL", "-u", user), frozenset({0, 1})),
    ]


def _disable_account_checks(user: str) -> list[list[str]]:
    return [["passwd", "--status", user], ["pgrep", "-u", user]]


def _disable_account_verified(results: list[CommandResult]) -> bool:
    status, sessions = results
    fields = status.output.split()
    return (
        status.exit_code == 0 and len(fields) > 1 and fields[1] == "L" and sessions.exit_code == 1
    )


def _incident_hosts(target: str, incident: Incident) -> list[str]:
    return [e.value for e in incident.entities if e.entity_type is EntityType.HOST]


def _isolate_host_commands(host: str) -> list[Step]:
    table = ("nft", "add", "table", "inet", ISOLATION_TABLE)
    chain = ("nft", "add", "chain", "inet", ISOLATION_TABLE)
    rule = ("nft", "add", "rule", "inet", ISOLATION_TABLE)
    return [
        Step(table),
        Step((*chain, "input", "{ type filter hook input priority -10 ; policy drop ; }")),
        Step((*chain, "output", "{ type filter hook output priority -10 ; policy drop ; }")),
        Step((*rule, "input", "iif", "lo", "accept")),
        Step((*rule, "output", "oif", "lo", "accept")),
        Step((*rule, "input", "ip", "saddr", MANAGEMENT_NETWORK, "accept")),
        Step((*rule, "output", "ip", "daddr", MANAGEMENT_NETWORK, "accept")),
    ]


def _isolate_host_checks(host: str) -> list[list[str]]:
    return [["nft", "list", "table", "inet", ISOLATION_TABLE]]


def _isolate_host_verified(results: list[CommandResult]) -> bool:
    [listing] = results
    return listing.exit_code == 0 and listing.output.count("policy drop") >= 2


CATALOG: dict[ActionType, CatalogEntry] = {
    ActionType.DISABLE_ACCOUNT: CatalogEntry(
        target_type=EntityType.ACCOUNT,
        pattern=ACCOUNT_NAME,
        commands=_disable_account_commands,
        checks=_disable_account_checks,
        verified=_disable_account_verified,
        hosts=_incident_hosts,
    ),
    ActionType.ISOLATE_HOST: CatalogEntry(
        target_type=EntityType.HOST,
        pattern=HOST_NAME,
        commands=_isolate_host_commands,
        checks=_isolate_host_checks,
        verified=_isolate_host_verified,
        hosts=lambda target, incident: [target],
    ),
}
