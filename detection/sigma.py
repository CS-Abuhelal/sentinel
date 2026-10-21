from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from contracts.models import Alert, Event, Severity, TelemetrySource


class RuleError(ValueError):
    pass


FIELDS: dict[str, Callable[[Event], Any]] = {
    "event_type": lambda e: e.event_type,
    "outcome": lambda e: e.outcome,
    "host": lambda e: e.host,
    "user": lambda e: e.user,
    "category": lambda e: e.category.value,
    "src_ip": lambda e: e.network.src_ip if e.network else None,
    "dst_port": lambda e: e.network.dst_port if e.network else None,
}

LOGSOURCES = {("linux", "auth"): TelemetrySource.LINUX_AUTH}

LEVELS = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

_METADATA_KEYS = frozenset(
    {
        "title",
        "id",
        "name",
        "status",
        "description",
        "author",
        "date",
        "modified",
        "references",
        "falsepositives",
        "level",
        "tags",
    }
)
_BASE_KEYS = _METADATA_KEYS | {"logsource", "detection"}
_CORRELATION_KEYS = _METADATA_KEYS | {"correlation"}
_CORRELATION_BODY_KEYS = frozenset({"type", "rules", "group-by", "timespan", "condition"})
_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_TIMESPAN_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


@dataclass(frozen=True)
class BaseRule:
    id: str
    name: str
    title: str
    level: Severity
    tags: tuple[str, ...]
    source: TelemetrySource
    selection: dict[str, tuple[str, ...]]

    def matches(self, event: Event) -> bool:
        if event.source is not self.source:
            return False
        return all(_value(event, name) in allowed for name, allowed in self.selection.items())


@dataclass(frozen=True)
class CorrelationRule:
    id: str
    title: str
    level: Severity
    tags: tuple[str, ...]
    rule_names: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan: timedelta
    timespan_text: str
    gte: int


@dataclass(frozen=True)
class RuleSet:
    base: dict[str, BaseRule]
    correlations: tuple[CorrelationRule, ...]


def load_rules(directory: Path) -> RuleSet:
    base: dict[str, BaseRule] = {}
    correlations: list[CorrelationRule] = []
    for path in sorted(directory.glob("*.yml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise RuleError("a rule file must hold one mapping")
            if "correlation" in document:
                correlations.append(_correlation_rule(document))
            else:
                rule = _base_rule(document)
                if rule.name in base:
                    raise RuleError(f"duplicate rule name {rule.name!r}")
                base[rule.name] = rule
        except (RuleError, yaml.YAMLError) as exc:
            raise RuleError(f"{path.name}: {exc}") from None
    for correlation in correlations:
        for name in correlation.rule_names:
            if name not in base:
                raise RuleError(f"{correlation.title}: references unknown rule {name!r}")
    return RuleSet(base=base, correlations=tuple(correlations))


def detect(events: list[Event], rules: RuleSet, case_id: str | None = None) -> list[Alert]:
    referenced = {name for c in rules.correlations for name in c.rule_names}
    alerts = []
    for rule in rules.base.values():
        if rule.name not in referenced:
            alerts.extend(_single_event_alert(rule, e, case_id) for e in events if rule.matches(e))
    for correlation in rules.correlations:
        alerts.extend(_event_count(correlation, rules, events, case_id))
    return sorted(alerts, key=lambda a: a.timestamp)


def _event_count(
    correlation: CorrelationRule, rules: RuleSet, events: list[Event], case_id: str | None
) -> Iterator[Alert]:
    base = [rules.base[name] for name in correlation.rule_names]
    groups: dict[tuple[str | None, ...], list[Event]] = defaultdict(list)
    for event in events:
        if any(rule.matches(event) for rule in base):
            key = tuple(_value(event, name) for name in correlation.group_by)
            groups[key].append(event)
    for key, group in groups.items():
        group.sort(key=lambda e: e.timestamp)
        start = 0
        while start < len(group):
            end = start
            while end < len(group) and group[end].timestamp - group[start].timestamp <= (
                correlation.timespan
            ):
                end += 1
            window = group[start:end]
            if len(window) >= correlation.gte:
                yield _correlation_alert(
                    correlation, dict(zip(correlation.group_by, key, strict=True)), window, case_id
                )
                start = end
            else:
                start += 1


def _correlation_alert(
    correlation: CorrelationRule,
    values: dict[str, str | None],
    window: list[Event],
    case_id: str | None,
) -> Alert:
    first = window[0]
    grouping = ", ".join(f"{name}={value}" for name, value in values.items())
    return Alert(
        rule_id=correlation.id,
        rule_name=correlation.title,
        rule_severity=correlation.level,
        timestamp=window[-1].timestamp,
        host=values.get("host") or first.host,
        user=values["user"] if "user" in values else first.user,
        src_ip=values["src_ip"] if "src_ip" in values else _value(first, "src_ip"),
        description=(
            f"{correlation.title}: {len(window)} matching events for {grouping} "
            f"within {correlation.timespan_text}"
        ),
        event_ids=[e.event_id for e in window],
        suggested_techniques=_techniques(correlation.tags),
        case_id=case_id,
    )


def _single_event_alert(rule: BaseRule, event: Event, case_id: str | None) -> Alert:
    return Alert(
        rule_id=rule.id,
        rule_name=rule.title,
        rule_severity=rule.level,
        timestamp=event.timestamp,
        host=event.host,
        user=event.user,
        src_ip=_value(event, "src_ip"),
        description=f"{rule.title}: {event.message or event.event_type}",
        event_ids=[event.event_id],
        suggested_techniques=_techniques(rule.tags),
        case_id=case_id,
    )


def _base_rule(document: dict[str, Any]) -> BaseRule:
    _check_keys(document, _BASE_KEYS, "rule")
    logsource = document.get("logsource")
    if not isinstance(logsource, dict) or set(logsource) - {"product", "service"}:
        raise RuleError(f"unsupported logsource {logsource!r}")
    source = LOGSOURCES.get((logsource.get("product"), logsource.get("service")))
    if source is None:
        raise RuleError(f"unsupported logsource {logsource!r}")
    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("missing detection")
    condition = detection.get("condition")
    selections = {k: v for k, v in detection.items() if k != "condition"}
    if len(selections) != 1 or condition not in selections:
        raise RuleError("the condition must name the single selection")
    selection = selections[condition]
    if not isinstance(selection, dict) or not selection:
        raise RuleError("a selection must be a non-empty mapping")
    parsed = {}
    for name, value in selection.items():
        if name not in FIELDS:
            raise RuleError(f"unsupported field or modifier {name!r}")
        values = value if isinstance(value, list) else [value]
        if not values or any(v is None or isinstance(v, dict | list) for v in values):
            raise RuleError(f"unsupported value for {name!r}")
        parsed[name] = tuple(str(v) for v in values)
    rule_id = _text(document, "id")
    return BaseRule(
        id=rule_id,
        name=document.get("name", rule_id),
        title=_text(document, "title"),
        level=_level(document),
        tags=_tags(document),
        source=source,
        selection=parsed,
    )


def _correlation_rule(document: dict[str, Any]) -> CorrelationRule:
    _check_keys(document, _CORRELATION_KEYS, "correlation rule")
    body = document["correlation"]
    if not isinstance(body, dict):
        raise RuleError("correlation must be a mapping")
    _check_keys(body, _CORRELATION_BODY_KEYS, "correlation")
    if body.get("type") != "event_count":
        raise RuleError(f"unsupported correlation type {body.get('type')!r}")
    rule_names = body.get("rules")
    if not isinstance(rule_names, list) or not rule_names:
        raise RuleError("correlation rules must be a non-empty list")
    group_by = body.get("group-by", [])
    if not isinstance(group_by, list) or any(name not in FIELDS for name in group_by):
        raise RuleError(f"unsupported group-by {group_by!r}")
    timespan_text = str(body.get("timespan"))
    match = _TIMESPAN.match(timespan_text)
    if match is None:
        raise RuleError(f"unsupported timespan {timespan_text!r}")
    condition = body.get("condition")
    if (
        not isinstance(condition, dict)
        or set(condition) != {"gte"}
        or not isinstance(condition["gte"], int)
        or condition["gte"] < 1
    ):
        raise RuleError(f"unsupported condition {condition!r}")
    return CorrelationRule(
        id=_text(document, "id"),
        title=_text(document, "title"),
        level=_level(document),
        tags=_tags(document),
        rule_names=tuple(str(name) for name in rule_names),
        group_by=tuple(group_by),
        timespan=timedelta(**{_TIMESPAN_UNITS[match[2]]: int(match[1])}),
        timespan_text=timespan_text,
        gte=condition["gte"],
    )


def _check_keys(mapping: dict[str, Any], allowed: frozenset[str], what: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise RuleError(f"unsupported {what} keys {sorted(unknown)}")


def _text(document: dict[str, Any], key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise RuleError(f"missing {key}")
    return value


def _level(document: dict[str, Any]) -> Severity:
    level = document.get("level")
    if level not in LEVELS:
        raise RuleError(f"unsupported level {level!r}")
    return LEVELS[level]


def _tags(document: dict[str, Any]) -> tuple[str, ...]:
    tags = document.get("tags", [])
    if not isinstance(tags, list):
        raise RuleError("tags must be a list")
    return tuple(str(tag) for tag in tags)


def _techniques(tags: tuple[str, ...]) -> list[str]:
    return [m[1].upper() for tag in tags if (m := _TECHNIQUE_TAG.match(tag))]


def _value(event: Event, name: str) -> str | None:
    value = FIELDS[name](event)
    return None if value is None else str(value)
