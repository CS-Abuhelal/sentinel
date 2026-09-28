from __future__ import annotations

from datetime import datetime
from typing import Any

from contracts.models import Finding, FindingKind, Severity
from ingest.wazuh import WazuhAlertError, parse_timestamp

MAX_TEXT = 1000
MAX_REFERENCES = 10
SEVERITIES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


class FindingError(ValueError):
    pass


def vulnerability_finding(doc: dict[str, Any], now: datetime) -> Finding:
    agent = _mapping(doc, "agent")
    package = _mapping(doc, "package")
    vulnerability = _mapping(doc, "vulnerability")
    host = _text(agent.get("name"))
    cve = _text(vulnerability.get("id"))
    name = _text(package.get("name"))
    if host is None or cve is None or name is None:
        raise FindingError(
            "A vulnerability needs agent.name, vulnerability.id and package.name."
        )
    version = _text(package.get("version"))
    score = vulnerability.get("score")
    base = score.get("base") if isinstance(score, dict) else None
    scanner = vulnerability.get("scanner")
    condition = _text(scanner.get("condition")) if isinstance(scanner, dict) else None
    severity = str(vulnerability.get("severity") or "").lower()
    return Finding(
        kind=FindingKind.VULNERABILITY,
        key=f"cve:{cve}:{name}",
        host=host,
        title=_clip(f"{cve} in {name} {version}" if version else f"{cve} in {name}"),
        severity=SEVERITIES.get(severity, Severity.LOW),
        priority=0,
        cve=cve,
        package=name,
        installed_version=version,
        cvss=_cvss(base),
        rationale=_clip(_text(vulnerability.get("description"))),
        official_remediation=_clip(condition),
        references=_references(vulnerability.get("reference")),
        first_seen=_time(vulnerability.get("detected_at"), now),
        last_seen=now,
        raw=doc,
    )


def sca_check_key(alert: dict[str, Any]) -> tuple[str, str, str]:
    host, policy, check = _sca_parts(alert)
    check_id = _text(check.get("id"))
    if check_id is None:
        raise FindingError("An SCA check alert needs data.sca.check.id.")
    return host, policy, check_id


def sca_finding(alert: dict[str, Any], now: datetime) -> Finding | None:
    host, policy, check_id = sca_check_key(alert)
    check = _sca_parts(alert)[2]
    if check.get("result") != "failed":
        return None
    title = _clip(_text(check.get("title"))) or f"CIS check {check_id}"
    return Finding(
        kind=FindingKind.CONFIGURATION,
        key=f"sca:{policy}:{check_id}",
        host=host,
        title=title,
        severity=Severity.MEDIUM,
        priority=0,
        policy_id=policy,
        check_id=check_id,
        rationale=_clip(_text(check.get("rationale"))),
        official_remediation=_clip(_text(check.get("remediation"))),
        references=_references(check.get("references")),
        first_seen=_time(alert.get("timestamp"), now),
        last_seen=now,
        raw=alert,
    )


def _sca_parts(alert: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    agent = alert.get("agent")
    host = _text(agent.get("name")) if isinstance(agent, dict) else None
    data = alert.get("data")
    sca = data.get("sca") if isinstance(data, dict) else None
    check = sca.get("check") if isinstance(sca, dict) else None
    policy = _text(sca.get("policy")) if isinstance(sca, dict) else None
    if host is None or policy is None or not isinstance(check, dict):
        raise FindingError(
            "An SCA check alert needs agent.name, data.sca.policy and "
            "data.sca.check."
        )
    return host, policy, check


def _mapping(doc: dict[str, Any], key: str) -> dict[str, Any]:
    value = doc.get(key)
    if not isinstance(value, dict):
        raise FindingError(f"'{key}' must be an object.")
    return value


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if text in {"", "-"} else text


def _clip(text: str | None) -> str | None:
    return None if text is None else text[:MAX_TEXT]


def _cvss(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if 0 <= value <= 10 else None


def _references(value: Any) -> list[str]:
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        items = [str(part).strip() for part in value]
    else:
        items = []
    return [item for item in items if item][:MAX_REFERENCES]


def _time(value: Any, fallback: datetime) -> datetime:
    text = _text(value)
    if text is None:
        return fallback
    try:
        return parse_timestamp(text)
    except WazuhAlertError:
        return fallback
