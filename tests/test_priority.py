from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from contracts.models import Finding, FindingKind, Severity
from policy.priority import band, base_score, prioritize, sort_key

T0 = datetime(2026, 9, 28, tzinfo=UTC)


def _vuln(cvss: float | None = None, severity: Severity = Severity.LOW, days: int = 0) -> Finding:
    return Finding(
        kind=FindingKind.VULNERABILITY,
        key=f"cve:CVE-2026-1:{cvss}:{severity}:{days}",
        host="my-pc",
        title="CVE-2026-1 in example 1.0",
        severity=severity,
        priority=0,
        cve="CVE-2026-1",
        package="example",
        cvss=cvss,
        first_seen=T0 - timedelta(days=days),
        last_seen=T0,
    )


def _check(title: str, days: int = 0, compliance: dict | None = None) -> Finding:
    raw = {"data": {"sca": {"check": {"compliance": compliance or {}}}}}
    return Finding(
        kind=FindingKind.CONFIGURATION,
        key=f"sca:p:{title}:{days}",
        host="my-pc",
        title=title,
        severity=Severity.MEDIUM,
        priority=0,
        first_seen=T0 - timedelta(days=days),
        last_seen=T0,
        raw=raw,
    )


@pytest.mark.parametrize(
    ("finding", "expected"),
    [
        (_vuln(cvss=9.6), 96),
        (_vuln(cvss=6.54), 65),
        (_vuln(severity=Severity.CRITICAL), 90),
        (_vuln(severity=Severity.HIGH), 70),
        (_vuln(severity=Severity.MEDIUM), 45),
        (_vuln(severity=Severity.LOW), 20),
        (_check("Ensure 'Windows Firewall: Public: Firewall state' is set to 'On'."), 70),
        (_check("Ensure Microsoft Defender Antivirus real-time protection is on."), 70),
        (_check("Ensure 'Minimum password length' is set to '14 or more'."), 60),
        (_check("Ensure 'Allow users to connect remotely by using Remote Desktop Services'."), 60),
        (_check("Ensure 'Audit Logon' is set to 'Success and Failure'."), 55),
        (_check("Ensure 'Enable Font Providers' is set to 'Disabled'."), 35),
        (_check("Ensure 'X' is set.", compliance={"note": "SMB signing"}), 60),
        (_check("Ensure 'Windows Firewall: Domain: Display a notification' is 'No'."), 35),
        (_check("Ensure 'Configure Microsoft Defender Antivirus notifications' is set."), 35),
        (_check("Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is 'Yes'."), 55),
        (_check("Ensure 'Microsoft Defender: Turn on logging' is 'Enabled'."), 55),
        (_check("Ensure 'Interactive logon: Machine account lockout threshold' is set."), 60),
    ],
)
def test_base_score(finding: Finding, expected: int) -> None:
    assert base_score(finding) == expected


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (100, Severity.CRITICAL),
        (80, Severity.CRITICAL),
        (79, Severity.HIGH),
        (60, Severity.HIGH),
        (40, Severity.MEDIUM),
        (20, Severity.LOW),
        (19, Severity.INFO),
    ],
)
def test_band(score: int, severity: Severity) -> None:
    assert band(score) is severity


def test_prioritize_adds_the_related_bonus_and_caps() -> None:
    plain = prioritize(_vuln(cvss=6.5), 0)
    related = prioritize(_vuln(cvss=6.5), 3)
    capped = prioritize(_vuln(cvss=9.6), 1)
    assert (plain.priority, plain.severity, plain.related_alert_count) == (65, Severity.HIGH, 0)
    assert (related.priority, related.related_alert_count) == (75, 3)
    assert (capped.priority, capped.severity) == (100, Severity.CRITICAL)


def test_sort_key_orders_by_priority_then_kind_then_age() -> None:
    vuln = prioritize(_vuln(severity=Severity.HIGH, days=1), 0)
    check_old = prioritize(_check("Ensure the firewall is on.", days=9), 0)
    check_new = prioritize(_check("Ensure the firewall logs.", days=2), 0)
    top = prioritize(_vuln(cvss=9.0, days=0), 0)
    ordered = sorted([check_new, vuln, check_old, top], key=sort_key)
    assert ordered == [top, vuln, check_old, check_new]


def test_sort_key_breaks_full_ties_by_key() -> None:
    first = _check("Ensure the firewall is on.").model_copy(update={"key": "sca:p:a"})
    second = first.model_copy(update={"key": "sca:p:b"})
    assert sorted([second, first], key=sort_key) == [first, second]
    assert sort_key(first)[-1] == "sca:p:a"
