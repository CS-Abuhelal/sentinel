from __future__ import annotations

import copy
from datetime import UTC, datetime

import pytest

from contracts.models import FindingKind, Severity
from ingest.wazuh_findings import (
    MAX_REFERENCES,
    MAX_TEXT,
    FindingError,
    sca_check_key,
    sca_finding,
    vulnerability_finding,
)
from tests.conftest import wazuh_payload

NOW = datetime(2026, 9, 28, 12, 0, tzinfo=UTC)


def test_vulnerability_state_becomes_a_finding() -> None:
    finding = vulnerability_finding(wazuh_payload("vulnerability_state"), NOW)
    assert finding.kind is FindingKind.VULNERABILITY
    assert finding.key == "cve:CVE-2026-81376:Microsoft Visual Studio Code (User)"
    assert finding.host == "my-pc"
    assert finding.title == "CVE-2026-81376 in Microsoft Visual Studio Code (User) 1.106.3"
    assert (finding.cve, finding.package, finding.installed_version) == (
        "CVE-2026-81376",
        "Microsoft Visual Studio Code (User)",
        "1.106.3",
    )
    assert finding.cvss == 9.6
    assert finding.severity is Severity.CRITICAL
    assert finding.priority == 0
    assert finding.official_remediation == "Package less than 1.136.2"
    assert finding.references == [
        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-81376"
    ]
    assert finding.first_seen == datetime(2026, 9, 27, 23, 18, 33, 497000, tzinfo=UTC)
    assert finding.last_seen == NOW
    assert finding.rationale is not None and finding.rationale.startswith("Incomplete comparison")


def test_vulnerability_without_package_is_rejected() -> None:
    doc = wazuh_payload("vulnerability_state")
    del doc["package"]
    with pytest.raises(FindingError):
        vulnerability_finding(doc, NOW)


def test_vulnerability_with_odd_fields_still_converts() -> None:
    doc = wazuh_payload("vulnerability_state")
    doc["vulnerability"]["score"] = {"base": "high"}
    doc["vulnerability"]["severity"] = "Unknown"
    doc["vulnerability"]["detected_at"] = "not a time"
    doc["vulnerability"]["description"] = "x" * (MAX_TEXT + 50)
    doc["vulnerability"]["reference"] = ", ".join(f"https://e.test/{n}" for n in range(15))
    finding = vulnerability_finding(doc, NOW)
    assert finding.cvss is None
    assert finding.severity is Severity.LOW
    assert finding.first_seen == NOW
    assert finding.rationale is not None and len(finding.rationale) == MAX_TEXT
    assert len(finding.references) == MAX_REFERENCES


def test_failed_check_becomes_a_finding() -> None:
    alert = wazuh_payload("sca_check_failed")
    finding = sca_finding(alert, NOW)
    assert finding is not None
    assert finding.kind is FindingKind.CONFIGURATION
    policy = "CIS Microsoft Windows 11 Enterprise Benchmark v3.0.0"
    assert finding.key == f"sca:{policy}:26138"
    assert (finding.policy_id, finding.check_id) == (policy, "26138")
    assert finding.title.startswith("Ensure 'Windows Firewall: Public: Logging")
    assert finding.official_remediation is not None
    assert finding.official_remediation.startswith("To establish the recommended configuration")
    assert finding.rationale is not None and finding.rationale.startswith("If events are not")
    assert finding.first_seen == datetime(2026, 9, 27, 23, 17, 30, 577000, tzinfo=UTC)
    assert sca_check_key(alert) == ("my-pc", policy, "26138")


def test_passed_check_is_not_a_finding() -> None:
    alert = wazuh_payload("sca_check_passed")
    assert sca_finding(alert, NOW) is None
    assert sca_check_key(alert)[2] == "26481"


def test_check_references_are_split() -> None:
    alert = copy.deepcopy(wazuh_payload("sca_check_failed"))
    alert["data"]["sca"]["check"]["references"] = "https://a.test/1, https://a.test/2"
    finding = sca_finding(alert, NOW)
    assert finding is not None
    assert finding.references == ["https://a.test/1", "https://a.test/2"]


@pytest.mark.parametrize("path", [("data", "sca"), ("agent",), ("data", "sca", "check")])
def test_malformed_checks_are_rejected(path: tuple[str, ...]) -> None:
    alert = copy.deepcopy(wazuh_payload("sca_check_failed"))
    target = alert
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    with pytest.raises(FindingError):
        sca_finding(alert, NOW)
    with pytest.raises(FindingError):
        sca_check_key(alert)
