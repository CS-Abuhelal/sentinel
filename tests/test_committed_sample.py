from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterator
from typing import Any

import pytest

from contracts.models import PcSample
from eval.pc_accuracy import load_labels, render, score
from tests.conftest import REPO

SAMPLE = REPO / "lab" / "wazuh" / "sample" / "pc-sample.json"
LABELS = REPO / "lab" / "wazuh" / "sample" / "labels.yml"
ACCURACY = REPO / "docs" / "pc-accuracy.md"

IPV4 = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?!\.?\d)")
MAC = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])"
)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
PROFILE = re.compile(r"(?<![A-Za-z0-9_])Users(?:\\+|/+)([^\\/\s\"'<>|:*?]+)", re.IGNORECASE)
PERSONAL_HOST = re.compile(r"(?<![A-Za-z0-9])(?:DESKTOP|LAPTOP)-[A-Za-z0-9]+", re.IGNORECASE)
SID = re.compile(r"S-1-\d+(?:-\d+)+", re.IGNORECASE)

KEPT_ADDRESSES = {"127.0.0.1", "0.0.0.0"}
PLACEHOLDER_NETWORK = ipaddress.ip_network("203.0.113.0/24")
PLACEHOLDER_MAC_PREFIX = "00:00:5e:00:53:"
PLACEHOLDER_EMAIL_DOMAIN = "example.com"
PLACEHOLDER_USER = re.compile(r"user\d+")
SHARED_PROFILES = {"public", "default", "all"}
PLACEHOLDER_SID = re.compile(
    r"S-1-5-21-1000000\d{3}-1000000\d{3}-1000000\d{3}-\d+"
    r"|S-1-12-1-1000000\d{3}-1000000\d{3}-1000000\d{3}-1000000\d{3}"
)
WELL_KNOWN_SID = re.compile(r"S-1-\d+(?:-\d+){1,3}", re.IGNORECASE)


def _texts(doc: Any) -> Iterator[str]:
    if isinstance(doc, dict):
        for key, value in doc.items():
            yield str(key)
            yield from _texts(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _texts(value)
    elif isinstance(doc, str):
        yield doc


def _versions(doc: Any) -> Iterator[str]:
    if isinstance(doc, dict):
        for key, value in doc.items():
            if "version" in str(key).lower() and isinstance(value, str):
                yield value
            yield from _versions(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _versions(value)


def _stray_address(text: str, versions: set[str]) -> list[str]:
    stray = []
    for found in IPV4.findall(text):
        try:
            address = ipaddress.ip_address(found)
        except ValueError:
            continue
        if found in KEPT_ADDRESSES or found in versions or address in PLACEHOLDER_NETWORK:
            continue
        stray.append(found)
    return stray


def shape_problems(texts: list[str], versions: set[str]) -> list[str]:
    problems: list[str] = []
    for text in texts:
        problems += [f"IPv4 address {found}" for found in _stray_address(text, versions)]
        for mac in MAC.finditer(text):
            if not mac.group(0).replace("-", ":").lower().startswith(PLACEHOLDER_MAC_PREFIX):
                problems.append(f"MAC address {mac.group(0)}")
        for email in EMAIL.finditer(text):
            if email.group(1).lower() != PLACEHOLDER_EMAIL_DOMAIN:
                problems.append(f"email address {email.group(0)}")
        for profile in PROFILE.finditer(text):
            name = profile.group(1).lower()
            if not PLACEHOLDER_USER.fullmatch(name) and name not in SHARED_PROFILES:
                problems.append(f"profile path {profile.group(0)}")
        problems += [f"personal host name {found}" for found in PERSONAL_HOST.findall(text)]
        for sid in SID.findall(text):
            if not PLACEHOLDER_SID.fullmatch(sid) and not WELL_KNOWN_SID.fullmatch(sid):
                problems.append(f"SID {sid}")
    return problems


def test_the_scan_accepts_placeholders_and_well_known_values() -> None:
    texts = [
        "127.0.0.1 and 0.0.0.0 and 203.0.113.7",
        "installed 2.10.91.91 next to 5.1.2.3.4",
        "00:00:5e:00:53:2a and 00-00-5E-00-53-01",
        "user1@example.com",
        r"C:\Users\user12\x.ps1 and C:\\Users\\Public\\x and /Users/user3/x",
        "S-1-0-0 S-1-5-18 S-1-5-32-544",
        "S-1-5-21-1000000000-1000000000-1000000000-1001",
        "S-1-12-1-1000000000-1000000000-1000000000-1000000000",
        "my-pc and HKEY_USERS and pkg@latest and tool@1.2.3",
    ]
    assert shape_problems(texts, {"2.10.91.91"}) == []


@pytest.mark.parametrize(
    ("text", "problem"),
    [
        ("from 192.168.1.20 to x", "IPv4 address 192.168.1.20"),
        ("from 203.0.114.1", "IPv4 address 203.0.114.1"),
        ("seen 3.14.150.0 here", "IPv4 address 3.14.150.0"),
        ("aa:bb:cc:dd:ee:ff", "MAC address aa:bb:cc:dd:ee:ff"),
        ("AA-BB-CC-DD-EE-FF", "MAC address AA-BB-CC-DD-EE-FF"),
        ("jane.doe@gmail.com", "email address jane.doe@gmail.com"),
        (r"C:\Users\jane.doe\x", r"profile path Users\jane.doe"),
        (r"C:\\Users\\jane.doe\\x", r"profile path Users\\jane.doe"),
        ("/Users/jane/x", "profile path Users/jane"),
        ("DESKTOP-9QXZ7", "personal host name DESKTOP-9QXZ7"),
        ("laptop-abc12", "personal host name laptop-abc12"),
        ("S-1-5-21-111-222-333-1001", "SID S-1-5-21-111-222-333-1001"),
        ("S-1-12-1-1-2-3-4", "SID S-1-12-1-1-2-3-4"),
    ],
)
def test_the_scan_finds_what_it_is_for(text: str, problem: str) -> None:
    assert shape_problems([text], set()) == [problem]


needs_sample = pytest.mark.skipif(not SAMPLE.exists(), reason="no committed sample")


@needs_sample
def test_the_committed_sample_is_a_valid_pc_sample() -> None:
    sample = PcSample.model_validate_json(SAMPLE.read_text(encoding="utf-8"))
    assert sample.runs
    assert sample.assessment is not None


@needs_sample
def test_the_committed_accuracy_report_is_what_the_sample_and_labels_give() -> None:
    sample = PcSample.model_validate_json(SAMPLE.read_text(encoding="utf-8"))
    report = score(sample, load_labels(LABELS))
    assert report.unused_labels == []
    assert ACCURACY.read_bytes() == render(report).encode("utf-8")


@needs_sample
def test_the_committed_sample_has_no_real_looking_identifiers() -> None:
    data = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert shape_problems(list(_texts(data)), set(_versions(data))) == []
