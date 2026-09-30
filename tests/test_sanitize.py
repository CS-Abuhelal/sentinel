from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pipeline.sanitize import Sanitizer, forbidden_terms, leftovers

DOC = {
    "event": {"host": "DESKTOP-9QXZ7", "user": "jane.doe", "network": {"src_ip": "192.168.1.23"}},
    "raw": {
        "agent": {"id": "007", "name": "my-pc"},
        "data": {
            "win": {
                "system": {"computer": "DESKTOP-9QXZ7"},
                "eventdata": {
                    "subjectUserName": "jane.doe",
                    "targetUserName": "SYSTEM",
                    "workstationName": "DESKTOP-9QXZ7",
                    "processName": r"C:\\Users\\jane.doe\\AppData\\app.exe",
                },
            }
        },
        "full_log": "Login by jane.doe from 192.168.1.23 on DESKTOP-9QXZ7 (mac 3C:52:82:AA:BB:CC)",
        "message": r"C:\Users\Jane.Doe\Documents and C:\Users\Public\x",
    },
    "loopback": "127.0.0.1 and ::1",
    "keep": "sentinel-test-nobody on my-pc",
}

WAZUH_FIXTURES = sorted((Path(__file__).parent / "data" / "wazuh").glob("*.json"))
ROOT = Path(__file__).resolve().parent.parent


def _clean() -> tuple[Sanitizer, object]:
    sanitizer = Sanitizer()
    sanitizer.learn(DOC)
    return sanitizer, sanitizer.apply(DOC)


def _run(doc: object) -> object:
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    return sanitizer.apply(doc)


def test_identifiers_are_replaced_everywhere() -> None:
    _, clean = _clean()
    text = repr(clean)
    secrets = ("DESKTOP-9QXZ7", "jane.doe", "Jane.Doe", "192.168.1.23", "3C:52:82:AA:BB:CC", "007")
    for secret in secrets:
        assert secret.lower() not in text.lower()


def test_placeholders_are_stable_and_sensible() -> None:
    sanitizer, clean = _clean()
    assert clean["event"]["host"] == "MY-PC"
    assert clean["event"]["user"] == "user1"
    assert clean["event"]["network"]["src_ip"] == "203.0.113.1"
    assert clean["raw"]["agent"] == {"id": "001", "name": "my-pc"}
    assert clean["raw"]["data"]["win"]["eventdata"]["targetUserName"] == "SYSTEM"
    eventdata = clean["raw"]["data"]["win"]["eventdata"]
    assert r"\\Users\\user1\\AppData" in eventdata["processName"]
    assert r"C:\Users\user1\Documents" in clean["raw"]["message"]
    assert r"C:\Users\Public\x" in clean["raw"]["message"]
    assert "00:00:5e:00:53:01" in clean["raw"]["full_log"]
    assert clean["loopback"] == "127.0.0.1 and ::1"
    assert clean["keep"] == "sentinel-test-nobody on my-pc"
    again = Sanitizer()
    again.learn(DOC)
    assert again.apply(DOC) == clean
    assert sanitizer.mapping["DESKTOP-9QXZ7"] == "MY-PC"
    assert sanitizer.mapping["jane.doe"] == "user1"


def test_sanitizing_twice_changes_nothing() -> None:
    _, clean = _clean()
    second = Sanitizer()
    second.learn(clean)
    assert second.apply(clean) == clean


@pytest.mark.parametrize(
    "doc",
    [
        {"account": "S-1-5-21-1234567890-987654321-1122334455-1001"},
        {"user": "S-1-12-1-1234567890-1234567890-1234567890-1234567890"},
        {"sourceHostname": "3C5282AABBCC", "m": "seen 3C5282AABBCC"},
        {"hostname": "3C:52:82:AA:BB:CC"},
        {"user": "3c52.82aa.bbcc"},
        {"hostname": "192.168.1.23:445"},
        {"workstationName": "[fe80::1]:3389"},
        {"sourceHostname": "192.168.1.23.nip.io"},
    ],
    ids=["sid", "azure", "bare-mac", "colon-mac", "dotted-mac", "ip-port", "ipv6-port", "ip-dns"],
)
def test_an_address_or_sid_in_a_name_field_is_sanitized_once(doc: dict[str, str]) -> None:
    first = _run(doc)
    assert first != doc
    assert _run(first) == first


@pytest.mark.parametrize("path", WAZUH_FIXTURES, ids=lambda path: path.name)
def test_the_recorded_wazuh_fixtures_are_already_clean(path: Path) -> None:
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert _run(doc) == doc


def test_machine_accounts_map_to_the_host() -> None:
    doc = {"event": {"host": "DESKTOP-9QXZ7"}, "raw": {"user": "DESKTOP-9QXZ7$"}}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc)["raw"]["user"] == "MY-PC$"


def test_leftovers_and_forbidden_terms(monkeypatch: pytest.MonkeyPatch) -> None:
    _, clean = _clean()
    assert leftovers(clean, ["jane", "desktop-9qxz7"]) == []
    assert leftovers(DOC, ["JANE"]) == ["JANE"]
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", " jane , ,DESKTOP ")
    assert forbidden_terms() == ["jane", "DESKTOP"]
    monkeypatch.delenv("SENTINEL_FORBIDDEN_TERMS")
    assert forbidden_terms() == []


def test_forbidden_terms_split_on_commas_semicolons_and_newlines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_FORBIDDEN_TERMS", "jane;doe, DESKTOP-9QXZ7\n,  ;\r\nzulu")
    assert forbidden_terms() == ["jane", "doe", "DESKTOP-9QXZ7", "zulu"]


def test_leftovers_looks_at_keys_numbers_and_ignores_blank_terms() -> None:
    assert leftovers({"jane.doe": 1}, ["jane"]) == ["jane"]
    assert leftovers({"port": 4433, "nested": [{"n": 4433}]}, ["4433"]) == ["4433"]
    assert leftovers({"a": "ja", "b": "ne"}, ["jane"]) == []
    assert leftovers(DOC, ["", "  "]) == []
    assert leftovers({"m": "STRASSE"}, ["straße"]) == ["straße"]


def test_short_user_names_are_never_learned() -> None:
    doc = {
        "event": {"user": "al", "host": "DESKTOP-9QXZ7"},
        "raw": {
            "targetUserName": "ed",
            "message": r"Also a final total by al and ed at C:\Users\al\x and C:\Users\ed\x",
        },
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean["event"] == {"user": "al", "host": "MY-PC"}
    assert clean["raw"] == doc["raw"]
    assert "al" not in sanitizer.mapping
    assert "ed" not in sanitizer.mapping


def test_short_host_names_are_never_learned() -> None:
    doc = {"host": "pc", "message": "the pc is a pc"}
    assert _run(doc) == doc


def test_names_are_learned_only_from_known_fields_and_profile_paths() -> None:
    doc = {
        "event": {"user": "jane.doe"},
        "raw": {"message": "the manager met mallory and the team; jane.doe left"},
    }
    clean = _run(doc)
    assert clean["raw"]["message"] == "the manager met mallory and the team; user1 left"


def test_generic_and_numeric_names_are_not_learned() -> None:
    doc = {
        "event": {"user": "User", "host": "1234"},
        "raw": {"targetUserName": "admin", "message": "Unknown user or bad admin at port 1234"},
    }
    assert _run(doc) == doc


def test_names_are_replaced_as_whole_tokens_only() -> None:
    doc = {"user": "jane", "message": "Janet met jane. Jane's jane2 and xjane, (JANE) and jane_x"}
    clean = _run(doc)
    assert clean["message"] == "Janet met user1. user1's jane2 and xjane, (user1) and user1_x"


def test_a_name_after_a_literal_escape_sequence_is_replaced() -> None:
    doc = {
        "user": "jane.doe",
        "full_log": "Account Name:\\t\\tjane.doe\\r\\nMAC:\\t3C-52-82-AA-BB-CC at\\t192.168.1.23.",
        "escaped": '{"m":"\\u0022jane.doe\\u0022 and \\u0022zed@example.org\\u0022"}',
    }
    clean = _run(doc)
    assert clean["full_log"] == (
        "Account Name:\\t\\tuser1\\r\\nMAC:\\t00:00:5e:00:53:01 at\\t203.0.113.1."
    )
    assert clean["escaped"] == '{"m":"\\u0022user1\\u0022 and \\u0022user2\\u0022"}'


def test_profile_paths_with_any_slash_style_are_learned() -> None:
    doc = {
        "a": r"C:\\Users\\amy.smith\\x",
        "b": "C:/Users/bob.jones/y",
        "c": r"d:\Users\cy.lee\z",
        "d": r"C:\Users\dan.kim. C:\Users\All Users\Microsoft and C:\Users\%USERNAME%\x",
        "e": r"C:\Users\Default User\q and C:\Users\Default\q and C:\Users\Public",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {
        "a": r"C:\\Users\\user1\\x",
        "b": "C:/Users/user2/y",
        "c": r"d:\Users\user3\z",
        "d": r"C:\Users\user4. C:\Users\All Users\Microsoft and C:\Users\%USERNAME%\x",
        "e": r"C:\Users\Default User\q and C:\Users\Default\q and C:\Users\Public",
    }
    assert sorted(sanitizer.mapping) == ["amy.smith", "bob.jones", "cy.lee", "dan.kim"]


def test_a_profile_folder_with_a_space_or_an_apostrophe_is_replaced_whole() -> None:
    doc = {
        "a": r"C:\Users\Jane Doe\AppData\x.exe",
        "b": r"c:\users\jane doe\desktop\notes.txt",
        "c": r"C:\Users\O'Brien\AppData\x",
        "d": r"C:\Users\Doe,Jane\x",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean == {
        "a": r"C:\Users\user4\AppData\x.exe",
        "b": r"c:\users\user4\desktop\notes.txt",
        "c": r"C:\Users\user5\AppData\x",
        "d": r"C:\Users\user2\x",
    }
    assert sorted(sanitizer.mapping) == ["doe", "doe,jane", "jane", "jane doe", "o'brien"]
    assert leftovers(clean, ["jane", "doe", "brien"]) == []


def test_a_profile_path_followed_by_more_text_learns_only_the_folder() -> None:
    doc = {"cmd": r"dir C:\Users\amy.smith then more /s /b", "note": "amy.smith"}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {"cmd": r"dir C:\Users\user1 then more /s /b", "note": "user1"}
    assert sorted(sanitizer.mapping) == ["amy.smith"]


def test_percent_encoded_profile_folders_are_replaced() -> None:
    doc = {"a": "C%3A%5CUsers%5CJane%20Doe%5Cx", "b": "file:///C:/Users/Jane%20Doe/notes.txt"}
    clean = _run(doc)
    assert clean == {"a": "C%3A%5CUsers%5Cuser2%5Cx", "b": "file:///C:/Users/user2/notes.txt"}
    assert leftovers(clean, ["jane", "doe"]) == []


def test_profile_paths_in_other_forms_are_learned() -> None:
    doc = {
        "device": r"\Device\HarddiskVolume3\Users\amy.smith\x.exe",
        "wsl": "/mnt/c/Users/bob.jones/x",
        "msys": "/c/Users/cy.lee/x",
        "env": r"%SystemDrive%\Users\dan.kim\x",
        "doubled": "C://Users//eve.ross//x",
        "old": r"C:\Documents and Settings\fay.wong\x",
        "encoded": "C%3A%5CUsers%5Cgus.hill%5Cx",
    }
    assert _run(doc) == {
        "device": r"\Device\HarddiskVolume3\Users\user1\x.exe",
        "wsl": "/mnt/c/Users/user2/x",
        "msys": "/c/Users/user3/x",
        "env": r"%SystemDrive%\Users\user4\x",
        "doubled": "C://Users//user5//x",
        "old": r"C:\Documents and Settings\user6\x",
        "encoded": "C%3A%5CUsers%5Cuser7%5Cx",
    }


def test_the_user_folder_of_a_linux_home_path_is_learned() -> None:
    doc = {
        "cmd": "wsl.exe -e bash /home/jdoe/run.sh",
        "url": "https://example.com/home/news/",
        "note": "jdoe ran it; news at home",
    }
    assert _run(doc) == {
        **doc,
        "cmd": "wsl.exe -e bash /home/user1/run.sh",
        "note": "user1 ran it; news at home",
    }


def test_a_linux_home_path_is_learned_only_at_the_start_of_a_token() -> None:
    doc = {
        "a": "/home/amy.smith/x",
        "b": 'cd "/home/bob.jones/y"',
        "c": "(/home/cy.lee/z)",
        "d": "HOME=/home/dan.kim/",
        "e": "line\\n/home/eve.ross/x",
        "f": "x:/home/fay.wong/",
        "g": "a/home/gus.hill/",
        "h": "C:/home/hal.berg/",
        "note": "amy.smith bob.jones cy.lee dan.kim eve.ross fay.wong gus.hill hal.berg",
    }
    clean = _run(doc)
    assert clean["note"] == "user1 user2 user3 user4 user5 fay.wong gus.hill hal.berg"


def test_container_cloud_and_web_home_folders_are_not_learned() -> None:
    doc = {
        "docker": r"docker run -v C:\src:/home/node/app node:20",
        "scp": "scp build.zip admin@10.0.0.9:/home/ubuntu/app/",
        "href": "<a href=/home/about/>About</a>",
        "get": "GET /home/index/ HTTP/1.1",
        "drive": "C:/home/assets/",
        "runner": "cat /home/runner/work/x/y",
        "kali": "wsl.exe -d kali-linux -e ls /home/kali/",
        "cloud": "ssh /home/ec2-user/ /home/azureuser/ /home/vagrant/ /home/debian/ /home/docker/",
        "note": "Node.js 20.11 is affected; Ubuntu 22.04 LTS; about, index, assets, runner, kali",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {
        **doc,
        "scp": "scp build.zip admin@203.0.113.1:/home/ubuntu/app/",
    }
    assert sorted(sanitizer.mapping) == ["10.0.0.9"]


def test_the_user_folder_of_a_wsl_path_is_learned() -> None:
    doc = {
        "defender": r"\\wsl.localhost\Ubuntu\home\jdoe\notes.txt",
        "sysmon": r"\\wsl$\Ubuntu-22.04\home\amy.smith\.bashrc",
        "escaped": json.dumps({"path": r"\\wsl.localhost\Debian\home\bob.jones\x"}),
        "kali": r"\\wsl.localhost\kali-linux\home\kali\x",
        "note": "jdoe amy.smith bob.jones kali Ubuntu Debian",
    }
    clean = _run(doc)
    assert clean == {
        "defender": r"\\wsl.localhost\Ubuntu\home\user3\notes.txt",
        "sysmon": r"\\wsl$\Ubuntu-22.04\home\user1\.bashrc",
        "escaped": json.dumps({"path": r"\\wsl.localhost\Debian\home\user2\x"}),
        "kali": doc["kali"],
        "note": "user3 user1 user2 kali Ubuntu Debian",
    }


def test_web_urls_and_the_sam_hive_are_not_profile_paths() -> None:
    doc = {
        "jira": "curl https://jira.example.com/rest/api/2/users/current/settings",
        "gitlab": "chrome.exe https://gitlab.com/users/auth/google_oauth2/callback?code=x",
        "login": "chrome.exe https://example.com/users/login/?next=/",
        "canvas": "chrome.exe https://canvas.example.edu/api/v1/users/self/profile",
        "json": json.dumps({"url": "https://api.example.com/users/octocat/repos"}),
        "share": r"\\NAS\Users\Shared\x.doc",
        "sam": r"HKLM\SAM\SAM\Domains\Account\Users\Names\jdoe",
        "rid": r"HKLM\SAM\SAM\Domains\Account\Users\000003E9\V",
        "hive": r"\REGISTRY\MACHINE\SAM\Users\zed.quinn\x",
        "no_drive": r"cd \Users\jdoe\Downloads",
        "file": "file:///C:/Users/amy.smith/notes.txt",
        "compact": '{"a":"https://x.example.com/","b":"C:/Users/kim.lee/x"}',
        "lines": json.dumps({"m": "seen\nfile:///D:/Users/lee.park/x"}),
        "text": (
            r"HKEY_CURRENT_USER\Software\x; the current version; auth_history returned 3 events;"
            " Failed login; Names are listed; Shared Folders; self-signed; octocat"
        ),
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {
        **doc,
        "share": r"\\HOST-2\Users\Shared\x.doc",
        "sam": r"HKLM\SAM\SAM\Domains\Account\Users\Names\user2",
        "no_drive": r"cd \Users\user2\Downloads",
        "file": "file:///C:/Users/user1/notes.txt",
        "compact": '{"a":"https://x.example.com/","b":"C:/Users/user3/x"}',
        "lines": json.dumps({"m": "seen\nfile:///D:/Users/user4/x"}),
    }
    assert sorted(sanitizer.mapping) == ["NAS", "amy.smith", "jdoe", "kim.lee", "lee.park"]


def test_domain_qualified_accounts_are_split() -> None:
    doc = [
        {"host": "DESKTOP-9QXZ7"},
        {"user": r"DESKTOP-9QXZ7\\jane.doe"},
        {"user": r"NT AUTHORITY\SYSTEM"},
        {"user": r"Window Manager\DWM-1"},
        {"user": r"Font Driver Host\UMFD-0"},
    ]
    assert _run(doc) == [
        {"host": "MY-PC"},
        {"user": r"MY-PC\\user1"},
        {"user": r"NT AUTHORITY\SYSTEM"},
        {"user": r"Window Manager\DWM-1"},
        {"user": r"Font Driver Host\UMFD-0"},
    ]


def test_the_domain_of_an_account_is_learned_as_a_host() -> None:
    doc = {"user": r"ZULU-BOX\jane.doe", "message": "on ZULU-BOX by jane.doe"}
    assert _run(doc) == {"user": r"HOST-2\user1", "message": "on HOST-2 by user1"}


def test_the_domain_of_a_built_in_account_is_learned_too() -> None:
    doc = {"user": r"ZULU-BOX\Administrator", "message": "on ZULU-BOX"}
    assert _run(doc) == {"user": r"HOST-2\Administrator", "message": "on HOST-2"}


def test_an_account_after_a_known_host_or_in_a_label_is_learned() -> None:
    doc = {
        "agent": {"id": "001", "name": "DESKTOP-9QXZ7"},
        "eventdata": {
            "contextInfo": r"Host Name = ConsoleHost; User = DESKTOP-9QXZ7\jdoe",
            "detection User": r"DESKTOP-9QXZ7\jdoe",
        },
        "message": "Account Name:\t\t" + r"ZULU-BOX\amy.smith" + "\r\n",
        "example": r"New Logon: Account Name: YANKEE-BOX\bob.jones Logon ID: 0x3E7",
        "other": r"ALPHA-BOX\cy.lee and C:\Tools\eve.ross",
        "full_log": json.dumps({"contextInfo": "User =\t" + r"desktop-9qxz7\kim.lee"}),
        "note": "jdoe, amy.smith, bob.jones, cy.lee, eve.ross, kim.lee",
    }
    clean = _run(doc)
    assert clean["eventdata"] == {
        "contextInfo": r"Host Name = ConsoleHost; User = MY-PC\user3",
        "detection User": r"MY-PC\user3",
    }
    assert clean["message"] == "Account Name:\t\t" + r"HOST-3\user1" + "\r\n"
    assert clean["example"] == r"New Logon: Account Name: HOST-2\user2 Logon ID: 0x3E7"
    assert clean["other"] == doc["other"]
    assert json.loads(clean["full_log"]) == {"contextInfo": "User =\t" + r"MY-PC\user4"}
    assert clean["note"] == "user3, user1, user2, cy.lee, eve.ross, user4"


def test_built_in_pseudo_domains_are_kept() -> None:
    doc = {
        "a": {"user": r"NT SERVICE\TrustedInstaller"},
        "b": {"user": r"IIS APPPOOL\DefaultAppPool"},
        "c": {
            "subjectDomainName": "WORKGROUP",
            "targetDomainName": "MicrosoftAccount",
            "user": r"AzureAD\amy.smith",
        },
        "d": {
            "subjectDomainName": "Window Manager",
            "targetDomainName": "Font Driver Host",
            "hostname": "BUILTIN",
            "userName": "TrustedInstaller",
        },
        "text": "TrustedInstaller; MicrosoftAccount; NT SERVICE; AzureAD; BUILTIN; amy.smith",
    }
    expected = copy.deepcopy(doc)
    expected["c"]["user"] = r"AzureAD\user1"
    expected["text"] = "TrustedInstaller; MicrosoftAccount; NT SERVICE; AzureAD; BUILTIN; user1"
    assert _run(doc) == expected


def test_built_in_group_names_are_kept() -> None:
    doc = [
        {"targetUserName": "Administrators", "targetDomainName": "Builtin"},
        {"targetUserName": "Remote Desktop Users", "subjectUserName": "amy.smith"},
        {"note": "amy.smith added a member to Administrators and Remote Desktop Users"},
    ]
    expected = copy.deepcopy(doc)
    expected[1]["subjectUserName"] = "user1"
    expected[2]["note"] = "user1 added a member to Administrators and Remote Desktop Users"
    assert _run(doc) == expected


def test_windows_service_accounts_are_kept() -> None:
    doc = {
        "a": {"accountName": "LocalSystem"},
        "b": {"accountName": "LocalService"},
        "c": {"accountName": "NetworkService"},
        "d": {"user": r"NT AUTHORITY\LOCAL SERVICE", "subjectUserName": "NETWORK SERVICE"},
        "note": "Service runs as LocalSystem, LocalService or NetworkService",
    }
    assert _run(doc) == doc


def test_keys_of_unrelated_dicts_are_not_learned_as_names() -> None:
    doc = {"users": {"count": 3, "active": 1}, "note": "count active"}
    assert _run(doc) == doc


def test_the_agent_name_is_the_pc_and_other_hosts_come_after() -> None:
    doc = {
        "agent": {"id": "002", "name": "Zulu-Laptop"},
        "data": {"win": {"eventdata": {"workstationName": "ALPHA-BOX"}}},
        "note": "Zulu-Laptop saw alpha-box",
    }
    clean = _run(doc)
    assert clean["agent"] == {"id": "001", "name": "MY-PC"}
    assert clean["data"]["win"]["eventdata"]["workstationName"] == "HOST-2"
    assert clean["note"] == "MY-PC saw HOST-2"


def test_a_host_written_as_an_address_is_an_address() -> None:
    doc = {"host": "192.168.1.5", "computer": "ZULU-PC", "note": "from 192.168.1.5 to ZULU-PC"}
    assert _run(doc) == {
        "host": "203.0.113.1",
        "computer": "MY-PC",
        "note": "from 203.0.113.1 to MY-PC",
    }


def test_a_remote_host_never_takes_the_pc_placeholder() -> None:
    doc = {"data": {"win": {"eventdata": {"workstationName": "ALPHA-BOX"}}}}
    assert _run(doc)["data"]["win"]["eventdata"]["workstationName"] == "HOST-2"


def test_a_name_that_is_both_host_and_user_gets_one_placeholder() -> None:
    doc = {"host": "Amy-Box", "user": "amy-box", "message": "AMY-BOX"}
    assert _run(doc) == {"host": "MY-PC", "user": "MY-PC", "message": "MY-PC"}


def test_more_host_keys_are_learned() -> None:
    doc = {
        "eventdata": {
            "subjectDomainName": "ZULU-BOX",
            "targetDomainName": "YANKEE-BOX",
            "workstation": "XRAY-TABLET",
            "targetServerName": "WHISKEY-NAS",
            "sourceHostname": "victor-phone",
            "destinationHostname": "uniform-tv",
            "clientName": "TANGO-LAPTOP",
        },
        "manager": {"name": "sierra-server"},
        "note": "zulu-box yankee-box xray-tablet whiskey-nas VICTOR-PHONE UNIFORM-TV tango-laptop",
    }
    clean = _run(doc)
    assert clean["note"] == "HOST-9 HOST-8 HOST-7 HOST-6 HOST-5 HOST-4 HOST-3"
    assert clean["manager"] == {"name": "HOST-2"}
    names = ["zulu", "yankee", "xray", "whiskey", "victor", "uniform", "tango", "sierra"]
    assert leftovers(clean, names) == []


def test_the_first_label_of_a_local_or_own_fqdn_is_learned() -> None:
    doc = {
        "computer": "DESKTOP-9QXZ7.home.lan",
        "sourceHostname": "zulu-phone.home.lan",
        "note": "DESKTOP-9QXZ7 and desktop-9qxz7.home.lan; zulu-phone and ZULU-PHONE.HOME.LAN",
    }
    assert _run(doc) == {
        "computer": "MY-PC",
        "sourceHostname": "HOST-2",
        "note": "MY-PC and MY-PC; HOST-2 and HOST-2",
    }


def test_a_public_fqdn_is_replaced_whole_without_learning_its_first_label() -> None:
    doc = {
        "computer": "ZULU-PC",
        "destinationHostname": "login.example.com",
        "hostname": "zulu-pc.example.net",
        "note": "login at login.example.com from zulu-pc.example.net",
    }
    assert _run(doc) == {
        "computer": "MY-PC",
        "destinationHostname": "HOST-2",
        "hostname": "MY-PC",
        "note": "login at HOST-2 from MY-PC",
    }


def test_a_netbios_truncated_name_maps_to_the_full_host() -> None:
    doc = {
        "computer": "ZULU-GAMING-LAPTOP",
        "eventdata": {"subjectDomainName": "ZULU-GAMING-LAP", "subjectUserName": "amy.smith"},
        "user": r"ZULU-GAMING-LAP\amy.smith",
    }
    assert _run(doc) == {
        "computer": "MY-PC",
        "eventdata": {"subjectDomainName": "MY-PC", "subjectUserName": "user1"},
        "user": r"MY-PC\user1",
    }


def test_a_host_field_with_leading_backslashes_is_learned() -> None:
    doc = {"workstation": r"\\ZULU-BOX", "note": "from zulu-box"}
    assert _run(doc) == {"workstation": r"\\HOST-2", "note": "from HOST-2"}


def test_unc_hosts_are_learned_but_escaped_root_paths_are_not() -> None:
    doc = {
        "a": r"\\ZULU-NAS\photos\x and \\zulu-nas\ipc$",
        "full_log": json.dumps(
            {
                "share": r"\\ALPHA-BOX\c$",
                "image": r"\Device\HarddiskVolume3\x.exe",
                "path": r"C:\Windows\System32\x.exe",
            }
        ),
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean["a"] == r"\\HOST-3\photos\x and \\HOST-3\ipc$"
    assert json.loads(clean["full_log"]) == {
        "share": r"\\HOST-2\c$",
        "image": r"\Device\HarddiskVolume3\x.exe",
        "path": r"C:\Windows\System32\x.exe",
    }
    assert sorted(sanitizer.mapping) == ["ALPHA-BOX", "ZULU-NAS"]


def test_the_last_segment_of_an_escaped_path_is_not_a_unc_host() -> None:
    message = (
        "Process Name:\t"
        r"C:\Windows\System32\svchost.exe"
        "\r\n"
        "File:\t"
        r"C:\hiberfil.sys"
        "\r\nShare Name:\t"
        r"\\ZULU-NAS\photos"
        "\r\n"
    )
    doc = {"full_log": json.dumps({"message": message}), "message": message}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sorted(sanitizer.mapping) == ["ZULU-NAS"]
    assert sanitizer.apply(doc)["message"] == message.replace("ZULU-NAS", "HOST-2")


def test_hosts_after_long_unc_prefixes_are_learned() -> None:
    doc = {
        "a": r"\\?\UNC\ZULU-NAS\photos\x.jpg",
        "b": r"\Device\Mup\ALPHA-NAS\share\y.jpg",
        "full_log": json.dumps({"c": r"\\?\UNC\BRAVO-NAS\z"}),
        "note": "zulu-nas alpha-nas bravo-nas",
    }
    clean = _run(doc)
    assert clean["a"] == r"\\?\UNC\HOST-4\photos\x.jpg"
    assert clean["b"] == r"\Device\Mup\HOST-2\share\y.jpg"
    assert json.loads(clean["full_log"]) == {"c": r"\\?\UNC\HOST-3\z"}
    assert clean["note"] == "HOST-4 HOST-2 HOST-3"


def test_dns_query_names_are_learned_only_when_local() -> None:
    doc = {
        "agent": {"id": "001", "name": "my-pc"},
        "queries": [
            {"queryName": "DESKTOP-9QXZ7.home.lan"},
            {"queryName": "ZULU-NAS"},
            {"queryName": "login.example.com"},
            {"queryName": "wpad"},
        ],
        "note": "DESKTOP-9QXZ7 zulu-nas login.example.com wpad",
    }
    clean = _run(doc)
    assert clean["queries"] == [
        {"queryName": "HOST-2"},
        {"queryName": "HOST-3"},
        {"queryName": "login.example.com"},
        {"queryName": "wpad"},
    ]
    assert clean["note"] == "HOST-2 HOST-3 login.example.com wpad"


def test_home_router_dns_suffixes_are_local() -> None:
    doc = {
        "queries": [{"queryName": "marys-iphone.fritz.box"}, {"queryName": "zulu-tv.mshome.net"}],
        "sourceHostname": "alpha-laptop.attlocal.net",
        "hostname": "bravo-nas.router",
        "note": "marys-iphone, zulu-tv, alpha-laptop and bravo-nas",
    }
    assert _run(doc) == {
        "queries": [{"queryName": "HOST-4"}, {"queryName": "HOST-5"}],
        "sourceHostname": "HOST-2",
        "hostname": "HOST-3",
        "note": "HOST-4, HOST-5, HOST-2 and HOST-3",
    }


def test_more_user_keys_are_learned() -> None:
    doc = {
        "syscheck": {
            "uname_after": "amy.smith",
            "uname_before": "bob.jones",
            "audit": {"user": {"name": "cy.lee", "id": "1001"}},
        },
        "eventdata": {
            "oldTargetUserName": "dan.kim",
            "newTargetUserName": "eve.ross",
            "targetOutboundUserName": "fay.wong",
            "displayName": "Gus Hill",
        },
        "tool": {"account": "hal.berg"},
        "approval": {"decided_by": "ivy.cole", "approved_by": "jon.pike"},
        "note": "amy.smith bob.jones cy.lee dan.kim eve.ross fay.wong Gus Hill hal.berg ivy.cole "
        "jon.pike",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean["note"] == "user1 user2 user3 user4 user5 user6 user8 user9 user11 user12"
    assert clean["eventdata"]["displayName"] == "user8"
    assert sanitizer.apply({"m": "Gus went home, Hill stayed"}) == {
        "m": "user7 went home, user10 stayed"
    }


def test_the_parts_of_an_approver_name_are_learned() -> None:
    doc = {
        "approvals": [{"decided_by": "Jane Doe", "note": "ok"}, {"approved_by": "Amy Smith"}],
        "summary": "Approved by Jane Doe. Jane checked it later; Doe signed. Amy agreed.",
    }
    assert _run(doc) == {
        "approvals": [{"decided_by": "user5", "note": "ok"}, {"approved_by": "user2"}],
        "summary": "Approved by user5. user4 checked it later; user3 signed. user1 agreed.",
    }


def test_names_in_file_permissions_are_learned() -> None:
    doc = {
        "syscheck": {
            "path": r"c:\tools\x.txt",
            "win_perm_before": [
                {"name": "Administrators", "allowed": ["read"]},
                {"name": "jdoe", "allowed": ["read"]},
            ],
            "win_perm_after": [
                {"name": "SYSTEM", "allowed": ["read"]},
                {"name": "ALL APPLICATION PACKAGES", "allowed": ["read"]},
                {"name": "amy.smith", "allowed": ["delete"]},
            ],
        },
        "note": "jdoe and amy.smith; ALL APPLICATION PACKAGES",
    }
    clean = _run(doc)
    assert [entry["name"] for entry in clean["syscheck"]["win_perm_before"]] == [
        "Administrators",
        "user2",
    ]
    assert [entry["name"] for entry in clean["syscheck"]["win_perm_after"]] == [
        "SYSTEM",
        "ALL APPLICATION PACKAGES",
        "user1",
    ]
    assert clean["note"] == "user2 and user1; ALL APPLICATION PACKAGES"


def test_names_in_registry_key_permissions_are_not_learned() -> None:
    services = r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services"
    doc = {
        "fim": [
            {
                "syscheck": {
                    "path": services + r"\EventLog\Application\Foo",
                    "win_perm_after": [
                        {"name": "EventLog"},
                        {"name": "SYSTEM"},
                        {"name": "Administrators"},
                        {"name": "Users"},
                    ],
                }
            },
            {
                "syscheck": {
                    "path": services + r"\Tcpip\Parameters\Interfaces\{a1}",
                    "win_perm_after": [
                        {"name": "Dhcp"},
                        {"name": "NETWORK SERVICE"},
                        {"name": "SYSTEM"},
                    ],
                }
            },
            {
                "syscheck": {
                    "path": r"HKEY_USERS\S-1-5-21-111-222-333-1001\Software\Run",
                    "win_perm_before": [{"name": "amy.smith"}, {"name": "RESTRICTED"}],
                    "win_perm_after": [{"name": "jdoe"}, {"name": "LOCAL"}, {"name": "IUSR"}],
                }
            },
            {"syscheck": {"path": r"hklm\SOFTWARE\x", "win_perm_after": [{"name": "MpsSvc"}]}},
            {
                "syscheck": {
                    "path": r"c:\tools\x.txt",
                    "win_perm_after": [{"name": "jdoe"}, {"name": "RESTRICTED"}],
                }
            },
        ],
        "system_event": {"providerName": "Microsoft-Windows-Dhcp-Client"},
        "sca": {
            "registry": r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EventLog"
            r"\Application:MaxSize"
        },
        "message4624": "\tRestricted Admin Mode:\t-\r\n",
        "note": "EventLog, Dhcp, DHCP, MpsSvc, RESTRICTED and amy.smith; jdoe",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert sorted(sanitizer.mapping) == ["S-1-5-21-111-222-333", "jdoe"]
    expected = copy.deepcopy(doc)
    third = expected["fim"][2]["syscheck"]
    third["path"] = r"HKEY_USERS\S-1-5-21-1000000000-1000000000-1000000000-1001\Software\Run"
    third["win_perm_after"][0]["name"] = "user1"
    expected["fim"][4]["syscheck"]["win_perm_after"][0]["name"] = "user1"
    expected["note"] = "EventLog, Dhcp, DHCP, MpsSvc, RESTRICTED and amy.smith; user1"
    assert clean == expected


def test_well_known_principals_in_file_permissions_are_kept() -> None:
    principals = [
        "RESTRICTED",
        "WRITE RESTRICTED",
        "LOCAL",
        "CONSOLE LOGON",
        "IUSR",
        "ALL SERVICES",
        "DIALUP",
        "REMOTE INTERACTIVE LOGON",
        "This Organization",
        "Local account",
        "Local account and member of Administrators group",
        "SELF",
        "TERMINAL SERVER USER",
    ]
    doc = {
        "syscheck": {
            "path": r"c:\tools\x.txt",
            "win_perm_after": [{"name": name, "allowed": ["read"]} for name in principals],
        },
        "note": "; ".join(principals) + "; HKEY_LOCAL_MACHINE; LOCAL SERVICE; self-signed",
    }
    assert _run(doc) == doc


def test_a_generic_workstation_name_is_not_learned_as_a_host() -> None:
    doc = {
        "workstationName": "WORKSTATION",
        "message": "Network Information:\r\n\tWorkstation Name:\tWORKSTATION\r\n",
    }
    assert _run(doc) == doc


def test_sysmon_and_account_management_user_fields_are_learned() -> None:
    doc = {
        "eventdata": {
            "sourceUser": r"ZULU-BOX\amy.smith",
            "targetUser": r"NT AUTHORITY\SYSTEM",
            "parentUser": r"ZULU-BOX\bob.jones",
            "userPrincipalName": "cy.lee@example.org",
            "displayName": "%%1793",
        },
        "note": "amy.smith bob.jones cy.lee %%1793 zulu-box",
    }
    assert _run(doc) == {
        "eventdata": {
            "sourceUser": r"HOST-2\user1",
            "targetUser": r"NT AUTHORITY\SYSTEM",
            "parentUser": r"HOST-2\user2",
            "userPrincipalName": "user3",
            "displayName": "%%1793",
        },
        "note": "user1 user2 user3 %%1793 HOST-2",
    }


def test_names_after_windows_message_labels_are_learned() -> None:
    message = (
        "Subject:\r\n\tAccount Name:\t\tZULU-BOX$\r\n\tAccount Domain:\t\tWORKGROUP\r\n"
        "New Logon:\r\n\tAccount Name:\t\tamy.smith@example.org\r\n"
        "\tAccount Domain:\t\tMicrosoftAccount\r\n"
        "\tAccount Name:\t\tSYSTEM\r\n\tAccount Domain:\t\tNT AUTHORITY\r\n"
        "Network Information:\r\n\tWorkstation Name:\tALPHA-BOX\r\n"
        "\tSource Workstation:\tBRAVO-BOX\r\n\tAccount Name:\t\t-\r\n\tAccount Name:\t\tal\r\n"
    )
    doc = {
        "message": message,
        "full_log": json.dumps({"message": message}),
        "note": "amy.smith, zulu-box, alpha-box, bravo-box, al",
    }
    clean = _run(doc)
    assert clean["note"] == "user1, HOST-4, HOST-2, HOST-3, al"
    assert leftovers(clean, ["amy", "example.org", "zulu", "alpha", "bravo"]) == []
    for kept in ("WORKGROUP", "MicrosoftAccount", "SYSTEM", "NT AUTHORITY", "Name:\t\t-\r\n"):
        assert kept in clean["message"]
    assert json.loads(clean["full_log"]) == {"message": clean["message"]}


def test_labels_in_a_whitespace_collapsed_message_are_learned() -> None:
    example = (
        "An account failed to log on. Subject: Security ID: S-1-5-18 Account Name: ZULU-BOX$ "
        "Account Domain: WORKGROUP Logon ID: 0x3E7 Account For Which Logon Failed: "
        "Security ID: S-1-0-0 Account Name: amy.smith Account Domain: ZULU-BOX "
        "Failure Information: Failure Reason: Unknown user name or bad password. "
        "Network Information: Workstation Name: ALPHA-BOX Source Network Address: 192.168.1.23 "
        "New Logon: Account Name: Bob Jones Account Domain: ZULU-BOX Logon ID: 0x3E7"
    )
    doc = {"content": {"example": example}, "note": "amy.smith, Bob Jones on zulu-box, alpha-box"}
    clean = _run(doc)
    assert clean["note"] == "user1, user2 on HOST-3, HOST-2"
    assert clean["content"]["example"] == (
        example.replace("ZULU-BOX", "HOST-3")
        .replace("amy.smith", "user1")
        .replace("Bob Jones", "user2")
        .replace("ALPHA-BOX", "HOST-2")
        .replace("192.168.1.23", "203.0.113.1")
    )


def test_an_empty_label_value_in_collapsed_text_learns_nothing() -> None:
    examples = [
        "Account For Which Logon Failed: Security ID: S-1-0-0 Account Name: sentinel-test-nobody "
        "Account Domain: Failure Information: Failure Reason: Unknown user name or bad password.",
        "Subject: Security ID: S-1-0-0 Account Name: Account Domain: Logon ID: 0x0",
        "Workstation Name: Source Network Address: 192.168.1.50 Source Port: 0",
        "Logon Account: sentinel-test-nobody Source Workstation: Error Code: 0xC000006A",
        "Session: Client Name: Client Address: 192.168.1.5",
        "New Logon: Account Name: jane.doe Account Domain: ZULU-BOX Logon ID: 0x3E7",
        "New Account: Account Domain: Attributes: SAM Account Name: jane.doe",
    ]
    doc = {
        "rule": {"description": "Logon Failure - Unknown user or bad password"},
        "system": {"severityValue": "AUDIT_FAILURE"},
        "evidence": [{"content": {"example": example}} for example in examples],
        "note": "Source Network Address, Account Name, Error Code; jane.doe on zulu-box",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert sorted(sanitizer.mapping) == ["192.168.1.5", "192.168.1.50", "ZULU-BOX", "jane.doe"]
    assert clean["rule"] == doc["rule"]
    assert clean["system"] == doc["system"]
    assert [item["content"]["example"] for item in clean["evidence"]] == [
        examples[0],
        examples[1],
        examples[2].replace("192.168.1.50", "203.0.113.2"),
        examples[3],
        examples[4].replace("192.168.1.5", "203.0.113.1"),
        "New Logon: Account Name: user1 Account Domain: HOST-2 Logon ID: 0x3E7",
        "New Account: Account Domain: Attributes: SAM Account Name: user1",
    ]
    assert clean["note"] == "Source Network Address, Account Name, Error Code; user1 on HOST-2"


def test_a_label_value_that_is_only_a_label_word_learns_nothing() -> None:
    examples = [
        "Account Name: bob.smith Account Domain: Read Operation: Enumerate Credentials",
        "Account Name: sentinel-test-nobody Account Domain: Failure",
        "Network Information: Workstation Name: Source",
        "Account Name: Account Domain: Changed Attributes: SAM Account Name: -",
        "Account Information: Account Name: Supplied Realm Name: HOME User ID: S-1-0-0",
        r"Account Domain: Device ID: SWD\x Device Name: y",
        "Account Domain: Cryptographic Parameters: Provider Name: Microsoft",
        r"Account Domain: Task Information: Task Name: \x",
        r"Account Domain: Share Information: Share Name: \\*\C$",
    ]
    doc = {
        "evidence": [{"example": example} for example in examples],
        "fim": {"allowed": ["read"]},
        "rule": "Logon Failure - Unknown user or bad password",
        "note": "Read Operation, Failure Reason, Source Network Address, Changed Attributes, "
        "Supplied Realm, Device ID, Cryptographic Parameters, Task Name, Share Name; bob.smith",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert sorted(sanitizer.mapping) == ["bob.smith"]
    expected = copy.deepcopy(doc)
    expected["evidence"][0]["example"] = examples[0].replace("bob.smith", "user1")
    expected["note"] = doc["note"].replace("bob.smith", "user1")
    assert clean == expected


def test_a_label_value_takes_a_backslash_part_only_after_a_one_word_domain() -> None:
    doc = {
        "c": r"Account Name: SYSTEM Account Domain: kali \Device\Mup\x\y",
        "d": r"New Logon: Account Name: NT AUTHORITY\SYSTEM Account Domain: NT AUTHORITY",
        "e": r"Account Name: Font Driver Host\UMFD-0 Logon ID: 0x3E7",
        "f": r"Account Name: ZULU-BOX\amy.smith Logon ID: 0x3E7",
        "note": "kali amy.smith zulu-box",
    }
    first = _run(doc)
    assert first == {
        "c": r"Account Name: SYSTEM Account Domain: HOST-2 \Device\Mup\x\y",
        "d": doc["d"],
        "e": doc["e"],
        "f": r"Account Name: HOST-3\user1 Logon ID: 0x3E7",
        "note": "HOST-2 user1 HOST-3",
    }
    assert _run(first) == first


def test_the_local_part_of_an_email_account_is_learned() -> None:
    doc = {
        "targetUserName": "jane.doe@example.org",
        "user": r"MicrosoftAccount\amy.smith@example.net",
        "note": (
            "jane.doe signed in as JANE.DOE@EXAMPLE.ORG; amy.smith; mail zed.quinn@example.com."
        ),
    }
    assert _run(doc) == {
        "targetUserName": "user2",
        "user": r"MicrosoftAccount\user1",
        "note": "user2 signed in as user2; user1; mail user3.",
    }


def test_role_mailboxes_are_replaced_whole_without_learning_their_local_part() -> None:
    doc = {"cmd": "git clone git@github.com:zulu/repo.git", "m": "mail noreply@example.org on git"}
    assert _run(doc) == {"cmd": "git clone user1:zulu/repo.git", "m": "mail user2 on git"}


def test_emails_in_free_text_are_replaced_whole_without_learning_their_local_part() -> None:
    doc = {
        "vulnerability": {
            "id": "CVE-2024-12345",
            "description": "Reported via cve@mitre.org; see report@snyk.io",
            "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
        },
        "title": "CVE-2024-12345 affects Foo",
        "note": "Generate a report for CVE-2024-12345",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    description = "Reported via user1; see user2"
    assert clean == {**doc, "vulnerability": {**doc["vulnerability"], "description": description}}
    assert sorted(sanitizer.mapping) == ["cve@mitre.org", "report@snyk.io"]


def test_email_local_parts_are_learned_from_account_and_mail_fields() -> None:
    doc = {
        "email": "jane.doe@example.org",
        "contact": {"mailAddress": "amy.smith@example.net"},
        "userPrincipalName": "bob.jones@example.com",
        "mail": {"eve.ross@example.org": 2},
        "note": "jane.doe, amy.smith, bob.jones and eve.ross; cy.lee@example.org wrote, cy.lee",
    }
    clean = _run(doc)
    assert clean["mail"] == {"user4": 2}
    assert clean["note"] == "user5, user1, user2 and user4; user3 wrote, cy.lee"


def test_addresses_and_names_in_dict_keys_are_learned() -> None:
    doc = {
        "event": {"user": "jane.doe"},
        "raw": {
            "baseline_successes": {"192.168.1.50": 3, "fe80::1": 1},
            "by_user": {"jane.doe": 2, "amy.smith": 1},
            "by_mac": {"3C:52:82:AA:BB:CC": 1},
            "files": {r"C:\Users\bob.jones\x": 1},
            "mail": {"cy.lee@example.org": 1},
            "S-1-5-21-1234567890-987654321-1122334455-1001": "sid",
            "inventory": {"hosts": {"ZULU-NAS": {"role": "nas"}}},
        },
    }
    clean = _run(doc)
    assert clean["raw"] == {
        "baseline_successes": {"203.0.113.1": 3, "2001:db8::1": 1},
        "by_user": {"user4": 2, "user1": 1},
        "by_mac": {"00:00:5e:00:53:01": 1},
        "files": {r"C:\Users\user2\x": 1},
        "mail": {"user3": 1},
        "S-1-5-21-1000000000-1000000000-1000000000-1001": "sid",
        "inventory": {"hosts": {"HOST-2": {"role": "nas"}}},
    }
    assert _run(clean) == clean


def test_keys_that_collide_after_sanitizing_raise() -> None:
    sanitizer = Sanitizer()
    sanitizer.learn({"user": ["jane.doe", "JANE.DOE"]})
    with pytest.raises(ValueError) as error:
        sanitizer.apply({"jane.doe": 1, "JANE.DOE": 2})
    assert "jane" not in str(error.value).lower()
    with pytest.raises(ValueError):
        sanitizer.apply({"nested": [{"user1": 1, "jane.doe": 2}]})


def test_entities_are_learned_from_their_type() -> None:
    doc = {
        "entities": [
            {"entity_type": "host", "value": "ZULU-LAPTOP"},
            {"entity_type": "account", "value": "amy.smith"},
            {"entity_type": "ip", "value": "192.168.7.9"},
        ],
        "actions": [{"target_type": "account", "target_value": "cy.lee"}],
        "message": "amy.smith and cy.lee on ZULU-LAPTOP",
    }
    clean = _run(doc)
    assert clean["message"] == "user1 and user2 on MY-PC"
    assert clean["entities"][0]["value"] == "MY-PC"
    assert clean["actions"][0]["target_value"] == "user2"
    assert clean["entities"][2]["value"] == "203.0.113.1"


def test_placeholders_do_not_depend_on_the_order_of_the_data() -> None:
    docs = [
        {"user": "zed.quinn", "src": "10.1.1.9", "id": "x"},
        {"user": "amy.smith", "src": "9.9.9.9", "v6": "fd12::9"},
        {"agent": {"id": "009"}, "m": "aa:bb:cc:dd:ee:02", "v6": "fd12::1"},
        {"agent": {"id": "003"}, "m": "AA:BB:CC:DD:EE:01"},
    ]
    forward = Sanitizer()
    forward.learn(docs)
    backward = Sanitizer()
    backward.learn(list(reversed(docs)))
    assert forward.mapping == backward.mapping
    assert forward.apply(docs) == backward.apply(list(reversed(docs)))[::-1]
    assert forward.mapping == {
        "amy.smith": "user1",
        "zed.quinn": "user2",
        "9.9.9.9": "203.0.113.1",
        "10.1.1.9": "203.0.113.2",
        "fd12::1": "2001:db8::1",
        "fd12::9": "2001:db8::2",
        "AA:BB:CC:DD:EE:01": "00:00:5e:00:53:01",
        "AA:BB:CC:DD:EE:02": "00:00:5e:00:53:02",
        "003": "001",
        "009": "002",
    }


def test_names_that_share_a_form_are_replaced_the_same_way_under_any_hash_seed() -> None:
    code = (
        "from pipeline.sanitize import Sanitizer\n"
        "sanitizer = Sanitizer()\n"
        "sanitizer.learn({'user': ['jane doe', 'jane+doe', 'jane doe+x', 'jane+doe x']})\n"
        "clean = sanitizer.apply({'a': 'jane+doe', 'b': 'jane+doe+x'})\n"
        "print(clean['a'], clean['b'])\n"
    )
    results = set()
    for seed in ("0", "1", "2", "3"):
        done = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        )
        results.add(done.stdout.strip())
    assert results == {"user3 user2"}


def test_agent_ids_are_replaced_only_in_agent_id_fields() -> None:
    doc = {
        "agent": {"id": "007", "name": "my-pc"},
        "agent_id": ["007"],
        "level": "007",
        "ipPort": "007",
        "ids": ["007"],
        "note": "rule 007 on 0070",
    }
    assert _run(doc) == {
        "agent": {"id": "001", "name": "my-pc"},
        "agent_id": ["001"],
        "level": "007",
        "ipPort": "007",
        "ids": ["007"],
        "note": "rule 007 on 0070",
    }


def test_the_manager_agent_is_kept() -> None:
    doc = {"agent": {"id": "000", "name": "wazuh.manager"}}
    assert _run(doc) == doc


def test_addresses_that_are_not_personal_are_kept() -> None:
    doc = {
        "package": {"version": "1.2.3.4"},
        "os": "10.0.26200.9457",
        "mask": "255.255.255.0",
        "broadcast": "255.255.255.255",
        "loopback": "127.0.0.1 and ::1 and [::1]:445",
        "any": "0.0.0.0 and ::",
        "multicast": "224.0.0.251",
        "placeholder": "203.0.113.7 and 2001:db8::7 and 2001:DB8:0:0:1::5",
        "mac": "00-00-5E-00-53-07 FF:FF:FF:FF:FF:FF",
        "not_an_ip": "999.1.1.1 and 1.2.3",
    }
    assert _run(doc) == doc


def test_real_ten_dot_zero_addresses_are_replaced() -> None:
    doc = {"src_ip": "10.0.0.23", "gw": "10.0.0.1", "placeholder": "203.0.113.9"}
    assert _run(doc) == {"src_ip": "203.0.113.2", "gw": "203.0.113.1", "placeholder": "203.0.113.9"}


def test_ipv4_with_leading_zeros_gets_the_same_placeholder() -> None:
    doc = {"a": "192.168.1.23", "b": "from 192.168.001.023 now"}
    assert _run(doc) == {"a": "203.0.113.1", "b": "from 203.0.113.1 now"}


def test_section_numbers_that_look_like_addresses_are_kept() -> None:
    doc = {
        "src": "10.2.1.2",
        "rule": {"pci_dss": ["10.2.1.2", "10.2.1.5"]},
        "data": {"compliance": {"pci_dss_v4": {"0": "1.2.1,10.2.1.2,10.2.1.5"}}},
    }
    clean = _run(doc)
    assert clean["src"] == "203.0.113.1"
    assert clean["rule"] == doc["rule"]
    assert clean["data"] == doc["data"]


def test_benchmark_numbers_and_versions_are_kept_but_lookalike_keys_are_not() -> None:
    doc = {
        "src": "192.168.1.23",
        "rule": {
            "cis": ["2.3.7.4", "18.9.47.5"],
            "cis_csc_v8": ["4.5.1.2"],
            "nist_800_53": ["1.2.3.4"],
        },
        "conversion": {"ip": "192.168.1.24"},
        "os_version": "10.0.1.2",
        "packageVersion": "1.2.3.4",
        "version": "5.6.7.8",
    }
    clean = _run(doc)
    assert clean == {**doc, "src": "203.0.113.1", "conversion": {"ip": "203.0.113.2"}}


def test_zero_network_addresses_and_cis_section_numbers_are_kept() -> None:
    doc = {
        "src_ip": "192.168.1.23",
        "recommendation": "CIS 2.3.7.4 and cis 18.10.43.5 require this",
        "title": "CVE-2024-31497 in PuTTY release 0.80 (64-bit) 0.80.0.0",
        "note": "2.3.7.4 is also an address",
    }
    assert _run(doc) == {**doc, "src_ip": "203.0.113.2", "note": "203.0.113.1 is also an address"}


def test_an_address_after_a_word_that_ends_in_cis_is_replaced() -> None:
    doc = {
        "src_ip": "192.168.1.23",
        "sshd": "Connection closed by invalid user francis 192.168.1.23 port 22",
        "other": "Host narcis 10.20.30.40 contacted",
        "recommendation": "CIS 2.3.7.4 and (cis 18.10.43.5)",
    }
    assert _run(doc) == {
        **doc,
        "src_ip": "203.0.113.2",
        "sshd": "Connection closed by invalid user francis 203.0.113.2 port 22",
        "other": "Host narcis 203.0.113.1 contacted",
    }


def test_versions_that_look_like_addresses_are_kept_when_a_version_key_holds_them() -> None:
    doc = {
        "findings": [
            {"title": "CVE-2024-1234 in Steam 2.10.91.91", "installed_version": "2.10.91.91"},
            {
                "title": "CVE-2024-5678 in VLC media player 3.0.21.0",
                "package": {"name": "VLC media player", "version": "3.0.21.0"},
            },
        ],
        "advice": "Update Steam 2.10.91.91 and VLC media player 3.0.21.0 today.",
        "other": "Epic Games Launcher 1.3.93.0",
        "src_ip": "192.168.1.23",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean == {**doc, "other": "Epic Games Launcher 203.0.113.1", "src_ip": "203.0.113.2"}
    assert sorted(sanitizer.mapping) == ["1.3.93.0", "192.168.1.23"]
    assert _run(clean) == clean


def test_an_address_is_replaced_even_when_a_version_has_the_same_digits() -> None:
    doc = {
        "finding": {"title": "Steam 2.10.91.91", "installed_version": "2.10.91.91"},
        "eventdata": {"ipAddress": "::ffff:2.10.91.91"},
        "other": {"title": "VLC media player 3.0.21.0", "version": "3.0.21.0"},
        "entity": {"entity_type": "ip_address", "value": "3.0.21.0"},
        "note": "Title 5.72.0.0 and address 5.72.0.0",
        "agent": {"version": "6.1.0.4"},
        "logons": {"6.1.0.4": 2},
    }
    assert _run(doc) == {
        "finding": {"title": "Steam 203.0.113.1", "installed_version": "2.10.91.91"},
        "eventdata": {"ipAddress": "::ffff:203.0.113.1"},
        "other": {"title": "VLC media player 203.0.113.2", "version": "3.0.21.0"},
        "entity": {"entity_type": "ip_address", "value": "203.0.113.2"},
        "note": "Title 203.0.113.3 and address 203.0.113.3",
        "agent": {"version": "6.1.0.4"},
        "logons": {"203.0.113.4": 2},
    }
    for key in ("src_ip", "srcip", "sourceIp", "ip", "clientAddress", "remote_addr"):
        assert _run({"version": "2.10.91.91", key: "2.10.91.91 port 22"})[key] == (
            "203.0.113.1 port 22"
        )


def test_neighbouring_addresses_are_told_apart() -> None:
    doc = {"m": "192.168.1.23 then 192.168.1.230 and 192.168.1.23:445, ::ffff:192.168.1.23"}
    assert _run(doc) == {
        "m": "203.0.113.1 then 203.0.113.2 and 203.0.113.1:445, ::ffff:203.0.113.1"
    }


def test_global_ipv6_addresses_are_replaced() -> None:
    doc = {
        "ipAddress": "3fff:0:1234:5600:a1b2:c3d4:e5f6:789",
        "note": "from [3FFF:0000:1234:5600:A1B2:C3D4:E5F6:0789]:443 and ipv6:fd12:3456:789a:1::23.",
    }
    assert _run(doc) == {
        "ipAddress": "2001:db8::1",
        "note": "from [2001:db8::1]:443 and ipv6:2001:db8::2.",
    }


def test_a_link_local_address_with_a_zone_is_replaced() -> None:
    message = "Source Network Address:\tfe80::3e52:82ff:feaa:bbcc%12\r\n"
    doc = {
        "ipAddress": "fe80::3e52:82ff:feaa:bbcc%12",
        "full_log": json.dumps({"message": message}),
        "iface": "FE80:0:0:0:3E52:82FF:FEAA:BBCC%eth0 up",
    }
    clean = _run(doc)
    assert clean["ipAddress"] == "2001:db8::1"
    assert json.loads(clean["full_log"]) == {"message": "Source Network Address:\t2001:db8::1\r\n"}
    assert clean["iface"] == "2001:db8::1 up"
    assert leftovers(clean, ["3e52", "82ff", "feaa", "bbcc"]) == []


def test_ipv6_loopback_is_kept_and_addresses_are_never_learned_as_hosts() -> None:
    doc = {
        "workstationName": "::1",
        "m": "Source Network Address: ::1 and [::1]:445 and :: and 127.0.0.1",
        "hostname": "fe80::1%3",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {**doc, "hostname": "2001:db8::1"}
    assert sanitizer.mapping == {"fe80::1": "2001:db8::1"}


def test_ipv4_mapped_ipv6_is_left_to_the_ipv4_rules() -> None:
    doc = {"src": "::ffff:192.168.1.23", "other": "192.168.1.23", "hex": "::ffff:c0a8:117"}
    assert _run(doc) == {"src": "::ffff:203.0.113.1", "other": "203.0.113.1", "hex": "2001:db8::1"}


def test_times_and_code_with_colons_are_not_ipv6() -> None:
    text = (
        "at 23:18:56 on 2026-09-29T23:18:56.123Z std::vector [Convert]::FromBase64String "
        r"a:b Class::Add( dead:beef C:\x"
    )
    doc = {"src": "fd12:3456:789a:1::23", "m": text}
    assert _run(doc) == {"src": "2001:db8::1", "m": text}


def test_powershell_static_members_are_not_ipv6() -> None:
    text = "[Math]::E and [System.Convert]::FromBase64String($x) and [Math]::PI"
    doc = {"src": "fd12:3456:789a:1::23", "m": text}
    assert _run(doc) == {"src": "2001:db8::1", "m": text}


def test_addresses_and_names_after_a_unicode_escape_are_replaced() -> None:
    doc = {
        "user": "jane.doe",
        "full_log": "\\u0022192.168.1.23\\u0022 \\u00223C:52:82:AA:BB:CC\\u0022 "
        "\\u0022fe80::1\\u0022 \\u0022jane.doe\\u0022 \\u00223c5282aabbcd\\u0022",
    }
    assert _run(doc)["full_log"] == (
        "\\u0022203.0.113.1\\u0022 \\u002200:00:5e:00:53:01\\u0022 "
        "\\u00222001:db8::1\\u0022 \\u0022user1\\u0022 \\u002200:00:5e:00:53:02\\u0022"
    )


def test_sanitizing_ipv6_twice_changes_nothing() -> None:
    doc = {
        "a": "fe80::3e52:82ff:feaa:bbcc%12",
        "b": "3fff::5 and ::ffff:192.168.1.23 and ::1",
        "c": "2001:db8::7",
    }
    first = _run(doc)
    assert first["c"] == "2001:db8::7"
    assert _run(first) == first


def test_mac_addresses_in_other_notations_are_replaced() -> None:
    doc = {
        "a": "3c5282aabbcc",
        "b": "3c52.82aa.bbcc",
        "c": "0x3C5282AABBCC",
        "d": "mac=3C:52:82:AA:BB:CC;",
    }
    assert _run(doc) == {
        "a": "00:00:5e:00:53:01",
        "b": "00:00:5e:00:53:01",
        "c": "00:00:5e:00:53:01",
        "d": "mac=00:00:5e:00:53:01;",
    }


def test_a_mac_glued_to_a_word_is_replaced_but_a_longer_hex_run_is_not() -> None:
    glued = {
        "a": "mac:3c:52:82:aa:bb:cc",
        "b": "BSSID:3C:52:82:AA:BB:CC",
        "c": "eth0:3c:52:82:aa:bb:cc",
        "d": "Device-3C-52-82-AA-BB-CC",
    }
    placeholder = "00:00:5e:00:53:01"
    expected = {
        "a": f"mac:{placeholder}",
        "b": f"BSSID:{placeholder}",
        "c": f"eth0:{placeholder}",
        "d": f"Device-{placeholder}",
    }
    assert _run(glued) == expected
    sanitizer = Sanitizer()
    sanitizer.learn({"m": "MAC 3C:52:82:AA:BB:CC"})
    assert sanitizer.apply(glued) == expected
    runs = {
        "eui": "3C-52-82-FF-FE-AA-BB-CC",
        "run": "id de:ad:be:ef:00:11:22 and a-3c-52-82-aa-bb-cd",
        "start": "de:ad:be:ef:00:11:22",
        "start1": "a-3c-52-82-aa-bb-cd",
        "v6": "fe80:0:12:34:56:78:9a:bc",
        "v6b": "fe80:1234:12:34:56:78:9a:bc",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(runs)
    assert sanitizer.apply(runs) == {**runs, "v6": "2001:db8::1", "v6b": "2001:db8::2"}
    assert sorted(sanitizer.mapping) == ["fe80:0:12:34:56:78:9a:bc", "fe80:1234:12:34:56:78:9a:bc"]


def test_hex_that_is_not_a_mac_is_kept() -> None:
    doc = {
        "mac": "3C:52:82:AA:BB:CC",
        "guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "number": "123456789012",
        "sha1": "3c5282aabbcc3c5282aabbcc3c5282aabbcc3c52",
        "keywords": "0x8010000000000000",
        "build": "1234.5678.9012",
    }
    assert _run(doc) == {**doc, "mac": "00:00:5e:00:53:01"}


def test_windows_machine_sids_are_generalised() -> None:
    doc = {
        "sid": "S-1-5-21-1234567890-987654321-1122334455-1001",
        "note": "s-1-5-21-1234567890-987654321-1122334455-500 and S-1-5-18",
    }
    assert _run(doc) == {
        "sid": "S-1-5-21-1000000000-1000000000-1000000000-1001",
        "note": "S-1-5-21-1000000000-1000000000-1000000000-500 and S-1-5-18",
    }


def test_azure_ad_sids_are_generalised() -> None:
    doc = {
        "sid": "S-1-12-1-1234567890-1234567890-1234567890-1234567890",
        "S-1-12-1-111-222-333-444": "as a key",
    }
    clean = _run(doc)
    placeholder = "S-1-12-1-1000000000-1000000000-1000000000-"
    assert clean == {"sid": f"{placeholder}1000000001", f"{placeholder}1000000000": "as a key"}
    assert _run(clean) == clean


def test_distinct_sids_get_distinct_placeholders() -> None:
    doc = {
        "perm": {"S-1-12-1-5-6-7-8": {"x": "b"}, "S-1-12-1-1-2-3-4": {"x": "a"}},
        "sids": {"S-1-5-21-10-5-6-1001": 2, "S-1-5-21-9-2-3-1001": 1},
        "note": "s-1-5-21-10-5-6-500 and S-1-12-1-5-6-7-8",
    }
    azure = "S-1-12-1-1000000000-1000000000-1000000000-"
    machine = "S-1-5-21-1000000000-1000000000-"
    clean = _run(doc)
    assert clean == {
        "perm": {f"{azure}1000000001": {"x": "b"}, f"{azure}1000000000": {"x": "a"}},
        "sids": {f"{machine}1000000001-1001": 2, f"{machine}1000000000-1001": 1},
        "note": f"{machine}1000000001-500 and {azure}1000000001",
    }
    assert _run(clean) == clean
    unlearned = Sanitizer().apply({"sid": "S-1-5-21-7-8-9-1001"})
    assert unlearned == {"sid": f"{machine}1000000000-1001"}
    mixed = {f"{machine}1000000000-500": 1, "S-1-5-21-5-2-3-500": 2}
    assert _run(mixed) == {f"{machine}1000000000-500": 1, f"{machine}1000000001-500": 2}


def test_unicode_case_variants_are_replaced_without_crashing() -> None:
    doc = {
        "user": "sam.smith",
        "targetUserName": "straße",
        "subjectUserName": "kim.lee",
        "hostname": "KELVIN-PC",
        "m": "ſam.ſmith, STRASSE, Straße, STRAẞE, KİM.LEE, kım.lee on \u212aELVIN-PC",
    }
    assert _run(doc)["m"] == "user2, user3, user3, user3, user1, user1 on HOST-2"


def test_apply_returns_a_new_value_and_keeps_the_input() -> None:
    snapshot = copy.deepcopy(DOC)
    sanitizer = Sanitizer()
    sanitizer.learn(DOC)
    clean = sanitizer.apply(DOC)
    assert DOC == snapshot
    assert clean is not DOC
    assert sanitizer.apply(("jane.doe", 5, None, True, 1.5)) == ["user1", 5, None, True, 1.5]


def test_apply_before_learning_changes_nothing() -> None:
    assert Sanitizer().apply(DOC) == DOC


def test_keys_are_sanitized_too() -> None:
    doc = {"jane.doe": {"user": "jane.doe"}}
    assert _run(doc) == {"user1": {"user": "user1"}}
