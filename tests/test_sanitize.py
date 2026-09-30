from __future__ import annotations

import copy
import json
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
                    "processName": "C:\\\\Users\\\\jane.doe\\\\AppData\\\\app.exe",
                },
            }
        },
        "full_log": "Login by jane.doe from 192.168.1.23 on DESKTOP-9QXZ7 (mac 3C:52:82:AA:BB:CC)",
        "message": "C:\\Users\\Jane.Doe\\Documents and C:\\Users\\Public\\x",
    },
    "loopback": "127.0.0.1 and ::1",
    "keep": "sentinel-test-nobody on my-pc",
}

WAZUH_FIXTURES = sorted((Path(__file__).parent / "data" / "wazuh").glob("*.json"))


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
    assert "\\\\Users\\\\user1\\\\AppData" in eventdata["processName"]
    assert "C:\\Users\\user1\\Documents" in clean["raw"]["message"]
    assert "C:\\Users\\Public\\x" in clean["raw"]["message"]
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


def test_leftovers_looks_at_keys_numbers_and_ignores_blank_terms() -> None:
    assert leftovers({"jane.doe": 1}, ["jane"]) == ["jane"]
    assert leftovers({"port": 4433, "nested": [{"n": 4433}]}, ["4433"]) == ["4433"]
    assert leftovers({"a": "ja", "b": "ne"}, ["jane"]) == []
    assert leftovers(DOC, ["", "  "]) == []


def test_short_user_names_are_never_learned() -> None:
    doc = {
        "event": {"user": "al", "host": "DESKTOP-9QXZ7"},
        "raw": {
            "targetUserName": "ed",
            "message": "Also a final total by al and ed at C:\\Users\\al\\x and C:\\Users\\ed\\x",
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
        "a": "C:\\\\Users\\\\amy.smith\\\\x",
        "b": "C:/Users/bob.jones/y",
        "c": "d:\\Users\\cy.lee\\z",
        "d": "C:\\Users\\dan.kim. C:\\Users\\All Users\\Microsoft and C:\\Users\\%USERNAME%\\x",
        "e": "C:\\Users\\Default User\\q and C:\\Users\\Default\\q and C:\\Users\\Public",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {
        "a": "C:\\\\Users\\\\user1\\\\x",
        "b": "C:/Users/user2/y",
        "c": "d:\\Users\\user3\\z",
        "d": "C:\\Users\\user4. C:\\Users\\All Users\\Microsoft and C:\\Users\\%USERNAME%\\x",
        "e": "C:\\Users\\Default User\\q and C:\\Users\\Default\\q and C:\\Users\\Public",
    }
    assert sorted(sanitizer.mapping) == ["amy.smith", "bob.jones", "cy.lee", "dan.kim"]


def test_a_profile_folder_with_a_space_or_an_apostrophe_is_replaced_whole() -> None:
    doc = {
        "a": "C:\\Users\\Jane Doe\\AppData\\x.exe",
        "b": "c:\\users\\jane doe\\desktop\\notes.txt",
        "c": "C:\\Users\\O'Brien\\AppData\\x",
        "d": "C:\\Users\\Doe,Jane\\x",
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean == {
        "a": "C:\\Users\\user4\\AppData\\x.exe",
        "b": "c:\\users\\user4\\desktop\\notes.txt",
        "c": "C:\\Users\\user5\\AppData\\x",
        "d": "C:\\Users\\user2\\x",
    }
    assert sorted(sanitizer.mapping) == ["doe", "doe,jane", "jane", "jane doe", "o'brien"]
    assert leftovers(clean, ["jane", "doe", "brien"]) == []


def test_a_profile_path_followed_by_more_text_learns_only_the_folder() -> None:
    doc = {"cmd": "dir C:\\Users\\amy.smith /s /b", "note": "amy.smith"}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sanitizer.apply(doc) == {"cmd": "dir C:\\Users\\user1 /s /b", "note": "user1"}
    assert sorted(sanitizer.mapping) == ["amy.smith"]


def test_percent_encoded_profile_folders_are_replaced() -> None:
    doc = {"a": "C%3A%5CUsers%5CJane%20Doe%5Cx", "b": "file:///C:/Users/Jane%20Doe/notes.txt"}
    clean = _run(doc)
    assert clean == {"a": "C%3A%5CUsers%5Cuser2%5Cx", "b": "file:///C:/Users/user2/notes.txt"}
    assert leftovers(clean, ["jane", "doe"]) == []


def test_profile_paths_in_other_forms_are_learned() -> None:
    doc = {
        "device": "\\Device\\HarddiskVolume3\\Users\\amy.smith\\x.exe",
        "wsl": "/mnt/c/Users/bob.jones/x",
        "msys": "/c/Users/cy.lee/x",
        "env": "%SystemDrive%\\Users\\dan.kim\\x",
        "doubled": "C://Users//eve.ross//x",
        "old": "C:\\Documents and Settings\\fay.wong\\x",
        "encoded": "C%3A%5CUsers%5Cgus.hill%5Cx",
    }
    assert _run(doc) == {
        "device": "\\Device\\HarddiskVolume3\\Users\\user1\\x.exe",
        "wsl": "/mnt/c/Users/user2/x",
        "msys": "/c/Users/user3/x",
        "env": "%SystemDrive%\\Users\\user4\\x",
        "doubled": "C://Users//user5//x",
        "old": "C:\\Documents and Settings\\user6\\x",
        "encoded": "C%3A%5CUsers%5Cuser7%5Cx",
    }


def test_domain_qualified_accounts_are_split() -> None:
    doc = [
        {"host": "DESKTOP-9QXZ7"},
        {"user": "DESKTOP-9QXZ7\\\\jane.doe"},
        {"user": "NT AUTHORITY\\SYSTEM"},
        {"user": "Window Manager\\DWM-1"},
        {"user": "Font Driver Host\\UMFD-0"},
    ]
    assert _run(doc) == [
        {"host": "MY-PC"},
        {"user": "MY-PC\\\\user1"},
        {"user": "NT AUTHORITY\\SYSTEM"},
        {"user": "Window Manager\\DWM-1"},
        {"user": "Font Driver Host\\UMFD-0"},
    ]


def test_the_domain_of_an_account_is_learned_as_a_host() -> None:
    doc = {"user": "ZULU-BOX\\jane.doe", "message": "on ZULU-BOX by jane.doe"}
    assert _run(doc) == {"user": "HOST-2\\user1", "message": "on HOST-2 by user1"}


def test_the_domain_of_a_built_in_account_is_learned_too() -> None:
    doc = {"user": "ZULU-BOX\\Administrator", "message": "on ZULU-BOX"}
    assert _run(doc) == {"user": "HOST-2\\Administrator", "message": "on HOST-2"}


def test_built_in_pseudo_domains_are_kept() -> None:
    doc = {
        "a": {"user": "NT SERVICE\\TrustedInstaller"},
        "b": {"user": "IIS APPPOOL\\DefaultAppPool"},
        "c": {
            "subjectDomainName": "WORKGROUP",
            "targetDomainName": "MicrosoftAccount",
            "user": "AzureAD\\amy.smith",
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
    expected["c"]["user"] = "AzureAD\\user1"
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
        "user": "ZULU-GAMING-LAP\\amy.smith",
    }
    assert _run(doc) == {
        "computer": "MY-PC",
        "eventdata": {"subjectDomainName": "MY-PC", "subjectUserName": "user1"},
        "user": "MY-PC\\user1",
    }


def test_a_host_field_with_leading_backslashes_is_learned() -> None:
    doc = {"workstation": "\\\\ZULU-BOX", "note": "from zulu-box"}
    assert _run(doc) == {"workstation": "\\\\HOST-2", "note": "from HOST-2"}


def test_unc_hosts_are_learned_but_escaped_root_paths_are_not() -> None:
    doc = {
        "a": "\\\\ZULU-NAS\\photos\\x and \\\\zulu-nas\\ipc$",
        "full_log": json.dumps(
            {
                "share": "\\\\ALPHA-BOX\\c$",
                "image": "\\Device\\HarddiskVolume3\\x.exe",
                "path": "C:\\Windows\\System32\\x.exe",
            }
        ),
    }
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    clean = sanitizer.apply(doc)
    assert clean["a"] == "\\\\HOST-3\\photos\\x and \\\\HOST-3\\ipc$"
    assert json.loads(clean["full_log"]) == {
        "share": "\\\\HOST-2\\c$",
        "image": "\\Device\\HarddiskVolume3\\x.exe",
        "path": "C:\\Windows\\System32\\x.exe",
    }
    assert sorted(sanitizer.mapping) == ["ALPHA-BOX", "ZULU-NAS"]


def test_the_last_segment_of_an_escaped_path_is_not_a_unc_host() -> None:
    message = (
        "Process Name:\tC:\\Windows\\System32\\svchost.exe\r\n"
        "File:\tC:\\hiberfil.sys\r\nShare Name:\t\\\\ZULU-NAS\\photos\r\n"
    )
    doc = {"full_log": json.dumps({"message": message}), "message": message}
    sanitizer = Sanitizer()
    sanitizer.learn(doc)
    assert sorted(sanitizer.mapping) == ["ZULU-NAS"]
    assert sanitizer.apply(doc)["message"] == message.replace("ZULU-NAS", "HOST-2")


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


def test_sysmon_and_account_management_user_fields_are_learned() -> None:
    doc = {
        "eventdata": {
            "sourceUser": "ZULU-BOX\\amy.smith",
            "targetUser": "NT AUTHORITY\\SYSTEM",
            "parentUser": "ZULU-BOX\\bob.jones",
            "userPrincipalName": "cy.lee@example.org",
            "displayName": "%%1793",
        },
        "note": "amy.smith bob.jones cy.lee %%1793 zulu-box",
    }
    assert _run(doc) == {
        "eventdata": {
            "sourceUser": "HOST-2\\user1",
            "targetUser": "NT AUTHORITY\\SYSTEM",
            "parentUser": "HOST-2\\user2",
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
        "Network Information: Workstation Name: ALPHA-BOX Source Network Address: 192.168.1.23"
    )
    doc = {"content": {"example": example}, "note": "amy.smith on zulu-box from alpha-box"}
    clean = _run(doc)
    assert clean["note"] == "user1 on HOST-3 from HOST-2"
    assert clean["content"]["example"] == (
        example.replace("ZULU-BOX", "HOST-3")
        .replace("amy.smith", "user1")
        .replace("ALPHA-BOX", "HOST-2")
        .replace("192.168.1.23", "203.0.113.1")
    )


def test_the_local_part_of_an_email_account_is_learned() -> None:
    doc = {
        "targetUserName": "jane.doe@example.org",
        "user": "MicrosoftAccount\\amy.smith@example.net",
        "note": (
            "jane.doe signed in as JANE.DOE@EXAMPLE.ORG; amy.smith; mail zed.quinn@example.com."
        ),
    }
    assert _run(doc) == {
        "targetUserName": "user2",
        "user": "MicrosoftAccount\\user1",
        "note": "user2 signed in as user2; user1; mail user3.",
    }


def test_role_mailboxes_are_replaced_whole_without_learning_their_local_part() -> None:
    doc = {"cmd": "git clone git@github.com:zulu/repo.git", "m": "mail noreply@example.org on git"}
    assert _run(doc) == {"cmd": "git clone user1:zulu/repo.git", "m": "mail user2 on git"}


def test_addresses_and_names_in_dict_keys_are_learned() -> None:
    doc = {
        "event": {"user": "jane.doe"},
        "raw": {
            "baseline_successes": {"192.168.1.50": 3, "fe80::1": 1},
            "by_user": {"jane.doe": 2, "amy.smith": 1},
            "by_mac": {"3C:52:82:AA:BB:CC": 1},
            "files": {"C:\\Users\\bob.jones\\x": 1},
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
        "files": {"C:\\Users\\user2\\x": 1},
        "mail": {"user3": 1},
        "S-1-5-21-1000000000-1000000000-1000000000-1001": "sid",
        "inventory": {"hosts": {"HOST-2": {"role": "nas"}}},
    }
    assert _run(clean) == clean


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


def test_agent_ids_are_replaced_only_as_whole_strings() -> None:
    doc = {"agent": {"id": "007", "name": "my-pc"}, "note": "rule 007 on 0070", "ids": ["007"]}
    clean = _run(doc)
    assert clean["agent"]["id"] == "001"
    assert clean["note"] == "rule 007 on 0070"
    assert clean["ids"] == ["001"]


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
        "a:b Class::Add( dead:beef C:\\x"
    )
    doc = {"src": "fd12:3456:789a:1::23", "m": text}
    assert _run(doc) == {"src": "2001:db8::1", "m": text}


def test_sanitizing_ipv6_twice_changes_nothing() -> None:
    doc = {
        "a": "fe80::3e52:82ff:feaa:bbcc%12",
        "b": "3fff::5 and ::ffff:192.168.1.23 and ::1",
        "c": "2001:db8::7",
    }
    first = _run(doc)
    assert first["c"] == "2001:db8::7"
    assert _run(first) == first


def test_windows_machine_sids_are_generalised() -> None:
    doc = {
        "sid": "S-1-5-21-1234567890-987654321-1122334455-1001",
        "note": "s-1-5-21-1234567890-987654321-1122334455-500 and S-1-5-18",
    }
    assert _run(doc) == {
        "sid": "S-1-5-21-1000000000-1000000000-1000000000-1001",
        "note": "S-1-5-21-1000000000-1000000000-1000000000-500 and S-1-5-18",
    }


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
