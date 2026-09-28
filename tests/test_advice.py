from __future__ import annotations

import pytest

from contracts.models import Recommendation
from policy.advice import vet, weakens_security


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
    assert vetted.steps == ["Lock the screen when you leave."]
    assert vetted.dropped_steps == ["Too long: ...", "Turn off the firewall."]
    assert vetted.recommendation_id == advice.recommendation_id
