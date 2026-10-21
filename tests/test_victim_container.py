from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from contracts.models import ActionType, EntityType, ExecutionStatus
from executor.core import execute
from executor.runners import DockerRunner
from tests.conftest import REPO
from tests.test_executor import _action, _approval, _decision

DOCKER = os.environ.get("SENTINEL_DOCKER", "")
IMAGE = "sentinel-victim:test"
HOST = "victim-web-01"
NOW = datetime(2026, 9, 25, 2, 30, tzinfo=UTC)

pytestmark = pytest.mark.skipif(
    not DOCKER, reason="set SENTINEL_DOCKER to test against real containers"
)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run([DOCKER, *args], capture_output=True, text=True, check=check)


@pytest.fixture(scope="module")
def lab_network() -> Iterator[str]:
    _docker("build", "-q", "-t", IMAGE, str(REPO / "lab" / "victim"))
    network = f"sentinel-test-{uuid4().hex[:8]}"
    _docker("network", "create", network)
    yield network
    _docker("network", "rm", network, check=False)


@pytest.fixture
def victim(lab_network: str) -> Iterator[str]:
    name = f"sentinel-victim-{uuid4().hex[:8]}"
    _docker("run", "-d", "--cap-add", "NET_ADMIN", "--network", lab_network, "--name", name, IMAGE)
    yield name
    _docker("rm", "-f", name, check=False)


@pytest.fixture
def peer(lab_network: str) -> Iterator[str]:
    name = f"sentinel-peer-{uuid4().hex[:8]}"
    _docker("run", "-d", "--network", lab_network, "--name", name, IMAGE, "nc", "-lk", "-p", "8080")
    yield name
    _docker("rm", "-f", name, check=False)


def _run(s1, victim: str, action):
    decision = _decision(s1.incident, action)
    runner = DockerRunner(victim, docker=DOCKER)
    return execute(
        decision,
        action,
        s1.incident,
        s1.inventory,
        _approval(decision),
        {HOST: runner}.get,
        lambda: NOW,
    )


def test_disable_account_locks_the_account_and_ends_its_session(s1, victim: str) -> None:
    _docker("exec", "-d", "-u", "jdoe", victim, "sleep", "3600")
    assert _docker("exec", victim, "pgrep", "-u", "jdoe", check=False).returncode == 0
    [result] = _run(s1, victim, _action())
    assert result.status is ExecutionStatus.SUCCEEDED, result.reason
    assert result.verified is True
    assert result.before[0].output.split()[1] == "P"
    assert result.before[1].exit_code == 0
    assert result.verification[0].output.split()[1] == "L"
    assert result.verification[1].exit_code == 1
    assert _docker("exec", victim, "pgrep", "-u", "jdoe", check=False).returncode == 1


def test_isolate_host_stops_traffic(s1, victim: str, peer: str) -> None:
    def reachable() -> bool:
        probe = _docker("exec", victim, "nc", "-z", "-w", "2", peer, "8080", check=False)
        return probe.returncode == 0

    assert reachable()
    [result] = _run(s1, victim, _action(ActionType.ISOLATE_HOST, EntityType.HOST, HOST))
    assert result.status is ExecutionStatus.SUCCEEDED, result.reason
    assert result.verified is True
    assert not reachable()
