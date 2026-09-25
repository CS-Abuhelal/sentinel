from __future__ import annotations

import re
import subprocess
from typing import Protocol

from contracts.models import CommandResult

_CONTAINER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
_MAX_OUTPUT = 2000


class Runner(Protocol):
    dry_run: bool

    def run(self, argv: list[str]) -> CommandResult: ...


class DryRunRunner:
    dry_run = True

    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def run(self, argv: list[str]) -> CommandResult:
        self.calls.append(list(argv))
        return CommandResult(argv=list(argv), exit_code=0, output="dry run: not executed")


class DockerRunner:
    dry_run = False

    def __init__(self, container: str, docker: str = "docker", timeout: float = 60.0) -> None:
        if not _CONTAINER.fullmatch(container):
            raise ValueError(f"not a valid container name: {container!r}")
        self._container = container
        self._docker = docker
        self._timeout = timeout

    def run(self, argv: list[str]) -> CommandResult:
        try:
            completed = subprocess.run(
                [self._docker, "exec", self._container, *argv],
                capture_output=True,
                text=True,
                timeout=self._timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CommandResult(argv=list(argv), exit_code=-1, output=str(exc)[:_MAX_OUTPUT])
        output = (completed.stdout + completed.stderr).strip()
        return CommandResult(
            argv=list(argv), exit_code=completed.returncode, output=output[-_MAX_OUTPUT:]
        )
