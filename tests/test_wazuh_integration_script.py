from __future__ import annotations

import importlib.util
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType

import pytest

from tests.conftest import REPO, wazuh_payload

SCRIPT = REPO / "lab" / "wazuh" / "integrations" / "custom-sentinel.py"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("custom_sentinel", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Receiver:
    def __init__(self, status: int) -> None:
        self.requests: list[tuple[str | None, bytes]] = []
        received = self.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers["Content-Length"])
                received.append((self.headers.get("Authorization"), self.rfile.read(length)))
                self.send_response(status)
                self.end_headers()

            def log_message(self, *args: object) -> None:
                return

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/ingest/wazuh"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Receiver:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def alert_file(tmp_path: Path) -> Path:
    path = tmp_path / "alert.json"
    path.write_text(json.dumps(wazuh_payload("logon_failure")), encoding="utf-8")
    return path


def test_posts_the_alert_with_the_token(alert_file: Path) -> None:
    with Receiver(202) as receiver:
        code = _script().main(["custom-sentinel", str(alert_file), "tok", receiver.url])
    assert code == 0
    [(authorization, body)] = receiver.requests
    assert authorization == "Bearer tok"
    assert json.loads(body) == wazuh_payload("logon_failure")


def test_a_rejected_alert_is_a_failure(alert_file: Path) -> None:
    with Receiver(401) as receiver:
        code = _script().main(["custom-sentinel", str(alert_file), "tok", receiver.url])
    assert code == 1


def test_an_unreachable_sentinel_is_a_failure(alert_file: Path) -> None:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}/api/ingest/wazuh"
    assert _script().main(["custom-sentinel", str(alert_file), "tok", url]) == 1


def test_invalid_json_is_never_sent(tmp_path: Path) -> None:
    path = tmp_path / "alert.json"
    path.write_text("not json", encoding="utf-8")
    with Receiver(202) as receiver:
        code = _script().main(["custom-sentinel", str(path), "tok", receiver.url])
    assert code == 1
    assert receiver.requests == []


def test_bad_usage() -> None:
    assert _script().main(["custom-sentinel"]) == 2
