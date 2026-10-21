from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from backend.app.main import allowed_hosts, app
from contracts.models import IncidentRun
from tests.conftest import REPO

FIXTURE = REPO / "contracts" / "fixtures" / "incident_run.json"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SENTINEL_RUNS_DIR", str(tmp_path))
    return TestClient(app)


def _incident_id() -> str:
    return IncidentRun.model_validate_json(FIXTURE.read_text(encoding="utf-8")).incident.incident_id


def test_list_runs(client: TestClient, tmp_path: Path) -> None:
    shutil.copy(FIXTURE, tmp_path / "case.json")
    response = client.get("/api/runs")
    assert response.status_code == 200
    [run] = response.json()
    assert run["incident"]["incident_id"] == _incident_id()


def test_list_is_empty_without_runs(client: TestClient) -> None:
    assert client.get("/api/runs").json() == []


def test_get_run(client: TestClient, tmp_path: Path) -> None:
    shutil.copy(FIXTURE, tmp_path / "case.json")
    response = client.get(f"/api/runs/{_incident_id()}")
    assert response.status_code == 200
    assert IncidentRun.model_validate(response.json()).incident.incident_id == _incident_id()


def test_unknown_run_is_404(client: TestClient, tmp_path: Path) -> None:
    shutil.copy(FIXTURE, tmp_path / "case.json")
    assert client.get("/api/runs/inc_missing").status_code == 404


def test_malformed_run_file_fails_loudly(client: TestClient, tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text('{"case_id": "x"}', encoding="utf-8")
    with pytest.raises(ValidationError):
        client.get("/api/runs")


def test_health(client: TestClient) -> None:
    assert client.get("/health").json()["status"] == "ok"


def test_unknown_host_headers_are_refused(client: TestClient) -> None:
    assert client.get("/health", headers={"Host": "evil.test"}).status_code == 400
    for host in ("127.0.0.1:8000", "localhost:5173", "backend:8000", "sentinel-backend:8000"):
        assert client.get("/health", headers={"Host": host}).status_code == 200


def test_allowed_hosts_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SENTINEL_ALLOWED_HOSTS", raising=False)
    assert allowed_hosts() == [
        "127.0.0.1",
        "localhost",
        "backend",
        "sentinel-backend",
        "testserver",
    ]
    monkeypatch.setenv("SENTINEL_ALLOWED_HOSTS", " my-pc.test , 127.0.0.1 ,")
    assert allowed_hosts() == ["my-pc.test", "127.0.0.1"]
