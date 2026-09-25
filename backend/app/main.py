from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException

from contracts.models import CONTRACT_VERSION, IncidentRun

REPO = Path(__file__).resolve().parents[2]

app = FastAPI(title="SENTINEL API", version="0.1.0")


def runs_dir() -> Path:
    return Path(os.environ.get("SENTINEL_RUNS_DIR", REPO / "runs"))


def load_runs() -> list[IncidentRun]:
    directory = runs_dir()
    if not directory.is_dir():
        return []
    runs = [
        IncidentRun.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(directory.glob("*.json"))
    ]
    return sorted(runs, key=lambda run: run.incident.created_at, reverse=True)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "contract_version": CONTRACT_VERSION}


@app.get("/api/runs", response_model=list[IncidentRun])
def list_runs() -> list[IncidentRun]:
    return load_runs()


@app.get("/api/runs/{incident_id}", response_model=IncidentRun)
def get_run(incident_id: str) -> IncidentRun:
    for run in load_runs():
        if run.incident.incident_id == incident_id:
            return run
    raise HTTPException(status_code=404, detail=f"no run for incident {incident_id}")
