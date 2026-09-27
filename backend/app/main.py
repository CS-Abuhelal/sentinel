from __future__ import annotations

import logging
import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException

from backend.app.backfill import IndexerSettings, backfill
from backend.app.db import get_engine
from backend.app.ingest import router as ingest_router
from backend.app.pc import router as pc_router
from contracts.models import CONTRACT_VERSION, IncidentRun, ServiceState

REPO = Path(__file__).resolve().parents[2]
logger = logging.getLogger(__name__)


def _backfill_in_background(app: FastAPI, settings: IndexerSettings) -> None:
    try:
        with settings.client() as client:
            app.state.backfill = backfill(get_engine(), client, datetime.now(UTC))
    except Exception as error:
        logger.warning("Wazuh backfill failed: %s", error)
        app.state.backfill = ServiceState(reachable=False, detail=f"Backfill failed: {error}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = IndexerSettings.from_env()
    if settings is None:
        app.state.backfill = ServiceState(reachable=False, detail="WAZUH_INDEXER_URL is not set.")
    else:
        app.state.backfill = ServiceState(reachable=False, detail="Backfill is running.")
        threading.Thread(
            target=_backfill_in_background, args=(app, settings), daemon=True
        ).start()
    yield


app = FastAPI(title="SENTINEL API", version="0.1.0", lifespan=lifespan)
app.include_router(ingest_router)
app.include_router(pc_router)


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
