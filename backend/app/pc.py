from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.findings import assessment, finding_hosts
from backend.app.incidents import (
    get_run,
    incident_status,
    incident_summaries,
    queue_length,
    requeue,
)
from backend.app.probes import HttpProbe, ModelProbe, get_model_probe, get_wazuh_probe
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from backend.app.sync import SyncRunner
from contracts.models import (
    HostAssessment,
    IncidentRun,
    IncidentStatus,
    PcFeed,
    PcStatus,
    ServiceState,
)

NOT_RUN = ServiceState(reachable=False, detail="Backfill has not run.")

router = APIRouter(prefix="/api/pc")


def get_backfill_state(request: Request) -> ServiceState:
    return getattr(request.app.state, "backfill", NOT_RUN)


def get_sync_runner(request: Request) -> SyncRunner:
    runner = getattr(request.app.state, "sync", None)
    return runner if isinstance(runner, SyncRunner) else SyncRunner(None)


@router.get("/feed", response_model=PcFeed)
def feed(
    engine: Annotated[Engine, Depends(get_engine)],
    probe: Annotated[HttpProbe, Depends(get_wazuh_probe)],
    model: Annotated[ModelProbe, Depends(get_model_probe)],
    backfill_state: Annotated[ServiceState, Depends(get_backfill_state)],
    runner: Annotated[SyncRunner, Depends(get_sync_runner)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> PcFeed:
    status = PcStatus(
        checked_at=datetime.now(UTC),
        wazuh_api=probe.state(),
        backfill=backfill_state,
        alert_count=alert_count(engine),
        last_alert_at=newest_alert_time(engine),
        queue_length=queue_length(engine),
        model=model.state(),
        sync=runner.state,
    )
    return PcFeed(
        status=status, alerts=latest_alerts(engine, limit), incidents=incident_summaries(engine)
    )


@router.get("/assessment", response_model=HostAssessment)
def host_assessment(
    engine: Annotated[Engine, Depends(get_engine)],
    host: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
) -> HostAssessment:
    hosts = finding_hosts(engine)
    target = host or (hosts[0] if hosts else None)
    view = assessment(engine, target, datetime.now(UTC)) if target else None
    if view is None:
        raise HTTPException(404, "No open findings yet. Rescan to pull them from Wazuh.")
    return view


@router.post("/rescan", status_code=202)
def rescan(runner: Annotated[SyncRunner, Depends(get_sync_runner)]) -> dict[str, str]:
    if not runner.configured:
        raise HTTPException(503, "WAZUH_INDEXER_URL is not set.")
    if not runner.start():
        raise HTTPException(409, "A sync is already running.")
    return {"status": "started"}


@router.get("/incidents/{incident_id}", response_model=IncidentRun)
def incident_run(incident_id: str, engine: Annotated[Engine, Depends(get_engine)]) -> IncidentRun:
    if incident_status(engine, incident_id) is None:
        raise HTTPException(404, f"No incident {incident_id}.")
    run = get_run(engine, incident_id)
    if run is None:
        raise HTTPException(409, "This incident has not been investigated yet.")
    return run


@router.post("/incidents/{incident_id}/retry", status_code=202)
def retry(incident_id: str, engine: Annotated[Engine, Depends(get_engine)]) -> dict[str, str]:
    status = incident_status(engine, incident_id)
    if status is None:
        raise HTTPException(404, f"No incident {incident_id}.")
    if status is not IncidentStatus.INVESTIGATION_FAILED:
        raise HTTPException(409, "Only a failed investigation can be retried.")
    requeue(engine, incident_id, datetime.now(UTC))
    return {"status": "queued"}
