from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.incidents import (
    get_run,
    incident_status,
    incident_summaries,
    queue_length,
    set_status,
)
from backend.app.probes import HttpProbe, get_model_probe, get_wazuh_probe
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from contracts.models import IncidentRun, IncidentStatus, PcFeed, PcStatus, ServiceState

NOT_RUN = ServiceState(reachable=False, detail="Backfill has not run.")

router = APIRouter(prefix="/api/pc")


def get_backfill_state(request: Request) -> ServiceState:
    return getattr(request.app.state, "backfill", NOT_RUN)


@router.get("/feed", response_model=PcFeed)
def feed(
    engine: Annotated[Engine, Depends(get_engine)],
    probe: Annotated[HttpProbe, Depends(get_wazuh_probe)],
    model: Annotated[HttpProbe, Depends(get_model_probe)],
    backfill_state: Annotated[ServiceState, Depends(get_backfill_state)],
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
    )
    return PcFeed(
        status=status, alerts=latest_alerts(engine, limit), incidents=incident_summaries(engine)
    )


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
    set_status(engine, incident_id, IncidentStatus.QUEUED, datetime.now(UTC))
    return {"status": "queued"}
