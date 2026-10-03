from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.engine import Engine

from backend.app.db import get_engine
from backend.app.store import alert_count, latest_alerts, newest_alert_time
from backend.app.wazuh import WazuhApiProbe, get_wazuh_probe
from contracts.models import PcFeed, PcStatus, ServiceState

NOT_RUN = ServiceState(reachable=False, detail="Backfill has not run.")

router = APIRouter(prefix="/api/pc")


def get_backfill_state(request: Request) -> ServiceState:
    return getattr(request.app.state, "backfill", NOT_RUN)


@router.get("/feed", response_model=PcFeed)
def feed(
    engine: Annotated[Engine, Depends(get_engine)],
    probe: Annotated[WazuhApiProbe, Depends(get_wazuh_probe)],
    backfill_state: Annotated[ServiceState, Depends(get_backfill_state)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
) -> PcFeed:
    status = PcStatus(
        checked_at=datetime.now(UTC),
        wazuh_api=probe.state(),
        backfill=backfill_state,
        alert_count=alert_count(engine),
        last_alert_at=newest_alert_time(engine),
    )
    return PcFeed(status=status, alerts=latest_alerts(engine, limit))
