from __future__ import annotations

import hmac
import json
import os
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.engine import Engine
from starlette.concurrency import run_in_threadpool

from backend.app.db import get_engine
from backend.app.store import insert_alert
from ingest.wazuh import WazuhAlertError, live_alert

MAX_BODY_BYTES = 1_000_000
TOO_LARGE = "Alert is larger than 1 MB."

router = APIRouter()


def _check_token(request: Request) -> None:
    token = os.environ.get("SENTINEL_INGEST_TOKEN")
    if not token:
        raise HTTPException(503, "Ingest is off: SENTINEL_INGEST_TOKEN is not set.")
    supplied = request.headers.get("authorization", "")
    if not hmac.compare_digest(supplied.encode(), f"Bearer {token}".encode()):
        raise HTTPException(401, "Wrong or missing ingest token.")


async def _read_json(request: Request) -> dict[str, Any]:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise HTTPException(413, TOO_LARGE)
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            raise HTTPException(413, TOO_LARGE)
    try:
        payload = json.loads(body)
    except ValueError as error:
        raise HTTPException(422, "Alert is not valid JSON.") from error
    if not isinstance(payload, dict):
        raise HTTPException(422, "Alert must be a JSON object.")
    return payload


@router.post("/api/ingest/wazuh", status_code=202)
async def ingest_wazuh(
    request: Request, engine: Annotated[Engine, Depends(get_engine)]
) -> dict[str, bool]:
    _check_token(request)
    payload = await _read_json(request)
    try:
        live = live_alert(payload, received_at=datetime.now(UTC))
    except WazuhAlertError as error:
        raise HTTPException(422, str(error)) from error
    stored = await run_in_threadpool(insert_alert, engine, live, payload)
    return {"stored": stored}
