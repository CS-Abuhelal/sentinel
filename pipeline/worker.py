from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
from sqlalchemy.engine import Engine

from agent.investigate import PC_PROMPT
from agent.llm import LLMClient, RecordingClient, ReplayClient
from agent.ollama import DEFAULT_MODEL, OllamaClient
from agent.tools import WAZUH_TOOLS
from backend.app.db import get_engine
from backend.app.incidents import (
    StoreHistory,
    host_alerts,
    incident_alerts,
    next_queued_incident,
    save_run,
    set_status,
    unfinished_incidents,
)
from contracts.models import (
    Event,
    EventCategory,
    HostRecord,
    Incident,
    IncidentStatus,
    Inventory,
    InvestigationStopReason,
    LiveAlert,
    ServiceState,
)
from pipeline.grouping import group_new_alerts
from pipeline.run import run_incident

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 10
AUTH_LOOKBACK = timedelta(days=30)


def utcnow() -> datetime:
    return datetime.now(UTC)


def pc_inventory(hosts: Iterable[str]) -> Inventory:
    return Inventory(hosts={h: HostRecord(role="monitored PC", personal=True) for h in hosts})


def investigation_events(
    engine: Engine, incident: Incident, alerts: list[LiveAlert]
) -> list[Event]:
    host = alerts[0].event.host
    history = host_alerts(
        engine, host, incident.window_start - AUTH_LOOKBACK, incident.window_end
    )
    events = {a.event.event_id: a.event for a in alerts}
    for live in history:
        if live.event.category is EventCategory.AUTHENTICATION:
            events.setdefault(live.event.event_id, live.event)
    return sorted(events.values(), key=lambda e: (e.timestamp, e.event_id))


def investigate_next(
    engine: Engine, llm: LLMClient, now: Callable[[], datetime]
) -> str | None:
    incident = next_queued_incident(engine)
    if incident is None:
        return None
    incident_id = incident.incident_id
    set_status(engine, incident_id, IncidentStatus.INVESTIGATING, now())
    alerts = incident_alerts(engine, incident_id)
    try:
        host = alerts[0].event.host
        run = run_incident(
            f"pc-{incident_id}",
            investigation_events(engine, incident, alerts),
            [a.alert for a in alerts],
            incident,
            pc_inventory({a.event.host for a in alerts}),
            llm,
            now=now,
            tools=WAZUH_TOOLS,
            system_prompt=PC_PROMPT,
            history=StoreHistory(engine, host),
            runner_for=lambda _: None,
        )
    except Exception as error:
        logger.warning("Investigation of %s failed: %s", incident_id, error)
        set_status(engine, incident_id, IncidentStatus.INVESTIGATION_FAILED, now())
        return incident_id
    if run.verdict.stop_reason is not InvestigationStopReason.VERDICT_REACHED:
        run.incident.status = IncidentStatus.INVESTIGATION_FAILED
    save_run(engine, run, now())
    return incident_id


def model_state(
    base_url: str, model: str, transport: httpx.BaseTransport | None = None
) -> ServiceState:
    try:
        with httpx.Client(base_url=base_url, timeout=3.0, transport=transport) as client:
            response = client.get("/api/tags")
            response.raise_for_status()
            names = {m.get("name") for m in response.json().get("models", [])}
    except (httpx.HTTPError, ValueError) as error:
        return ServiceState(reachable=False, detail=f"Ollama unreachable: {error}")
    if model not in names:
        return ServiceState(reachable=False, detail=f"Ollama is up but {model} is not pulled.")
    return ServiceState(reachable=True, detail=f"Ollama has {model}.")


def run_once(
    engine: Engine, llm: LLMClient, now: Callable[[], datetime], model_ready: bool
) -> dict[str, object]:
    grouped = group_new_alerts(engine, now())
    investigated = investigate_next(engine, llm, now) if model_ready else None
    return {"grouped": grouped, "investigated": investigated}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pipeline.worker",
        description="Group the PC's Wazuh alerts into incidents and investigate the queue.",
    )
    parser.add_argument("--once", action="store_true", help="run one cycle and exit")
    parser.add_argument("--interval", type=float, default=INTERVAL_SECONDS)
    parser.add_argument("--llm", choices=["ollama", "replay"], default="ollama")
    parser.add_argument("--recording", type=Path, help="recording to replay with --llm replay")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--ollama-url", default=os.environ.get("OLLAMA_URL", "http://localhost:11434")
    )
    parser.add_argument(
        "--record-dir", type=Path, help="save each investigation's responses here"
    )
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    engine = get_engine()
    for incident_id in unfinished_incidents(engine):
        set_status(engine, incident_id, IncidentStatus.QUEUED, utcnow())
    while True:
        if args.llm == "replay":
            if args.recording is None:
                raise SystemExit("--llm replay needs --recording")
            base: LLMClient = ReplayClient.from_file(args.recording)
            ready = True
        else:
            base = OllamaClient(model=args.model, base_url=args.ollama_url)
            state = model_state(args.ollama_url, args.model)
            ready = state.reachable
            if not ready:
                logger.info("%s", state.detail)
        recorder = RecordingClient(base)
        result = run_once(engine, recorder, utcnow, ready)
        if result["grouped"] or result["investigated"]:
            logger.info(
                "grouped %s, investigated %s", result["grouped"], result["investigated"]
            )
        if args.record_dir and result["investigated"]:
            args.record_dir.mkdir(parents=True, exist_ok=True)
            path = args.record_dir / f"{result['investigated']}.json"
            path.write_text(
                recorder.recording().model_dump_json(indent=2) + "\n", encoding="utf-8"
            )
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
