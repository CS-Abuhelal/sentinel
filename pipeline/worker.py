from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.engine import Connection, Engine

from agent.fix import write_fix
from agent.investigate import PC_PROMPT
from agent.llm import LLMClient, RecordingClient, ReplayClient
from agent.ollama import DEFAULT_MODEL, OllamaClient
from agent.ollama import model_state as model_state
from agent.tools import WAZUH_TOOLS
from backend.app.db import get_engine
from backend.app.findings import next_finding_to_advise, set_advice, unit_findings
from backend.app.incidents import (
    StoreHistory,
    host_auth_events,
    incident_alerts,
    next_queued_incident,
    requeue,
    save_run,
    set_status,
    unfinished_incidents,
)
from contracts.models import (
    Event,
    HostRecord,
    Incident,
    IncidentStatus,
    Inventory,
    InvestigationStopReason,
    LiveAlert,
)
from pipeline.grouping import group_new_alerts
from pipeline.run import run_incident
from policy.advice import check_fix

logger = logging.getLogger(__name__)

INTERVAL_SECONDS = 10
WORKER_LOCK = 0x53454E54
LOOKBACK = timedelta(days=30)
FIX_TOP = 10


def utcnow() -> datetime:
    return datetime.now(UTC)


def pc_inventory(hosts: Iterable[str]) -> Inventory:
    return Inventory(hosts={h: HostRecord(role="monitored PC", personal=True) for h in hosts})


def investigation_events(
    engine: Engine, incident: Incident, alerts: list[LiveAlert]
) -> list[Event]:
    host = alerts[0].event.host
    history = host_auth_events(
        engine, host, incident.window_start - LOOKBACK, incident.window_end
    )
    events = {a.event.event_id: a.event for a in alerts}
    for event in history:
        events.setdefault(event.event_id, event)
    return sorted(events.values(), key=lambda e: (e.timestamp, e.event_id))


def investigate_next(
    engine: Engine, llm: LLMClient, now: Callable[[], datetime]
) -> str | None:
    incident = next_queued_incident(engine)
    if incident is None:
        return None
    incident_id = incident.incident_id
    try:
        set_status(engine, incident_id, IncidentStatus.INVESTIGATING, now())
        alerts = incident_alerts(engine, incident_id)
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
            history=StoreHistory(
                engine,
                host,
                incident.window_start - LOOKBACK,
                incident.window_end + timedelta(seconds=1),
            ),
            runner_for=lambda _: None,
        )
    except Exception as error:
        logger.warning("Investigation of %s failed: %s", incident_id, error, exc_info=True)
        set_status(engine, incident_id, IncidentStatus.INVESTIGATION_FAILED, now())
        return incident_id
    if run.verdict.stop_reason is not InvestigationStopReason.VERDICT_REACHED:
        run.incident.status = IncidentStatus.INVESTIGATION_FAILED
    save_run(engine, run, now())
    return incident_id


def advise_next(engine: Engine, llm: LLMClient, now: Callable[[], datetime]) -> str | None:
    finding = next_finding_to_advise(engine, FIX_TOP)
    if finding is None:
        return None
    unit = unit_findings(engine, finding)
    other = [f.cve for f in unit if f.cve and f.cve != finding.cve]
    try:
        result = write_fix(finding, llm, other)
    except Exception as error:
        logger.warning("Fix steps for %s failed: %s", finding.finding_id, error)
        set_advice(engine, finding.finding_id, None, llm.model_name, now())
        return finding.finding_id
    checked = None
    if result.recommendation is not None:
        rec = result.recommendation.model_copy(
            update={"finding_ids": [f.finding_id for f in unit]}
        )
        checked = check_fix(rec, {f.finding_id: f for f in unit})
    set_advice(engine, finding.finding_id, checked, result.model_name, now())
    return finding.finding_id


def acquire_worker_lock(engine: Engine) -> Connection | None:
    connection = engine.connect()
    try:
        locked = connection.execute(select(func.pg_try_advisory_lock(WORKER_LOCK))).scalar_one()
        connection.commit()
    except Exception:
        connection.close()
        raise
    if not locked:
        connection.close()
        return None
    return connection


def release_worker_lock(connection: Connection) -> None:
    try:
        connection.execute(select(func.pg_advisory_unlock(WORKER_LOCK)))
        connection.commit()
    finally:
        connection.close()


def run_once(
    engine: Engine, llm: LLMClient, now: Callable[[], datetime], model_ready: bool
) -> dict[str, object]:
    grouped = group_new_alerts(engine, now())
    investigated = investigate_next(engine, llm, now) if model_ready else None
    advised = advise_next(engine, llm, now) if model_ready and investigated is None else None
    return {"grouped": grouped, "investigated": investigated, "advised": advised}


def cycle(
    engine: Engine, args: argparse.Namespace, ollama: LLMClient | None
) -> dict[str, object]:
    if ollama is None:
        base: LLMClient = ReplayClient.from_file(args.recording)
        ready = True
    else:
        base = ollama
        state = model_state(args.ollama_url, args.model)
        ready = state.reachable
        if not ready:
            logger.info("%s", state.detail)
    recorder = RecordingClient(base)
    result = run_once(engine, recorder, utcnow, ready)
    if result["grouped"] or result["investigated"] or result["advised"]:
        logger.info(
            "grouped %s, investigated %s, advised %s",
            result["grouped"],
            result["investigated"],
            result["advised"],
        )
    recorded = result["investigated"] or result["advised"]
    if args.record_dir and recorded:
        args.record_dir.mkdir(parents=True, exist_ok=True)
        path = args.record_dir / f"{recorded}.json"
        path.write_text(
            recorder.recording().model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
    return result


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
        "--ollama-url", default=os.environ.get("OLLAMA_URL") or "http://localhost:11434"
    )
    parser.add_argument(
        "--record-dir", type=Path, help="save each investigation's responses here"
    )
    args = parser.parse_args(argv)
    if args.llm == "replay" and args.recording is None:
        parser.error("--llm replay needs --recording")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    engine = get_engine()
    ollama = (
        OllamaClient(model=args.model, base_url=args.ollama_url) if args.llm == "ollama" else None
    )
    lock: Connection | None = None
    requeued = False
    try:
        while True:
            failed = False
            try:
                if lock is None:
                    lock = acquire_worker_lock(engine)
                    if lock is None:
                        logger.error("Another worker is already running.")
                        return 1
                if not requeued:
                    for incident_id in unfinished_incidents(engine):
                        requeue(engine, incident_id, utcnow())
                    requeued = True
                cycle(engine, args, ollama)
            except Exception:
                logger.exception("Worker cycle failed; trying again in %s s.", args.interval)
                failed = True
            if args.once:
                return 1 if failed else 0
            time.sleep(args.interval)
    finally:
        if lock is not None:
            release_worker_lock(lock)


if __name__ == "__main__":
    sys.exit(main())
