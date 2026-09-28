from __future__ import annotations

from datetime import datetime

from sqlalchemy.engine import Engine

from backend.app.incidents import (
    find_open_incident,
    mark_grouped,
    save_incident_and_mark,
    ungrouped_alerts,
)
from contracts.models import (
    Entity,
    EntityType,
    Incident,
    IncidentStatus,
    LiveAlert,
    PcIncidentSummary,
)
from ingest.wazuh import POSTURE_GROUPS as POSTURE_GROUPS
from ingest.wazuh import is_posture as _payload_is_posture

INVESTIGATE_LEVEL = 7


def is_posture(live: LiveAlert) -> bool:
    return _payload_is_posture(live.event.raw)


def group_key(live: LiveAlert) -> str:
    techniques = live.alert.suggested_techniques
    return f"{live.event.host}|{techniques[0] if techniques else live.alert.rule_id}"


def triage(max_level: int) -> IncidentStatus:
    return (
        IncidentStatus.QUEUED
        if max_level >= INVESTIGATE_LEVEL
        else IncidentStatus.LOW_PRIORITY
    )


def new_incident(live: LiveAlert) -> Incident:
    return Incident(
        title=f"{live.alert.rule_name} on {live.event.host}",
        status=triage(live.level),
        created_at=live.event.timestamp,
        window_start=live.event.timestamp,
        window_end=live.event.timestamp,
        alert_ids=[live.alert.alert_id],
        entities=_entities([], live),
    )


def extend_incident(summary: PcIncidentSummary, live: LiveAlert) -> PcIncidentSummary:
    max_level = max(summary.max_level, live.level)
    incident = summary.incident.model_copy(
        update={
            "status": triage(max_level),
            "window_start": min(summary.incident.window_start, live.event.timestamp),
            "window_end": max(summary.incident.window_end, live.event.timestamp),
            "alert_ids": [*summary.incident.alert_ids, live.alert.alert_id],
            "entities": _entities(summary.incident.entities, live),
        }
    )
    return PcIncidentSummary(
        incident=incident, alert_count=summary.alert_count + 1, max_level=max_level
    )


def group_new_alerts(engine: Engine, now: datetime) -> int:
    handled = 0
    for live in ungrouped_alerts(engine):
        handled += 1
        if is_posture(live):
            mark_grouped(engine, live.wazuh_id, None, now)
            continue
        host = live.event.host
        key = group_key(live)
        summary = find_open_incident(engine, host, key, live.event.timestamp)
        if summary is None:
            summary = PcIncidentSummary(
                incident=new_incident(live), alert_count=1, max_level=live.level
            )
        else:
            summary = extend_incident(summary, live)
        save_incident_and_mark(
            engine,
            summary.incident,
            host,
            key,
            summary.alert_count,
            summary.max_level,
            live.wazuh_id,
            now,
        )
    return handled


def _entities(existing: list[Entity], live: LiveAlert) -> list[Entity]:
    candidates = [Entity(entity_type=EntityType.HOST, value=live.event.host)]
    if live.event.user:
        candidates.append(Entity(entity_type=EntityType.ACCOUNT, value=live.event.user))
    if live.event.network and live.event.network.src_ip:
        candidates.append(
            Entity(entity_type=EntityType.IP_ADDRESS, value=live.event.network.src_ip)
        )
    seen = {(e.entity_type, e.value) for e in existing}
    merged = list(existing)
    for entity in candidates:
        if (entity.entity_type, entity.value) not in seen:
            seen.add((entity.entity_type, entity.value))
            merged.append(entity)
    return merged
