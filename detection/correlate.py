from __future__ import annotations

from contracts.models import Alert, Entity, EntityType, Event, Incident, Inventory


def correlate(
    alerts: list[Alert], events: list[Event], inventory: Inventory, case_id: str | None = None
) -> list[Incident]:
    events_by_id = {e.event_id: e for e in events}
    groups: dict[tuple[str, str | None], list[Alert]] = {}
    for alert in sorted(alerts, key=lambda a: a.timestamp):
        groups.setdefault((alert.host, alert.user), []).append(alert)
    return [
        _incident(host, user, group, events_by_id, inventory, case_id)
        for (host, user), group in groups.items()
    ]


def _incident(
    host: str,
    user: str | None,
    alerts: list[Alert],
    events_by_id: dict[str, Event],
    inventory: Inventory,
    case_id: str | None,
) -> Incident:
    times = [events_by_id[i].timestamp for a in alerts for i in a.event_ids]
    entities = [_entity(EntityType.HOST, host, inventory)]
    if user is not None:
        entities.append(_entity(EntityType.ACCOUNT, user, inventory))
    for src_ip in dict.fromkeys(a.src_ip for a in alerts if a.src_ip):
        entities.append(_entity(EntityType.IP_ADDRESS, src_ip, inventory))
    title = (
        f"Possible account compromise: {user} on {host}"
        if user
        else f"Suspicious activity on {host}"
    )
    return Incident(
        title=title,
        created_at=alerts[-1].timestamp,
        window_start=min(times),
        window_end=max(times),
        alert_ids=[a.alert_id for a in alerts],
        entities=entities,
        case_id=case_id,
    )


def _entity(entity_type: EntityType, value: str, inventory: Inventory) -> Entity:
    return Entity(
        entity_type=entity_type,
        value=value,
        is_protected=inventory.is_protected(entity_type, value),
    )
