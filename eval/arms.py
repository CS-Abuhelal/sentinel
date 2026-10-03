from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from contracts.models import (
    Alert,
    Classification,
    EvaluationArm,
    Event,
    EvidenceItem,
    Incident,
    InvestigationStopReason,
    Severity,
    Verdict,
)

RULES_CONFIDENCE = {
    Severity.INFO: 0.3,
    Severity.LOW: 0.4,
    Severity.MEDIUM: 0.6,
    Severity.HIGH: 0.8,
    Severity.CRITICAL: 0.9,
}
ORDER = list(RULES_CONFIDENCE)


def rules_only(
    incident: Incident,
    alerts: list[Alert],
    events: list[Event],
    llm: Any,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    **_: Any,
) -> tuple[Verdict, list[EvidenceItem]]:
    top = max((alert.rule_severity for alert in alerts), key=ORDER.index)
    names = sorted({alert.rule_name for alert in alerts if alert.rule_severity is top})
    return (
        Verdict(
            incident_id=incident.incident_id,
            arm=EvaluationArm.A1_RULES_ONLY,
            classification=Classification.MALICIOUS,
            confidence=RULES_CONFIDENCE[top],
            summary=(
                f"Rule {', '.join(names)} fired. Rules alone call every alert like this "
                "malicious; they cannot look at context."
            ),
            produced_at=now(),
            stop_reason=InvestigationStopReason.VERDICT_REACHED,
        ),
        [],
    )
