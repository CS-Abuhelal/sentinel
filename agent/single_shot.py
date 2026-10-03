from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any

from agent.investigate import (
    SYSTEM_PROMPT,
    build_verdict,
    evidence_item,
    fallback_verdict,
    incident_message,
    parse_draft,
    utcnow,
)
from agent.llm import FinalAnswer, LLMClient, Message
from agent.tools import TOOLS, HostHistory, Tool, ToolContext
from contracts.models import (
    Alert,
    ChangeWindow,
    EntityType,
    EvaluationArm,
    Event,
    EvidenceItem,
    Incident,
    Inventory,
    InvestigationStopReason,
    Verdict,
)

SINGLE_SHOT_NOTE = (
    "In this run you have no tools. All the evidence is already below as refs E1 to E4, "
    "gathered for the incident's own account, host and source IP. Do not call tools. "
    "Answer once with the final JSON."
)


def _first(incident: Incident, entity_type: EntityType) -> str | None:
    return next(
        (entity.value for entity in incident.entities if entity.entity_type is entity_type), None
    )


def bundle_queries(incident: Incident) -> list[tuple[str, dict[str, Any]]]:
    account = _first(incident, EntityType.ACCOUNT)
    host = _first(incident, EntityType.HOST)
    ip = _first(incident, EntityType.IP_ADDRESS)
    queries: list[tuple[str, dict[str, Any]]] = []
    if account is not None:
        queries.append(("auth_history", {"account": account}))
        queries.append(("account_context", {"account": account}))
    if ip is not None:
        queries.append(("source_ip_history", {"ip": ip}))
    subjects = {"account": account, "host": host, "ip": ip}
    scoped = {name: value for name, value in subjects.items() if value is not None}
    if scoped:
        queries.append(("change_windows", scoped))
    return queries


def single_shot(
    incident: Incident,
    alerts: list[Alert],
    events: list[Event],
    llm: LLMClient,
    *,
    tools: dict[str, Tool] = TOOLS,
    now: Callable[[], datetime] = utcnow,
    history: HostHistory | None = None,
    inventory: Inventory | None = None,
    changes: list[ChangeWindow] | None = None,
    **_: Any,
) -> tuple[Verdict, list[EvidenceItem]]:
    started = time.perf_counter()
    context = ToolContext(
        incident=incident,
        events=events,
        history=history,
        inventory=inventory,
        changes=list(changes or []),
    )
    evidence: list[EvidenceItem] = []
    refs: dict[str, str] = {}
    shown: list[dict[str, Any]] = []
    for name, args in bundle_queries(incident):
        tool = tools[name]
        params = tool.params.model_validate(args)
        query = params.model_dump(mode="json")
        result = tool.run(params, context)
        item = evidence_item(tool, query, result, incident, now)
        ref = f"E{len(evidence) + 1}"
        evidence.append(item)
        refs[ref] = item.evidence_id
        shown.append(
            {
                "ref": ref,
                "tool": name,
                "data": {"summary": result.summary, "content": result.content},
            }
        )

    messages = [
        Message(
            "system", SYSTEM_PROMPT.replace("{max_tool_calls}", "0") + "\n\n" + SINGLE_SHOT_NOTE
        ),
        Message(
            "user",
            incident_message(incident, alerts) + "\n\nEvidence:\n" + json.dumps(shown, indent=2),
        ),
    ]
    response = llm.complete(messages, [])
    draft = parse_draft(response.payload, refs) if isinstance(response, FinalAnswer) else None
    stop = (
        InvestigationStopReason.VERDICT_REACHED if draft else InvestigationStopReason.INVALID_OUTPUT
    )
    common: dict[str, Any] = {
        "incident_id": incident.incident_id,
        "arm": EvaluationArm.A2B_FULL_CONTEXT,
        "produced_at": now(),
        "model_name": llm.model_name,
        "tool_calls_made": 0,
        "input_tokens": response.input_tokens,
        "output_tokens": response.output_tokens,
        "latency_ms": (
            response.elapsed_ms
            if response.elapsed_ms > 0
            else int((time.perf_counter() - started) * 1000)
        ),
        "stop_reason": stop,
    }
    if draft is None:
        return fallback_verdict(stop, common), evidence
    return build_verdict(draft, refs, common), evidence
