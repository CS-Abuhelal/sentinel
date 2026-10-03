from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from agent.tools.base import Tool, ToolContext, ToolResult
from contracts.models import EvidenceClass


class AccountContextParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account: str = Field(min_length=1, max_length=256)


def account_context(params: AccountContextParams, context: ToolContext) -> ToolResult:
    inventory = context.inventory
    record = inventory.accounts.get(params.account) if inventory else None
    content = {
        "account": params.account,
        "known": record is not None,
        "role": record.role if record else None,
        "privileged": record.privileged if record else False,
        "protected": record.protected if record else False,
    }
    if record is None:
        summary = f"{params.account} is not in the inventory."
    else:
        flags = [flag for flag in ("privileged", "protected") if content[flag]]
        summary = f"{params.account}: {record.role}" + "".join(f", {f}" for f in flags) + "."
    return ToolResult(summary=summary, content=content, source_event_ids=[])


ACCOUNT_CONTEXT = Tool(
    name="account_context",
    description=(
        "What the inventory says about one account: its role, and whether it is privileged or "
        "protected. Says so when the account is not in the inventory."
    ),
    params=AccountContextParams,
    evidence_class=EvidenceClass.ENTITY_CONTEXT,
    run=account_context,
)
