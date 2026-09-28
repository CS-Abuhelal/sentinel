from agent.tools.auth_history import AUTH_HISTORY
from agent.tools.base import HostHistory, Tool, ToolContext, ToolResult
from agent.tools.wazuh import PROCESS_ACTIVITY, RELATED_ALERTS, RULE_CONTEXT

TOOLS: dict[str, Tool] = {tool.name: tool for tool in (AUTH_HISTORY,)}
WAZUH_TOOLS: dict[str, Tool] = {
    tool.name: tool
    for tool in (AUTH_HISTORY, RELATED_ALERTS, PROCESS_ACTIVITY, RULE_CONTEXT)
}

__all__ = ["TOOLS", "WAZUH_TOOLS", "HostHistory", "Tool", "ToolContext", "ToolResult"]
