from agent.tools.account_context import ACCOUNT_CONTEXT
from agent.tools.auth_history import AUTH_HISTORY
from agent.tools.base import HostHistory, Tool, ToolContext, ToolResult
from agent.tools.change_windows import CHANGE_WINDOWS
from agent.tools.source_ip_history import SOURCE_IP_HISTORY
from agent.tools.wazuh import HOST_POSTURE, PROCESS_ACTIVITY, RELATED_ALERTS, RULE_CONTEXT

TOOLS: dict[str, Tool] = {
    tool.name: tool for tool in (AUTH_HISTORY, ACCOUNT_CONTEXT, SOURCE_IP_HISTORY, CHANGE_WINDOWS)
}
WAZUH_TOOLS: dict[str, Tool] = {
    tool.name: tool
    for tool in (AUTH_HISTORY, RELATED_ALERTS, PROCESS_ACTIVITY, RULE_CONTEXT, HOST_POSTURE)
}

__all__ = ["TOOLS", "WAZUH_TOOLS", "HostHistory", "Tool", "ToolContext", "ToolResult"]
