from agent.tools.auth_history import AUTH_HISTORY
from agent.tools.base import Tool, ToolContext, ToolResult

TOOLS: dict[str, Tool] = {tool.name: tool for tool in (AUTH_HISTORY,)}

__all__ = ["TOOLS", "Tool", "ToolContext", "ToolResult"]
