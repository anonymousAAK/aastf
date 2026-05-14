"""
Sandbox tool factory — creates LangGraph-compatible @tool functions
that call the sandbox server instead of real backends.
"""

from __future__ import annotations

import re
from typing import Any

_TOOL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def validate_tool_name(name: str) -> str:
    """Validate that a tool name is safe for use in URLs and identifiers."""
    if not _TOOL_NAME_RE.match(name):
        raise ValueError(
            f"Invalid tool name {name!r}: must match ^[a-zA-Z_][a-zA-Z0-9_]*$"
        )
    return name


def create_sandbox_tools(base_url: str, tool_names: list[str]) -> list[Any]:
    """
    Return a list of LangGraph @tool-decorated async functions, each wired
    to POST {base_url}/tools/{name} with the call kwargs as JSON.

    Args:
        base_url: Sandbox base URL, e.g. "http://127.0.0.1:18080"
        tool_names: List of tool names to create, e.g. ["web_search", "send_email"]

    Returns:
        List of LangGraph-compatible tool objects.
    """
    try:
        from langchain_core.tools import tool as lc_tool
    except ImportError as e:
        raise ImportError(
            "langchain-core is required for create_sandbox_tools. "
            "Install with: pip install 'aastf[langgraph]'"
        ) from e

    tools = []

    def _make_tool(name: str):
        async def _tool_fn(**kwargs: Any) -> dict[str, Any]:
            import httpx

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{base_url}/tools/{name}",
                    json=kwargs,
                    timeout=15.0,
                )
                if response.status_code >= 500:
                    return {"error": response.text, "tool": name}
                try:
                    return response.json()
                except Exception:
                    return {"raw": response.text, "tool": name}

        _tool_fn.__name__ = name
        _tool_fn.__doc__ = f"Sandbox-wired tool: {name}. Calls {base_url}/tools/{name}."
        return lc_tool(_tool_fn)

    for tool_name in tool_names:
        validate_tool_name(tool_name)
        tools.append(_make_tool(tool_name))

    return tools
