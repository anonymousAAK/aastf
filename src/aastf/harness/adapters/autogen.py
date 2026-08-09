"""AutoGen (AG2) adapter for AASTF.

Instruments AutoGen agents by wrapping registered tools with the
AASTF instrument decorator prior to agent construction. AutoGen's
async-native run loop requires no additional threading wrappers.
"""

from __future__ import annotations

from typing import Any, Callable

from .generic import instrument


def wrap_tools(tools: list[Callable[..., Any] | dict[str, Any]]) -> list[Callable[..., Any] | dict[str, Any]]:
    """Wrap AutoGen-compatible tools with the AASTF instrument decorator.

    AutoGen agents accept tools as plain callables or dictionary definitions
    (e.g., ``FunctionTool`` kwargs). This utility inspects the provided list
    and wraps any callable so that invocations are captured by the
    TraceCollector via contextvars.

    Args:
        tools: A list of tool definitions as accepted by
               ``autogen.agentchat.AssistantAgent`` or AG2 core agents.

    Returns:
        A new list with all callables instrumented.
    """
    wrapped: list[Callable[..., Any] | dict[str, Any]] = []
    for tool in tools:
        if callable(tool):
            wrapped.append(instrument(tool))
        elif isinstance(tool, dict) and "func" in tool:
            tool_copy = tool.copy()
            tool_copy["func"] = instrument(tool["func"])
            wrapped.append(tool_copy)
        else:
            wrapped.append(tool)
    return wrapped
