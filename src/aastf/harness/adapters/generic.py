"""
Generic adapter — @instrument decorator for non-LangChain agent frameworks.

Usage:
    from aastf.harness.adapters.generic import instrument

    @instrument
    async def my_tool(query: str) -> dict:
        ...
"""

from __future__ import annotations

import contextvars
import functools
from collections.abc import Callable
from typing import Any

from ...models.trace import ToolInvocation, TraceEvent, TraceEventType
from ..collector import TraceCollector

# Context variable holds the active TraceCollector for the current async task
_current_collector: contextvars.ContextVar[TraceCollector | None] = (
    contextvars.ContextVar("_aastf_collector", default=None)
)


def set_collector(collector: TraceCollector | None) -> contextvars.Token:  # type: ignore[type-arg]
    """Set the active collector for the current async context. Returns a reset token."""
    return _current_collector.set(collector)


def get_collector() -> TraceCollector | None:
    return _current_collector.get()


def instrument(func: Callable | None = None, *, name: str | None = None) -> Any:
    """
    Decorator that instruments any async callable as a tracked tool.

    Can be used with or without arguments:

        @instrument
        async def web_search(query: str) -> dict: ...

        @instrument(name="search")
        async def web_search(query: str) -> dict: ...
    """
    def decorator(fn: Callable) -> Callable:
        tool_name = name or fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            collector = _current_collector.get()

            if collector:
                collector.record_event(TraceEvent(
                    event_type=TraceEventType.TOOL_START,
                    run_id=f"{tool_name}-start",
                    name=tool_name,
                    data={"args": str(args), "kwargs": str(kwargs)},
                ))

            try:
                result = await fn(*args, **kwargs)

                if collector:
                    collector.record_invocation(ToolInvocation(
                        tool_name=tool_name,
                        inputs={"args": str(args), "kwargs": str(kwargs)},
                        outputs=str(result),
                        sandbox_intercepted=False,
                    ))

                return result

            except Exception as e:
                if collector:
                    collector.record_event(TraceEvent(
                        event_type=TraceEventType.TOOL_ERROR,
                        run_id=f"{tool_name}-error",
                        name=tool_name,
                        data={"error": str(e)},
                    ))
                raise

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator
