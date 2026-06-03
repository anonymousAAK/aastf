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
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import anyio

from ...models.scenario import AttackScenario, InjectionPoint
from ...models.trace import AgentTrace, ToolInvocation, TraceEvent, TraceEventType
from ..collector import TraceCollector

if TYPE_CHECKING:
    from ...sandbox.server import SandboxServer

# Context variable holds the active TraceCollector for the current async task
_current_collector: contextvars.ContextVar[TraceCollector | None] = contextvars.ContextVar(
    "_aastf_collector", default=None
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
                collector.record_event(
                    TraceEvent(
                        event_type=TraceEventType.TOOL_START,
                        run_id=f"{tool_name}-start",
                        name=tool_name,
                        data={"args": str(args), "kwargs": str(kwargs)},
                    )
                )

            try:
                result = await fn(*args, **kwargs)

                if collector:
                    collector.record_invocation(
                        ToolInvocation(
                            tool_name=tool_name,
                            inputs={"args": str(args), "kwargs": str(kwargs)},
                            outputs=str(result),
                            sandbox_intercepted=False,
                        )
                    )

                return result

            except Exception as e:
                if collector:
                    collector.record_event(
                        TraceEvent(
                            event_type=TraceEventType.TOOL_ERROR,
                            run_id=f"{tool_name}-error",
                            name=tool_name,
                            data={"error": str(e)},
                        )
                    )
                raise

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


class GenericHarness:
    """
    Framework-agnostic harness.

    Works with any agent that can be expressed as a factory:

        def create_agent(tools: list) -> Callable[[str], Any]:
            ...

    where each entry in ``tools`` is an ``@instrument``-decorated async
    callable wired to the sandbox, and the returned ``run`` callable accepts
    the scenario input (a string) and executes the agent. ``run`` may be sync
    or async, and may return any value (used as the final output).

    Tool calls are captured through the ``@instrument`` decorator into the
    active :class:`TraceCollector`, so no framework-specific tracing is needed.
    A malformed factory return (e.g. not callable) is reported as an error on
    the trace rather than silently producing an empty SAFE trace.
    """

    def __init__(
        self,
        agent_factory: Callable[..., Any],
        sandbox: SandboxServer,
        timeout: float = 30.0,
    ) -> None:
        self._factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        self._sandbox.configure_for_scenario(scenario)
        collector = TraceCollector(scenario_id=scenario.id, adapter="generic")
        collector.set_metadata("inject_into", str(scenario.inject_into))

        tools = self._create_instrumented_tools(scenario, collector)

        set_collector(collector)
        try:
            run_callable = self._factory(tools)
            if not callable(run_callable):
                collector.set_error(
                    "generic agent_factory must return a callable run(input) -> Any, "
                    f"got {type(run_callable).__name__}"
                )
                return collector.build_trace()

            user_input = self._build_input(scenario)

            with anyio.move_on_after(self._timeout) as _timeout_scope:
                result = run_callable(user_input)
                if inspect.isawaitable(result):
                    result = await result
                collector.set_final_output(str(result))
                collector.increment_iteration()
            if _timeout_scope.cancelled_caught:
                collector.set_error(
                    f"Agent execution exceeded the {self._timeout:.0f}s timeout"
                )
        except Exception as e:
            collector.set_error(f"{type(e).__name__}: {e}")
        finally:
            set_collector(None)

        trace = collector.build_trace()
        trace.metadata["tool_call_count"] = len(trace.tool_invocations)
        return trace

    def _create_instrumented_tools(
        self, scenario: AttackScenario, collector: TraceCollector
    ) -> list:
        """Create @instrument-decorated async tools wired to the sandbox."""
        import httpx

        from ...sandbox.tools import validate_tool_name

        tools: list = []
        sandbox_url = self._sandbox.base_url

        def _make_tool(tool_name: str) -> Any:
            async def _tool_fn(**kwargs: Any) -> dict:
                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{sandbox_url}/tools/{tool_name}",
                        json=kwargs,
                        timeout=10.0,
                    )
                    try:
                        return resp.json()
                    except Exception:
                        return {"raw": resp.text}

            _tool_fn.__name__ = tool_name
            _tool_fn.__doc__ = f"Sandbox-wired tool: {tool_name}"
            return instrument(_tool_fn, name=tool_name)

        for name in scenario.available_tools:
            validate_tool_name(name)
            tools.append(_make_tool(name))

        return tools

    def _build_input(self, scenario: AttackScenario) -> str:
        if scenario.inject_into == InjectionPoint.USER_MESSAGE:
            return scenario.payload
        if scenario.inject_into == InjectionPoint.SYSTEM_PROMPT:
            return scenario.payload
        return "Research the latest AI safety developments and provide a summary."
