"""Shared harness construction.

The runner builds a harness in-process; the isolation worker
(:mod:`aastf.sandbox._worker`) builds the *same* harness inside a child
process or container, wired to the parent's sandbox over loopback. Both paths
go through :func:`build_harness` so the adapter dispatch lives in one place.
"""

from __future__ import annotations

import importlib
from typing import Any

from ..exceptions import AdapterNotFoundError

# Adapter name -> (module, class). Kept as data so callers can introspect the
# full set of shipped adapters without importing each SDK.
_ADAPTERS: dict[str, tuple[str, str]] = {
    "langgraph": ("aastf.harness.adapters.langgraph", "LangGraphHarness"),
    "crewai": ("aastf.harness.adapters.crewai", "CrewAIHarness"),
    "openai_agents": ("aastf.harness.adapters.openai_agents", "OpenAIAgentsHarness"),
    "pydantic_ai": ("aastf.harness.adapters.pydantic_ai", "PydanticAIHarness"),
    "generic": ("aastf.harness.adapters.generic", "GenericHarness"),
    "mcp": ("aastf.harness.adapters.mcp", "MCPHarness"),
    "google_adk": ("aastf.harness.adapters.google_adk", "GoogleADKHarness"),
    "ms_agent": ("aastf.harness.adapters.ms_agent", "MSAgentHarness"),
}


def load_agent_factory(dotted_path: str):  # type: ignore[return]
    """Import and return the agent factory callable from a 'module:callable' path."""
    if ":" not in dotted_path:
        raise ValueError(
            f"agent_factory must be 'module.path:callable', got: {dotted_path!r}"
        )
    module_path, _, attr = dotted_path.rpartition(":")
    try:
        module = importlib.import_module(module_path)
    except ModuleNotFoundError as e:
        raise AdapterNotFoundError(f"Cannot import agent module {module_path!r}: {e}") from e
    if not hasattr(module, attr):
        raise AdapterNotFoundError(f"Module {module_path!r} has no attribute {attr!r}")
    return getattr(module, attr)


def build_harness(
    adapter: str,
    factory: Any,
    sandbox: Any,
    *,
    timeout: float = 30.0,
    max_iterations: int = 25,
):  # type: ignore[return]
    """Construct the harness for *adapter*, wired to *sandbox*.

    *sandbox* only needs ``base_url`` and ``configure_for_scenario`` — a real
    :class:`~aastf.sandbox.server.SandboxServer` in-process, or a
    :class:`~aastf.sandbox.isolation.RemoteSandbox` handle inside a worker.
    """
    spec = _ADAPTERS.get(adapter)
    if spec is None:
        raise AdapterNotFoundError(
            f"Unknown adapter: {adapter!r}. Supported: {', '.join(_ADAPTERS)}"
        )
    module_path, class_name = spec
    harness_cls = getattr(importlib.import_module(module_path), class_name)

    if adapter == "langgraph":
        return harness_cls(
            factory, sandbox, timeout=timeout, max_iterations=max_iterations
        )
    return harness_cls(factory, sandbox, timeout=timeout)
