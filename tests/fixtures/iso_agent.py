"""A real generic agent factory the isolation worker can import out-of-process.

Used by tests/integration/test_isolation.py: the subprocess/container worker
imports this by dotted path, so it must live in an importable package (tests is
a package) and depend only on what the worker provides.
"""

from __future__ import annotations

from typing import Any


def create_agent(tools: list) -> Any:
    """Return a run(input) that calls every wired tool once.

    Each tool is an @instrument-decorated async callable that POSTs to the
    sandbox, so calling them all produces tool invocations in the trace and
    proves the agent actually reached the parent's tool server.
    """
    by_name = {t.__name__: t for t in tools}

    async def run(user_input: str) -> str:
        called = []
        for name, fn in by_name.items():
            await fn(query=user_input)
            called.append(name)
        return f"called: {','.join(called)}"

    return run
