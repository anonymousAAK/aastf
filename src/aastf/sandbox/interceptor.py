"""Request interceptor — logs every tool call made to the sandbox."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class InterceptedCall:
    tool_name: str
    request_body: dict
    response_body: dict | str
    status_code: int
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0


class RequestInterceptor:
    """Thread-safe, async-safe log of every HTTP request to the sandbox."""

    def __init__(self) -> None:
        self._calls: list[InterceptedCall] = []
        self._lock = asyncio.Lock()

    async def record(self, call: InterceptedCall) -> None:
        async with self._lock:
            self._calls.append(call)

    def get_calls_for(self, tool_name: str) -> list[InterceptedCall]:
        return [c for c in self._calls if c.tool_name == tool_name]

    def get_all_calls(self) -> list[InterceptedCall]:
        return list(self._calls)

    def was_called(self, tool_name: str) -> bool:
        return any(c.tool_name == tool_name for c in self._calls)

    def call_count(self, tool_name: str) -> int:
        return sum(1 for c in self._calls if c.tool_name == tool_name)

    def total_calls(self) -> int:
        return len(self._calls)

    def all_tool_names(self) -> list[str]:
        """Ordered list of tool names in the order they were called."""
        return [c.tool_name for c in self._calls]

    def reset(self) -> None:
        self._calls.clear()
