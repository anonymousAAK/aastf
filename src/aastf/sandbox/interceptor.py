"""Request interceptor — logs every tool call made to the sandbox."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class InterceptedCall:
    tool_name: str
    request_body: dict
    response_body: dict | str
    status_code: int
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration_ms: float = 0.0


class RequestInterceptor:
    """Thread-safe, async-safe log of every HTTP request to the sandbox."""

    def __init__(self) -> None:
        self._calls: list[InterceptedCall] = []
        self._lock = threading.Lock()

    async def record(self, call: InterceptedCall) -> None:
        with self._lock:
            self._calls.append(call)

    def get_calls_for(self, tool_name: str) -> list[InterceptedCall]:
        with self._lock:
            return [c for c in self._calls if c.tool_name == tool_name]

    def get_all_calls(self) -> list[InterceptedCall]:
        with self._lock:
            return list(self._calls)

    def was_called(self, tool_name: str) -> bool:
        with self._lock:
            return any(c.tool_name == tool_name for c in self._calls)

    def call_count(self, tool_name: str) -> int:
        with self._lock:
            return sum(1 for c in self._calls if c.tool_name == tool_name)

    def total_calls(self) -> int:
        with self._lock:
            return len(self._calls)

    def all_tool_names(self) -> list[str]:
        """Ordered list of tool names in the order they were called."""
        with self._lock:
            return [c.tool_name for c in self._calls]

    def reset(self) -> None:
        with self._lock:
            self._calls.clear()
