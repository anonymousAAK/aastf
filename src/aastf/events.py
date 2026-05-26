"""Typed event bus for AASTF scan lifecycle instrumentation.

Emits structured events during scan execution — tool calls, verdicts,
inter-agent messages, memory writes, and scan lifecycle transitions.
Consumers subscribe by event type; all events are buffered for export.
"""

from __future__ import annotations

import inspect
import logging
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models.result import Verdict
from .models.scenario import ASICategory, Severity

logger = logging.getLogger(__name__)


# ── Base event ───────────────────────────────────────────────────────

class BaseEvent(BaseModel):
    """Base class for all AASTF events."""

    event_type: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def model_post_init(self, __context: Any) -> None:
        if not self.event_type:
            self.event_type = type(self).__name__


# ── Concrete events ─────────────────────────────────────────────────

class ToolCallEvent(BaseEvent):
    """Emitted when the agent invokes a tool."""

    tool_name: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    scenario_id: str = ""


class ToolResponseEvent(BaseEvent):
    """Emitted when a tool returns a response."""

    tool_name: str
    response_content: Any = None
    latency_ms: float = 0.0


class MCPToolResponseEvent(ToolResponseEvent):
    """Tool response from an MCP server — extends ToolResponseEvent."""

    mcp_server_id: str = ""


class InterAgentMessageEvent(BaseEvent):
    """Emitted when one agent sends a message to another."""

    source_agent: str
    target_agent: str
    message_content: str = ""


class MemoryWriteEvent(BaseEvent):
    """Emitted when an agent writes to memory."""

    key: str
    value: Any = None
    scope: str = "session"  # session | user | org


class VerdictEvent(BaseEvent):
    """Emitted when a scenario evaluation produces a verdict."""

    scenario_id: str
    verdict: Verdict
    severity: Severity
    category: ASICategory


class ScanStartEvent(BaseEvent):
    """Emitted at the beginning of a scan run."""

    adapter: str
    scenario_count: int = 0
    config_hash: str = ""


class ScanCompleteEvent(BaseEvent):
    """Emitted when a scan finishes."""

    total_findings: int = 0
    risk_score: float = 0.0
    duration_seconds: float = 0.0


# ── Event bus ────────────────────────────────────────────────────────

class EventBus:
    """In-process publish/subscribe event bus with buffering and NDJSON export.

    Usage::

        bus = EventBus()
        bus.subscribe(VerdictEvent, my_callback)
        bus.emit(VerdictEvent(scenario_id="ASI01-001", ...))
        bus.to_ndjson(Path("events.ndjson"))
    """

    def __init__(self) -> None:
        self._subscribers: dict[type[BaseEvent], list[Callable[..., Any]]] = {}
        self._buffer: list[BaseEvent] = []

    # ── subscribe / emit ─────────────────────────────────────────────

    def subscribe(self, event_type: type[BaseEvent], callback: Callable[..., Any]) -> None:
        """Register *callback* for all events of *event_type* (exact match)."""
        self._subscribers.setdefault(event_type, []).append(callback)

    def emit(self, event: BaseEvent) -> None:
        """Emit *event* synchronously — calls all subscribers, then buffers."""
        self._buffer.append(event)
        for cb in self._subscribers.get(type(event), []):
            try:
                cb(event)
            except Exception:
                logger.warning(
                    "Subscriber %s raised on %s", cb, type(event).__name__, exc_info=True,
                )

    async def emit_async(self, event: BaseEvent) -> None:
        """Emit *event* — awaits async subscribers, calls sync ones normally."""
        self._buffer.append(event)
        for cb in self._subscribers.get(type(event), []):
            try:
                if inspect.iscoroutinefunction(cb):
                    await cb(event)
                else:
                    cb(event)
            except Exception:
                logger.warning(
                    "Subscriber %s raised on %s", cb, type(event).__name__, exc_info=True,
                )

    # ── query / export ───────────────────────────────────────────────

    def get_events(self, event_type: type[BaseEvent] | None = None) -> list[BaseEvent]:
        """Return buffered events, optionally filtered by type."""
        if event_type is None:
            return list(self._buffer)
        return [e for e in self._buffer if isinstance(e, event_type)]

    def clear(self) -> None:
        """Drop all buffered events."""
        self._buffer.clear()

    def to_ndjson(self, path: Path) -> None:
        """Write all buffered events as newline-delimited JSON."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as fh:
            for event in self._buffer:
                fh.write(event.model_dump_json() + "\n")
