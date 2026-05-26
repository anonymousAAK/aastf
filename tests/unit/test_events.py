"""Tests for the AASTF typed event bus."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aastf.events import (
    BaseEvent,
    EventBus,
    InterAgentMessageEvent,
    MCPToolResponseEvent,
    MemoryWriteEvent,
    ScanCompleteEvent,
    ScanStartEvent,
    ToolCallEvent,
    ToolResponseEvent,
    VerdictEvent,
)
from aastf.models.result import Verdict
from aastf.models.scenario import ASICategory, Severity

# ── BaseEvent defaults ───────────────────────────────────────────────


class TestBaseEvent:
    def test_event_type_auto_populated(self) -> None:
        event = ToolCallEvent(tool_name="read_file")
        assert event.event_type == "ToolCallEvent"

    def test_timestamp_auto_populated(self) -> None:
        before = datetime.now(timezone.utc)
        event = BaseEvent()
        after = datetime.now(timezone.utc)
        assert before <= event.timestamp <= after

    def test_scan_id_auto_populated(self) -> None:
        event = BaseEvent()
        assert len(event.scan_id) == 36  # UUID4

    def test_explicit_event_type_preserved(self) -> None:
        event = BaseEvent(event_type="custom")
        assert event.event_type == "custom"


# ── Concrete event construction ──────────────────────────────────────


class TestConcreteEvents:
    def test_tool_call_event(self) -> None:
        e = ToolCallEvent(
            tool_name="execute_sql",
            parameters={"query": "SELECT 1"},
            scenario_id="ASI02-001",
        )
        assert e.tool_name == "execute_sql"
        assert e.parameters == {"query": "SELECT 1"}
        assert e.scenario_id == "ASI02-001"

    def test_tool_response_event(self) -> None:
        e = ToolResponseEvent(tool_name="read_file", response_content="ok", latency_ms=42.5)
        assert e.latency_ms == 42.5

    def test_mcp_tool_response_inherits(self) -> None:
        e = MCPToolResponseEvent(
            tool_name="mcp_tool",
            response_content={"data": 1},
            latency_ms=10.0,
            mcp_server_id="server-1",
        )
        assert isinstance(e, ToolResponseEvent)
        assert e.mcp_server_id == "server-1"

    def test_inter_agent_message_event(self) -> None:
        e = InterAgentMessageEvent(
            source_agent="planner",
            target_agent="executor",
            message_content="run step 3",
        )
        assert e.source_agent == "planner"
        assert e.event_type == "InterAgentMessageEvent"

    def test_memory_write_event(self) -> None:
        e = MemoryWriteEvent(key="user_pref", value="dark_mode", scope="user")
        assert e.scope == "user"

    def test_memory_write_default_scope(self) -> None:
        e = MemoryWriteEvent(key="tmp", value=1)
        assert e.scope == "session"

    def test_verdict_event(self) -> None:
        e = VerdictEvent(
            scenario_id="ASI01-001",
            verdict=Verdict.VULNERABLE,
            severity=Severity.CRITICAL,
            category=ASICategory.ASI01,
        )
        assert e.verdict == Verdict.VULNERABLE

    def test_scan_start_event(self) -> None:
        e = ScanStartEvent(adapter="langgraph", scenario_count=50, config_hash="abc123")
        assert e.scenario_count == 50

    def test_scan_complete_event(self) -> None:
        e = ScanCompleteEvent(total_findings=3, risk_score=72.5, duration_seconds=12.1)
        assert e.risk_score == 72.5


# ── EventBus: subscribe / emit ───────────────────────────────────────


class TestEventBusSync:
    def test_emit_calls_subscriber(self) -> None:
        bus = EventBus()
        received: list[BaseEvent] = []
        bus.subscribe(ToolCallEvent, received.append)

        event = ToolCallEvent(tool_name="x")
        bus.emit(event)

        assert len(received) == 1
        assert received[0] is event

    def test_subscriber_only_receives_matching_type(self) -> None:
        bus = EventBus()
        calls: list[BaseEvent] = []
        bus.subscribe(VerdictEvent, calls.append)

        bus.emit(ToolCallEvent(tool_name="x"))
        bus.emit(
            VerdictEvent(
                scenario_id="ASI01-001",
                verdict=Verdict.SAFE,
                severity=Severity.LOW,
                category=ASICategory.ASI01,
            ),
        )
        assert len(calls) == 1
        assert isinstance(calls[0], VerdictEvent)

    def test_multiple_subscribers(self) -> None:
        bus = EventBus()
        a: list[BaseEvent] = []
        b: list[BaseEvent] = []
        bus.subscribe(ScanStartEvent, a.append)
        bus.subscribe(ScanStartEvent, b.append)

        bus.emit(ScanStartEvent(adapter="crewai"))
        assert len(a) == 1
        assert len(b) == 1

    def test_subscriber_exception_does_not_break_emit(self) -> None:
        bus = EventBus()
        received: list[BaseEvent] = []

        def bad_cb(_: BaseEvent) -> None:
            raise RuntimeError("boom")

        bus.subscribe(ToolCallEvent, bad_cb)
        bus.subscribe(ToolCallEvent, received.append)

        bus.emit(ToolCallEvent(tool_name="y"))
        # Second subscriber still ran despite first raising
        assert len(received) == 1


# ── EventBus: async emit ─────────────────────────────────────────────


class TestEventBusAsync:
    @pytest.mark.asyncio
    async def test_emit_async_calls_async_subscriber(self) -> None:
        bus = EventBus()
        received: list[BaseEvent] = []

        async def async_cb(event: BaseEvent) -> None:
            received.append(event)

        bus.subscribe(ToolCallEvent, async_cb)
        await bus.emit_async(ToolCallEvent(tool_name="a"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_emit_async_calls_sync_subscriber(self) -> None:
        bus = EventBus()
        received: list[BaseEvent] = []
        bus.subscribe(ToolCallEvent, received.append)
        await bus.emit_async(ToolCallEvent(tool_name="b"))
        assert len(received) == 1

    @pytest.mark.asyncio
    async def test_emit_async_exception_resilient(self) -> None:
        bus = EventBus()
        received: list[BaseEvent] = []

        async def bad_async(_: BaseEvent) -> None:
            raise ValueError("async boom")

        bus.subscribe(ScanCompleteEvent, bad_async)
        bus.subscribe(ScanCompleteEvent, received.append)

        await bus.emit_async(ScanCompleteEvent(total_findings=0))
        assert len(received) == 1


# ── EventBus: buffer / get_events ────────────────────────────────────


class TestEventBusBuffer:
    def test_all_emitted_events_buffered(self) -> None:
        bus = EventBus()
        bus.emit(ToolCallEvent(tool_name="a"))
        bus.emit(ScanStartEvent(adapter="x"))
        bus.emit(ToolCallEvent(tool_name="b"))
        assert len(bus.get_events()) == 3

    def test_get_events_filtered(self) -> None:
        bus = EventBus()
        bus.emit(ToolCallEvent(tool_name="a"))
        bus.emit(ScanStartEvent(adapter="x"))
        bus.emit(ToolCallEvent(tool_name="b"))

        tool_events = bus.get_events(ToolCallEvent)
        assert len(tool_events) == 2
        assert all(isinstance(e, ToolCallEvent) for e in tool_events)

    def test_get_events_returns_copy(self) -> None:
        bus = EventBus()
        bus.emit(BaseEvent())
        events = bus.get_events()
        events.clear()
        assert len(bus.get_events()) == 1

    def test_get_events_mcp_subclass_matches_parent(self) -> None:
        bus = EventBus()
        bus.emit(MCPToolResponseEvent(tool_name="t", mcp_server_id="s1"))

        # isinstance check means subclass events match parent type filter
        assert len(bus.get_events(ToolResponseEvent)) == 1
        assert len(bus.get_events(MCPToolResponseEvent)) == 1

    def test_clear_empties_buffer(self) -> None:
        bus = EventBus()
        bus.emit(BaseEvent())
        bus.emit(BaseEvent())
        assert len(bus.get_events()) == 2
        bus.clear()
        assert len(bus.get_events()) == 0

    @pytest.mark.asyncio
    async def test_emit_async_also_buffers(self) -> None:
        bus = EventBus()
        await bus.emit_async(ScanCompleteEvent(total_findings=5))
        assert len(bus.get_events()) == 1


# ── EventBus: NDJSON export ──────────────────────────────────────────


class TestEventBusNdjson:
    def test_to_ndjson_creates_file(self, tmp_path: Path) -> None:
        bus = EventBus()
        bus.emit(ToolCallEvent(tool_name="x", scenario_id="ASI01-001"))
        bus.emit(ScanStartEvent(adapter="langgraph", scenario_count=10))

        out = tmp_path / "events.ndjson"
        bus.to_ndjson(out)

        lines = out.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

        first = json.loads(lines[0])
        assert first["event_type"] == "ToolCallEvent"
        assert first["tool_name"] == "x"

        second = json.loads(lines[1])
        assert second["event_type"] == "ScanStartEvent"

    def test_to_ndjson_creates_parent_dirs(self, tmp_path: Path) -> None:
        bus = EventBus()
        bus.emit(BaseEvent())
        out = tmp_path / "sub" / "dir" / "events.ndjson"
        bus.to_ndjson(out)
        assert out.exists()

    def test_to_ndjson_empty_buffer(self, tmp_path: Path) -> None:
        bus = EventBus()
        out = tmp_path / "empty.ndjson"
        bus.to_ndjson(out)
        assert out.read_text(encoding="utf-8") == ""

    def test_ndjson_roundtrip_verdict_event(self, tmp_path: Path) -> None:
        bus = EventBus()
        bus.emit(
            VerdictEvent(
                scenario_id="ASI01-001",
                verdict=Verdict.VULNERABLE,
                severity=Severity.CRITICAL,
                category=ASICategory.ASI01,
                scan_id="test-scan-id",
            ),
        )
        out = tmp_path / "v.ndjson"
        bus.to_ndjson(out)

        data = json.loads(out.read_text(encoding="utf-8").strip())
        assert data["verdict"] == "VULNERABLE"
        assert data["severity"] == "CRITICAL"
        assert data["category"] == "ASI01"
        assert data["scan_id"] == "test-scan-id"
