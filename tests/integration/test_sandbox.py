"""Integration tests for the sandbox server — hits real HTTP endpoints."""

from __future__ import annotations

import httpx
import pytest

from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
    ToolResponseConfig,
)
from aastf.sandbox.server import SandboxServer

# ------------------------------------------------------------------ fixtures

@pytest.fixture
async def sandbox():
    """Start a fresh sandbox for each test, stop it afterwards."""
    sb = SandboxServer()
    await sb.start()
    yield sb
    await sb.stop()


def _make_scenario(tool_responses: list[ToolResponseConfig] | None = None) -> AttackScenario:
    return AttackScenario(
        id="ASI02-001",
        name="Test",
        category=ASICategory.ASI02,
        severity=Severity.HIGH,
        description="desc",
        attack_vector="vector",
        inject_into=InjectionPoint.TOOL_RESPONSE,
        payload="inject",
        tool_responses=tool_responses or [],
        available_tools=["web_search", "send_email"],
        detection=DetectionCriteria(tool_called=["send_email"]),
        expected_behavior="safe",
        remediation="fix",
    )


# ------------------------------------------------------------------ health

@pytest.mark.asyncio
async def test_health_endpoint(sandbox: SandboxServer):
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{sandbox.base_url}/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["calls"] == 0


# ------------------------------------------------------------------ logging

@pytest.mark.asyncio
async def test_logs_tool_call(sandbox: SandboxServer):
    async with httpx.AsyncClient() as client:
        await client.post(f"{sandbox.base_url}/tools/web_search", json={"query": "test"})

    assert sandbox.interceptor.was_called("web_search")
    assert sandbox.interceptor.call_count("web_search") == 1
    assert sandbox.interceptor.total_calls() == 1


@pytest.mark.asyncio
async def test_logs_multiple_calls_in_order(sandbox: SandboxServer):
    async with httpx.AsyncClient() as client:
        await client.post(f"{sandbox.base_url}/tools/web_search", json={})
        await client.post(f"{sandbox.base_url}/tools/send_email", json={})
        await client.post(f"{sandbox.base_url}/tools/web_search", json={})

    assert sandbox.interceptor.call_count("web_search") == 2
    assert sandbox.interceptor.call_count("send_email") == 1
    assert sandbox.interceptor.all_tool_names() == ["web_search", "send_email", "web_search"]


@pytest.mark.asyncio
async def test_logs_request_body(sandbox: SandboxServer):
    async with httpx.AsyncClient() as client:
        await client.post(
            f"{sandbox.base_url}/tools/web_search",
            json={"query": "hello world", "limit": 5}
        )

    calls = sandbox.interceptor.get_calls_for("web_search")
    assert len(calls) == 1
    assert calls[0].request_body["query"] == "hello world"
    assert calls[0].request_body["limit"] == 5


# ------------------------------------------------------------------ reset

@pytest.mark.asyncio
async def test_configure_resets_call_log(sandbox: SandboxServer):
    scenario = _make_scenario()
    async with httpx.AsyncClient() as client:
        await client.post(f"{sandbox.base_url}/tools/web_search", json={})

    assert sandbox.interceptor.total_calls() == 1
    sandbox.configure_for_scenario(scenario)
    assert sandbox.interceptor.total_calls() == 0


# ------------------------------------------------------------------ response modes

@pytest.mark.asyncio
async def test_default_response_returns_ok(sandbox: SandboxServer):
    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{sandbox.base_url}/tools/unknown_tool", json={})

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["tool"] == "unknown_tool"


@pytest.mark.asyncio
async def test_configured_success_response(sandbox: SandboxServer):
    scenario = _make_scenario(tool_responses=[
        ToolResponseConfig(
            tool_name="web_search",
            response_payload={"results": [{"title": "Test", "snippet": "hello"}]},
            response_mode="success",
        )
    ])
    sandbox.configure_for_scenario(scenario)

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{sandbox.base_url}/tools/web_search", json={"query": "x"})

    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert data["results"][0]["snippet"] == "hello"


@pytest.mark.asyncio
async def test_error_mode_returns_500(sandbox: SandboxServer):
    scenario = _make_scenario(tool_responses=[
        ToolResponseConfig(
            tool_name="web_search",
            response_payload=None,
            response_mode="error",
        )
    ])
    sandbox.configure_for_scenario(scenario)

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{sandbox.base_url}/tools/web_search", json={})

    assert resp.status_code == 500
    assert sandbox.interceptor.was_called("web_search")


@pytest.mark.asyncio
async def test_malformed_mode_returns_invalid_json(sandbox: SandboxServer):
    scenario = _make_scenario(tool_responses=[
        ToolResponseConfig(
            tool_name="web_search",
            response_payload=None,
            response_mode="malformed",
        )
    ])
    sandbox.configure_for_scenario(scenario)

    async with httpx.AsyncClient() as client:
        resp = await client.post(f"{sandbox.base_url}/tools/web_search", json={})

    assert resp.status_code == 200
    import json
    with pytest.raises(json.JSONDecodeError):  # malformed response is not valid JSON
        resp.json()
    assert sandbox.interceptor.was_called("web_search")


@pytest.mark.asyncio
async def test_delayed_mode_takes_time(sandbox: SandboxServer):
    import time
    scenario = _make_scenario(tool_responses=[
        ToolResponseConfig(
            tool_name="slow_tool",
            response_payload={"result": "slow"},
            response_mode="delayed",
            delay_seconds=0.2,
        )
    ])
    sandbox.configure_for_scenario(scenario)

    t0 = time.monotonic()
    async with httpx.AsyncClient() as client:
        await client.post(f"{sandbox.base_url}/tools/slow_tool", json={}, timeout=5.0)
    elapsed = time.monotonic() - t0

    assert elapsed >= 0.2


# ------------------------------------------------------------------ jinja2 rendering

@pytest.mark.asyncio
async def test_jinja2_payload_renders_request_context(sandbox: SandboxServer):
    scenario = _make_scenario(tool_responses=[
        ToolResponseConfig(
            tool_name="web_search",
            response_payload={"echo_query": "{{ query }}"},
            response_mode="success",
        )
    ])
    sandbox.configure_for_scenario(scenario)

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{sandbox.base_url}/tools/web_search",
            json={"query": "hello_from_test"}
        )

    data = resp.json()
    assert data["echo_query"] == "hello_from_test"


# ------------------------------------------------------------------ two sandboxes

@pytest.mark.asyncio
async def test_two_sandboxes_use_different_ports():
    sb1 = SandboxServer()
    sb2 = SandboxServer()
    await sb1.start()
    await sb2.start()
    try:
        assert sb1._port != sb2._port
        async with httpx.AsyncClient() as client:
            r1 = await client.get(f"{sb1.base_url}/health")
            r2 = await client.get(f"{sb2.base_url}/health")
        assert r1.status_code == 200
        assert r2.status_code == 200
    finally:
        await sb1.stop()
        await sb2.stop()
