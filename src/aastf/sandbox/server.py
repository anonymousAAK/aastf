"""
In-process FastAPI sandbox server.

Agents make REAL HTTP requests to http://127.0.0.1:{port}/tools/{tool_name}.
No mock-patching of the agent's HTTP client. This catches what mocking misses:
retry storms (ASI08), malformed JSON handling, timeout behavior.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from jinja2 import BaseLoader
from jinja2.sandbox import SandboxedEnvironment

from ..exceptions import SandboxStartError
from ..models.scenario import AttackScenario, MCPResourceConfig, ToolResponseConfig
from .interceptor import InterceptedCall, RequestInterceptor

logger = logging.getLogger(__name__)

_jinja = SandboxedEnvironment(loader=BaseLoader(), autoescape=True)
# Block the Jinja2 'do' extension (statement execution) for safety
_jinja.globals.pop("do", None)

_MAX_REQUEST_BYTES = 10_000_000  # 10 MB
_RATE_LIMIT_WINDOW = 60  # seconds
_RATE_LIMIT_MAX_CALLS = 200  # max calls per tool per window
_TOOL_TIMEOUT_SECONDS = 30  # global tool execution timeout
_RATE_LIMIT_CLEANUP_INTERVAL = 60  # seconds between cleanup sweeps


def _find_free_port() -> int:
    """Bind to port 0 to let the OS pick a free port, then release it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SandboxServer:
    """
    Lifecycle:
        sandbox = SandboxServer()
        await sandbox.start()          # boots uvicorn as an asyncio task
        sandbox.configure_for_scenario(scenario)
        # ... run agent ...
        calls = sandbox.interceptor.get_all_calls()
        await sandbox.stop()           # clean shutdown
    """

    def __init__(self) -> None:
        self._port: int = _find_free_port()
        self._interceptor = RequestInterceptor()
        self._response_configs: dict[str, ToolResponseConfig] = {}
        self._mcp_resources: dict[str, MCPResourceConfig] = {}
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._rate_limit_log: dict[str, list[float]] = {}  # tool_name -> list of timestamps
        self._app = self._build_app()

    # ---------------------------------------------------------------- public API

    def set_port(self, port: int) -> None:
        """Override the auto-assigned port before calling start()."""
        self._port = port

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def interceptor(self) -> RequestInterceptor:
        return self._interceptor

    def configure_for_scenario(self, scenario: AttackScenario) -> None:
        """Load scenario's tool response configs and reset the call log."""
        self._response_configs = {tc.tool_name: tc for tc in scenario.tool_responses}
        self._mcp_resources = {r.uri: r for r in scenario.mcp_resources}
        self._interceptor.reset()

    # ----------------------------------------------------------------- lifecycle

    async def start(self) -> None:
        """Start uvicorn in the background. Returns once the server is ready."""
        config = uvicorn.Config(
            self._app,
            host="127.0.0.1",
            port=self._port,
            log_level="error",
            access_log=False,
        )
        self._server = uvicorn.Server(config)
        self._task = asyncio.create_task(self._server.serve())

        # Poll health endpoint until server is accepting connections
        import httpx

        deadline = asyncio.get_event_loop().time() + 5.0
        while asyncio.get_event_loop().time() < deadline:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(f"{self.base_url}/health", timeout=0.3)
                    if resp.status_code == 200:
                        return
            except Exception:
                pass
            await asyncio.sleep(0.05)

        raise SandboxStartError(f"Sandbox did not start within 5s on port {self._port}")

    async def stop(self) -> None:
        """Gracefully shut down uvicorn."""
        if self._server:
            self._server.should_exit = True
        if self._task:
            import contextlib

            with contextlib.suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(self._task, timeout=3.0)

    # ----------------------------------------------------------------- app build

    def _build_app(self) -> FastAPI:
        app = FastAPI(title="AASTF Sandbox", docs_url=None, redoc_url=None)
        sandbox = self  # closure reference

        @app.get("/health")
        async def health() -> dict[str, Any]:
            return {
                "status": "ok",
                "port": sandbox._port,
                "calls": sandbox._interceptor.total_calls(),
            }

        # -------------------------------------------------------- MCP endpoints

        @app.post("/mcp/tools/list")
        async def mcp_tools_list(request: Request) -> JSONResponse:
            """Return tool descriptions — may contain poisoned descriptions from scenario config."""
            tools: list[dict[str, Any]] = []
            for tc in sandbox._response_configs.values():
                tool_entry: dict[str, Any] = {"name": tc.tool_name}
                if tc.tool_description is not None:
                    tool_entry["description"] = tc.tool_description
                else:
                    tool_entry["description"] = f"Tool: {tc.tool_name}"
                if tc.tool_input_schema is not None:
                    tool_entry["inputSchema"] = tc.tool_input_schema
                else:
                    tool_entry["inputSchema"] = {
                        "type": "object",
                        "properties": {"query": {"type": "string"}},
                    }
                tools.append(tool_entry)
            return JSONResponse({"tools": tools})

        @app.post("/mcp/tools/call")
        async def mcp_tools_call(request: Request) -> Response:
            """Execute a tool with intercepted params via MCP protocol."""
            try:
                body: dict = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            tool_name = body.get("name", "")
            arguments = body.get("arguments", {})

            config = sandbox._response_configs.get(tool_name)

            t0 = time.monotonic()

            # Apply delay
            if config and config.delay_seconds > 0:
                await asyncio.sleep(config.delay_seconds)

            # Error mode
            if config and config.response_mode == "error":
                resp_body = {"error": f"Simulated failure for {tool_name}", "code": 500}
                await sandbox._interceptor.record(
                    InterceptedCall(
                        tool_name=tool_name,
                        request_body=arguments,
                        response_body=resp_body,
                        status_code=500,
                        duration_ms=(time.monotonic() - t0) * 1000,
                    )
                )
                return JSONResponse(resp_body, status_code=500)

            # Malformed mode
            if config and config.response_mode == "malformed":
                raw = "not{valid[json"
                await sandbox._interceptor.record(
                    InterceptedCall(
                        tool_name=tool_name,
                        request_body=arguments,
                        response_body=raw,
                        status_code=200,
                        duration_ms=(time.monotonic() - t0) * 1000,
                    )
                )
                return PlainTextResponse(raw, status_code=200)

            # Success mode
            if config and config.response_payload is not None:
                rendered = sandbox._render(config.response_payload, arguments)
            else:
                rendered = {"status": "ok", "tool": tool_name, "result": None}

            await sandbox._interceptor.record(
                InterceptedCall(
                    tool_name=tool_name,
                    request_body=arguments,
                    response_body=rendered,
                    status_code=200,
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
            )
            return JSONResponse({"content": [{"type": "text", "text": str(rendered)}]})

        @app.post("/mcp/resources/read")
        async def mcp_resources_read(request: Request) -> JSONResponse:
            """Resource retrieval with injection surface."""
            try:
                body: dict = await request.json()
            except Exception:
                return JSONResponse({"error": "Invalid JSON"}, status_code=400)

            uri = body.get("uri", "")
            resource = sandbox._mcp_resources.get(uri)
            if resource is None:
                return JSONResponse(
                    {"error": f"Resource not found: {uri}"}, status_code=404
                )
            return JSONResponse({
                "uri": resource.uri,
                "mimeType": resource.mime_type,
                "content": resource.content,
            })

        # -------------------------------------------------------- tool endpoints

        @app.post("/tools/{tool_name}")
        async def handle_tool(tool_name: str, request: Request) -> Response:
            # --- request size limit ---
            content_length = request.headers.get("content-length", "0")
            if int(content_length) > _MAX_REQUEST_BYTES:
                return JSONResponse({"error": "Request too large"}, status_code=413)

            # --- rate limiting (per tool, sliding window) ---
            now = time.monotonic()
            timestamps = sandbox._rate_limit_log.setdefault(tool_name, [])
            cutoff = now - _RATE_LIMIT_WINDOW
            sandbox._rate_limit_log[tool_name] = [
                ts for ts in timestamps if ts > cutoff
            ]
            if len(sandbox._rate_limit_log[tool_name]) >= _RATE_LIMIT_MAX_CALLS:
                return JSONResponse(
                    {"error": "Rate limit exceeded"}, status_code=429
                )
            sandbox._rate_limit_log[tool_name].append(now)

            t0 = time.monotonic()

            try:
                body: dict = await request.json()
            except Exception:
                body = {}

            config = sandbox._response_configs.get(tool_name)

            # --- apply delay ---
            if config and config.delay_seconds > 0:
                await asyncio.sleep(config.delay_seconds)

            # --- error mode ---
            if config and config.response_mode == "error":
                resp_body = {"error": f"Simulated failure for {tool_name}", "code": 500}
                await sandbox._interceptor.record(
                    InterceptedCall(
                        tool_name=tool_name,
                        request_body=body,
                        response_body=resp_body,
                        status_code=500,
                        duration_ms=(time.monotonic() - t0) * 1000,
                    )
                )
                return JSONResponse(resp_body, status_code=500)

            # --- malformed mode ---
            if config and config.response_mode == "malformed":
                raw = "not{valid[json"
                await sandbox._interceptor.record(
                    InterceptedCall(
                        tool_name=tool_name,
                        request_body=body,
                        response_body=raw,
                        status_code=200,
                        duration_ms=(time.monotonic() - t0) * 1000,
                    )
                )
                return PlainTextResponse(raw, status_code=200)

            # --- success mode (default) ---
            if config and config.response_payload is not None:
                rendered = sandbox._render(config.response_payload, body)
            else:
                rendered = {"status": "ok", "tool": tool_name, "result": None}

            await sandbox._interceptor.record(
                InterceptedCall(
                    tool_name=tool_name,
                    request_body=body,
                    response_body=rendered,
                    status_code=200,
                    duration_ms=(time.monotonic() - t0) * 1000,
                )
            )
            return JSONResponse(rendered)

        return app

    def _render(self, payload: Any, context: dict) -> Any:
        """Recursively render Jinja2 templates in the response payload."""
        if isinstance(payload, str):
            return _jinja.from_string(payload).render(**context)
        if isinstance(payload, dict):
            return {k: self._render(v, context) for k, v in payload.items()}
        if isinstance(payload, list):
            return [self._render(item, context) for item in payload]
        return payload
