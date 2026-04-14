"""
In-process FastAPI sandbox server.

Agents make REAL HTTP requests to http://127.0.0.1:{port}/tools/{tool_name}.
No mock-patching of the agent's HTTP client. This catches what mocking misses:
retry storms (ASI08), malformed JSON handling, timeout behavior.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from jinja2 import BaseLoader, Environment

from ..exceptions import SandboxStartError
from ..models.scenario import AttackScenario, ToolResponseConfig
from .interceptor import InterceptedCall, RequestInterceptor

_jinja = Environment(loader=BaseLoader(), autoescape=False)


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
        self._server: uvicorn.Server | None = None
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]
        self._app = self._build_app()

    # ---------------------------------------------------------------- public API

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}"

    @property
    def interceptor(self) -> RequestInterceptor:
        return self._interceptor

    def configure_for_scenario(self, scenario: AttackScenario) -> None:
        """Load scenario's tool response configs and reset the call log."""
        self._response_configs = {tc.tool_name: tc for tc in scenario.tool_responses}
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

        @app.post("/tools/{tool_name}")
        async def handle_tool(tool_name: str, request: Request) -> Response:
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
                await sandbox._interceptor.record(InterceptedCall(
                    tool_name=tool_name, request_body=body,
                    response_body=resp_body, status_code=500,
                    duration_ms=(time.monotonic() - t0) * 1000,
                ))
                return JSONResponse(resp_body, status_code=500)

            # --- malformed mode ---
            if config and config.response_mode == "malformed":
                raw = "not{valid[json"
                await sandbox._interceptor.record(InterceptedCall(
                    tool_name=tool_name, request_body=body,
                    response_body=raw, status_code=200,
                    duration_ms=(time.monotonic() - t0) * 1000,
                ))
                return PlainTextResponse(raw, status_code=200)

            # --- success mode (default) ---
            if config and config.response_payload is not None:
                rendered = sandbox._render(config.response_payload, body)
            else:
                rendered = {"status": "ok", "tool": tool_name, "result": None}

            await sandbox._interceptor.record(InterceptedCall(
                tool_name=tool_name, request_body=body,
                response_body=rendered, status_code=200,
                duration_ms=(time.monotonic() - t0) * 1000,
            ))
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
