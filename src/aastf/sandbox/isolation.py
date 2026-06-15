"""Execution isolation backends for the agent-under-test.

The sandbox *tool server* (:mod:`aastf.sandbox.server`) always runs in the
runner's process and records every tool call the agent makes. What varies is
*where the agent itself runs*:

* ``inprocess`` — the agent runs in the runner's own Python process. Fast and
  dependency-free, but a hostile agent shares the runner's memory, file
  descriptors, and host. This is the historical default.
* ``subprocess`` — each scenario runs in a fresh child process that reaches the
  tool server over loopback. Crashes, ``os._exit`` calls, and most resource
  abuse are contained to the child.
* ``container`` — the agent runs in a Docker container that reaches the tool
  server via ``host.docker.internal``. Strongest boundary; requires Docker and
  an image with ``aastf`` installed.

All backends expose the same ``async run_scenario(scenario) -> AgentTrace``
surface as a harness, so the runner is agnostic to which one it holds.
Detection is scored against the returned :class:`AgentTrace`, which serialises
cleanly across the process/container boundary.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from ..models.scenario import AttackScenario
from ..models.trace import AgentTrace

logger = logging.getLogger(__name__)

_WORKER_MODULE = "aastf.sandbox._worker"


class RemoteSandbox:
    """Sandbox handle used inside a worker.

    The real tool server lives in the parent process; a worker only needs the
    server's URL to wire tools, and a no-op ``configure_for_scenario`` because
    the parent has already loaded the scenario's responses before spawning us.
    """

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        return self._base_url

    def configure_for_scenario(self, scenario: AttackScenario) -> None:  # noqa: ARG002
        # Intentionally a no-op: the parent process owns the tool server and has
        # already configured it for this scenario.
        return None


class ExecutionBackend(ABC):
    """Runs one scenario and returns its :class:`AgentTrace`."""

    name: str

    @abstractmethod
    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace: ...


class InProcessBackend(ExecutionBackend):
    """Run the agent in the runner's own process (historical default)."""

    name = "inprocess"

    def __init__(self, harness: Any) -> None:
        self._harness = harness

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        return await self._harness.run_scenario(scenario)


class _WorkerBackend(ExecutionBackend):
    """Shared logic for backends that run the worker out-of-process."""

    def __init__(
        self,
        *,
        adapter: str,
        agent_factory: str,
        sandbox: Any,
        timeout: float,
        max_iterations: int,
    ) -> None:
        self._adapter = adapter
        self._agent_factory = agent_factory
        self._sandbox = sandbox
        self._timeout = timeout
        self._max_iterations = max_iterations

    def _request(self, scenario: AttackScenario, base_url: str) -> dict[str, Any]:
        return {
            "adapter": self._adapter,
            "agent_factory": self._agent_factory,
            "scenario": scenario.model_dump(mode="json"),
            "base_url": base_url,
            "timeout": self._timeout,
            "max_iterations": self._max_iterations,
        }

    def _error_trace(self, scenario: AttackScenario, message: str) -> AgentTrace:
        return AgentTrace(
            scenario_id=scenario.id, adapter=self._adapter, error=message
        )

    def _parse_output(self, scenario: AttackScenario, out_file: Path) -> AgentTrace:
        try:
            raw = out_file.read_text(encoding="utf-8")
        except OSError as e:
            return self._error_trace(scenario, f"isolation worker produced no output: {e}")
        if not raw.strip():
            return self._error_trace(scenario, "isolation worker produced empty output")
        try:
            return AgentTrace.model_validate_json(raw)
        except Exception as e:  # noqa: BLE001
            return self._error_trace(scenario, f"could not parse worker trace: {e}")


class SubprocessBackend(_WorkerBackend):
    """Run each scenario in a child Python process."""

    name = "subprocess"

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        # The parent owns the tool server; configure it before the child starts.
        self._sandbox.configure_for_scenario(scenario)

        work_dir = Path(tempfile.mkdtemp(prefix="aastf-iso-"))
        req_file = work_dir / "request.json"
        out_file = work_dir / "trace.json"
        req_file.write_text(
            json.dumps(self._request(scenario, self._sandbox.base_url)),
            encoding="utf-8",
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                _WORKER_MODULE,
                str(req_file),
                str(out_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            # Generous wall-clock ceiling: the worker enforces the real per-agent
            # timeout itself; this only guards against a wedged child.
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout + 30
                )
            except (TimeoutError, asyncio.TimeoutError):
                proc.kill()
                await proc.wait()
                return self._error_trace(
                    scenario, "isolation subprocess timed out and was killed"
                )

            if proc.returncode != 0:
                tail = (stderr or b"").decode("utf-8", "replace")[-2000:]
                return self._error_trace(
                    scenario,
                    f"isolation subprocess exited with code {proc.returncode}: {tail}",
                )
            return self._parse_output(scenario, out_file)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)


class ContainerBackend(_WorkerBackend):
    """Run each scenario inside a Docker container.

    The working directory is mounted read-only at ``/workspace`` so the agent
    factory is importable, and the container reaches the host's tool server via
    ``host.docker.internal``.
    """

    name = "container"

    def __init__(self, *, image: str, project_dir: Path | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if not image:
            raise ValueError(
                "container isolation requires an image (--container-image / "
                "FrameworkConfig.container_image)"
            )
        self._image = image
        self._project_dir = (project_dir or Path.cwd()).resolve()

    @staticmethod
    def docker_available() -> bool:
        return shutil.which("docker") is not None

    def _container_base_url(self) -> str:
        # Replace the loopback host so the container reaches the host's server.
        # `--add-host=host.docker.internal:host-gateway` (added below) makes this
        # resolvable on Linux as well as Docker Desktop.
        port = self._sandbox.base_url.rsplit(":", 1)[-1]
        return f"http://host.docker.internal:{port}"

    def _build_docker_command(self, req_name: str, out_name: str) -> list[str]:
        return [
            "docker",
            "run",
            "--rm",
            "--add-host=host.docker.internal:host-gateway",
            "--network",
            "bridge",
            "-v",
            f"{self._project_dir}:/workspace:ro",
            "-v",
            f"{self._work_dir}:/io",
            "-w",
            "/workspace",
            "-e",
            "PYTHONPATH=/workspace",
            self._image,
            "python",
            "-m",
            _WORKER_MODULE,
            f"/io/{req_name}",
            f"/io/{out_name}",
        ]

    async def run_scenario(self, scenario: AttackScenario) -> AgentTrace:
        if not self.docker_available():
            return self._error_trace(
                scenario, "container isolation requested but 'docker' is not on PATH"
            )

        self._sandbox.configure_for_scenario(scenario)

        self._work_dir = Path(tempfile.mkdtemp(prefix="aastf-iso-"))
        req_file = self._work_dir / "request.json"
        out_file = self._work_dir / "trace.json"
        req_file.write_text(
            json.dumps(self._request(scenario, self._container_base_url())),
            encoding="utf-8",
        )
        cmd = self._build_docker_command(req_file.name, out_file.name)
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self._timeout + 60
                )
            except (TimeoutError, asyncio.TimeoutError):
                proc.kill()
                await proc.wait()
                return self._error_trace(
                    scenario, "isolation container timed out and was killed"
                )
            if proc.returncode != 0:
                tail = (stderr or b"").decode("utf-8", "replace")[-2000:]
                return self._error_trace(
                    scenario,
                    f"isolation container exited with code {proc.returncode}: {tail}",
                )
            return self._parse_output(scenario, out_file)
        finally:
            shutil.rmtree(self._work_dir, ignore_errors=True)


def build_execution_backend(
    config: Any,
    harness: Any,
    sandbox: Any,
) -> ExecutionBackend:
    """Select the execution backend for *config*.

    ``inprocess`` wraps the already-built *harness*; the isolated backends carry
    the config needed to reconstruct that harness inside a worker.
    """
    isolation = getattr(config, "isolation", "inprocess")
    if isolation == "inprocess":
        return InProcessBackend(harness)

    common = dict(
        adapter=config.adapter,
        agent_factory=config.agent_factory,
        sandbox=sandbox,
        timeout=config.timeout_seconds,
        max_iterations=config.max_iterations,
    )
    if isolation == "subprocess":
        return SubprocessBackend(**common)
    if isolation == "container":
        return ContainerBackend(image=config.container_image or "", **common)
    raise ValueError(f"Unknown isolation mode: {isolation!r}")
