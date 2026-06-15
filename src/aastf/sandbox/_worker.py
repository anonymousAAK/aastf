"""Isolation worker — runs one scenario against the agent and emits its trace.

Invoked as ``python -m aastf.sandbox._worker <request.json> <trace.json>`` by
:mod:`aastf.sandbox.isolation` inside a child process or container. It builds
the same harness the runner would, but wired to the parent's tool server over
loopback (``RemoteSandbox``), runs the scenario, and writes the resulting
:class:`AgentTrace` as JSON to the output path.

The worker never raises across the boundary: any failure is captured as an
error on the trace so the runner records it as an ERROR result rather than a
crash.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path


def _run(request: dict) -> str:
    from ..harness.factory import build_harness, load_agent_factory
    from ..models.scenario import AttackScenario
    from ..models.trace import AgentTrace
    from .isolation import RemoteSandbox

    adapter = request["adapter"]
    scenario = AttackScenario.model_validate(request["scenario"])

    try:
        factory = load_agent_factory(request["agent_factory"])
        sandbox = RemoteSandbox(request["base_url"])
        harness = build_harness(
            adapter,
            factory,
            sandbox,
            timeout=request.get("timeout", 30.0),
            max_iterations=request.get("max_iterations", 25),
        )
        trace = asyncio.run(harness.run_scenario(scenario))
    except Exception as e:  # noqa: BLE001 — boundary: report, never propagate
        trace = AgentTrace(
            scenario_id=scenario.id,
            adapter=adapter,
            error=f"isolation worker failed: {type(e).__name__}: {e}",
        )
    return trace.model_dump_json()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 2:
        sys.stderr.write("usage: python -m aastf.sandbox._worker <request> <output>\n")
        return 2
    req_path, out_path = Path(argv[0]), Path(argv[1])
    request = json.loads(req_path.read_text(encoding="utf-8"))
    out_path.write_text(_run(request), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
