"""
Run a single benchmark configuration by name.
Used by parallel runners — one process per config.

Usage:
    python benchmark/run_single.py claude_haiku_langgraph
    python benchmark/run_single.py claude_sonnet_langgraph
    python benchmark/run_single.py claude_opus_langgraph
    python benchmark/run_single.py claude_haiku_native
    python benchmark/run_single.py claude_code_agent
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path

CONFIGURATIONS = {
    "claude_haiku_langgraph": {
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_haiku",
        "model": "claude-haiku-4-5-20251001",
    },
    "claude_sonnet_langgraph": {
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_sonnet",
        "model": "claude-sonnet-4-6",
    },
    "claude_opus_langgraph": {
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_opus",
        "model": "claude-opus-4-6",
    },
    "claude_haiku_native": {
        "adapter": "anthropic",
        "factory": "claude-haiku-4-5-20251001",
        "model": "claude-haiku-4-5-20251001",
    },
    "claude_code_agent": {
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_code_agent:create_claude_code_agent",
        "model": "claude-sonnet-4-6",
    },
}


async def run(name: str) -> None:
    if name not in CONFIGURATIONS:
        print(f"Unknown config: {name}")
        print(f"Available: {', '.join(CONFIGURATIONS)}")
        sys.exit(1)

    cfg = CONFIGURATIONS[name]
    out_dir = Path(f"benchmark/results/{name}")
    out_dir.mkdir(parents=True, exist_ok=True)

    log_path = out_dir / "run.log"
    print(f"[{name}] Starting — model={cfg['model']} adapter={cfg['adapter']}")
    print(f"[{name}] Log: {log_path}")

    from aastf.models.config import FrameworkConfig
    from aastf.reporting.json_reporter import JSONReporter
    from aastf.runner import Runner

    config = FrameworkConfig(
        adapter=cfg["adapter"],
        agent_factory=cfg["factory"],
        timeout_seconds=60.0,
        max_iterations=10,
        report_formats=["json"],
        output_dir=str(out_dir),
    )

    started = datetime.now()
    report = await Runner(config).run()
    elapsed = (datetime.now() - started).total_seconds()

    JSONReporter().write(report, out_dir / "report.json")

    summary = {
        "name": name,
        "model": cfg["model"],
        "adapter": cfg["adapter"],
        "total_scenarios": report.total_scenarios,
        "vulnerable": report.vulnerable,
        "safe": report.safe,
        "errors": report.errors,
        "vulnerability_rate_pct": report.vulnerability_rate,
        "risk_score": report.overall_risk_score,
        "eu_ai_act_readiness": report.eu_ai_act_readiness,
        "elapsed_seconds": round(elapsed, 1),
        "asi_breakdown": report.asi_summary,
        "findings": [
            {
                "id": f.scenario_id,
                "name": f.scenario_name,
                "severity": f.severity.value,
                "triggered_by": f.triggered_by,
            }
            for f in report.findings
        ],
    }

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2))

    print(f"\n[{name}] DONE in {elapsed:.0f}s")
    print(f"[{name}] Vulnerable: {report.vulnerable}/{report.total_scenarios} ({report.vulnerability_rate}%)")
    print(f"[{name}] Risk Score: {report.overall_risk_score}/100")
    print(f"[{name}] EU AI Act:  {report.eu_ai_act_readiness.upper()}")
    print(f"[{name}] Report:     {out_dir / 'report.json'}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python benchmark/run_single.py <config_name>")
        print(f"Configs: {', '.join(CONFIGURATIONS)}")
        sys.exit(1)
    asyncio.run(run(sys.argv[1]))
