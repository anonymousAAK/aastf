"""
AASTF Claude CLI Benchmark
===========================
Tests Claude models against all 50 OWASP ASI scenarios.

Configurations:
  1. Claude Haiku  (claude-haiku-4-5-20251001) via LangGraph  — fast, cheap
  2. Claude Sonnet (claude-sonnet-4-6)           via LangGraph  — balanced
  3. Claude Opus   (claude-opus-4-6)             via LangGraph  — most capable
  4. Claude Haiku  (native Anthropic SDK)        — mirrors Claude Code behaviour

Usage:
    set ANTHROPIC_API_KEY=sk-ant-...
    python benchmark/run_claude_benchmark.py

    # Run specific models only:
    python benchmark/run_claude_benchmark.py --models haiku sonnet

    # Run only specific ASI categories:
    python benchmark/run_claude_benchmark.py --categories ASI01 ASI02 ASI03

Cost estimate:
    Haiku  (~50 scenarios): ~$0.05
    Sonnet (~50 scenarios): ~$0.50
    Opus   (~50 scenarios): ~$2.00
    Total full run:         ~$2.55
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime
from pathlib import Path

from aastf.models.config import FrameworkConfig
from aastf.reporting.json_reporter import JSONReporter
from aastf.runner import Runner

RESULTS_DIR = Path("benchmark/results/claude")

CONFIGURATIONS = [
    {
        "name": "claude_haiku_langgraph",
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_haiku",
        "model": "claude-haiku-4-5-20251001",
        "description": "Claude Haiku via LangGraph (fast, $0.05)",
    },
    {
        "name": "claude_sonnet_langgraph",
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_sonnet",
        "model": "claude-sonnet-4-6",
        "description": "Claude Sonnet via LangGraph (balanced, $0.50)",
    },
    {
        "name": "claude_opus_langgraph",
        "adapter": "langgraph",
        "factory": "benchmark.agents.claude_langgraph:create_claude_opus",
        "model": "claude-opus-4-6",
        "description": "Claude Opus via LangGraph (most capable, $2.00)",
    },
    {
        "name": "claude_haiku_native",
        "adapter": "anthropic",
        "factory": "claude-haiku-4-5-20251001",  # passed as model name for native adapter
        "model": "claude-haiku-4-5-20251001",
        "description": "Claude Haiku — native Anthropic SDK (mirrors Claude Code)",
    },
]


def print_header(config: dict) -> None:
    print(f"\n{'='*65}")
    print(f"  {config['name']}")
    print(f"  Model: {config['model']}")
    print(f"  Adapter: {config['adapter']}")
    print(f"  {config['description']}")
    print(f"{'='*65}")


async def run_one(config: dict, categories: list[str] | None) -> dict:
    print_header(config)

    out_dir = RESULTS_DIR / config["name"]
    out_dir.mkdir(parents=True, exist_ok=True)

    framework_config = FrameworkConfig(
        adapter=config["adapter"],
        agent_factory=config["factory"],
        categories=categories or [],
        timeout_seconds=60.0,
        max_iterations=10,
        report_formats=["json"],
        output_dir=str(out_dir),
    )

    started = datetime.now()
    report = await Runner(framework_config).run()
    elapsed = (datetime.now() - started).total_seconds()

    # Save report
    JSONReporter().write(report, out_dir / "report.json")

    summary = {
        "name": config["name"],
        "model": config["model"],
        "adapter": config["adapter"],
        "total_scenarios": report.total_scenarios,
        "vulnerable": report.vulnerable,
        "safe": report.safe,
        "inconclusive": report.inconclusive,
        "errors": report.errors,
        "vulnerability_rate_pct": report.vulnerability_rate,
        "risk_score": report.overall_risk_score,
        "eu_ai_act_readiness": report.eu_ai_act_readiness,
        "elapsed_seconds": round(elapsed, 1),
        "asi_breakdown": report.asi_summary,
        "critical_findings": [
            {"id": f.scenario_id, "name": f.scenario_name, "triggered_by": f.triggered_by}
            for f in report.findings
            if f.severity.value == "CRITICAL"
        ],
    }

    print(f"\n  Vulnerable:  {report.vulnerable}/{report.total_scenarios} ({report.vulnerability_rate}%)")
    print(f"  Risk Score:  {report.overall_risk_score}/100")
    print(f"  EU AI Act:   {report.eu_ai_act_readiness.upper()}")
    print(f"  Elapsed:     {elapsed:.0f}s")

    if report.findings:
        print(f"\n  Findings ({len(report.findings)}):")
        for f in sorted(report.findings, key=lambda x: x.severity.numeric(), reverse=True)[:5]:
            print(f"    [{f.severity.value:8}] {f.scenario_id} — {f.scenario_name[:45]}")
        if len(report.findings) > 5:
            print(f"    ... and {len(report.findings) - 5} more (see report.json)")

    return summary


async def main(models: list[str] | None, categories: list[str] | None) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # Filter configurations
    configs = CONFIGURATIONS
    if models:
        configs = [c for c in configs if any(m in c["name"] for m in models)]

    if not configs:
        print("No matching configurations. Available: haiku, sonnet, opus, native")
        return

    print("\nAASTV Claude Benchmark")
    print(f"Running {len(configs)} configuration(s) × {50 if not categories else len(categories)*5} scenarios")
    print(f"Results: {RESULTS_DIR.absolute()}\n")

    all_results = []
    for config in configs:
        try:
            result = await run_one(config, categories)
            all_results.append(result)
        except Exception as e:
            print(f"\n  ERROR in {config['name']}: {e}")
            all_results.append({"name": config["name"], "error": str(e)})

    # Save combined results
    combined_path = RESULTS_DIR / "combined.json"
    combined_path.write_text(json.dumps(all_results, indent=2), encoding="utf-8")

    # Print final comparison table
    print(f"\n\n{'='*65}")
    print("  CLAUDE BENCHMARK RESULTS")
    print(f"{'='*65}")
    print(f"  {'Configuration':<30} {'Vuln%':>6} {'Risk':>6} {'EU AI Act':>12}")
    print(f"  {'-'*55}")
    for r in all_results:
        if "error" not in r:
            print(
                f"  {r['name']:<30} "
                f"{r['vulnerability_rate_pct']:>5}% "
                f"{r['risk_score']:>6.1f} "
                f"{r['eu_ai_act_readiness'].upper():>12}"
            )
        else:
            print(f"  {r['name']:<30} ERROR: {r['error'][:25]}")

    print(f"\n  Full reports: {RESULTS_DIR.absolute()}")
    print(f"  Combined:     {combined_path.absolute()}")

    # Per-category breakdown
    if all_results and "asi_breakdown" in all_results[0]:
        print("\n  Per-category vulnerability rates:")
        print(f"  {'Category':<10}", end="")
        for r in all_results:
            if "error" not in r:
                print(f"  {r['name'][:15]:>16}", end="")
        print()
        all_cats = sorted(all_results[0].get("asi_breakdown", {}).keys())
        for cat in all_cats:
            print(f"  {cat:<10}", end="")
            for r in all_results:
                if "error" not in r:
                    breakdown = r.get("asi_breakdown", {}).get(cat, {})
                    vuln = breakdown.get("vulnerable", 0)
                    total = sum(breakdown.values())
                    pct = f"{vuln}/{total}" if total > 0 else "n/a"
                    print(f"  {pct:>16}", end="")
            print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AASTF Claude Benchmark")
    parser.add_argument(
        "--models", nargs="+",
        choices=["haiku", "sonnet", "opus", "native"],
        help="Which models to test (default: all)",
    )
    parser.add_argument(
        "--categories", nargs="+",
        help="ASI categories to test e.g. ASI01 ASI02 (default: all 10)",
    )
    args = parser.parse_args()
    asyncio.run(main(args.models, args.categories))
