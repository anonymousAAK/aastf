"""
Merge all completed benchmark runs into a single comparison report.
Run this after all parallel runs finish.

Usage:
    python benchmark/merge_results.py
"""

from __future__ import annotations

import json
from pathlib import Path

RESULTS_DIR = Path("benchmark/results")


def merge() -> None:
    summaries = []
    missing = []

    configs = [
        "claude_haiku_langgraph",
        "claude_sonnet_langgraph",
        "claude_opus_langgraph",
        "claude_haiku_native",
        "claude_code_agent",
    ]

    for name in configs:
        summary_path = RESULTS_DIR / name / "summary.json"
        if summary_path.exists():
            data = json.loads(summary_path.read_text())
            summaries.append(data)
            print(f"  [OK] {name}")
        else:
            missing.append(name)
            print(f"  [--] {name} (not yet complete)")

    if not summaries:
        print("\nNo results found. Run benchmark/run_single.py first.")
        return

    # Save combined
    combined = RESULTS_DIR / "combined.json"
    combined.write_text(json.dumps(summaries, indent=2))

    # Print comparison table
    print(f"\n{'='*75}")
    print("  AASTF CLAUDE BENCHMARK — FINAL RESULTS")
    print(f"{'='*75}")
    print(f"  {'Configuration':<28} {'Model':<30} {'Vuln%':>6} {'Risk':>6} {'EU AI Act':>12}")
    print(f"  {'-'*70}")

    for r in sorted(summaries, key=lambda x: x["risk_score"], reverse=True):
        print(
            f"  {r['name']:<28} "
            f"{r['model']:<30} "
            f"{r['vulnerability_rate_pct']:>5}% "
            f"{r['risk_score']:>6.1f} "
            f"{r['eu_ai_act_readiness'].upper():>12}"
        )

    if missing:
        print(f"\n  Still running: {', '.join(missing)}")

    # Per-category breakdown
    print("\n  Per-category breakdown (vulnerable/total):")
    print(f"  {'Category':<10}", end="")
    for r in summaries:
        print(f"  {r['name'][:18]:>20}", end="")
    print()

    all_cats = sorted(summaries[0].get("asi_breakdown", {}).keys())
    for cat in all_cats:
        print(f"  {cat:<10}", end="")
        for r in summaries:
            breakdown = r.get("asi_breakdown", {}).get(cat, {})
            vuln = breakdown.get("vulnerable", 0)
            total = sum(breakdown.values())
            pct = f"{vuln}/{total}" if total else "n/a"
            print(f"  {pct:>20}", end="")
        print()

    print(f"\n  Combined report: {combined.absolute()}")


if __name__ == "__main__":
    merge()
