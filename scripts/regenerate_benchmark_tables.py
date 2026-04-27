"""
Generate Markdown benchmark tables from AASTF JSON benchmark outputs.

Usage:
    python scripts/regenerate_benchmark_tables.py
    python scripts/regenerate_benchmark_tables.py --bench-dir benchmarks/ --out tables.md

Two tables are produced:

1. CLI three-class table — one row per model:
   | Model | VULN (CI) | REFUSAL_ECHO (CI) | SAFE (CI) | Inconclusive | n |

2. Framework benchmark table — one row per config:
   | Config | Vuln rate | Echo rate | Risk score |
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# Wilson CI helper (pure-stdlib fallback if scipy not available at report time)
# ---------------------------------------------------------------------------

def _wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score 95% CI (closed-form, no scipy dependency for this script)."""
    if n == 0:
        return 0.0, 0.0
    p_hat = k / n
    denom = 1 + z ** 2 / n
    centre = (p_hat + z ** 2 / (2 * n)) / denom
    margin = (z * (p_hat * (1 - p_hat) / n + z ** 2 / (4 * n ** 2)) ** 0.5) / denom
    return max(0.0, round(centre - margin, 4)), min(1.0, round(centre + margin, 4))


# ---------------------------------------------------------------------------
# JSON loader
# ---------------------------------------------------------------------------

def load_benchmark(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_all(bench_dir: Path) -> list[dict]:
    files = sorted(bench_dir.glob("*.json"))
    if not files:
        print(f"No JSON files found in {bench_dir}", file=sys.stderr)
        return []
    loaded = []
    for f in files:
        try:
            data = load_benchmark(f)
            data["_source_file"] = f.name
            loaded.append(data)
        except Exception as e:
            print(f"  WARNING: could not load {f.name}: {e}", file=sys.stderr)
    return loaded


# ---------------------------------------------------------------------------
# Detect benchmark type
# ---------------------------------------------------------------------------

def is_framework_benchmark(data: dict) -> bool:
    """Framework benchmarks have an 'adapter' that is not a *_cli adapter."""
    adapter = data.get("adapter", "")
    return not adapter.endswith("_cli")


# ---------------------------------------------------------------------------
# CLI three-class table
# ---------------------------------------------------------------------------

def _pct(count: int, total: int) -> str:
    if total == 0:
        return "0%"
    return f"{count / total * 100:.0f}%"


def _ci_str(ci_low: float, ci_high: float) -> str:
    return f"[{ci_low:.2f}–{ci_high:.2f}]"


def _aggregate_ci(scenarios: list[dict], verdict: str) -> tuple[float, float]:
    """
    Aggregate Wilson CI across all scenarios for a given verdict:
    treat total k = sum(votes[verdict]) over n_total = sum(n) as a pooled estimate.
    """
    total_k = sum(s.get("votes", {}).get(verdict, 0) for s in scenarios)
    total_n = sum(s.get("n", 5) for s in scenarios)
    return _wilson_ci(total_k, total_n)


def build_cli_table(benchmarks: list[dict]) -> str:
    cli_runs = [b for b in benchmarks if not is_framework_benchmark(b)]
    if not cli_runs:
        return "_No CLI benchmark data found._\n"

    # Latest file per model (sort by generated_at)
    by_model: dict[str, dict] = {}
    for b in cli_runs:
        model = b.get("model", b["_source_file"])
        existing = by_model.get(model)
        if existing is None or b.get("generated_at", "") > existing.get("generated_at", ""):
            by_model[model] = b

    lines = [
        "| Model | Behavioral VULN | REFUSAL_ECHO | Clean SAFE | Inconclusive | n/scenario |",
        "|-------|-----------------|--------------|------------|--------------|------------|",
    ]

    for model, data in sorted(by_model.items()):
        scenarios = data.get("scenarios", [])
        n_total = len(scenarios)
        if n_total == 0:
            continue
        n_per = data.get("n_runs_per_scenario", 5)
        counts: Counter[str] = Counter(s["final_verdict"] for s in scenarios)

        vuln = counts.get("VULNERABLE", 0)
        echo = counts.get("REFUSAL_ECHO", 0)
        safe = counts.get("SAFE", 0)
        inconcl = counts.get("INCONCLUSIVE", 0)

        vuln_ci = _ci_str(*_aggregate_ci(scenarios, "VULNERABLE"))
        echo_ci = _ci_str(*_aggregate_ci(scenarios, "REFUSAL_ECHO"))
        safe_ci = _ci_str(*_aggregate_ci(scenarios, "SAFE"))

        lines.append(
            f"| {model} "
            f"| {vuln}/{n_total} ({_pct(vuln, n_total)}) {vuln_ci} "
            f"| {echo}/{n_total} ({_pct(echo, n_total)}) {echo_ci} "
            f"| {safe}/{n_total} ({_pct(safe, n_total)}) {safe_ci} "
            f"| {inconcl} "
            f"| {n_per} |"
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Framework benchmark table
# ---------------------------------------------------------------------------

def build_framework_table(benchmarks: list[dict]) -> str:
    fw_runs = [b for b in benchmarks if is_framework_benchmark(b)]
    if not fw_runs:
        return "_No framework benchmark data found._\n"

    # Latest file per config (model + adapter)
    by_config: dict[str, dict] = {}
    for b in fw_runs:
        key = f"{b.get('adapter', '?')} / {b.get('model', '?')}"
        existing = by_config.get(key)
        if existing is None or b.get("generated_at", "") > existing.get("generated_at", ""):
            by_config[key] = b

    lines = [
        "| Config | Vuln rate | Echo rate | Risk score | n/scenario |",
        "|--------|-----------|-----------|------------|------------|",
    ]

    for config, data in sorted(by_config.items()):
        summary = data.get("summary", {})
        n_total = data.get("total_scenarios", 0)
        n_per = data.get("n_runs_per_scenario", 3)

        vuln = summary.get("vulnerable", 0)
        echo = summary.get("refusal_echo", 0)
        # risk_score may be stored directly or must be computed
        risk_score = data.get("overall_risk_score") or data.get("risk_score")
        risk_str = f"{risk_score:.1f}/100" if risk_score is not None else "n/a"

        lines.append(
            f"| {config} "
            f"| {_pct(vuln, n_total)} "
            f"| {_pct(echo, n_total)} "
            f"| {risk_str} "
            f"| {n_per} |"
        )

    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Markdown benchmark tables")
    parser.add_argument(
        "--bench-dir", default="benchmarks",
        help="Directory containing JSON benchmark outputs (default: benchmarks/)",
    )
    parser.add_argument(
        "--out", default=None,
        help="Write tables to this file instead of stdout",
    )
    args = parser.parse_args()

    bench_dir = Path(args.bench_dir)
    if not bench_dir.exists():
        print(f"ERROR: bench-dir '{bench_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    benchmarks = load_all(bench_dir)
    print(f"Loaded {len(benchmarks)} benchmark file(s) from {bench_dir}\n", file=sys.stderr)

    cli_table = build_cli_table(benchmarks)
    fw_table = build_framework_table(benchmarks)

    output = (
        "## CLI Benchmark - Three-Class Results (n=5 stability)\n\n"
        + cli_table
        + "\n"
        "## Framework Benchmark Results\n\n"
        + fw_table
    )

    if args.out:
        out_path = Path(args.out)
        out_path.write_text(output, encoding="utf-8")
        print(f"Tables written to {out_path}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
