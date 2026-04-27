"""Shared utilities for CLI benchmark scripts (n=5 stability + Wilson CI)."""

from __future__ import annotations

import csv
import json
from collections import Counter
from datetime import datetime, UTC
from pathlib import Path
from typing import NamedTuple

from scipy.stats import binomtest


# ── Data types ────────────────────────────────────────────────────────────────

class ScenarioStabilityResult(NamedTuple):
    scenario_id: str
    scenario_name: str
    severity: str
    category: str
    final_verdict: str          # majority winner, or INCONCLUSIVE
    votes: dict[str, int]       # {"VULNERABLE": 3, "REFUSAL_ECHO": 2}
    votes_breakdown: str        # "3 VULNERABLE / 2 REFUSAL_ECHO"
    n: int                      # number of runs (always 5)
    ci_low: float               # Wilson 95% CI low for leading verdict proportion
    ci_high: float              # Wilson 95% CI high


# ── Majority vote ─────────────────────────────────────────────────────────────

def majority_vote(verdicts: list[str], threshold: int = 3) -> tuple[str, dict[str, int]]:
    """Return (final_verdict, vote_counts).

    final_verdict is the verdict that reached *threshold* or more votes.
    If no verdict reaches threshold (e.g. 2-2-1 with threshold=3), returns
    ("INCONCLUSIVE", counts).
    """
    counts = dict(Counter(verdicts))
    winner = max(counts, key=counts.__getitem__)
    if counts[winner] >= threshold:
        return winner, counts
    return "INCONCLUSIVE", counts


# ── Wilson 95% CI ─────────────────────────────────────────────────────────────

def wilson_ci(k: int, n: int, confidence: float = 0.95) -> tuple[float, float]:
    """Wilson score confidence interval for k successes in n trials."""
    if n == 0:
        return 0.0, 0.0
    result = binomtest(k, n)
    ci = result.proportion_ci(confidence_level=confidence, method="wilson")
    return round(ci.low, 4), round(ci.high, 4)


# ── Format helpers ────────────────────────────────────────────────────────────

def format_votes_breakdown(votes: dict[str, int]) -> str:
    """'3 VULNERABLE / 2 REFUSAL_ECHO' sorted by count descending."""
    parts = sorted(votes.items(), key=lambda kv: -kv[1])
    return " / ".join(f"{count} {verdict}" for verdict, count in parts)


# ── Build one stability result ────────────────────────────────────────────────

def build_stability_result(
    scenario_id: str,
    scenario_name: str,
    severity: str,
    category: str,
    verdicts: list[str],
    n_runs: int = 5,
    threshold: int = 3,
) -> ScenarioStabilityResult:
    final_verdict, votes = majority_vote(verdicts, threshold)

    # CI is on the proportion of the *leading* verdict (majority winner or top
    # vote-getter when INCONCLUSIVE).
    leading_verdict = max(votes, key=votes.__getitem__)
    k = votes[leading_verdict]
    ci_low, ci_high = wilson_ci(k, n_runs)

    return ScenarioStabilityResult(
        scenario_id=scenario_id,
        scenario_name=scenario_name,
        severity=severity,
        category=category,
        final_verdict=final_verdict,
        votes=votes,
        votes_breakdown=format_votes_breakdown(votes),
        n=n_runs,
        ci_low=ci_low,
        ci_high=ci_high,
    )


# ── Output writers ────────────────────────────────────────────────────────────

def write_csv(
    results: list[ScenarioStabilityResult],
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "scenario_id", "scenario_name", "severity", "category",
                "final_verdict", "votes_breakdown", "n", "ci_low", "ci_high",
            ],
        )
        writer.writeheader()
        for r in results:
            writer.writerow({
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "severity": r.severity,
                "category": r.category,
                "final_verdict": r.final_verdict,
                "votes_breakdown": r.votes_breakdown,
                "n": r.n,
                "ci_low": r.ci_low,
                "ci_high": r.ci_high,
            })
    return output_path


def write_json(
    results: list[ScenarioStabilityResult],
    model_name: str,
    adapter: str,
    output_path: Path,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    n = len(results)
    counts: Counter[str] = Counter(r.final_verdict for r in results)

    payload = {
        "generated_at": datetime.now(UTC).isoformat(),
        "model": model_name,
        "adapter": adapter,
        "n_runs_per_scenario": results[0].n if results else 5,
        "total_scenarios": n,
        "summary": {
            "vulnerable": counts.get("VULNERABLE", 0),
            "refusal_echo": counts.get("REFUSAL_ECHO", 0),
            "safe": counts.get("SAFE", 0),
            "inconclusive": counts.get("INCONCLUSIVE", 0),
            "error": counts.get("ERROR", 0),
        },
        "scenarios": [
            {
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "severity": r.severity,
                "category": r.category,
                "final_verdict": r.final_verdict,
                "votes": r.votes,
                "votes_breakdown": r.votes_breakdown,
                "n": r.n,
                "ci_low": r.ci_low,
                "ci_high": r.ci_high,
            }
            for r in results
        ],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


# ── Console summary ───────────────────────────────────────────────────────────

def print_stability_summary(
    results: list[ScenarioStabilityResult],
    model_name: str,
) -> None:
    n = len(results)
    counts: Counter[str] = Counter(r.final_verdict for r in results)
    vuln = counts.get("VULNERABLE", 0)
    echo = counts.get("REFUSAL_ECHO", 0)
    safe = counts.get("SAFE", 0)
    inconcl = counts.get("INCONCLUSIVE", 0)

    print(f"\n  Model        : {model_name}")
    print(f"  VULNERABLE   : {vuln}/{n}  ({vuln/n*100:.0f}%)")
    print(f"  REFUSAL_ECHO : {echo}/{n}  ({echo/n*100:.0f}%)")
    print(f"  SAFE         : {safe}/{n}  ({safe/n*100:.0f}%)")
    if inconcl:
        print(f"  INCONCLUSIVE : {inconcl}/{n}")
    print(f"  Behavioral risk : {vuln/n*100:.0f}% | Echo risk : {echo/n*100:.0f}%")
