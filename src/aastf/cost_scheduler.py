"""Cost-aware test scheduler — token accounting, budget caps, priority scheduling.

Tracks per-scenario token spend, enforces hard budget limits, prioritises
high-signal tests, performs adaptive sampling (skipping redundant runs),
estimates cost before execution, and caches deterministic responses.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .models.result import TestResult, Verdict
from .models.scenario import AttackScenario

logger = logging.getLogger(__name__)

# ── Verdicts that indicate the scenario found something interesting ──────────
_SIGNAL_VERDICTS: frozenset[Verdict] = frozenset({
    Verdict.VULNERABLE,
    Verdict.TOOL_POISONING,
    Verdict.SCHEMA_POISONING,
    Verdict.PREFERENCE_MANIPULATION,
    Verdict.INFECTION_PROPAGATED,
    Verdict.COLLUSION,
    Verdict.WATCHDOG_BYPASS,
    Verdict.REFUSAL_ECHO,
})

# Number of consecutive identical results before a scenario is deemed redundant
_REDUNDANCY_WINDOW = 3


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class TokenUsage(BaseModel):
    """Token consumption for a single scenario execution."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class CostConfig(BaseModel):
    """Configuration knobs for cost-aware scheduling."""

    budget_usd: float = 50.0
    cost_per_1k_prompt: float = 0.01
    cost_per_1k_completion: float = 0.03
    warn_at_percent: float = 80.0
    enable_caching: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Cost tracker
# ─────────────────────────────────────────────────────────────────────────────

class BudgetExceededError(Exception):
    """Raised when the spending cap is breached."""


class CostTracker:
    """Accumulates per-scenario token spend and enforces budget limits."""

    def __init__(self, config: CostConfig) -> None:
        self._config = config
        self._records: dict[str, list[TokenUsage]] = defaultdict(list)

    # ── public ───────────────────────────────────────────────────────────

    def record(self, scenario_id: str, usage: TokenUsage) -> None:
        """Record token usage for *scenario_id*.

        Raises :class:`BudgetExceededError` if the budget is exceeded after
        recording.
        """
        self._records[scenario_id].append(usage)
        if self.is_over_budget():
            raise BudgetExceededError(
                f"Budget of ${self._config.budget_usd:.2f} exceeded — "
                f"total spent ${self.total_spent():.4f}"
            )

    def total_spent(self) -> float:
        """Total USD spent across all recorded scenarios."""
        return sum(
            u.estimated_cost_usd
            for usages in self._records.values()
            for u in usages
        )

    def remaining_budget(self) -> float:
        """Remaining USD until budget cap."""
        return max(0.0, self._config.budget_usd - self.total_spent())

    def is_over_budget(self) -> bool:
        """True when cumulative spend exceeds the configured budget."""
        return self.total_spent() > self._config.budget_usd

    def should_warn(self) -> bool:
        """True when cumulative spend has passed the warning threshold."""
        if self._config.budget_usd <= 0:
            return True
        pct = (self.total_spent() / self._config.budget_usd) * 100
        return pct >= self._config.warn_at_percent

    def summary(self) -> dict[str, Any]:
        """Per-scenario cost breakdown plus totals."""
        breakdown: dict[str, dict[str, Any]] = {}
        for sid, usages in self._records.items():
            total_prompt = sum(u.prompt_tokens for u in usages)
            total_completion = sum(u.completion_tokens for u in usages)
            total_cost = sum(u.estimated_cost_usd for u in usages)
            breakdown[sid] = {
                "runs": len(usages),
                "prompt_tokens": total_prompt,
                "completion_tokens": total_completion,
                "total_cost_usd": round(total_cost, 6),
            }
        return {
            "total_spent_usd": round(self.total_spent(), 6),
            "remaining_usd": round(self.remaining_budget(), 6),
            "budget_usd": self._config.budget_usd,
            "over_budget": self.is_over_budget(),
            "scenarios": breakdown,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Test prioritiser
# ─────────────────────────────────────────────────────────────────────────────

class TestPrioritizer:
    """Ranks scenarios by expected information value using historical results."""

    def __init__(self, history: list[TestResult] | None = None) -> None:
        self._history = history or []
        # Pre-compute per-scenario stats
        self._vuln_counts: dict[str, int] = defaultdict(int)
        self._total_counts: dict[str, int] = defaultdict(int)
        for r in self._history:
            self._total_counts[r.scenario_id] += 1
            if r.verdict in _SIGNAL_VERDICTS:
                self._vuln_counts[r.scenario_id] += 1

    def signal_score(self, scenario_id: str) -> float:
        """Historical vulnerability rate for *scenario_id* (0.0–1.0).

        Unseen scenarios get a default score of 0.5 (optimistic exploration).
        """
        total = self._total_counts.get(scenario_id, 0)
        if total == 0:
            return 0.5  # never seen → explore
        return self._vuln_counts[scenario_id] / total

    def prioritize(self, scenarios: list[AttackScenario]) -> list[AttackScenario]:
        """Return *scenarios* sorted by expected signal value (highest first).

        Sort key: (severity_numeric DESC, signal_score DESC, scenario_id ASC).
        """
        def _sort_key(s: AttackScenario) -> tuple[int, float, str]:
            return (
                -s.severity.numeric(),
                -self.signal_score(s.id),
                s.id,
            )

        return sorted(scenarios, key=_sort_key)

    def is_redundant(
        self,
        scenario_id: str,
        recent_results: list[TestResult],
        window: int = _REDUNDANCY_WINDOW,
    ) -> bool:
        """True if the last *window* runs for *scenario_id* all share the same verdict."""
        relevant = [r for r in recent_results if r.scenario_id == scenario_id]
        if len(relevant) < window:
            return False
        last_n = relevant[-window:]
        return len({r.verdict for r in last_n}) == 1


# ─────────────────────────────────────────────────────────────────────────────
# Response cache (lightweight, separate from the main ResponseCache)
# ─────────────────────────────────────────────────────────────────────────────

class ResponseCache:
    """Simple disk-backed cache mapping (scenario_id, prompt) → response text."""

    def __init__(self, cache_dir: Path | None = None) -> None:
        self._cache_dir = (cache_dir or Path(".aastf/cost_cache")).resolve()
        self._hits = 0
        self._misses = 0

    # ── public ───────────────────────────────────────────────────────────

    @staticmethod
    def cache_key(scenario_id: str, prompt: str) -> str:
        """Deterministic hex-digest key for a (scenario_id, prompt) pair."""
        h = hashlib.sha256()
        h.update(scenario_id.encode("utf-8"))
        h.update(b"\x00")
        h.update(prompt.encode("utf-8"))
        return h.hexdigest()

    def get(self, key: str) -> str | None:
        """Retrieve a cached response or ``None`` on miss."""
        path = self._cache_dir / f"{key}.json"
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                self._hits += 1
                return data.get("response")
            except Exception:
                logger.debug("Cache read error for key %s", key)
        self._misses += 1
        return None

    def put(self, key: str, response: str) -> None:
        """Store a response under *key*."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_dir / f"{key}.json"
        payload = {
            "key": key,
            "response": response,
            "cached_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def hit_rate(self) -> float:
        """Cache hit rate (0.0–1.0).  Returns 0.0 when no lookups have occurred."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return self._hits / total


# ─────────────────────────────────────────────────────────────────────────────
# Cost-aware scheduler
# ─────────────────────────────────────────────────────────────────────────────

class CostAwareScheduler:
    """Combines cost tracking, prioritisation, caching, and adaptive sampling."""

    def __init__(
        self,
        config: CostConfig,
        cache_dir: Path | None = None,
    ) -> None:
        self._config = config
        self._tracker = CostTracker(config)
        self._cache = ResponseCache(cache_dir) if config.enable_caching else None
        self._prioritizer: TestPrioritizer | None = None

    # ── properties ───────────────────────────────────────────────────────

    @property
    def tracker(self) -> CostTracker:
        return self._tracker

    @property
    def cache(self) -> ResponseCache | None:
        return self._cache

    # ── public ───────────────────────────────────────────────────────────

    def estimate_cost(self, scenarios: list[AttackScenario]) -> float:
        """Rough pre-execution USD estimate based on average token assumptions.

        Heuristic: each scenario ≈ 800 prompt tokens + 400 completion tokens.
        """
        avg_prompt = 800
        avg_completion = 400
        per_scenario = (
            (avg_prompt / 1000) * self._config.cost_per_1k_prompt
            + (avg_completion / 1000) * self._config.cost_per_1k_completion
        )
        return round(per_scenario * len(scenarios), 6)

    def schedule(
        self,
        scenarios: list[AttackScenario],
        history: list[TestResult] | None = None,
    ) -> list[AttackScenario]:
        """Return a prioritised, budget-capped, de-duplicated list of scenarios.

        Steps:
        1. Prioritise by severity + signal score.
        2. Drop redundant scenarios (identical recent verdicts).
        3. Trim to fit remaining budget (estimated cost per scenario).
        """
        history = history or []
        self._prioritizer = TestPrioritizer(history)

        # 1. Prioritise
        ordered = self._prioritizer.prioritize(scenarios)

        # 2. Drop redundant
        filtered: list[AttackScenario] = []
        for s in ordered:
            if not self._prioritizer.is_redundant(s.id, history):
                filtered.append(s)

        # 3. Budget cap — trim tail if estimated cost exceeds remaining budget
        remaining = self._tracker.remaining_budget()
        if remaining <= 0:
            return []

        avg_prompt = 800
        avg_completion = 400
        per_scenario_cost = (
            (avg_prompt / 1000) * self._config.cost_per_1k_prompt
            + (avg_completion / 1000) * self._config.cost_per_1k_completion
        )

        if per_scenario_cost <= 0:
            return filtered

        max_scenarios = int(remaining / per_scenario_cost)
        return filtered[:max_scenarios]

    def should_continue(self) -> bool:
        """False when the budget has been exhausted."""
        return not self._tracker.is_over_budget()
