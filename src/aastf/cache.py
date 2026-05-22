"""Disk-based response cache for AASTF scans.

Caches agent responses keyed by scenario content hash to avoid
redundant LLM/agent calls during development re-runs.

Storage: one JSON file per cached response in ``.aastf/cache/``.
TTL: 14 days by default, configurable.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models.scenario import AttackScenario
from .models.trace import AgentTrace

logger = logging.getLogger(__name__)


class ResponseCache:
    """Disk-based cache for agent responses, keyed by scenario content hash."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl_days: int = 14,
        enabled: bool = True,
    ) -> None:
        self._cache_dir = cache_dir or Path.cwd() / ".aastf" / "cache"
        self._ttl_days = ttl_days
        self._enabled = enabled
        self._hits = 0
        self._misses = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def hits(self) -> int:
        return self._hits

    @property
    def misses(self) -> int:
        return self._misses

    def compute_key(self, scenario: AttackScenario, adapter: str) -> str:
        """Return hex SHA-256 hash of scenario_id + payload + available_tools + adapter."""
        parts = "|".join([
            scenario.id,
            scenario.payload,
            ",".join(sorted(scenario.available_tools)),
            adapter,
        ])
        return hashlib.sha256(parts.encode("utf-8")).hexdigest()

    def get(self, scenario: AttackScenario, adapter: str) -> AgentTrace | None:
        """Return cached AgentTrace if a valid entry exists, else None."""
        if not self._enabled:
            self._misses += 1
            return None

        key = self.compute_key(scenario, adapter)
        path = self._cache_dir / f"{key}.json"

        if not path.exists():
            self._misses += 1
            return None

        try:
            raw = path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(raw)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupted cache entry %s: %s", path.name, exc)
            self._misses += 1
            return None

        # Check TTL
        cached_at_str = data.get("cached_at")
        ttl = data.get("ttl_days", self._ttl_days)
        if cached_at_str:
            try:
                cached_at = datetime.fromisoformat(cached_at_str)
                age_days = (datetime.now(timezone.utc) - cached_at).total_seconds() / 86400
                if age_days > ttl:
                    logger.info(
                        "Cache entry expired for %s (%.1f days old)",
                        scenario.id,
                        age_days,
                    )
                    self._misses += 1
                    return None
            except (ValueError, TypeError):
                logger.warning("Invalid cached_at in %s, treating as miss", path.name)
                self._misses += 1
                return None

        # Deserialize trace
        trace_data = data.get("trace")
        if trace_data is None:
            logger.warning("No trace data in cache entry %s", path.name)
            self._misses += 1
            return None

        try:
            trace = AgentTrace.model_validate(trace_data)
        except Exception as exc:
            logger.warning("Failed to deserialize cached trace %s: %s", path.name, exc)
            self._misses += 1
            return None

        self._hits += 1
        return trace

    def put(self, scenario: AttackScenario, adapter: str, trace: AgentTrace) -> None:
        """Store a trace in the cache."""
        if not self._enabled:
            return

        key = self.compute_key(scenario, adapter)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_dir / f"{key}.json"

        entry = {
            "scenario_id": scenario.id,
            "cache_key": key,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "ttl_days": self._ttl_days,
            "trace": trace.model_dump(mode="json"),
        }

        try:
            path.write_text(
                json.dumps(entry, indent=2, default=str), encoding="utf-8",
            )
        except OSError as exc:
            logger.warning("Failed to write cache entry %s: %s", path.name, exc)

    def clear(self) -> int:
        """Clear all cached entries. Returns count of files deleted."""
        if not self._cache_dir.exists():
            return 0

        count = 0
        for f in self._cache_dir.glob("*.json"):
            try:
                f.unlink()
                count += 1
            except OSError:
                pass
        return count

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        if not self._cache_dir.exists():
            return {
                "entries": 0,
                "size_bytes": 0,
                "oldest": None,
                "newest": None,
            }

        files = list(self._cache_dir.glob("*.json"))
        if not files:
            return {
                "entries": 0,
                "size_bytes": 0,
                "oldest": None,
                "newest": None,
            }

        total_size = 0
        oldest_ts: str | None = None
        newest_ts: str | None = None

        for f in files:
            total_size += f.stat().st_size
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                ts = data.get("cached_at")
                if ts:
                    if oldest_ts is None or ts < oldest_ts:
                        oldest_ts = ts
                    if newest_ts is None or ts > newest_ts:
                        newest_ts = ts
            except (json.JSONDecodeError, OSError):
                pass

        return {
            "entries": len(files),
            "size_bytes": total_size,
            "oldest": oldest_ts,
            "newest": newest_ts,
        }
