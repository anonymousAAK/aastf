"""Unit tests for response cache."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from aastf.cache import ResponseCache
from aastf.models.scenario import (
    ASICategory,
    AttackScenario,
    DetectionCriteria,
    InjectionPoint,
    Severity,
)
from aastf.models.trace import AgentTrace

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _scenario(
    scenario_id: str = "ASI01-001",
    payload: str = "test payload",
    tools: list[str] | None = None,
) -> AttackScenario:
    return AttackScenario(
        id=scenario_id,
        name="Test scenario",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        description="Test",
        attack_vector="prompt_injection",
        inject_into=InjectionPoint.USER_MESSAGE,
        payload=payload,
        available_tools=tools or ["tool_a", "tool_b"],
        detection=DetectionCriteria(tool_called=["tool_a"]),
        expected_behavior="Agent should refuse",
        remediation="Add guardrails",
    )


def _trace(scenario_id: str = "ASI01-001") -> AgentTrace:
    return AgentTrace(
        scenario_id=scenario_id,
        adapter="test",
        final_output="I cannot do that.",
    )


# ---------------------------------------------------------------------------
# Basic put/get
# ---------------------------------------------------------------------------


class TestPutGet:
    def test_roundtrip(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        trace = _trace()
        cache.put(scenario, "test", trace)
        result = cache.get(scenario, "test")
        assert result is not None
        assert result.scenario_id == "ASI01-001"
        assert result.adapter == "test"

    def test_roundtrip_preserves_final_output(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        trace = _trace()
        cache.put(scenario, "test", trace)
        result = cache.get(scenario, "test")
        assert result is not None
        assert result.final_output == "I cannot do that."

    def test_different_adapters_different_keys(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        trace_a = AgentTrace(scenario_id="ASI01-001", adapter="adapter_a", final_output="A")
        trace_b = AgentTrace(scenario_id="ASI01-001", adapter="adapter_b", final_output="B")
        cache.put(scenario, "adapter_a", trace_a)
        cache.put(scenario, "adapter_b", trace_b)

        result_a = cache.get(scenario, "adapter_a")
        result_b = cache.get(scenario, "adapter_b")
        assert result_a is not None
        assert result_b is not None
        assert result_a.final_output == "A"
        assert result_b.final_output == "B"


# ---------------------------------------------------------------------------
# Cache miss
# ---------------------------------------------------------------------------


class TestCacheMiss:
    def test_miss_returns_none(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        assert cache.get(scenario, "test") is None

    def test_miss_increments_counter(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        cache.get(scenario, "test")
        cache.get(scenario, "other")
        assert cache.misses == 2
        assert cache.hits == 0


# ---------------------------------------------------------------------------
# TTL expiry
# ---------------------------------------------------------------------------


class TestTTLExpiry:
    def test_expired_entry_returns_none(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache", ttl_days=1)
        scenario = _scenario()
        trace = _trace()
        cache.put(scenario, "test", trace)

        # Manually set cached_at to 2 days ago
        key = cache.compute_key(scenario, "test")
        path = tmp_path / "cache" / f"{key}.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        old_time = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        data["cached_at"] = old_time
        path.write_text(json.dumps(data, default=str), encoding="utf-8")

        assert cache.get(scenario, "test") is None

    def test_valid_entry_within_ttl(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache", ttl_days=14)
        scenario = _scenario()
        trace = _trace()
        cache.put(scenario, "test", trace)
        assert cache.get(scenario, "test") is not None


# ---------------------------------------------------------------------------
# compute_key()
# ---------------------------------------------------------------------------


class TestComputeKey:
    def test_deterministic(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        key1 = cache.compute_key(scenario, "test")
        key2 = cache.compute_key(scenario, "test")
        assert key1 == key2

    def test_different_payloads_different_keys(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        s1 = _scenario(payload="payload_a")
        s2 = _scenario(payload="payload_b")
        assert cache.compute_key(s1, "test") != cache.compute_key(s2, "test")

    def test_different_adapters_different_keys(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        assert cache.compute_key(scenario, "a") != cache.compute_key(scenario, "b")

    def test_returns_hex_string(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        key = cache.compute_key(_scenario(), "test")
        assert len(key) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in key)

    def test_different_tools_different_keys(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        s1 = _scenario(tools=["a", "b"])
        s2 = _scenario(tools=["a", "c"])
        assert cache.compute_key(s1, "test") != cache.compute_key(s2, "test")


# ---------------------------------------------------------------------------
# clear()
# ---------------------------------------------------------------------------


class TestClear:
    def test_clear_removes_all(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        s1 = _scenario(scenario_id="ASI01-001", payload="p1")
        s2 = _scenario(scenario_id="ASI01-002", payload="p2")
        cache.put(s1, "test", _trace("ASI01-001"))
        cache.put(s2, "test", _trace("ASI01-002"))
        removed = cache.clear()
        assert removed == 2
        assert cache.get(s1, "test") is None
        assert cache.get(s2, "test") is None

    def test_clear_empty_cache(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        removed = cache.clear()
        assert removed == 0

    def test_clear_nonexistent_dir(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "nonexistent")
        removed = cache.clear()
        assert removed == 0


# ---------------------------------------------------------------------------
# stats()
# ---------------------------------------------------------------------------


class TestStats:
    def test_initial_stats_empty(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        stats = cache.stats()
        assert stats["entries"] == 0

    def test_stats_after_put(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        cache.put(_scenario(), "test", _trace())
        stats = cache.stats()
        assert stats["entries"] == 1
        assert stats["size_bytes"] > 0

    def test_stats_tracks_hits_misses(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache")
        scenario = _scenario()
        cache.put(scenario, "test", _trace())
        cache.get(scenario, "test")  # hit
        cache.get(_scenario(payload="different"), "test")  # miss
        assert cache.hits == 1
        assert cache.misses == 1


# ---------------------------------------------------------------------------
# Corrupted cache
# ---------------------------------------------------------------------------


class TestCorruptedCache:
    def test_corrupted_json_returns_none(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache = ResponseCache(cache_dir=cache_dir)
        scenario = _scenario()

        # Write corrupted file at the expected key path
        key = cache.compute_key(scenario, "test")
        (cache_dir / f"{key}.json").write_text("not valid json {{{", encoding="utf-8")

        assert cache.get(scenario, "test") is None
        assert cache.misses == 1

    def test_missing_trace_data_returns_none(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache = ResponseCache(cache_dir=cache_dir)
        scenario = _scenario()

        key = cache.compute_key(scenario, "test")
        entry = {
            "scenario_id": "ASI01-001",
            "cache_key": key,
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "ttl_days": 14,
            # "trace" key intentionally missing
        }
        (cache_dir / f"{key}.json").write_text(json.dumps(entry), encoding="utf-8")

        assert cache.get(scenario, "test") is None

    def test_invalid_cached_at_returns_none(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache_dir.mkdir()
        cache = ResponseCache(cache_dir=cache_dir)
        scenario = _scenario()

        key = cache.compute_key(scenario, "test")
        entry = {
            "scenario_id": "ASI01-001",
            "cache_key": key,
            "cached_at": "not-a-date",
            "ttl_days": 14,
            "trace": _trace().model_dump(mode="json"),
        }
        (cache_dir / f"{key}.json").write_text(
            json.dumps(entry, default=str), encoding="utf-8"
        )

        assert cache.get(scenario, "test") is None


# ---------------------------------------------------------------------------
# Disabled cache
# ---------------------------------------------------------------------------


class TestDisabledCache:
    def test_get_returns_none(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache", enabled=False)
        scenario = _scenario()
        # Put should be no-op, get should return None
        cache.put(scenario, "test", _trace())
        assert cache.get(scenario, "test") is None

    def test_put_is_noop(self, tmp_path):
        cache_dir = tmp_path / "cache"
        cache = ResponseCache(cache_dir=cache_dir, enabled=False)
        cache.put(_scenario(), "test", _trace())
        # Cache dir should not have been created (or should be empty)
        if cache_dir.exists():
            assert list(cache_dir.glob("*.json")) == []

    def test_disabled_increments_misses(self, tmp_path):
        cache = ResponseCache(cache_dir=tmp_path / "cache", enabled=False)
        cache.get(_scenario(), "test")
        cache.get(_scenario(), "other")
        assert cache.misses == 2

    def test_enabled_property(self, tmp_path):
        enabled = ResponseCache(cache_dir=tmp_path / "a", enabled=True)
        disabled = ResponseCache(cache_dir=tmp_path / "b", enabled=False)
        assert enabled.enabled is True
        assert disabled.enabled is False


# ---------------------------------------------------------------------------
# Cache directory handling
# ---------------------------------------------------------------------------


class TestCacheDirectory:
    def test_creates_cache_dir_on_put(self, tmp_path):
        cache_dir = tmp_path / "deep" / "nested" / "cache"
        cache = ResponseCache(cache_dir=cache_dir)
        cache.put(_scenario(), "test", _trace())
        assert cache_dir.exists()

    def test_default_cache_dir(self):
        """Default cache dir should be .aastf/cache relative to cwd."""
        cache = ResponseCache(enabled=False)
        # Just verify it doesn't crash; we use enabled=False to avoid
        # creating dirs in the actual cwd
        assert cache.enabled is False
