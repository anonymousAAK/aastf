"""
Category B — Adapter robustness.

Hypotheses:
  B1. `generic` adapter listed in FrameworkConfig raises at runtime (BUG-01).
  B2. PydanticAI harness raises AdapterNotFoundError when pydantic_ai not installed.
  B3. Runner raises AdapterNotFoundError with useful message for unknown adapter.
  B4. agent_factory path without ':' raises ValueError.
  B5. agent_factory pointing to nonexistent module raises AdapterNotFoundError.
  B6. agent_factory pointing to existing module with missing attribute raises AdapterNotFoundError.
"""

from __future__ import annotations

import pytest

from aastf.exceptions import AdapterNotFoundError
from aastf.models.config import FrameworkConfig
from aastf.runner import Runner


def _make_config(**kwargs) -> FrameworkConfig:
    defaults = dict(
        adapter="langgraph",
        agent_factory="myapp.agent:create_agent",
    )
    defaults.update(kwargs)
    return FrameworkConfig(**defaults)


# --------------------------------------------------------------------------- B1
class TestGenericAdapterBug:
    """B1: 'generic' is now rejected at config validation time (BUG-01 fixed)."""

    def test_generic_is_rejected_by_pydantic(self):
        """
        Hypothesis (BUG-01 FIXED): FrameworkConfig now rejects adapter='generic'
        with a Pydantic ValidationError — fail-fast at config time, not at runtime.
        """
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            _make_config(adapter="generic")

    def test_valid_adapters_do_not_raise_at_dispatch(self):
        """
        Hypothesis: The four real adapters don't raise AdapterNotFoundError at dispatch
        (they may raise import errors for missing SDKs, but not 'unknown adapter').
        """
        import types
        fake_sandbox = types.SimpleNamespace(base_url="http://127.0.0.1:9999")
        for adapter in ("langgraph", "crewai", "openai_agents", "pydantic_ai"):
            config = _make_config(adapter=adapter, agent_factory="os:getcwd")
            runner = Runner(config)
            # Should raise ImportError/AdapterNotFoundError about missing SDK,
            # NOT 'Unknown adapter'
            try:
                runner._build_harness(fake_sandbox)
            except AdapterNotFoundError as e:
                assert "Unknown adapter" not in str(e), (
                    f"{adapter} was rejected as 'Unknown adapter': {e}"
                )
            except Exception:
                pass  # ImportError for missing SDK — acceptable


# --------------------------------------------------------------------------- B2
class TestPydanticAIAdapterImportGuard:
    """B2: PydanticAIHarness raises AdapterNotFoundError when pydantic_ai not installed."""

    def test_pydantic_ai_harness_raises_if_not_installed(self):
        """
        Hypothesis: If pydantic_ai is not importable, PydanticAIHarness raises
        AdapterNotFoundError with an install hint.
        """
        import sys
        # Mock pydantic_ai as not installed
        saved = sys.modules.get("pydantic_ai")
        sys.modules["pydantic_ai"] = None  # type: ignore[assignment]
        try:
            # Force reimport of the module to re-evaluate HAS_PYDANTIC_AI
            import importlib
            import aastf.harness.adapters.pydantic_ai as pai_mod
            importlib.reload(pai_mod)

            if not pai_mod.HAS_PYDANTIC_AI:
                fake_sandbox = object()
                with pytest.raises(AdapterNotFoundError) as exc_info:
                    pai_mod.PydanticAIHarness(lambda tools: None, fake_sandbox)  # type: ignore
                assert "pydantic-ai" in str(exc_info.value).lower() or "pydantic_ai" in str(exc_info.value).lower()
            else:
                pytest.skip("pydantic_ai is actually installed — skip mock test")
        finally:
            if saved is None:
                sys.modules.pop("pydantic_ai", None)
            else:
                sys.modules["pydantic_ai"] = saved


# --------------------------------------------------------------------------- B3
class TestRunnerAgentFactoryLoading:
    """B3–B6: Runner agent factory loading edge cases."""

    def test_no_colon_in_factory_raises_value_error(self):
        """Hypothesis: agent_factory without ':' raises ValueError with clear message."""
        config = _make_config(agent_factory="myapp.agent")
        runner = Runner(config)
        with pytest.raises(ValueError, match="module.path:callable"):
            runner._load_agent_factory()

    def test_nonexistent_module_raises_adapter_not_found(self):
        """Hypothesis: importing a nonexistent module raises AdapterNotFoundError."""
        config = _make_config(agent_factory="this_module_does_not_exist_xyz:create_agent")
        runner = Runner(config)
        with pytest.raises(AdapterNotFoundError, match="Cannot import"):
            runner._load_agent_factory()

    def test_missing_attribute_raises_adapter_not_found(self):
        """Hypothesis: existing module with missing attribute raises AdapterNotFoundError."""
        config = _make_config(agent_factory="os:this_function_does_not_exist_xyz")
        runner = Runner(config)
        with pytest.raises(AdapterNotFoundError, match="no attribute"):
            runner._load_agent_factory()

    def test_valid_factory_path_loads_callable(self):
        """Hypothesis: valid dotted path to a callable loads without error."""
        config = _make_config(agent_factory="os:getcwd")
        runner = Runner(config)
        factory = runner._load_agent_factory()
        assert callable(factory)
