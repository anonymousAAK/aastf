"""Tests for Google ADK and MS Agent adapter stubs."""

from __future__ import annotations

import inspect
from unittest.mock import patch

import pytest

from aastf.exceptions import AdapterNotFoundError
from aastf.harness.adapters.google_adk import GoogleADKHarness
from aastf.harness.adapters.ms_agent import MSAgentHarness
from aastf.models.config import FrameworkConfig

# ------------------------------------------------------------------ class basics


class TestGoogleADKHarnessExists:
    def test_class_exists(self):
        assert GoogleADKHarness is not None

    def test_has_run_scenario(self):
        assert hasattr(GoogleADKHarness, "run_scenario")
        assert inspect.iscoroutinefunction(GoogleADKHarness.run_scenario)

    def test_run_scenario_signature(self):
        sig = inspect.signature(GoogleADKHarness.run_scenario)
        params = list(sig.parameters.keys())
        assert "self" in params
        assert "scenario" in params


class TestMSAgentHarnessExists:
    def test_class_exists(self):
        assert MSAgentHarness is not None

    def test_has_run_scenario(self):
        assert hasattr(MSAgentHarness, "run_scenario")
        assert inspect.iscoroutinefunction(MSAgentHarness.run_scenario)

    def test_run_scenario_signature(self):
        sig = inspect.signature(MSAgentHarness.run_scenario)
        params = list(sig.parameters.keys())
        assert "self" in params
        assert "scenario" in params


# --------------------------------------------------------- import error messages


class TestGoogleADKImportError:
    def test_raises_helpful_message_when_sdk_missing(self):
        with (
            patch("aastf.harness.adapters.google_adk.HAS_GOOGLE_ADK", False),
            pytest.raises(AdapterNotFoundError, match="google-adk"),
        ):
            GoogleADKHarness(
                agent_factory=lambda tools: None,
                sandbox=None,  # type: ignore[arg-type]
            )


class TestMSAgentImportError:
    def test_raises_helpful_message_when_sdk_missing(self):
        with (
            patch("aastf.harness.adapters.ms_agent.HAS_SEMANTIC_KERNEL", False),
            pytest.raises(AdapterNotFoundError, match="semantic-kernel"),
        ):
            MSAgentHarness(
                agent_factory=lambda tools: None,
                sandbox=None,  # type: ignore[arg-type]
            )


# -------------------------------------------------------- runner registration


class TestRunnerRegistration:
    def test_google_adk_branch_exists(self):
        """Runner._build_harness has a google_adk branch."""
        from aastf.runner import Runner

        source = inspect.getsource(Runner._build_harness)
        assert "google_adk" in source

    def test_ms_agent_branch_exists(self):
        """Runner._build_harness has an ms_agent branch."""
        from aastf.runner import Runner

        source = inspect.getsource(Runner._build_harness)
        assert "ms_agent" in source


# ---------------------------------------------------------- config acceptance


class TestConfigAcceptsNewAdapters:
    def test_google_adk_config(self):
        cfg = FrameworkConfig(adapter="google_adk", agent_factory="myapp:create")
        assert cfg.adapter == "google_adk"

    def test_ms_agent_config(self):
        cfg = FrameworkConfig(adapter="ms_agent", agent_factory="myapp:create")
        assert cfg.adapter == "ms_agent"

    def test_existing_adapters_still_valid(self):
        for adapter in ("langgraph", "openai_agents", "crewai", "pydantic_ai", "mcp"):
            cfg = FrameworkConfig(adapter=adapter, agent_factory="myapp:create")
            assert cfg.adapter == adapter
