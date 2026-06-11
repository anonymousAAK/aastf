"""Unit tests for AutoGen adapter."""

from __future__ import annotations

import pytest


class TestAutoGenHarnessImport:
    def test_raises_adapter_not_found_when_autogen_missing(self):
        """If autogen-agentchat is not installed, harness raises AdapterNotFoundError."""
        import sys

        backup = sys.modules.get("autogen_agentchat")
        sys.modules["autogen_agentchat"] = None  # type: ignore[assignment]

        try:
            import importlib

            import aastf.harness.adapters.autogen as autogen_mod

            importlib.reload(autogen_mod)

            if not autogen_mod.HAS_AUTOGEN:
                from aastf.exceptions import AdapterNotFoundError
                from aastf.sandbox.server import SandboxServer

                with pytest.raises(AdapterNotFoundError, match="autogen-agentchat"):
                    autogen_mod.AutoGenHarness(lambda tools: None, SandboxServer())
        finally:
            if backup is not None:
                sys.modules["autogen_agentchat"] = backup
            elif "autogen_agentchat" in sys.modules:
                del sys.modules["autogen_agentchat"]

    def test_harness_module_importable(self):
        """Module should import without error regardless of autogen-agentchat presence."""
        from aastf.harness.adapters import autogen as autogen_mod  # noqa: F401

        assert hasattr(autogen_mod, "AutoGenHarness")
        assert hasattr(autogen_mod, "HAS_AUTOGEN")


class TestAutoGenHarnessStructure:
    """Test the harness structure using a mock agent (no real autogen-agentchat needed)."""

    def _make_harness(self, agent_factory=lambda t: None):
        import sys
        import types

        mock_mod = types.ModuleType("autogen_agentchat")
        sys.modules["autogen_agentchat"] = mock_mod

        try:
            import importlib

            import aastf.harness.adapters.autogen as autogen_mod

            importlib.reload(autogen_mod)
            autogen_mod.HAS_AUTOGEN = True

            from aastf.sandbox.server import SandboxServer

            return autogen_mod.AutoGenHarness(agent_factory, SandboxServer())
        finally:
            if "autogen_agentchat" in sys.modules:
                del sys.modules["autogen_agentchat"]

    @staticmethod
    def _scenario(inject_into):
        from aastf.models.scenario import (
            ASICategory,
            AttackScenario,
            DetectionCriteria,
            Severity,
        )

        return AttackScenario(
            id="ASI01-001",
            name="T",
            category=ASICategory.ASI01,
            severity=Severity.HIGH,
            description="d",
            attack_vector="v",
            inject_into=inject_into,
            payload="INJECTED PAYLOAD",
            detection=DetectionCriteria(),
            expected_behavior="safe",
            remediation="fix",
        )

    def test_build_input_user_message(self):
        """_build_input returns the payload for USER_MESSAGE injection."""
        from aastf.models.scenario import InjectionPoint

        harness = self._make_harness()
        scenario = self._scenario(InjectionPoint.USER_MESSAGE)
        assert harness._build_input(scenario) == "INJECTED PAYLOAD"

    def test_build_input_system_prompt(self):
        """_build_input wraps the payload with [SYSTEM]/[USER] markers for SYSTEM_PROMPT injection."""
        from aastf.models.scenario import InjectionPoint

        harness = self._make_harness()
        scenario = self._scenario(InjectionPoint.SYSTEM_PROMPT)
        result = harness._build_input(scenario)
        assert "[SYSTEM] INJECTED PAYLOAD" in result
        assert "[USER]" in result

    def test_extract_final_output_from_messages(self):
        """_extract_final_output returns the content of the last message."""
        import types

        harness = self._make_harness()
        result = types.SimpleNamespace(
            messages=[
                types.SimpleNamespace(source="user", content="hello"),
                types.SimpleNamespace(source="assistant", content="final answer"),
            ]
        )
        assert harness._extract_final_output(result) == "final answer"

    def test_extract_final_output_no_messages(self):
        """_extract_final_output falls back to str(result) when there are no messages."""
        import types

        harness = self._make_harness()
        result = types.SimpleNamespace(messages=[])
        assert harness._extract_final_output(result) == str(result)

    @pytest.mark.asyncio
    async def test_run_scenario_with_malformed_factory(self):
        """A factory returning an object without run() is reported as an error, not silently SAFE."""
        from aastf.models.scenario import InjectionPoint

        harness = self._make_harness(agent_factory=lambda tools: object())
        scenario = self._scenario(InjectionPoint.USER_MESSAGE)

        trace = await harness.run_scenario(scenario)
        assert trace.error is not None
        assert "run()" in trace.error
