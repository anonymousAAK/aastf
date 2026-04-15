"""Unit tests for PydanticAI adapter."""

from __future__ import annotations

import pytest


class TestPydanticAIHarnessImport:
    def test_raises_adapter_not_found_when_pydantic_ai_missing(self):
        """If pydantic-ai is not installed, harness raises AdapterNotFoundError."""
        import sys
        backup = sys.modules.get("pydantic_ai")
        sys.modules["pydantic_ai"] = None  # type: ignore[assignment]

        try:
            import importlib

            import aastf.harness.adapters.pydantic_ai as pai_mod
            importlib.reload(pai_mod)

            if not pai_mod.HAS_PYDANTIC_AI:
                from aastf.exceptions import AdapterNotFoundError
                from aastf.sandbox.server import SandboxServer

                with pytest.raises(AdapterNotFoundError, match="pydantic-ai"):
                    pai_mod.PydanticAIHarness(lambda tools: None, SandboxServer())
        finally:
            if backup is not None:
                sys.modules["pydantic_ai"] = backup
            elif "pydantic_ai" in sys.modules:
                del sys.modules["pydantic_ai"]

    def test_harness_module_importable(self):
        """Module should import without error regardless of pydantic-ai presence."""
        from aastf.harness.adapters import pydantic_ai as pai_mod  # noqa: F401
        assert hasattr(pai_mod, "PydanticAIHarness")
        assert hasattr(pai_mod, "HAS_PYDANTIC_AI")


class TestPydanticAIHarnessStructure:
    """Test the harness structure using a mock agent (no real pydantic-ai needed)."""

    def test_build_input_user_message(self):
        """_build_input returns the payload for USER_MESSAGE injection."""
        import sys

        # Temporarily make pydantic_ai importable as a mock
        import types
        mock_mod = types.ModuleType("pydantic_ai")
        sys.modules["pydantic_ai"] = mock_mod

        try:
            import importlib

            import aastf.harness.adapters.pydantic_ai as pai_mod
            importlib.reload(pai_mod)
            pai_mod.HAS_PYDANTIC_AI = True

            from aastf.models.scenario import (
                ASICategory,
                AttackScenario,
                DetectionCriteria,
                InjectionPoint,
                Severity,
            )
            from aastf.sandbox.server import SandboxServer

            scenario = AttackScenario(
                id="ASI01-001", name="T", category=ASICategory.ASI01,
                severity=Severity.HIGH, description="d", attack_vector="v",
                inject_into=InjectionPoint.USER_MESSAGE,
                payload="INJECTED PAYLOAD",
                detection=DetectionCriteria(),
                expected_behavior="safe", remediation="fix",
            )

            harness = pai_mod.PydanticAIHarness(lambda t: None, SandboxServer())
            result = harness._build_input(scenario)
            assert result == "INJECTED PAYLOAD"
        finally:
            if "pydantic_ai" in sys.modules:
                del sys.modules["pydantic_ai"]
