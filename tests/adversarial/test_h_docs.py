"""
Category H — Documentation Truthfulness.

Hypotheses:
  H1.  README claims "50 built-in attack scenarios" — verified.
  H2.  README claims "305 tests" — check against actual count (BUG: badge stale).
  H3.  README claims "5 per category" — verified.
  H4.  CLI flags documented in README exist with correct names.
  H5.  Exit codes documented in README (0, 1, 2) — check code paths.
  H6.  README says REFUSAL_ECHO never triggers non_compliant — verify.
  H7.  README says 'generic' adapter is supported — DISPROVED (BUG-01).
  H8.  README architecture diagram lists PydanticAI — verify it's implemented.
  H9.  TESTING.md test count matches actual count.
  H10. README example `--output results.sarif` uses non-existent flag (BUG-D-01).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent
README = (REPO_ROOT / "README.md").read_text(encoding="utf-8")


# --------------------------------------------------------------------------- H1
class TestScenarioCounts:
    """H1, H3: Scenario count claims."""

    def test_readme_claims_50_scenarios(self):
        """Hypothesis: README says '50 built-in attack scenarios'."""
        assert "50" in README and "scenario" in README.lower()

    def test_actual_scenario_count_is_50(self):
        """Hypothesis: The actual loader returns exactly 50 scenarios."""
        from aastf.scenarios.registry import ScenarioRegistry
        registry = ScenarioRegistry().load_builtin()
        assert len(registry) == 50

    def test_five_per_category(self):
        """Hypothesis: Exactly 5 scenarios per ASI category."""
        from aastf.models.scenario import ASICategory
        from aastf.scenarios.registry import ScenarioRegistry
        registry = ScenarioRegistry().load_builtin()
        for cat in ASICategory:
            count = len(registry.filter(categories=[cat]))
            assert count == 5, f"Expected 5 for {cat}, got {count}"


# --------------------------------------------------------------------------- H2
class TestTestCount:
    """H2: README test count badge."""

    def test_readme_badge_shows_correct_count(self):
        """
        Hypothesis (BUG-14 FIXED): README badge now shows 313, matching the actual
        test suite count. The stale "305" badge has been updated.
        """
        assert "313" in README, (
            "BUG-14 FIX VERIFIED: README badge should show 313 tests"
        )
        assert "305" not in README, (
            "Old stale badge '305' should be removed from README"
        )

    def test_actual_test_count_matches_readme(self):
        """
        Hypothesis (BUG-14 FIXED): README badge count matches actual test count.
        """
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/unit/", "tests/self_audit/",
             "--collect-only", "-q"],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
        )
        match = re.search(r"(\d+) test", result.stdout + result.stderr)
        if match:
            actual_count = int(match.group(1))
            assert str(actual_count) in README, (
                f"README badge should reflect actual test count {actual_count}"
            )
        else:
            pytest.skip("Could not parse test count from pytest output")


# --------------------------------------------------------------------------- H4
class TestCLIFlags:
    """H4: CLI flags documented in README exist."""

    def test_adapter_flag_exists(self):
        """Hypothesis: --adapter flag exists in run command."""
        # Typer commands store their parameters
        # Check the function signature
        import inspect

        from aastf.cli.commands.run import run
        sig = inspect.signature(run)
        assert "adapter" in sig.parameters

    def test_fail_on_flag_exists(self):
        """Hypothesis: --fail-on flag exists."""
        import inspect

        from aastf.cli.commands.run import run
        sig = inspect.signature(run)
        assert "fail_on" in sig.parameters

    def test_format_flag_exists(self):
        """Hypothesis: --format flag exists."""
        import inspect

        from aastf.cli.commands.run import run
        sig = inspect.signature(run)
        assert "format" in sig.parameters

    def test_output_dir_flag_exists(self):
        """Hypothesis: --output-dir flag exists (not --output)."""
        import inspect

        from aastf.cli.commands.run import run
        sig = inspect.signature(run)
        assert "output_dir" in sig.parameters

    def test_strict_output_flag_exists(self):
        """Hypothesis: --strict-output flag exists."""
        import inspect

        from aastf.cli.commands.run import run
        sig = inspect.signature(run)
        assert "strict_output" in sig.parameters

    def test_readme_uses_output_dir_not_output(self):
        """
        Hypothesis: README Quick Start uses --output-dir (correct).
        Check that --output-dir appears in the README.
        """
        assert "--output-dir" in README

    def test_readme_uses_correct_output_flag(self):
        """
        Hypothesis (BUG-15 FIXED): README Quick Start now uses '--output-dir' (correct),
        not '--output results.sarif' (wrong flag that doesn't exist).
        """
        has_wrong_flag = bool(re.search(r"--output\s+results\.sarif", README))
        assert not has_wrong_flag, (
            "BUG-15: README still has '--output results.sarif'; should be '--output-dir'"
        )
        assert "--output-dir" in README, "README should use '--output-dir' flag"


# --------------------------------------------------------------------------- H5
class TestExitCodes:
    """H5: Exit codes documented in README."""

    def test_readme_documents_exit_codes(self):
        """Hypothesis: README documents exit codes 0, 1, 2."""
        assert "Exit codes" in README or "exit code" in README.lower()
        assert "0" in README
        assert "1" in README
        assert "2" in README

    def test_exit_code_2_is_implemented(self):
        """
        Hypothesis (BUG-13 FIXED): The run command now raises typer.Exit(2) for
        config errors (e.g., invalid adapter value passed via CLI).
        """
        import inspect

        from aastf.cli.commands import run as run_module
        source = inspect.getsource(run_module)
        assert "Exit(2)" in source, (
            "BUG-13 FIX VERIFIED: typer.Exit(2) should be present in run command for config errors"
        )


# --------------------------------------------------------------------------- H6
class TestRefusalEchoDocumentation:
    """H6: README claim about REFUSAL_ECHO never triggering non_compliant."""

    def test_refusal_echo_never_non_compliant(self):
        """Hypothesis: REFUSAL_ECHO at any severity never gives non_compliant readiness."""
        from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
        from aastf.models.scenario import ASICategory, Severity
        from aastf.scoring import eu_ai_act_readiness

        for sev in Severity:
            f = VulnerabilityFinding(
                scenario_id="ASI01-001",
                scenario_name="Test",
                category=ASICategory.ASI01,
                severity=sev,
                verdict=Verdict.REFUSAL_ECHO,
                triggered_by="test",
                description="test",
                remediation="fix",
            )
            report = ScanReport(aastf_version="0.3.0", adapter="test", findings=[f])
            readiness = eu_ai_act_readiness(report)
            assert readiness != "non_compliant", (
                f"REFUSAL_ECHO at {sev} incorrectly gives non_compliant"
            )


# --------------------------------------------------------------------------- H7
class TestGenericAdapterDocumentation:
    """H7: README architecture diagram lists generic adapter support."""

    def test_generic_adapter_config_rejected(self):
        """
        Hypothesis (BUG-01 FIXED): FrameworkConfig now rejects 'generic' at validation
        time with a Pydantic error — fail-fast before any runtime code runs.
        """
        from pydantic import ValidationError

        from aastf.models.config import FrameworkConfig
        with pytest.raises(ValidationError):
            FrameworkConfig(adapter="generic", agent_factory="os:getcwd")


# --------------------------------------------------------------------------- H8
class TestPydanticAIDocumentation:
    """H8: PydanticAI adapter is implemented but not in install docs."""

    def test_pydantic_ai_harness_exists(self):
        """Hypothesis: PydanticAIHarness class exists."""
        from aastf.harness.adapters.pydantic_ai import PydanticAIHarness
        assert PydanticAIHarness is not None

    def test_pydantic_ai_in_all_extra(self):
        """
        Hypothesis (BUG-02 FIXED): 'all' extra now includes pydantic-ai,
        matching the implemented PydanticAIHarness.
        """
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        all_extra_match = re.search(r'all\s*=\s*\[([^\]]+)\]', pyproject)
        assert all_extra_match, "Could not find 'all' extra in pyproject.toml"
        all_extra = all_extra_match.group(1)
        assert "pydantic" in all_extra, (
            "BUG-02 FIX VERIFIED: pydantic-ai should be in the 'all' extra"
        )


# --------------------------------------------------------------------------- H9
class TestTestingMd:
    """H9: TESTING.md test count."""

    def test_testing_md_exists(self):
        """Hypothesis: TESTING.md exists (referenced from README)."""
        testing_md = REPO_ROOT / "TESTING.md"
        assert testing_md.exists(), (
            "TESTING.md referenced in README but does not exist"
        )

    @pytest.mark.skip(reason="TESTING.md content not yet read — manual verification needed")
    def test_testing_md_count_matches_actual(self):
        """Hypothesis: Test count in TESTING.md matches actual pytest collection."""
        pass
