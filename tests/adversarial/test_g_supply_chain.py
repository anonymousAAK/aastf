"""
Category G — Supply Chain & Install Integrity.

Hypotheses:
  G1. Package entry point 'aastf' is declared in pyproject.toml and resolves correctly.
  G2. Version strings in pyproject.toml and __init__.py match.
  G3. All declared optional extras reference packages that can be imported (if installed).
  G4. Package structure matches wheel build configuration (src layout).
  G5. No hardcoded secrets or API keys appear in source files.
  G6. YAML loader uses yaml.safe_load, not yaml.load (supply chain safety).
  G7. Jinja2 payload renderer does not expose dangerous builtins.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent.parent


# --------------------------------------------------------------------------- G1
class TestEntryPoints:
    """G1: Entry point resolves correctly."""

    def test_aastf_module_importable(self):
        """Hypothesis: 'aastf' package is importable."""
        import aastf
        assert aastf.__version__ is not None

    def test_version_is_semver(self):
        """Hypothesis: __version__ follows semver (X.Y.Z)."""
        import aastf
        assert re.match(r"^\d+\.\d+\.\d+$", aastf.__version__), (
            f"__version__ {aastf.__version__!r} does not match semver"
        )


# --------------------------------------------------------------------------- G2
class TestVersionConsistency:
    """G2: Version strings in pyproject.toml and __init__.py match."""

    def test_pyproject_and_init_version_match(self):
        """Hypothesis: pyproject.toml version == aastf.__version__."""
        import aastf

        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.MULTILINE)
        assert match, "Could not find version in pyproject.toml"
        pyproject_version = match.group(1)

        assert aastf.__version__ == pyproject_version, (
            f"Version mismatch: pyproject.toml={pyproject_version!r}, "
            f"__init__.py={aastf.__version__!r}"
        )


# --------------------------------------------------------------------------- G3
class TestOptionalExtras:
    """G3: Optional extras are correctly declared."""

    def test_pyproject_has_langgraph_extra(self):
        """Hypothesis: pyproject.toml declares langgraph optional dependency."""
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "langgraph" in pyproject

    def test_pyproject_has_openai_agents_extra(self):
        """Hypothesis: pyproject.toml declares openai optional dependency."""
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "openai" in pyproject

    def test_pydantic_ai_in_extras(self):
        """
        Hypothesis (BUG-02 FIXED): pydantic-ai is now declared as an optional extra
        in pyproject.toml, matching the implemented PydanticAIHarness.
        """
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        in_extras = bool(
            re.search(r'\[project\.optional-dependencies\].*pydantic.ai', pyproject, re.DOTALL)
        )
        assert in_extras, (
            "BUG-02 FIX VERIFIED: pydantic-ai should be declared in optional-dependencies"
        )


# --------------------------------------------------------------------------- G4
class TestPackageStructure:
    """G4: Package structure matches wheel build config."""

    def test_src_layout_exists(self):
        """Hypothesis: src/aastf/ directory exists (src layout)."""
        src = REPO_ROOT / "src" / "aastf"
        assert src.is_dir()

    def test_all_subpackages_have_init(self):
        """
        Hypothesis: Every Python subpackage directory has an __init__.py.
        Non-Python asset directories (templates/, etc.) are excluded.

        NOTE: src/aastf/reporting/templates/ contains report.html.j2 but NO
        __init__.py — it is a template asset directory, not a Python package.
        This is intentional. However, html_reporter.py uses an INLINE template
        string and never loads from this directory (BUG-09: dead template file).
        """
        # These directories are intentionally not Python packages
        NON_PACKAGE_DIRS = {"templates", "builtin"}
        src = REPO_ROOT / "src" / "aastf"
        missing = []
        for d in src.rglob("*/"):
            if d.name.startswith("__") or d.name.startswith("."):
                continue
            if d.name in NON_PACKAGE_DIRS:
                continue
            # Skip category subdirectories under builtin (asi01/, asi02/, etc.)
            if d.parent.name == "builtin":
                continue
            if d.is_dir():
                init = d / "__init__.py"
                if not init.exists():
                    missing.append(str(d.relative_to(REPO_ROOT)))
        assert not missing, f"Missing __init__.py in Python package dirs: {missing}"

    def test_builtin_scenarios_exist(self):
        """Hypothesis: All 10 ASI category directories exist with 5 scenarios each."""
        builtin = REPO_ROOT / "src" / "aastf" / "scenarios" / "builtin"
        for cat in [f"asi{str(i).zfill(2)}" for i in range(1, 11)]:
            cat_dir = builtin / cat
            assert cat_dir.exists(), f"Missing builtin directory: {cat}"
            yaml_files = list(cat_dir.glob("*.yaml"))
            assert len(yaml_files) == 5, (
                f"{cat} has {len(yaml_files)} scenarios, expected 5"
            )


# --------------------------------------------------------------------------- G5
class TestNoHardcodedSecrets:
    """G5: No hardcoded secrets or API keys in source."""

    SECRET_PATTERNS = [
        r'sk-[A-Za-z0-9]{20,}',          # OpenAI API key
        r'AKIA[0-9A-Z]{16}',              # AWS access key
        r'ghp_[A-Za-z0-9]{36}',          # GitHub personal access token
        r'xoxb-[0-9]+-[A-Za-z0-9]+',     # Slack bot token
        r'-----BEGIN [A-Z]+ PRIVATE KEY', # Private key
    ]

    def test_no_secrets_in_python_source(self):
        """Hypothesis: No hardcoded API keys or secrets in Python source files."""
        src = REPO_ROOT / "src"
        violations = []
        for py_file in src.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in self.SECRET_PATTERNS:
                if re.search(pattern, content):
                    violations.append(f"{py_file.relative_to(REPO_ROOT)}: {pattern}")
        assert not violations, "Potential secrets found:\n" + "\n".join(violations)

    def test_no_secrets_in_yaml_scenarios(self):
        """Hypothesis: No hardcoded API keys in YAML scenario files."""
        builtin = REPO_ROOT / "src" / "aastf" / "scenarios" / "builtin"
        violations = []
        for yaml_file in builtin.rglob("*.yaml"):
            content = yaml_file.read_text(encoding="utf-8", errors="ignore")
            for pattern in self.SECRET_PATTERNS:
                if re.search(pattern, content):
                    violations.append(f"{yaml_file.name}: {pattern}")
        assert not violations, "Potential secrets in scenarios:\n" + "\n".join(violations)


# --------------------------------------------------------------------------- G6
class TestYAMLLoaderSafety:
    """G6: YAML loader uses safe_load."""

    def test_loader_uses_safe_load(self):
        """Hypothesis: loader.py contains yaml.safe_load, not yaml.load."""
        loader_src = (REPO_ROOT / "src" / "aastf" / "scenarios" / "loader.py").read_text()
        assert "yaml.safe_load" in loader_src
        # Ensure the unsafe yaml.load is NOT present (without safe_load prefix)
        # Allow yaml.safe_load but not bare yaml.load(
        import re
        bare_load = re.findall(r'\byaml\.load\b(?!_)', loader_src)
        assert not bare_load, f"Unsafe yaml.load found: {bare_load}"


# --------------------------------------------------------------------------- G7
class TestJinja2Safety:
    """G7: Jinja2 payload renderer does not expose dangerous builtins."""

    def test_jinja2_sandbox_does_not_expose_builtins(self):
        """
        Hypothesis: render_payload() using StrictUndefined raises UndefinedError
        for undefined variables, not silently passing them.
        """
        from jinja2 import UndefinedError

        from aastf.scenarios.loader import render_payload

        with pytest.raises(UndefinedError):
            render_payload("Hello {{ undefined_var }}")

    def test_jinja2_render_with_context(self):
        """Hypothesis: Jinja2 templates render correctly with provided context."""
        from aastf.scenarios.loader import render_payload
        result = render_payload("Hello {{ name }}!", {"name": "world"})
        assert result == "Hello world!"

    def test_jinja2_cannot_access_config_via_template(self):
        """
        Hypothesis: Jinja2 template cannot access Python's config/module globals.
        StrictUndefined prevents accessing undefined names.
        """
        from jinja2 import UndefinedError

        from aastf.scenarios.loader import render_payload

        # Try to access __class__ through undefined
        with pytest.raises(UndefinedError):
            render_payload("{{ __class__ }}")

    def test_html_reporter_jinja2_autoescapes(self):
        """
        Hypothesis: HTMLReporter uses autoescape=select_autoescape(['html'])
        so variables in templates are HTML-escaped.
        """
        from aastf.reporting.html_reporter import HTMLReporter
        reporter = HTMLReporter()
        # Autoescape should be enabled for HTML templates
        assert reporter._env.autoescape is not False
