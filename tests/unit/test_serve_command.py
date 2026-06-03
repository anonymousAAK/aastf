"""CLI tests for `aastf serve` (the standalone sandbox server command).

Regression: `serve` was previously registered as a sub-Typer, so it could only
be invoked as `aastf serve serve`. It is now a top-level command (`aastf serve`)
and was otherwise untested.
"""

from __future__ import annotations

import inspect
import re

from typer.testing import CliRunner

from aastf.cli.app import app
from aastf.cli.commands import serve as serve_cmd

runner = CliRunner()

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip ANSI color codes. Rich colorizes option names (e.g. splitting
    '--port' into escape-separated dashes), so help output must be de-styled
    before substring assertions; CI emits colors even when a local TTY does not.
    """
    return _ANSI.sub("", text)


def test_serve_is_top_level_command_not_subgroup():
    """`aastf serve --help` works directly (not `aastf serve serve`)."""
    result = runner.invoke(app, ["serve", "--help"])
    assert result.exit_code == 0
    out = _plain(result.stdout)
    assert "--port" in out
    # A leftover sub-group would surface a nested 'serve' command in help.
    assert "serve serve" not in out


def test_serve_rejects_unknown_option():
    result = runner.invoke(app, ["serve", "--nonexistent-flag"])
    assert result.exit_code != 0


def test_serve_signature_has_port_and_scenario():
    sig = inspect.signature(serve_cmd.serve)
    assert "port" in sig.parameters
    assert "scenario_id" in sig.parameters


def test_serve_default_port_is_18080():
    sig = inspect.signature(serve_cmd.serve)
    # Typer wraps the default in an OptionInfo; its .default carries the value.
    port_param = sig.parameters["port"].default
    default = getattr(port_param, "default", port_param)
    assert default == 18080
