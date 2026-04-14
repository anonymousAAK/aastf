"""YAML scenario loader with Jinja2 payload rendering."""

from pathlib import Path
from typing import Any

import yaml
from jinja2 import BaseLoader, Environment, StrictUndefined

from ..exceptions import ScenarioValidationError
from ..models.scenario import AttackScenario

_jinja_env = Environment(loader=BaseLoader(), undefined=StrictUndefined, autoescape=False)


def load_scenario(path: Path) -> AttackScenario:
    """Load and validate a single YAML scenario file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ScenarioValidationError(str(path), [f"Cannot read file: {e}"]) from e

    try:
        data: dict[str, Any] = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ScenarioValidationError(str(path), [f"YAML parse error: {e}"]) from e

    if not isinstance(data, dict):
        raise ScenarioValidationError(str(path), ["File must contain a YAML mapping, not a list or scalar"])

    try:
        return AttackScenario.model_validate(data)
    except Exception as e:  # ValidationError
        from pydantic import ValidationError as PydanticValidationError
        if isinstance(e, PydanticValidationError):
            raise ScenarioValidationError(str(path), e.errors()) from e
        raise ScenarioValidationError(str(path), [str(e)]) from e


def render_payload(payload: str, context: dict[str, Any] | None = None) -> str:
    """Render Jinja2 templates in a payload string."""
    template = _jinja_env.from_string(payload)
    return template.render(**(context or {}))


def load_directory(path: Path) -> list[AttackScenario]:
    """Recursively load all *.yaml scenario files from a directory.

    Files named meta.yaml are skipped (they contain category metadata, not scenarios).
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario directory not found: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")

    scenarios: list[AttackScenario] = []
    errors: list[str] = []

    for yaml_file in sorted(path.rglob("*.yaml")):
        if yaml_file.name == "meta.yaml":
            continue
        try:
            scenarios.append(load_scenario(yaml_file))
        except ScenarioValidationError as e:
            errors.append(str(e))

    if errors:
        raise ScenarioValidationError(str(path), errors)

    return scenarios
