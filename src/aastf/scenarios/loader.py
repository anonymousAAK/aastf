"""YAML scenario loader with Jinja2 payload rendering."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from jinja2 import BaseLoader, StrictUndefined
from jinja2.sandbox import SandboxedEnvironment

from ..exceptions import ScenarioValidationError
from ..models.scenario import AttackScenario

# SandboxedEnvironment (not a plain Environment) so that rendering an
# attacker-controlled scenario/pack payload cannot reach Python internals via
# ``{{ ''.__class__.__mro__... }}`` style SSTI. autoescape stays False because
# payloads are injected as raw agent input, not HTML.
_jinja_env = SandboxedEnvironment(
    loader=BaseLoader(), undefined=StrictUndefined, autoescape=False
)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    Plain ``yaml.safe_load`` silently keeps only the last value when a key is
    repeated, which previously caused multiple ``tool_input_contains`` patterns
    written under the same tool name to collapse to one — dropping detection
    signatures. Failing loudly prevents that class of silent data loss in both
    builtin scenarios and third-party packs.
    """


def _construct_mapping_no_dups(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False):
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_dups
)


def load_scenario(path: Path) -> AttackScenario:
    """Load and validate a single YAML scenario file."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ScenarioValidationError(str(path), [f"Cannot read file: {e}"]) from e

    try:
        data: dict[str, Any] = yaml.load(raw, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as e:
        raise ScenarioValidationError(str(path), [f"YAML parse error: {e}"]) from e

    if not isinstance(data, dict):
        raise ScenarioValidationError(
            str(path), ["File must contain a YAML mapping, not a list or scalar"]
        )

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

    Raises ``ValueError`` if *path* contains path-traversal components (``..``).
    """
    path = Path(path)
    # Reject path-traversal attempts before resolving to avoid symlink tricks
    if ".." in path.parts:
        raise ValueError(
            f"Path traversal detected in scenario directory path: {path!r}. "
            "Use absolute paths or paths relative to the project root."
        )
    if not path.exists():
        raise FileNotFoundError(f"Scenario directory not found: {path}")
    if not path.is_dir():
        raise NotADirectoryError(f"Not a directory: {path}")
    resolved_root = path.resolve()

    scenarios: list[AttackScenario] = []
    errors: list[str] = []

    for yaml_file in sorted(path.rglob("*.yaml")):
        if yaml_file.name == "meta.yaml":
            continue
        # Guard against symlink escape: resolved file must stay within resolved root
        if not yaml_file.resolve().is_relative_to(resolved_root):
            errors.append(f"Symlink escape: {yaml_file} resolves outside {path}")
            continue
        try:
            scenarios.append(load_scenario(yaml_file))
        except ScenarioValidationError as e:
            errors.append(str(e))

    if errors:
        raise ScenarioValidationError(str(path), errors)

    return scenarios
