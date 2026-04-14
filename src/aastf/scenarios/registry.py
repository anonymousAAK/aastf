"""Scenario registry — discovers, indexes, and filters attack scenarios."""

from pathlib import Path

from ..models.scenario import ASICategory, AttackScenario, Severity
from .loader import load_directory

_BUILTIN_DIR = Path(__file__).parent / "builtin"


class ScenarioRegistry:
    """In-memory index of all loaded AttackScenario objects."""

    def __init__(self) -> None:
        self._scenarios: dict[str, AttackScenario] = {}

    # ------------------------------------------------------------------ loading

    def load_builtin(self) -> "ScenarioRegistry":
        """Load all scenarios shipped with aastf."""
        for s in load_directory(_BUILTIN_DIR):
            self._scenarios[s.id] = s
        return self

    def load_directory(self, path: Path) -> "ScenarioRegistry":
        """Load additional scenarios from a user-supplied directory."""
        for s in load_directory(path):
            if s.id in self._scenarios:
                raise ValueError(
                    f"Duplicate scenario ID {s.id!r} — "
                    f"already loaded from built-in registry"
                )
            self._scenarios[s.id] = s
        return self

    # ------------------------------------------------------------------ access

    def get(self, scenario_id: str) -> AttackScenario:
        if scenario_id not in self._scenarios:
            raise KeyError(f"Scenario not found: {scenario_id!r}")
        return self._scenarios[scenario_id]

    def all(self) -> list[AttackScenario]:
        return list(self._scenarios.values())

    def __len__(self) -> int:
        return len(self._scenarios)

    def __contains__(self, scenario_id: str) -> bool:
        return scenario_id in self._scenarios

    # ----------------------------------------------------------------- filtering

    def filter(
        self,
        categories: list[ASICategory] | list[str] | None = None,
        min_severity: Severity | str | None = None,
        tags: list[str] | None = None,
        exclude_ids: list[str] | None = None,
    ) -> list[AttackScenario]:
        """Return scenarios matching all supplied criteria, sorted by severity desc."""
        results = list(self._scenarios.values())

        if categories:
            cat_set = {ASICategory(c) if isinstance(c, str) else c for c in categories}
            results = [s for s in results if s.category in cat_set]

        if min_severity:
            floor = Severity(min_severity) if isinstance(min_severity, str) else min_severity
            results = [s for s in results if s.severity >= floor]

        if tags:
            tag_set = set(tags)
            results = [s for s in results if tag_set.intersection(s.tags)]

        if exclude_ids:
            excl = set(exclude_ids)
            results = [s for s in results if s.id not in excl]

        # Primary sort: category (ASI01 first), secondary: severity desc
        return sorted(results, key=lambda s: (s.category.value, -s.severity.numeric()))
