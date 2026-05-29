"""Baseline-drift alerts — persist baselines, detect regressions across runs.

Complements the lower-level :class:`DriftDetector` (drift.py) by adding
persistent baseline storage, model-version change detection, configurable
alert policies, and human-readable regression summaries.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from .models.result import ScanReport, Verdict

logger = logging.getLogger(__name__)

# ── Severity helpers ─────────────────────────────────────────────────

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

_VULNERABLE_VERDICTS: set[str] = {
    Verdict.VULNERABLE.value,
    Verdict.TOOL_POISONING.value,
    Verdict.SCHEMA_POISONING.value,
    Verdict.PREFERENCE_MANIPULATION.value,
    Verdict.REFUSAL_ECHO.value,
    Verdict.INFECTION_PROPAGATED.value,
    Verdict.COLLUSION.value,
    Verdict.WATCHDOG_BYPASS.value,
}


def _verdict_is_vulnerable(v: str) -> bool:
    return v.upper() in _VULNERABLE_VERDICTS


def _drift_severity(old: str, new: str) -> str:
    """Compute alert severity based on verdict transition."""
    old_vuln = _verdict_is_vulnerable(old)
    new_vuln = _verdict_is_vulnerable(new)
    if not old_vuln and new_vuln:
        return "critical"  # regression: safe -> vulnerable
    if old_vuln and not new_vuln:
        return "info"  # improvement
    if old == new:
        return "none"
    return "medium"  # inconclusive transitions, verdict swaps


# ── Models ───────────────────────────────────────────────────────────


class DriftAlert(BaseModel):
    """A single verdict change between baseline and current scan."""

    scenario_id: str
    old_verdict: str
    new_verdict: str
    severity: str  # critical | high | medium | low | info | none
    model_version: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DriftAlertPolicy(BaseModel):
    """Configurable policy controlling which drift alerts are actionable."""

    fail_on_regression: bool = True
    ignore_inconclusive: bool = True
    severity_threshold: str = "medium"
    notify_channels: list[str] = Field(default_factory=list)

    def filter_alerts(self, alerts: list[DriftAlert]) -> list[DriftAlert]:
        """Return only alerts that exceed the policy threshold."""
        threshold = _SEVERITY_ORDER.get(self.severity_threshold.lower(), 2)
        filtered: list[DriftAlert] = []
        for a in alerts:
            # Skip inconclusive transitions if policy says so
            if self.ignore_inconclusive and (
                a.old_verdict == Verdict.INCONCLUSIVE.value
                or a.new_verdict == Verdict.INCONCLUSIVE.value
            ):
                continue
            sev = _SEVERITY_ORDER.get(a.severity.lower(), 0)
            if sev >= threshold:
                filtered.append(a)
        return filtered

    def should_fail(self, alerts: list[DriftAlert]) -> bool:
        """Return True if any actionable alert exists and policy says fail."""
        if not self.fail_on_regression:
            return False
        return len(self.filter_alerts(alerts)) > 0


# ── Baseline store ───────────────────────────────────────────────────


class BaselineStore:
    """Persist and retrieve :class:`ScanReport` baselines as JSON on disk."""

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path_for(self, label: str) -> Path:
        safe_label = label.replace("/", "_").replace("\\", "_")
        return self.directory / f"{safe_label}.json"

    def save_baseline(self, report: ScanReport, label: str) -> Path:
        """Serialize *report* to disk under *label*. Returns the file path."""
        path = self._path_for(label)
        path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
        logger.info("Saved baseline '%s' -> %s", label, path)
        return path

    def load_baseline(self, label: str) -> ScanReport | None:
        """Load a previously saved baseline, or ``None`` if not found."""
        path = self._path_for(label)
        if not path.exists():
            return None
        data = path.read_text(encoding="utf-8")
        return ScanReport.model_validate_json(data)

    def list_baselines(self) -> list[str]:
        """Return sorted list of available baseline labels."""
        return sorted(
            p.stem for p in self.directory.glob("*.json")
        )

    def delete_baseline(self, label: str) -> bool:
        """Remove a baseline. Returns True if it existed."""
        path = self._path_for(label)
        if path.exists():
            path.unlink()
            return True
        return False


# ── Drift detector ───────────────────────────────────────────────────


def _extract_model_version(report: ScanReport) -> str:
    """Best-effort model version extraction from a ScanReport.

    ScanReport carries ``adapter`` and ``aastf_version``; we combine them
    to form a pseudo model-version fingerprint.  Downstream callers can
    override by setting a custom field on the report metadata.
    """
    return f"{report.adapter}@{report.aastf_version}"


class BaselineDriftDetector:
    """Compare a current :class:`ScanReport` against a stored baseline."""

    def __init__(self, store: BaselineStore) -> None:
        self.store = store

    def compare(
        self, current: ScanReport, baseline_label: str
    ) -> list[DriftAlert]:
        """Detect verdict-level regressions between *current* and baseline.

        Returns a list of :class:`DriftAlert` — one per scenario whose
        verdict changed.
        """
        baseline = self.store.load_baseline(baseline_label)
        if baseline is None:
            return []

        baseline_map = {r.scenario_id: r for r in baseline.results}
        current_map = {r.scenario_id: r for r in current.results}

        model_version = _extract_model_version(current)
        now = datetime.now(timezone.utc)

        alerts: list[DriftAlert] = []
        all_ids = sorted(set(baseline_map) | set(current_map))

        for sid in all_ids:
            base = baseline_map.get(sid)
            curr = current_map.get(sid)

            if base is None or curr is None:
                # New or removed scenario — not a regression
                continue

            old_v = str(base.verdict)
            new_v = str(curr.verdict)

            if old_v == new_v:
                continue

            severity = _drift_severity(old_v, new_v)
            alerts.append(
                DriftAlert(
                    scenario_id=sid,
                    old_verdict=old_v,
                    new_verdict=new_v,
                    severity=severity,
                    model_version=model_version,
                    timestamp=now,
                )
            )

        return alerts

    def detect_model_change(
        self, current: ScanReport, baseline_label: str
    ) -> bool:
        """Return True if the model/adapter version differs from baseline."""
        baseline = self.store.load_baseline(baseline_label)
        if baseline is None:
            return False
        return _extract_model_version(current) != _extract_model_version(baseline)

    def should_retest(
        self, current: ScanReport, baseline_label: str
    ) -> bool:
        """Return True if a full re-test is warranted (model version changed)."""
        return self.detect_model_change(current, baseline_label)

    def regression_summary(self, alerts: list[DriftAlert]) -> str:
        """Produce a human-readable diff report from a list of alerts."""
        if not alerts:
            return "No regressions detected."

        regressions: list[DriftAlert] = []
        improvements: list[DriftAlert] = []
        other: list[DriftAlert] = []

        for a in alerts:
            if a.severity in ("critical", "high"):
                regressions.append(a)
            elif a.severity == "info":
                improvements.append(a)
            else:
                other.append(a)

        lines: list[str] = []
        lines.append(f"Drift Summary: {len(alerts)} change(s) detected")
        lines.append("=" * 50)

        if regressions:
            lines.append("")
            lines.append(f"REGRESSIONS ({len(regressions)}):")
            for a in regressions:
                lines.append(
                    f"  [{a.severity.upper()}] {a.scenario_id}: "
                    f"{a.old_verdict} -> {a.new_verdict}"
                )

        if improvements:
            lines.append("")
            lines.append(f"IMPROVEMENTS ({len(improvements)}):")
            for a in improvements:
                lines.append(
                    f"  [RESOLVED] {a.scenario_id}: "
                    f"{a.old_verdict} -> {a.new_verdict}"
                )

        if other:
            lines.append("")
            lines.append(f"OTHER CHANGES ({len(other)}):")
            for a in other:
                lines.append(
                    f"  [{a.severity.upper()}] {a.scenario_id}: "
                    f"{a.old_verdict} -> {a.new_verdict}"
                )

        return "\n".join(lines)
