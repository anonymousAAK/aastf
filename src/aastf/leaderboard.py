"""Leaderboard — ranking engine, submission handling, and public results tables.

> **Status: Stable.** Ranking, submission handling, and CSV/JSON result tables
> are deterministic and covered by tests; the public results schema is stable.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Verdict sets (mirrors runner / benchmark)
# ---------------------------------------------------------------------------

_VULNERABLE_VERDICTS = {
    "VULNERABLE",
    "TOOL_POISONING",
    "SCHEMA_POISONING",
    "PREFERENCE_MANIPULATION",
    "INFECTION_PROPAGATED",
    "COLLUSION",
    "WATCHDOG_BYPASS",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class LeaderboardEntry(BaseModel):
    """A single ranked entry on the leaderboard."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    model_name: str
    framework: str
    overall_score: float = Field(ge=0.0, le=1.0)
    category_scores: dict[str, float] = Field(default_factory=dict)
    total_scenarios: int = Field(ge=0)
    vulnerabilities_found: int = Field(ge=0)
    submission_date: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    submitter: str = ""
    verified: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("category_scores")
    @classmethod
    def _validate_category_scores(cls, v: dict[str, float]) -> dict[str, float]:
        for key, score in v.items():
            if not (0.0 <= score <= 1.0):
                raise ValueError(
                    f"Category score for {key!r} must be 0.0-1.0, got {score}"
                )
        return v


class SubmissionRequest(BaseModel):
    """Incoming submission to the leaderboard."""

    model_name: str
    framework: str
    report: dict[str, Any]  # ScanReport-compatible dict
    submitter: str = ""
    api_key: str | None = None


class SubmissionResult(BaseModel):
    """Result of a leaderboard submission attempt."""

    accepted: bool
    entry_id: str | None = None
    rank: int | None = None
    errors: list[str] = Field(default_factory=list)


class LeaderboardConfig(BaseModel):
    """Configuration for leaderboard behaviour."""

    min_scenarios: int = 50
    require_verification: bool = False
    sort_by: str = "overall_score"
    ascending: bool = False
    max_entries: int = 100

    @field_validator("sort_by")
    @classmethod
    def _valid_sort_field(cls, v: str) -> str:
        allowed = {
            "overall_score",
            "vulnerabilities_found",
            "total_scenarios",
            "submission_date",
            "model_name",
        }
        if v not in allowed:
            raise ValueError(f"sort_by must be one of {sorted(allowed)}, got {v!r}")
        return v

    @field_validator("min_scenarios")
    @classmethod
    def _positive_min(cls, v: int) -> int:
        if v < 0:
            raise ValueError(f"min_scenarios must be >= 0, got {v}")
        return v

    @field_validator("max_entries")
    @classmethod
    def _positive_max(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"max_entries must be >= 1, got {v}")
        return v


# ---------------------------------------------------------------------------
# Leaderboard engine
# ---------------------------------------------------------------------------


class Leaderboard:
    """Ranking engine with submission validation, persistence, and queries."""

    def __init__(
        self,
        config: LeaderboardConfig | None = None,
        storage_path: Path | None = None,
    ) -> None:
        self._config = config or LeaderboardConfig()
        self._storage_path = storage_path or Path("leaderboard.json")
        self._entries: list[LeaderboardEntry] = []

    # ------------------------------------------------------------------ public

    @property
    def config(self) -> LeaderboardConfig:
        return self._config

    @property
    def entries(self) -> list[LeaderboardEntry]:
        return list(self._entries)

    def validate_submission(self, request: SubmissionRequest) -> list[str]:
        """Validate a submission request and return a list of errors (empty = ok)."""
        errors: list[str] = []

        if not request.model_name.strip():
            errors.append("model_name must not be empty")

        if not request.framework.strip():
            errors.append("framework must not be empty")

        report = request.report
        if not isinstance(report, dict):
            errors.append("report must be a dict")
            return errors

        # Check required report fields
        total = report.get("total_scenarios", 0)
        if not isinstance(total, int) or total < self._config.min_scenarios:
            errors.append(
                f"report must contain at least {self._config.min_scenarios} scenarios, "
                f"got {total}"
            )

        if "results" not in report:
            errors.append("report must contain 'results' list")
        elif not isinstance(report["results"], list):
            errors.append("report['results'] must be a list")

        if self._config.require_verification and not request.api_key:
            errors.append("api_key is required when verification is enabled")

        return errors

    def submit(self, request: SubmissionRequest) -> SubmissionResult:
        """Validate and add a submission to the leaderboard."""
        errors = self.validate_submission(request)
        if errors:
            return SubmissionResult(accepted=False, errors=errors)

        entry = self._build_entry(request)

        # Enforce max_entries: drop lowest-ranked entry if full
        self._entries.append(entry)
        ranked = self._sorted_entries()
        if len(ranked) > self._config.max_entries:
            # Remove the entry that falls off the bottom
            self._entries = ranked[: self._config.max_entries]
            # If the new entry was dropped, report it
            if entry not in self._entries:
                return SubmissionResult(
                    accepted=False,
                    errors=["Score too low to make the leaderboard"],
                )

        rank = self._rank_of(entry)
        logger.info(
            "Leaderboard submission accepted: %s (%s) — rank #%d",
            entry.model_name,
            entry.framework,
            rank,
        )
        return SubmissionResult(accepted=True, entry_id=entry.entry_id, rank=rank)

    def rankings(self) -> list[LeaderboardEntry]:
        """Return all entries sorted by the configured field."""
        return self._sorted_entries()

    def top_n(self, n: int) -> list[LeaderboardEntry]:
        """Return the top *n* entries."""
        return self._sorted_entries()[:n]

    def by_model(self, model_name: str) -> list[LeaderboardEntry]:
        """Return all entries for a given model name."""
        return [e for e in self._sorted_entries() if e.model_name == model_name]

    def by_framework(self, framework: str) -> list[LeaderboardEntry]:
        """Return all entries for a given framework."""
        return [e for e in self._sorted_entries() if e.framework == framework]

    def category_rankings(self, category: str) -> list[LeaderboardEntry]:
        """Rank entries by their score in a specific category."""
        eligible = [e for e in self._entries if category in e.category_scores]
        return sorted(
            eligible,
            key=lambda e: e.category_scores.get(category, 0.0),
            reverse=not self._config.ascending,
        )

    def save(self) -> Path:
        """Persist the leaderboard to JSON."""
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "config": self._config.model_dump(),
            "entries": [e.model_dump(mode="json") for e in self._entries],
        }
        self._storage_path.write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8",
        )
        logger.info("Leaderboard saved to %s", self._storage_path)
        return self._storage_path

    def load(self) -> None:
        """Load leaderboard state from JSON."""
        if not self._storage_path.exists():
            logger.warning("No leaderboard file at %s — starting fresh", self._storage_path)
            return
        raw = json.loads(self._storage_path.read_text(encoding="utf-8"))
        self._config = LeaderboardConfig(**raw.get("config", {}))
        self._entries = [
            LeaderboardEntry(**e) for e in raw.get("entries", [])
        ]
        logger.info(
            "Leaderboard loaded: %d entries from %s",
            len(self._entries),
            self._storage_path,
        )

    # ----------------------------------------------------------------- private

    def _sorted_entries(self) -> list[LeaderboardEntry]:
        """Sort entries by the configured field and direction."""
        return sorted(
            self._entries,
            key=lambda e: getattr(e, self._config.sort_by),
            reverse=not self._config.ascending,
        )

    def _rank_of(self, entry: LeaderboardEntry) -> int:
        """1-based rank of an entry in the current standings."""
        ranked = self._sorted_entries()
        for idx, e in enumerate(ranked):
            if e.entry_id == entry.entry_id:
                return idx + 1
        return -1

    def _build_entry(self, request: SubmissionRequest) -> LeaderboardEntry:
        """Convert a SubmissionRequest into a LeaderboardEntry."""
        report = request.report
        results = report.get("results", [])
        total = report.get("total_scenarios", len(results))
        vulns = report.get("vulnerable", 0)

        # Compute overall_score: proportion of safe scenarios
        overall_score = round(1.0 - vulns / total, 4) if total > 0 else 0.0

        # Compute per-category scores
        category_scores = self._compute_category_scores(results)

        return LeaderboardEntry(
            model_name=request.model_name,
            framework=request.framework,
            overall_score=overall_score,
            category_scores=category_scores,
            total_scenarios=total,
            vulnerabilities_found=vulns,
            submitter=request.submitter,
            verified=request.api_key is not None,
            metadata={"aastf_version": report.get("aastf_version", "unknown")},
        )

    @staticmethod
    def _compute_category_scores(results: list[dict[str, Any]]) -> dict[str, float]:
        """Compute per-category safety scores from raw results."""
        by_cat: dict[str, list[bool]] = {}
        for r in results:
            cat = r.get("category", "unknown")
            verdict = r.get("verdict", "ERROR")
            is_safe = verdict not in _VULNERABLE_VERDICTS
            by_cat.setdefault(cat, []).append(is_safe)

        scores: dict[str, float] = {}
        for cat, bools in by_cat.items():
            scores[cat] = round(sum(bools) / len(bools), 4) if bools else 0.0
        return scores


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------


class LeaderboardReporter:
    """Generates formatted output from leaderboard entries."""

    @staticmethod
    def to_markdown(entries: list[LeaderboardEntry]) -> str:
        """Produce a ranked Markdown table (HELM-inspired)."""
        lines: list[str] = []
        lines.append("# AASTF Security Leaderboard")
        lines.append("")
        lines.append(
            "| Rank | Model | Framework | Safety Score | Scenarios "
            "| Vulns | Verified | Submitted |"
        )
        lines.append(
            "|------|-------|-----------|-------------|-----------|"
            "-------|----------|-----------|"
        )
        for idx, entry in enumerate(entries, 1):
            verified = "Yes" if entry.verified else "No"
            date_str = entry.submission_date.strftime("%Y-%m-%d")
            lines.append(
                f"| {idx} | {entry.model_name} | {entry.framework} "
                f"| {entry.overall_score:.2%} | {entry.total_scenarios} "
                f"| {entry.vulnerabilities_found} | {verified} | {date_str} |"
            )
        lines.append("")
        lines.append(f"*{len(entries)} entries.*")
        lines.append("")
        return "\n".join(lines)

    @staticmethod
    def to_csv(entries: list[LeaderboardEntry]) -> str:
        """Produce CSV output."""
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "rank", "model_name", "framework", "overall_score",
            "total_scenarios", "vulnerabilities_found", "verified",
            "submission_date", "submitter",
        ])
        for idx, entry in enumerate(entries, 1):
            writer.writerow([
                idx,
                entry.model_name,
                entry.framework,
                f"{entry.overall_score:.4f}",
                entry.total_scenarios,
                entry.vulnerabilities_found,
                entry.verified,
                entry.submission_date.isoformat(),
                entry.submitter,
            ])
        return buf.getvalue()

    @staticmethod
    def to_html(entries: list[LeaderboardEntry]) -> str:
        """Produce a styled HTML table."""
        rows: list[str] = []
        rows.append("<!DOCTYPE html>")
        rows.append("<html><head><meta charset='utf-8'>")
        rows.append("<title>AASTF Security Leaderboard</title>")
        rows.append("<style>")
        rows.append("body { font-family: system-ui, sans-serif; margin: 2rem; }")
        rows.append("table { border-collapse: collapse; width: 100%; }")
        rows.append("th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }")
        rows.append("th { background: #1a1a2e; color: #fff; }")
        rows.append("tr:nth-child(even) { background: #f4f4f8; }")
        rows.append("tr:hover { background: #e8e8f0; }")
        rows.append(".score-high { color: #0a7; font-weight: bold; }")
        rows.append(".score-low { color: #d33; font-weight: bold; }")
        rows.append("</style></head><body>")
        rows.append("<h1>AASTF Security Leaderboard</h1>")
        rows.append("<table>")
        rows.append(
            "<tr><th>Rank</th><th>Model</th><th>Framework</th>"
            "<th>Safety Score</th><th>Scenarios</th><th>Vulns</th>"
            "<th>Verified</th><th>Submitted</th></tr>"
        )
        for idx, entry in enumerate(entries, 1):
            score_cls = "score-high" if entry.overall_score >= 0.8 else "score-low"
            verified = "&#10003;" if entry.verified else ""
            date_str = entry.submission_date.strftime("%Y-%m-%d")
            rows.append(
                f"<tr><td>{idx}</td><td>{entry.model_name}</td>"
                f"<td>{entry.framework}</td>"
                f"<td class='{score_cls}'>{entry.overall_score:.2%}</td>"
                f"<td>{entry.total_scenarios}</td>"
                f"<td>{entry.vulnerabilities_found}</td>"
                f"<td>{verified}</td><td>{date_str}</td></tr>"
            )
        rows.append("</table>")
        rows.append(f"<p><em>{len(entries)} entries.</em></p>")
        rows.append("</body></html>")
        return "\n".join(rows)

    @staticmethod
    def comparison_chart(entries: list[LeaderboardEntry]) -> str:
        """ASCII bar chart comparing safety scores."""
        if not entries:
            return "(no entries)"

        lines: list[str] = []
        lines.append("AASTF Safety Score Comparison")
        lines.append("=" * 60)

        max_label = max(len(e.model_name) for e in entries)
        bar_width = 40

        for entry in entries:
            label = entry.model_name.ljust(max_label)
            filled = int(entry.overall_score * bar_width)
            bar = "#" * filled + "-" * (bar_width - filled)
            pct = f"{entry.overall_score:.1%}"
            lines.append(f"  {label} |{bar}| {pct}")

        lines.append("=" * 60)
        return "\n".join(lines)
