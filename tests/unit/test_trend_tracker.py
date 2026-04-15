"""Unit tests for TrendTracker — SQLite-backed cross-run history."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.reporting.trend_tracker import TrendTracker

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(
    *,
    adapter: str = "langgraph",
    total_scenarios: int = 10,
    vulnerable: int = 2,
    safe: int = 7,
    inconclusive: int = 1,
    errors: int = 0,
    risk_score: float = 30.0,
    eu_ai_act: str = "at_risk",
    findings: list | None = None,
    generated_at: datetime | None = None,
) -> ScanReport:
    report = ScanReport(
        aastf_version="0.9.0",
        adapter=adapter,
        total_scenarios=total_scenarios,
        vulnerable=vulnerable,
        safe=safe,
        inconclusive=inconclusive,
        errors=errors,
        overall_risk_score=risk_score,
        eu_ai_act_readiness=eu_ai_act,  # type: ignore[arg-type]
        findings=findings or [],
    )
    if generated_at is not None:
        # Override the auto-generated timestamp for ordering tests
        object.__setattr__(report, "generated_at", generated_at)
    return report


def _make_finding(scenario_id: str = "ASI01-001") -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id=scenario_id,
        scenario_name="Test Finding",
        category=ASICategory.ASI01,
        severity=Severity.HIGH,
        verdict=Verdict.VULNERABLE,
        triggered_by="tool_called: bad_tool",
        description="desc",
        remediation="fix it",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestTrendTrackerRecord:
    def test_records_and_retrieves_run(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        report = _make_report()
        tracker.record(report)

        rows = tracker.last_n_runs(10)
        assert len(rows) == 1
        assert rows[0]["run_id"] == report.run_id
        assert rows[0]["adapter"] == "langgraph"
        assert rows[0]["vulnerable"] == 2
        assert rows[0]["risk_score"] == pytest.approx(30.0)

    def test_last_n_runs_ordering(self, tmp_path: Path) -> None:
        """Newest run (highest generated_at) must appear first."""
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)

        now = datetime(2026, 1, 1, 12, 0, 0)
        older = _make_report(risk_score=10.0, generated_at=now)
        newer = _make_report(risk_score=20.0, generated_at=now + timedelta(hours=1))

        tracker.record(older)
        tracker.record(newer)

        rows = tracker.last_n_runs(10)
        assert len(rows) == 2
        # newest first
        assert rows[0]["risk_score"] == pytest.approx(20.0)
        assert rows[1]["risk_score"] == pytest.approx(10.0)

    def test_last_n_runs_limits_results(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        for i in range(5):
            tracker.record(_make_report(risk_score=float(i)))
        rows = tracker.last_n_runs(3)
        assert len(rows) == 3

    def test_get_run_returns_full_report(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        original = _make_report(vulnerable=5, risk_score=55.5)
        tracker.record(original)

        retrieved = tracker.get_run(original.run_id)
        assert retrieved is not None
        assert retrieved.run_id == original.run_id
        assert retrieved.vulnerable == 5
        assert retrieved.overall_risk_score == pytest.approx(55.5)

    def test_get_run_returns_none_for_missing(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        result = tracker.get_run("nonexistent-run-id")
        assert result is None

    def test_duplicate_run_id_replaced(self, tmp_path: Path) -> None:
        """INSERT OR REPLACE — recording same run_id twice keeps only the latest."""
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        report = _make_report(vulnerable=1, risk_score=10.0)
        tracker.record(report)

        # Mutate fields and re-record with same run_id
        report2 = report.model_copy(update={"vulnerable": 9, "overall_risk_score": 90.0})
        tracker.record(report2)

        rows = tracker.last_n_runs(10)
        assert len(rows) == 1
        assert rows[0]["vulnerable"] == 9
        assert rows[0]["risk_score"] == pytest.approx(90.0)


class TestTrendTrackerTrendSummary:
    def test_trend_summary_no_data(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        summary = tracker.trend_summary()
        assert summary["runs"] == 0
        assert summary["trend"] == "no_data"

    def test_trend_summary_with_runs(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        now = datetime(2026, 1, 1)
        for i in range(3):
            tracker.record(_make_report(
                risk_score=50.0,
                vulnerable=2,
                total_scenarios=10,
                generated_at=now + timedelta(hours=i),
            ))

        summary = tracker.trend_summary(10)
        assert summary["runs"] == 3
        assert summary["latest_risk_score"] == pytest.approx(50.0)
        assert summary["average_risk_score"] == pytest.approx(50.0)
        assert "average_vulnerability_rate" in summary
        assert "run_ids" in summary
        assert len(summary["run_ids"]) == 3

    def test_trend_direction_improving(self, tmp_path: Path) -> None:
        """
        last_n_runs returns newest first.
        scores[0] is latest, scores[-1] is oldest.
        improving = scores[0] < scores[-1] * 0.9  (latest score much lower than oldest).
        """
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        now = datetime(2026, 1, 1)
        # oldest run: high risk score
        tracker.record(_make_report(risk_score=80.0, generated_at=now))
        # newest run: much lower risk score (improved)
        tracker.record(_make_report(risk_score=50.0, generated_at=now + timedelta(hours=1)))

        summary = tracker.trend_summary(10)
        assert summary["trend"] == "improving"

    def test_trend_direction_worsening(self, tmp_path: Path) -> None:
        """
        worsening = scores[0] > scores[-1] * 1.1  (latest score much higher than oldest).
        """
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        now = datetime(2026, 1, 1)
        # oldest run: low risk score
        tracker.record(_make_report(risk_score=20.0, generated_at=now))
        # newest run: much higher risk score (worsened)
        tracker.record(_make_report(risk_score=60.0, generated_at=now + timedelta(hours=1)))

        summary = tracker.trend_summary(10)
        assert summary["trend"] == "worsening"

    def test_trend_direction_stable(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        now = datetime(2026, 1, 1)
        tracker.record(_make_report(risk_score=50.0, generated_at=now))
        tracker.record(_make_report(risk_score=51.0, generated_at=now + timedelta(hours=1)))

        summary = tracker.trend_summary(10)
        assert summary["trend"] == "stable"

    def test_trend_summary_single_run_has_no_previous(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        tracker.record(_make_report(risk_score=42.0))
        summary = tracker.trend_summary(10)
        assert summary["runs"] == 1
        assert summary["previous_risk_score"] is None
        assert summary["latest_risk_score"] == pytest.approx(42.0)


class TestTrendTrackerCompare:
    def test_compare_two_runs(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)

        a = _make_report(vulnerable=5, risk_score=60.0)
        b = _make_report(vulnerable=3, risk_score=40.0)
        tracker.record(a)
        tracker.record(b)

        result = tracker.compare(a.run_id, b.run_id)
        assert result["run_a"]["id"] == a.run_id
        assert result["run_b"]["id"] == b.run_id
        assert result["delta_risk_score"] == pytest.approx(20.0)
        assert result["delta_vulnerable"] == 2

    def test_compare_finds_new_and_resolved_findings(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)

        finding_shared = _make_finding("ASI01-001")
        finding_only_in_a = _make_finding("ASI02-001")
        finding_only_in_b = _make_finding("ASI03-001")

        a = _make_report(findings=[finding_shared, finding_only_in_a], vulnerable=2)
        b = _make_report(findings=[finding_shared, finding_only_in_b], vulnerable=2)
        tracker.record(a)
        tracker.record(b)

        result = tracker.compare(a.run_id, b.run_id)
        assert "ASI02-001" in result["new_findings"]
        assert "ASI01-001" not in result["new_findings"]
        assert "ASI03-001" in result["resolved_findings"]
        assert "ASI01-001" not in result["resolved_findings"]

    def test_compare_missing_run_raises_key_error(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)
        a = _make_report()
        tracker.record(a)

        with pytest.raises(KeyError):
            tracker.compare(a.run_id, "does-not-exist")

    def test_compare_both_missing_raises_key_error(self, tmp_path: Path) -> None:
        db = tmp_path / "trend.db"
        tracker = TrendTracker(db)

        with pytest.raises(KeyError):
            tracker.compare("ghost-a", "ghost-b")
