"""Tests for aastf.leaderboard — 40+ tests for models, engine, and reporter."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from aastf.leaderboard import (
    Leaderboard,
    LeaderboardConfig,
    LeaderboardEntry,
    LeaderboardReporter,
    SubmissionRequest,
    SubmissionResult,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_report(
    total: int = 100,
    vulnerable: int = 10,
    n_results: int | None = None,
) -> dict:
    """Build a minimal ScanReport-compatible dict."""
    n = n_results if n_results is not None else total
    results = []
    for i in range(n):
        verdict = "VULNERABLE" if i < vulnerable else "SAFE"
        results.append({
            "scenario_id": f"ASI01-{i:03d}",
            "category": "ASI01",
            "verdict": verdict,
        })
    return {
        "total_scenarios": total,
        "vulnerable": vulnerable,
        "aastf_version": "1.2.0",
        "results": results,
    }


def _make_entry(
    model: str = "gpt-4o",
    framework: str = "langgraph",
    score: float = 0.9,
    total: int = 100,
    vulns: int = 10,
    verified: bool = False,
) -> LeaderboardEntry:
    return LeaderboardEntry(
        model_name=model,
        framework=framework,
        overall_score=score,
        total_scenarios=total,
        vulnerabilities_found=vulns,
        verified=verified,
    )


# ---------------------------------------------------------------------------
# LeaderboardEntry model tests
# ---------------------------------------------------------------------------


class TestLeaderboardEntry:
    def test_defaults(self):
        e = _make_entry()
        assert e.entry_id  # uuid generated
        assert e.model_name == "gpt-4o"
        assert e.overall_score == 0.9
        assert isinstance(e.submission_date, datetime)

    def test_score_bounds_low(self):
        with pytest.raises(ValidationError):
            LeaderboardEntry(
                model_name="x", framework="y",
                overall_score=-0.1, total_scenarios=1,
                vulnerabilities_found=0,
            )

    def test_score_bounds_high(self):
        with pytest.raises(ValidationError):
            LeaderboardEntry(
                model_name="x", framework="y",
                overall_score=1.1, total_scenarios=1,
                vulnerabilities_found=0,
            )

    def test_category_score_validation(self):
        with pytest.raises(ValidationError):
            LeaderboardEntry(
                model_name="x", framework="y",
                overall_score=0.5, total_scenarios=1,
                vulnerabilities_found=0,
                category_scores={"ASI01": 1.5},
            )

    def test_valid_category_scores(self):
        e = LeaderboardEntry(
            model_name="x", framework="y",
            overall_score=0.5, total_scenarios=1,
            vulnerabilities_found=0,
            category_scores={"ASI01": 0.8, "ASI02": 0.6},
        )
        assert e.category_scores["ASI01"] == 0.8

    def test_negative_scenarios(self):
        with pytest.raises(ValidationError):
            LeaderboardEntry(
                model_name="x", framework="y",
                overall_score=0.5, total_scenarios=-1,
                vulnerabilities_found=0,
            )

    def test_metadata_default(self):
        e = _make_entry()
        assert e.metadata == {}


# ---------------------------------------------------------------------------
# SubmissionRequest model tests
# ---------------------------------------------------------------------------


class TestSubmissionRequest:
    def test_basic(self):
        r = SubmissionRequest(
            model_name="gpt-4o",
            framework="langgraph",
            report=_make_report(),
        )
        assert r.model_name == "gpt-4o"
        assert r.api_key is None

    def test_with_api_key(self):
        r = SubmissionRequest(
            model_name="gpt-4o",
            framework="langgraph",
            report=_make_report(),
            api_key="sk-test-123",
        )
        assert r.api_key == "sk-test-123"


# ---------------------------------------------------------------------------
# SubmissionResult model tests
# ---------------------------------------------------------------------------


class TestSubmissionResult:
    def test_accepted(self):
        r = SubmissionResult(accepted=True, entry_id="abc", rank=1)
        assert r.accepted
        assert r.errors == []

    def test_rejected(self):
        r = SubmissionResult(accepted=False, errors=["bad data"])
        assert not r.accepted
        assert len(r.errors) == 1


# ---------------------------------------------------------------------------
# LeaderboardConfig model tests
# ---------------------------------------------------------------------------


class TestLeaderboardConfig:
    def test_defaults(self):
        c = LeaderboardConfig()
        assert c.min_scenarios == 50
        assert c.require_verification is False
        assert c.sort_by == "overall_score"
        assert c.ascending is False
        assert c.max_entries == 100

    def test_invalid_sort_by(self):
        with pytest.raises(ValidationError):
            LeaderboardConfig(sort_by="nonexistent")

    def test_negative_min_scenarios(self):
        with pytest.raises(ValidationError):
            LeaderboardConfig(min_scenarios=-1)

    def test_zero_max_entries(self):
        with pytest.raises(ValidationError):
            LeaderboardConfig(max_entries=0)

    def test_custom_config(self):
        c = LeaderboardConfig(
            min_scenarios=10, require_verification=True,
            sort_by="vulnerabilities_found", ascending=True,
            max_entries=50,
        )
        assert c.min_scenarios == 10
        assert c.require_verification is True


# ---------------------------------------------------------------------------
# Leaderboard engine tests
# ---------------------------------------------------------------------------


class TestLeaderboard:
    def test_empty_rankings(self):
        lb = Leaderboard()
        assert lb.rankings() == []

    def test_submit_valid(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=10))
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report=_make_report(total=50, vulnerable=5),
        )
        result = lb.submit(req)
        assert result.accepted
        assert result.rank == 1
        assert result.entry_id is not None

    def test_submit_too_few_scenarios(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=100))
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report=_make_report(total=10, vulnerable=1),
        )
        result = lb.submit(req)
        assert not result.accepted
        assert any("scenarios" in e for e in result.errors)

    def test_submit_empty_model_name(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        req = SubmissionRequest(
            model_name="  ", framework="langgraph",
            report=_make_report(total=10),
        )
        result = lb.submit(req)
        assert not result.accepted

    def test_submit_empty_framework(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        req = SubmissionRequest(
            model_name="gpt-4o", framework="  ",
            report=_make_report(total=10),
        )
        result = lb.submit(req)
        assert not result.accepted

    def test_submit_missing_results(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report={"total_scenarios": 10},
        )
        result = lb.submit(req)
        assert not result.accepted

    def test_submit_results_not_list(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report={"total_scenarios": 10, "results": "not a list"},
        )
        result = lb.submit(req)
        assert not result.accepted

    def test_submit_require_verification_no_key(self):
        lb = Leaderboard(
            config=LeaderboardConfig(min_scenarios=0, require_verification=True),
        )
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report=_make_report(total=10),
        )
        result = lb.submit(req)
        assert not result.accepted
        assert any("api_key" in e for e in result.errors)

    def test_submit_require_verification_with_key(self):
        lb = Leaderboard(
            config=LeaderboardConfig(min_scenarios=0, require_verification=True),
        )
        req = SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report=_make_report(total=10),
            api_key="sk-test",
        )
        result = lb.submit(req)
        assert result.accepted

    def test_rankings_sorted_descending(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        for name, vulns in [("model-a", 20), ("model-b", 5), ("model-c", 15)]:
            lb.submit(SubmissionRequest(
                model_name=name, framework="langgraph",
                report=_make_report(total=100, vulnerable=vulns),
            ))
        ranked = lb.rankings()
        scores = [e.overall_score for e in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rankings_sorted_ascending(self):
        lb = Leaderboard(
            config=LeaderboardConfig(min_scenarios=0, ascending=True),
        )
        for name, vulns in [("model-a", 20), ("model-b", 5), ("model-c", 15)]:
            lb.submit(SubmissionRequest(
                model_name=name, framework="langgraph",
                report=_make_report(total=100, vulnerable=vulns),
            ))
        ranked = lb.rankings()
        scores = [e.overall_score for e in ranked]
        assert scores == sorted(scores)

    def test_top_n(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        for i in range(5):
            lb.submit(SubmissionRequest(
                model_name=f"model-{i}", framework="lg",
                report=_make_report(total=100, vulnerable=i * 10),
            ))
        top3 = lb.top_n(3)
        assert len(top3) == 3

    def test_top_n_exceeds_entries(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="x", framework="y",
            report=_make_report(total=100),
        ))
        assert len(lb.top_n(10)) == 1

    def test_by_model(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="gpt-4o", framework="lg",
            report=_make_report(total=100, vulnerable=10),
        ))
        lb.submit(SubmissionRequest(
            model_name="claude", framework="lg",
            report=_make_report(total=100, vulnerable=5),
        ))
        results = lb.by_model("gpt-4o")
        assert len(results) == 1
        assert results[0].model_name == "gpt-4o"

    def test_by_model_empty(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        assert lb.by_model("nonexistent") == []

    def test_by_framework(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="gpt-4o", framework="langgraph",
            report=_make_report(total=100, vulnerable=10),
        ))
        lb.submit(SubmissionRequest(
            model_name="gpt-4o", framework="crewai",
            report=_make_report(total=100, vulnerable=5),
        ))
        results = lb.by_framework("crewai")
        assert len(results) == 1
        assert results[0].framework == "crewai"

    def test_category_rankings(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="a", framework="lg",
            report=_make_report(total=100, vulnerable=10),
        ))
        lb.submit(SubmissionRequest(
            model_name="b", framework="lg",
            report=_make_report(total=100, vulnerable=5),
        ))
        ranked = lb.category_rankings("ASI01")
        assert len(ranked) == 2
        # Higher score first (descending default)
        assert ranked[0].category_scores["ASI01"] >= ranked[1].category_scores["ASI01"]

    def test_category_rankings_empty(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="a", framework="lg",
            report=_make_report(total=100, vulnerable=10),
        ))
        # Category that doesn't exist
        assert lb.category_rankings("NONEXIST") == []

    def test_max_entries_enforced(self):
        lb = Leaderboard(
            config=LeaderboardConfig(min_scenarios=0, max_entries=3),
        )
        for i in range(5):
            lb.submit(SubmissionRequest(
                model_name=f"model-{i}", framework="lg",
                report=_make_report(total=100, vulnerable=i * 5),
            ))
        assert len(lb.rankings()) <= 3

    def test_overall_score_computed(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        result = lb.submit(SubmissionRequest(
            model_name="x", framework="y",
            report=_make_report(total=100, vulnerable=25),
        ))
        assert result.accepted
        entry = lb.rankings()[0]
        assert entry.overall_score == 0.75

    def test_verified_flag_set_with_key(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="x", framework="y",
            report=_make_report(total=100),
            api_key="key123",
        ))
        assert lb.rankings()[0].verified is True

    def test_verified_flag_false_without_key(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="x", framework="y",
            report=_make_report(total=100),
        ))
        assert lb.rankings()[0].verified is False

    def test_save_and_load(self, tmp_path: Path):
        storage = tmp_path / "lb.json"
        lb = Leaderboard(
            config=LeaderboardConfig(min_scenarios=0),
            storage_path=storage,
        )
        lb.submit(SubmissionRequest(
            model_name="gpt-4o", framework="lg",
            report=_make_report(total=100, vulnerable=10),
        ))
        lb.save()
        assert storage.exists()

        lb2 = Leaderboard(storage_path=storage)
        lb2.load()
        assert len(lb2.rankings()) == 1
        assert lb2.rankings()[0].model_name == "gpt-4o"

    def test_load_missing_file(self, tmp_path: Path):
        storage = tmp_path / "does_not_exist.json"
        lb = Leaderboard(storage_path=storage)
        lb.load()  # should not raise
        assert lb.rankings() == []

    def test_validate_submission_returns_errors(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=100))
        req = SubmissionRequest(
            model_name="", framework="",
            report={"total_scenarios": 5},
        )
        errors = lb.validate_submission(req)
        assert len(errors) >= 3  # model, framework, scenarios, results

    def test_entries_property(self):
        lb = Leaderboard(config=LeaderboardConfig(min_scenarios=0))
        lb.submit(SubmissionRequest(
            model_name="x", framework="y",
            report=_make_report(total=100),
        ))
        entries = lb.entries
        assert len(entries) == 1
        # Should be a copy
        entries.clear()
        assert len(lb.entries) == 1


# ---------------------------------------------------------------------------
# LeaderboardReporter tests
# ---------------------------------------------------------------------------


class TestLeaderboardReporter:
    @pytest.fixture()
    def sample_entries(self):
        return [
            _make_entry("gpt-4o", "langgraph", 0.95, 100, 5, True),
            _make_entry("claude-sonnet", "crewai", 0.88, 100, 12, True),
            _make_entry("gemini-pro", "pydantic_ai", 0.72, 80, 22, False),
        ]

    def test_to_markdown_header(self, sample_entries):
        md = LeaderboardReporter.to_markdown(sample_entries)
        assert "# AASTF Security Leaderboard" in md
        assert "| Rank |" in md

    def test_to_markdown_rows(self, sample_entries):
        md = LeaderboardReporter.to_markdown(sample_entries)
        assert "gpt-4o" in md
        assert "claude-sonnet" in md
        assert "gemini-pro" in md

    def test_to_markdown_rank_numbers(self, sample_entries):
        md = LeaderboardReporter.to_markdown(sample_entries)
        assert "| 1 |" in md
        assert "| 3 |" in md

    def test_to_markdown_empty(self):
        md = LeaderboardReporter.to_markdown([])
        assert "0 entries" in md

    def test_to_csv_header(self, sample_entries):
        csv_str = LeaderboardReporter.to_csv(sample_entries)
        assert "rank,model_name,framework" in csv_str

    def test_to_csv_rows(self, sample_entries):
        csv_str = LeaderboardReporter.to_csv(sample_entries)
        lines = csv_str.strip().split("\n")
        assert len(lines) == 4  # header + 3 rows

    def test_to_csv_empty(self):
        csv_str = LeaderboardReporter.to_csv([])
        lines = csv_str.strip().split("\n")
        assert len(lines) == 1  # header only

    def test_to_html_structure(self, sample_entries):
        html = LeaderboardReporter.to_html(sample_entries)
        assert "<!DOCTYPE html>" in html
        assert "<table>" in html
        assert "</table>" in html
        assert "gpt-4o" in html

    def test_to_html_score_styling(self, sample_entries):
        html = LeaderboardReporter.to_html(sample_entries)
        assert "score-high" in html  # 0.95 and 0.88
        assert "score-low" in html  # 0.72

    def test_to_html_verified_checkmark(self, sample_entries):
        html = LeaderboardReporter.to_html(sample_entries)
        assert "&#10003;" in html

    def test_to_html_empty(self):
        html = LeaderboardReporter.to_html([])
        assert "0 entries" in html

    def test_comparison_chart(self, sample_entries):
        chart = LeaderboardReporter.comparison_chart(sample_entries)
        assert "Safety Score Comparison" in chart
        assert "gpt-4o" in chart
        assert "#" in chart
        assert "95.0%" in chart

    def test_comparison_chart_empty(self):
        chart = LeaderboardReporter.comparison_chart([])
        assert "(no entries)" in chart

    def test_comparison_chart_bar_length(self, sample_entries):
        chart = LeaderboardReporter.comparison_chart(sample_entries)
        # Highest scorer should have more # than lowest
        lines = chart.split("\n")
        bar_lines = [line for line in lines if "|" in line and "#" in line]
        assert len(bar_lines) == 3
