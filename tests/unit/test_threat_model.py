"""Tests for the STRIDE threat model module."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aastf.threat_model import (
    _RISK_SCORE,
    AASTF_THREAT_MODEL,
    STRIDECategory,
    ThreatEntry,
    ThreatModel,
    ThreatModelReporter,
)

# ---------------------------------------------------------------------------
# STRIDECategory enum
# ---------------------------------------------------------------------------


class TestSTRIDECategory:
    def test_all_six_categories_exist(self) -> None:
        assert len(STRIDECategory) == 6

    def test_spoofing_value(self) -> None:
        assert STRIDECategory.SPOOFING.value == "SPOOFING"

    def test_tampering_value(self) -> None:
        assert STRIDECategory.TAMPERING.value == "TAMPERING"

    def test_repudiation_value(self) -> None:
        assert STRIDECategory.REPUDIATION.value == "REPUDIATION"

    def test_info_disclosure_value(self) -> None:
        assert STRIDECategory.INFO_DISCLOSURE.value == "INFO_DISCLOSURE"

    def test_denial_of_service_value(self) -> None:
        assert STRIDECategory.DENIAL_OF_SERVICE.value == "DENIAL_OF_SERVICE"

    def test_elevation_of_privilege_value(self) -> None:
        assert STRIDECategory.ELEVATION_OF_PRIVILEGE.value == "ELEVATION_OF_PRIVILEGE"

    def test_str_representation(self) -> None:
        assert str(STRIDECategory.SPOOFING) == "SPOOFING"


# ---------------------------------------------------------------------------
# ThreatEntry model
# ---------------------------------------------------------------------------


class TestThreatEntry:
    def test_create_minimal_entry(self) -> None:
        entry = ThreatEntry(
            id="T-001",
            category=STRIDECategory.SPOOFING,
            title="Test threat",
            description="A test.",
            affected_component="test",
            likelihood="low",
            impact="low",
            status="open",
        )
        assert entry.id == "T-001"
        assert entry.mitigations == []

    def test_create_entry_with_mitigations(self) -> None:
        entry = ThreatEntry(
            id="T-002",
            category=STRIDECategory.TAMPERING,
            title="Tamper",
            description="desc",
            affected_component="comp",
            likelihood="high",
            impact="high",
            mitigations=["m1", "m2"],
            status="mitigated",
        )
        assert len(entry.mitigations) == 2

    def test_likelihood_validation(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ThreatEntry(
                id="T-003",
                category=STRIDECategory.SPOOFING,
                title="Bad",
                description="d",
                affected_component="c",
                likelihood="extreme",  # type: ignore[arg-type]
                impact="low",
                status="open",
            )

    def test_impact_validation(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ThreatEntry(
                id="T-004",
                category=STRIDECategory.SPOOFING,
                title="Bad",
                description="d",
                affected_component="c",
                likelihood="low",
                impact="catastrophic",  # type: ignore[arg-type]
                status="open",
            )

    def test_status_validation(self) -> None:
        with pytest.raises((TypeError, ValueError)):
            ThreatEntry(
                id="T-005",
                category=STRIDECategory.SPOOFING,
                title="Bad",
                description="d",
                affected_component="c",
                likelihood="low",
                impact="low",
                status="resolved",  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# ThreatModel
# ---------------------------------------------------------------------------


class TestThreatModel:
    @pytest.fixture()
    def sample_model(self) -> ThreatModel:
        return ThreatModel(
            name="Test Model",
            version="1.0.0",
            entries=[
                ThreatEntry(
                    id="A",
                    category=STRIDECategory.SPOOFING,
                    title="Spoof",
                    description="d",
                    affected_component="c",
                    likelihood="low",
                    impact="high",
                    status="open",
                ),
                ThreatEntry(
                    id="B",
                    category=STRIDECategory.SPOOFING,
                    title="Spoof2",
                    description="d",
                    affected_component="c",
                    likelihood="medium",
                    impact="medium",
                    status="mitigated",
                ),
                ThreatEntry(
                    id="C",
                    category=STRIDECategory.TAMPERING,
                    title="Tamper",
                    description="d",
                    affected_component="c",
                    likelihood="high",
                    impact="high",
                    status="accepted",
                ),
            ],
        )

    def test_by_category(self, sample_model: ThreatModel) -> None:
        spoofing = sample_model.by_category(STRIDECategory.SPOOFING)
        assert len(spoofing) == 2

    def test_by_category_empty(self, sample_model: ThreatModel) -> None:
        dos = sample_model.by_category(STRIDECategory.DENIAL_OF_SERVICE)
        assert dos == []

    def test_by_status_open(self, sample_model: ThreatModel) -> None:
        assert len(sample_model.by_status("open")) == 1

    def test_by_status_mitigated(self, sample_model: ThreatModel) -> None:
        assert len(sample_model.by_status("mitigated")) == 1

    def test_open_threats(self, sample_model: ThreatModel) -> None:
        # open_threats returns anything NOT mitigated
        open_t = sample_model.open_threats()
        assert len(open_t) == 2  # open + accepted

    def test_default_created_at(self) -> None:
        model = ThreatModel(name="T", version="0")
        assert model.created_at.tzinfo is not None

    def test_explicit_created_at(self) -> None:
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        model = ThreatModel(name="T", version="0", created_at=dt)
        assert model.created_at == dt


# ---------------------------------------------------------------------------
# AASTF_THREAT_MODEL (pre-built)
# ---------------------------------------------------------------------------


class TestAASTFThreatModel:
    def test_has_at_least_12_entries(self) -> None:
        assert len(AASTF_THREAT_MODEL.entries) >= 12

    def test_name(self) -> None:
        assert "AASTF" in AASTF_THREAT_MODEL.name

    def test_version(self) -> None:
        assert AASTF_THREAT_MODEL.version == "2.0.0"

    def test_all_six_categories_covered(self) -> None:
        cats = {e.category for e in AASTF_THREAT_MODEL.entries}
        assert cats == set(STRIDECategory)

    def test_unique_ids(self) -> None:
        ids = [e.id for e in AASTF_THREAT_MODEL.entries]
        assert len(ids) == len(set(ids))

    def test_spoofing_entries(self) -> None:
        s = AASTF_THREAT_MODEL.by_category(STRIDECategory.SPOOFING)
        assert len(s) >= 2

    def test_tampering_entries(self) -> None:
        t = AASTF_THREAT_MODEL.by_category(STRIDECategory.TAMPERING)
        assert len(t) >= 2

    def test_repudiation_entries(self) -> None:
        r = AASTF_THREAT_MODEL.by_category(STRIDECategory.REPUDIATION)
        assert len(r) >= 1

    def test_info_disclosure_entries(self) -> None:
        i = AASTF_THREAT_MODEL.by_category(STRIDECategory.INFO_DISCLOSURE)
        assert len(i) >= 2

    def test_dos_entries(self) -> None:
        d = AASTF_THREAT_MODEL.by_category(STRIDECategory.DENIAL_OF_SERVICE)
        assert len(d) >= 2

    def test_eop_entries(self) -> None:
        e = AASTF_THREAT_MODEL.by_category(STRIDECategory.ELEVATION_OF_PRIVILEGE)
        assert len(e) >= 2

    def test_has_open_threats(self) -> None:
        assert len(AASTF_THREAT_MODEL.by_status("open")) > 0

    def test_has_mitigated_threats(self) -> None:
        assert len(AASTF_THREAT_MODEL.by_status("mitigated")) > 0

    def test_all_entries_have_descriptions(self) -> None:
        for e in AASTF_THREAT_MODEL.entries:
            assert len(e.description) > 10


# ---------------------------------------------------------------------------
# Risk score lookup
# ---------------------------------------------------------------------------


class TestRiskScore:
    def test_low_low(self) -> None:
        assert _RISK_SCORE[("low", "low")] == "LOW"

    def test_high_high(self) -> None:
        assert _RISK_SCORE[("high", "high")] == "CRITICAL"

    def test_medium_high(self) -> None:
        assert _RISK_SCORE[("medium", "high")] == "HIGH"

    def test_all_combinations_covered(self) -> None:
        levels = ["low", "medium", "high"]
        for lk in levels:
            for im in levels:
                assert (lk, im) in _RISK_SCORE


# ---------------------------------------------------------------------------
# ThreatModelReporter
# ---------------------------------------------------------------------------


class TestThreatModelReporterMarkdown:
    def test_contains_title(self) -> None:
        md = ThreatModelReporter.to_markdown(AASTF_THREAT_MODEL)
        assert AASTF_THREAT_MODEL.name in md

    def test_contains_version(self) -> None:
        md = ThreatModelReporter.to_markdown(AASTF_THREAT_MODEL)
        assert AASTF_THREAT_MODEL.version in md

    def test_contains_all_ids(self) -> None:
        md = ThreatModelReporter.to_markdown(AASTF_THREAT_MODEL)
        for e in AASTF_THREAT_MODEL.entries:
            assert e.id in md

    def test_contains_status(self) -> None:
        md = ThreatModelReporter.to_markdown(AASTF_THREAT_MODEL)
        assert "mitigated" in md
        assert "open" in md

    def test_returns_string(self) -> None:
        assert isinstance(ThreatModelReporter.to_markdown(AASTF_THREAT_MODEL), str)


class TestThreatModelReporterHTML:
    def test_contains_html_tags(self) -> None:
        html = ThreatModelReporter.to_html(AASTF_THREAT_MODEL)
        assert "<html" in html
        assert "</html>" in html

    def test_contains_table(self) -> None:
        html = ThreatModelReporter.to_html(AASTF_THREAT_MODEL)
        assert "<table>" in html

    def test_contains_all_ids(self) -> None:
        html = ThreatModelReporter.to_html(AASTF_THREAT_MODEL)
        for e in AASTF_THREAT_MODEL.entries:
            assert e.id in html

    def test_contains_status_colors(self) -> None:
        html = ThreatModelReporter.to_html(AASTF_THREAT_MODEL)
        assert "#27ae60" in html  # mitigated green
        assert "#e74c3c" in html  # open red

    def test_returns_string(self) -> None:
        assert isinstance(ThreatModelReporter.to_html(AASTF_THREAT_MODEL), str)


class TestThreatModelReporterRiskMatrix:
    def test_contains_header(self) -> None:
        matrix = ThreatModelReporter.risk_matrix(AASTF_THREAT_MODEL)
        assert "Likelihood" in matrix
        assert "Impact" in matrix

    def test_contains_separator(self) -> None:
        matrix = ThreatModelReporter.risk_matrix(AASTF_THREAT_MODEL)
        assert "---" in matrix

    def test_contains_levels(self) -> None:
        matrix = ThreatModelReporter.risk_matrix(AASTF_THREAT_MODEL)
        assert "high" in matrix
        assert "medium" in matrix
        assert "low" in matrix

    def test_returns_string(self) -> None:
        assert isinstance(ThreatModelReporter.risk_matrix(AASTF_THREAT_MODEL), str)


class TestThreatModelReporterSummary:
    def test_total(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert s["total"] == len(AASTF_THREAT_MODEL.entries)

    def test_by_category_keys(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert "SPOOFING" in s["by_category"]

    def test_by_status_keys(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert set(s["by_status"].keys()) == {"mitigated", "accepted", "open"}

    def test_open_count(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert s["open_count"] == s["by_status"]["open"]

    def test_mitigated_count(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert s["mitigated_count"] == s["by_status"]["mitigated"]

    def test_risk_distribution_has_keys(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert "LOW" in s["risk_distribution"]
        assert "CRITICAL" in s["risk_distribution"]

    def test_status_counts_sum_to_total(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert sum(s["by_status"].values()) == s["total"]

    def test_category_counts_sum_to_total(self) -> None:
        s = ThreatModelReporter.summary(AASTF_THREAT_MODEL)
        assert sum(s["by_category"].values()) == s["total"]

    def test_returns_dict(self) -> None:
        assert isinstance(ThreatModelReporter.summary(AASTF_THREAT_MODEL), dict)
