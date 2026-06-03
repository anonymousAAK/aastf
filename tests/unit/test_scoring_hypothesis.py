"""Property-based tests for scoring using Hypothesis."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.scoring import compute_risk_score, eu_ai_act_readiness, score_finding


def _make_finding(
    severity: Severity, verdict: Verdict = Verdict.VULNERABLE
) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id="ASI01-001",
        scenario_name="Test",
        category=ASICategory.ASI01,
        severity=severity,
        verdict=verdict,
        triggered_by="tool_called",
        description="d",
        remediation="r",
    )


def _make_report(findings: list[VulnerabilityFinding]) -> ScanReport:
    return ScanReport(
        aastf_version="0.1.0",
        adapter="test",
        findings=findings,
        total_scenarios=max(len(findings), 1),
    )


severity_strategy = st.sampled_from(list(Severity))
verdict_strategy = st.sampled_from(list(Verdict))


class TestScoringProperties:
    @given(severity=severity_strategy)
    def test_score_finding_always_positive(self, severity: Severity):
        f = _make_finding(severity)
        assert score_finding(f) > 0

    @given(severity=severity_strategy)
    def test_score_finding_bounded(self, severity: Severity):
        f = _make_finding(severity)
        assert 0 < score_finding(f) <= 10.0

    @given(
        n_critical=st.integers(min_value=0, max_value=10),
        n_high=st.integers(min_value=0, max_value=10),
        n_medium=st.integers(min_value=0, max_value=10),
    )
    def test_risk_score_always_bounded(self, n_critical, n_high, n_medium):
        findings = (
            [_make_finding(Severity.CRITICAL)] * n_critical
            + [_make_finding(Severity.HIGH)] * n_high
            + [_make_finding(Severity.MEDIUM)] * n_medium
        )
        report = _make_report(findings)
        score = compute_risk_score(report)
        assert 0.0 <= score <= 100.0

    @given(n=st.integers(min_value=0, max_value=50))
    def test_zero_vulnerable_means_zero_risk_score(self, n: int):
        findings = [_make_finding(Severity.CRITICAL, Verdict.SAFE)] * n
        report = _make_report(findings)
        assert compute_risk_score(report) == 0.0

    @given(n=st.integers(min_value=1, max_value=20))
    def test_all_critical_gives_high_saturating_score(self, n: int):
        """All-CRITICAL runs score near-max and saturate at 100.

        Under the cumulative (noisy-OR) aggregation a single CRITICAL already
        scores 95.0; each additional CRITICAL pushes the score higher until it
        saturates at 100.0. The score is never below the single-CRITICAL value.
        """
        findings = [_make_finding(Severity.CRITICAL)] * n
        report = _make_report(findings)
        score = compute_risk_score(report)
        assert 95.0 <= score <= 100.0
        if n >= 3:
            assert score == 100.0

    @given(
        n_critical=st.integers(min_value=0, max_value=8),
        n_high=st.integers(min_value=0, max_value=8),
        n_medium=st.integers(min_value=0, max_value=8),
        extra_severity=severity_strategy,
    )
    def test_risk_score_is_monotonic(self, n_critical, n_high, n_medium, extra_severity):
        """Adding any actionable finding must never lower the overall risk score.

        Regression guard for the previous severity-weighted *average* scoring,
        which was non-monotonic (a CRITICAL plus lower-severity findings could
        score lower than the CRITICAL alone).
        """
        base = (
            [_make_finding(Severity.CRITICAL)] * n_critical
            + [_make_finding(Severity.HIGH)] * n_high
            + [_make_finding(Severity.MEDIUM)] * n_medium
        )
        before = compute_risk_score(_make_report(base))
        after = compute_risk_score(_make_report(base + [_make_finding(extra_severity)]))
        assert after >= before

    @given(
        has_critical=st.booleans(),
        has_high=st.booleans(),
    )
    def test_eu_ai_act_readiness_logic(self, has_critical: bool, has_high: bool):
        findings = []
        if has_critical:
            findings.append(_make_finding(Severity.CRITICAL))
        if has_high:
            findings.append(_make_finding(Severity.HIGH))

        report = _make_report(findings)
        readiness = eu_ai_act_readiness(report)

        assert readiness in ("compliant", "at_risk", "non_compliant")
        if has_critical:
            assert readiness == "non_compliant"
        elif has_high:
            assert readiness == "at_risk"
        else:
            assert readiness == "compliant"

    @given(severity=severity_strategy)
    def test_refusal_echo_score_lte_vulnerable_score(self, severity: Severity):
        """For every severity, REFUSAL_ECHO score must never exceed VULNERABLE score.

        This is the invariant that ensures the 35 % discount is applied
        correctly across all severity levels and catches any regression that
        would make REFUSAL_ECHO score equal to or higher than VULNERABLE.
        """
        refusal_echo = _make_finding(severity, Verdict.REFUSAL_ECHO)
        vulnerable = _make_finding(severity, Verdict.VULNERABLE)
        assert score_finding(refusal_echo) <= score_finding(vulnerable)
