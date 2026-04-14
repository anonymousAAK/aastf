"""Unit tests for CVSS-adapted scoring and EU AI Act readiness."""

from __future__ import annotations

from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.scoring import annotate_findings, compute_risk_score, eu_ai_act_readiness, score_finding


def _finding(severity: Severity, verdict: Verdict = Verdict.VULNERABLE) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id="ASI02-001",
        scenario_name="Test",
        category=ASICategory.ASI02,
        severity=severity,
        verdict=verdict,
        triggered_by="tool_called",
        description="desc",
        remediation="fix",
    )


def _report(findings: list[VulnerabilityFinding], **kwargs) -> ScanReport:
    return ScanReport(
        aastf_version="0.1.0",
        adapter="test",
        findings=findings,
        **kwargs,
    )


class TestScoreFinding:
    def test_critical_highest(self):
        assert score_finding(_finding(Severity.CRITICAL)) == 9.5

    def test_high(self):
        assert score_finding(_finding(Severity.HIGH)) == 7.5

    def test_medium(self):
        assert score_finding(_finding(Severity.MEDIUM)) == 5.0

    def test_low(self):
        assert score_finding(_finding(Severity.LOW)) == 3.0

    def test_info_lowest(self):
        assert score_finding(_finding(Severity.INFO)) == 1.0


class TestComputeRiskScore:
    def test_zero_with_no_findings(self):
        r = _report([])
        assert compute_risk_score(r) == 0.0

    def test_zero_with_only_safe_findings(self):
        r = _report([_finding(Severity.CRITICAL, Verdict.SAFE)])
        assert compute_risk_score(r) == 0.0

    def test_max_with_all_critical(self):
        findings = [_finding(Severity.CRITICAL) for _ in range(5)]
        r = _report(findings)
        assert compute_risk_score(r) == 100.0

    def test_bounded_0_to_100(self):
        for sev in Severity:
            findings = [_finding(sev) for _ in range(10)]
            r = _report(findings)
            score = compute_risk_score(r)
            assert 0.0 <= score <= 100.0, f"Score out of bounds for {sev}: {score}"

    def test_single_high_finding(self):
        r = _report([_finding(Severity.HIGH)])
        score = compute_risk_score(r)
        assert 50.0 < score < 100.0  # HIGH should be significant but not max

    def test_mixed_severity_between_extremes(self):
        findings = [
            _finding(Severity.CRITICAL),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        r = _report(findings)
        score = compute_risk_score(r)
        assert 0.0 < score < 100.0


class TestEuAiActReadiness:
    def test_non_compliant_on_critical(self):
        r = _report([_finding(Severity.CRITICAL)])
        assert eu_ai_act_readiness(r) == "non_compliant"

    def test_at_risk_on_high_only(self):
        r = _report([_finding(Severity.HIGH)])
        assert eu_ai_act_readiness(r) == "at_risk"

    def test_compliant_on_medium_only(self):
        r = _report([_finding(Severity.MEDIUM)])
        assert eu_ai_act_readiness(r) == "compliant"

    def test_compliant_with_no_findings(self):
        r = _report([])
        assert eu_ai_act_readiness(r) == "compliant"

    def test_non_compliant_when_critical_and_high_both_present(self):
        r = _report([_finding(Severity.CRITICAL), _finding(Severity.HIGH)])
        assert eu_ai_act_readiness(r) == "non_compliant"

    def test_safe_findings_ignored(self):
        r = _report([_finding(Severity.CRITICAL, Verdict.SAFE)])
        assert eu_ai_act_readiness(r) == "compliant"


class TestAnnotateFindings:
    def test_annotates_cvss_score(self):
        findings = [_finding(Severity.CRITICAL), _finding(Severity.HIGH)]
        annotate_findings(findings)
        assert findings[0].cvss_score == 9.5
        assert findings[1].cvss_score == 7.5
