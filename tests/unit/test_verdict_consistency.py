"""Regression tests: behavioural-compromise verdicts must be handled consistently
across every consumer.

Previously the MCP verdicts (TOOL_POISONING/SCHEMA_POISONING/PREFERENCE_MANIPULATION)
and the multi-agent verdicts (INFECTION_PROPAGATED/COLLUSION/WATCHDOG_BYPASS) were
counted as ``vulnerable`` by the runner but ignored by the risk score, EU AI Act
readiness, the SARIF/HTML/console reporters, and ``--fail-on`` gating — producing a
report that said "Vulnerable: 3" while showing risk 0.0, "compliant", an empty SARIF,
and exiting 0 under ``--fail-on critical``. These tests guard against that regression.
"""

from __future__ import annotations

import pytest

from aastf.cli.commands.run import get_blocking_findings
from aastf.models.result import (
    VULNERABLE_VERDICTS,
    ScanReport,
    Verdict,
    VulnerabilityFinding,
)
from aastf.models.scenario import ASICategory, Severity
from aastf.reporting.html_reporter import HTMLReporter
from aastf.reporting.sarif_reporter import SARIFReporter
from aastf.scoring import compute_risk_score, eu_ai_act_readiness

# The multi-agent + MCP verdicts that were previously half-wired.
_NON_PLAIN_VULNERABLE = sorted(VULNERABLE_VERDICTS - {Verdict.VULNERABLE}, key=str)


def _finding(verdict: Verdict, severity: Severity = Severity.CRITICAL) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        scenario_id="MAS01-001",
        scenario_name="multi-agent compromise",
        category=ASICategory.ASI07,
        severity=severity,
        verdict=verdict,
        triggered_by="x",
        description="d",
        remediation="r",
    )


def _report(findings: list[VulnerabilityFinding]) -> ScanReport:
    return ScanReport(
        aastf_version="2.0.0",
        adapter="test",
        findings=findings,
        total_scenarios=len(findings),
        vulnerable=len(findings),
    )


@pytest.mark.parametrize("verdict", _NON_PLAIN_VULNERABLE)
class TestBehaviouralCompromiseVerdictsAreConsistent:
    def test_risk_score_nonzero(self, verdict: Verdict):
        assert compute_risk_score(_report([_finding(verdict)])) > 0.0

    def test_critical_is_non_compliant(self, verdict: Verdict):
        readiness = eu_ai_act_readiness(_report([_finding(verdict, Severity.CRITICAL)]))
        assert readiness == "non_compliant"

    def test_emitted_in_sarif(self, verdict: Verdict):
        doc = SARIFReporter().generate(_report([_finding(verdict)]))
        results = doc["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["level"] == "error"  # CRITICAL behavioural compromise

    def test_blocks_fail_on(self, verdict: Verdict):
        blocking = get_blocking_findings(
            _report([_finding(verdict)]), Severity.CRITICAL, strict_output=False
        )
        assert len(blocking) == 1

    def test_shown_as_vulnerability_in_html(self, verdict: Verdict):
        html = HTMLReporter().generate(_report([_finding(verdict)]))
        # The findings section must not claim "no vulnerabilities" when one exists.
        assert "multi-agent compromise" in html
