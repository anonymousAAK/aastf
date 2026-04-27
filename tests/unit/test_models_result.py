"""Unit tests for result models."""


from aastf.models.result import ScanReport, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace


class TestVerdict:
    def test_all_five_verdicts(self):
        assert len(list(Verdict)) == 5

    def test_verdict_values(self):
        assert Verdict.VULNERABLE.value == "VULNERABLE"
        assert Verdict.REFUSAL_ECHO.value == "REFUSAL_ECHO"
        assert Verdict.SAFE.value == "SAFE"
        assert Verdict.INCONCLUSIVE.value == "INCONCLUSIVE"
        assert Verdict.ERROR.value == "ERROR"

    def test_refusal_echo_ordering(self):
        """REFUSAL_ECHO sits between VULNERABLE and SAFE in enum order."""
        members = list(Verdict)
        assert members.index(Verdict.VULNERABLE) < members.index(Verdict.REFUSAL_ECHO)
        assert members.index(Verdict.REFUSAL_ECHO) < members.index(Verdict.SAFE)

    def test_refusal_echo_json_serialization(self):
        """REFUSAL_ECHO must serialize to the string 'REFUSAL_ECHO' for JSON/SARIF/SQLite compat."""
        assert str(Verdict.REFUSAL_ECHO) == "REFUSAL_ECHO"
        assert Verdict.REFUSAL_ECHO == "REFUSAL_ECHO"  # StrEnum equality with literal


class TestScanReport:
    def _make_report(self, **kwargs) -> ScanReport:
        defaults = dict(aastf_version="0.1.0", adapter="langgraph")
        defaults.update(kwargs)
        return ScanReport(**defaults)

    def test_vulnerability_rate_zero_scenarios(self):
        r = self._make_report(total_scenarios=0, vulnerable=0)
        assert r.vulnerability_rate == 0.0

    def test_vulnerability_rate_all_vulnerable(self):
        r = self._make_report(total_scenarios=10, vulnerable=10)
        assert r.vulnerability_rate == 100.0

    def test_vulnerability_rate_partial(self):
        r = self._make_report(total_scenarios=10, vulnerable=5)
        assert r.vulnerability_rate == 50.0

    def test_vulnerability_rate_rounded(self):
        r = self._make_report(total_scenarios=3, vulnerable=1)
        assert r.vulnerability_rate == 33.3

    def test_auto_run_id(self):
        r = self._make_report()
        assert len(r.run_id) > 0

    def test_two_reports_different_ids(self):
        r1 = self._make_report()
        r2 = self._make_report()
        assert r1.run_id != r2.run_id

    def test_critical_findings_filter(self):
        AgentTrace(scenario_id="ASI02-001", adapter="test")
        finding_critical = VulnerabilityFinding(
            scenario_id="ASI02-001", scenario_name="Test", category=ASICategory.ASI02,
            severity=Severity.CRITICAL, verdict=Verdict.VULNERABLE,
            triggered_by="tool_called: delete_file",
            description="desc", remediation="fix",
        )
        finding_high = VulnerabilityFinding(
            scenario_id="ASI01-001", scenario_name="Test2", category=ASICategory.ASI01,
            severity=Severity.HIGH, verdict=Verdict.VULNERABLE,
            triggered_by="tool_called: send_email",
            description="desc", remediation="fix",
        )
        r = self._make_report(findings=[finding_critical, finding_high])
        assert len(r.critical_findings) == 1
        assert r.critical_findings[0].severity == Severity.CRITICAL

    def test_refusal_echo_count_defaults_to_zero(self):
        r = self._make_report()
        assert r.refusal_echo_count == 0

    def test_vulnerability_rate_excludes_refusal_echo(self):
        """Critical regression: vulnerability_rate must NOT include REFUSAL_ECHO findings.

        Setup: 10 scenarios, 2 behaviorally vulnerable, 5 refusal-echo.
        Expected vulnerability_rate: 20.0 (2/10), NOT 70.0 (7/10).
        """
        r = self._make_report(total_scenarios=10, vulnerable=2, refusal_echo_count=5)
        assert r.vulnerability_rate == 20.0

    def test_informational_risk_rate(self):
        r = self._make_report(total_scenarios=10, refusal_echo_count=3)
        assert r.informational_risk_rate == 30.0

    def test_informational_risk_rate_zero_scenarios(self):
        r = self._make_report(total_scenarios=0, refusal_echo_count=0)
        assert r.informational_risk_rate == 0.0

    def test_eu_ai_act_readiness_default(self):
        r = self._make_report()
        assert r.eu_ai_act_readiness == "at_risk"

    def test_json_serializable(self):
        r = self._make_report()
        json_str = r.model_dump_json()
        assert "aastf_version" in json_str
