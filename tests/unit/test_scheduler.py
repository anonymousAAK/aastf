"""Tests for the continuous mode scheduler."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aastf.models.config import FrameworkConfig
from aastf.models.result import ScanReport, TestResult, Verdict, VulnerabilityFinding
from aastf.models.scenario import ASICategory, Severity
from aastf.models.trace import AgentTrace
from aastf.scheduler import ContinuousScheduler, parse_interval

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_config() -> FrameworkConfig:
    return FrameworkConfig(
        adapter="langgraph",
        agent_factory="fake.module:create_agent",
        categories=[],
        output_dir="test-output",
    )


def _make_report(
    *,
    run_id: str = "run-001",
    vulnerable: int = 0,
    safe: int = 5,
    risk_score: float = 10.0,
    results: list[TestResult] | None = None,
    findings: list[VulnerabilityFinding] | None = None,
) -> ScanReport:
    return ScanReport(
        run_id=run_id,
        aastf_version="0.7.0",
        adapter="langgraph",
        total_scenarios=vulnerable + safe,
        vulnerable=vulnerable,
        safe=safe,
        overall_risk_score=risk_score,
        results=results or [],
        findings=findings or [],
    )


def _make_test_result(
    scenario_id: str,
    verdict: Verdict,
    category: ASICategory = ASICategory.ASI01,
) -> TestResult:
    return TestResult(
        scenario_id=scenario_id,
        scenario_name=f"Test {scenario_id}",
        category=category,
        severity=Severity.HIGH,
        verdict=verdict,
        trace=AgentTrace(scenario_id=scenario_id, adapter="langgraph"),
    )


# ---------------------------------------------------------------------------
# parse_interval
# ---------------------------------------------------------------------------


class TestParseInterval:
    def test_hours(self) -> None:
        assert parse_interval("24h") == 86400

    def test_minutes(self) -> None:
        assert parse_interval("30m") == 1800

    def test_seconds(self) -> None:
        assert parse_interval("90s") == 90

    def test_combined_hm(self) -> None:
        assert parse_interval("1h30m") == 5400

    def test_combined_hms(self) -> None:
        assert parse_interval("1h30m15s") == 5415

    def test_plain_integer(self) -> None:
        assert parse_interval("3600") == 3600

    def test_whitespace_stripped(self) -> None:
        assert parse_interval("  1h  ") == 3600

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid interval"):
            parse_interval("abc")

    def test_zero_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            parse_interval("0")

    def test_zero_h_raises(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            parse_interval("0h0m0s")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid interval"):
            parse_interval("")

    def test_negative_plain_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid interval"):
            parse_interval("-1")


# ---------------------------------------------------------------------------
# ContinuousScheduler.__init__
# ---------------------------------------------------------------------------


class TestSchedulerInit:
    def test_defaults(self) -> None:
        sched = ContinuousScheduler(config=_make_config())
        assert sched.interval == 86400
        assert sched.history_dir.name == "history"
        assert sched._webhook_url is None
        assert sched._sarif_endpoint is None

    def test_custom_params(self, tmp_path: Path) -> None:
        sched = ContinuousScheduler(
            config=_make_config(),
            interval_seconds=3600,
            history_dir=tmp_path / "my-history",
            webhook_url="https://example.com/hook",
            sarif_endpoint="https://api.github.com/sarif",
        )
        assert sched.interval == 3600
        assert sched.history_dir == (tmp_path / "my-history").resolve()
        assert sched._webhook_url == "https://example.com/hook"
        assert sched._sarif_endpoint == "https://api.github.com/sarif"


# ---------------------------------------------------------------------------
# History persistence + loading
# ---------------------------------------------------------------------------


class TestHistory:
    def test_save_and_load(self, tmp_path: Path) -> None:
        sched = ContinuousScheduler(
            config=_make_config(),
            history_dir=tmp_path / "history",
        )
        report = _make_report(run_id="aaa-111")
        path = sched._save_report(report)

        assert path.exists()
        assert path.suffix == ".json"

        loaded = sched.get_history()
        assert len(loaded) == 1
        assert loaded[0].run_id == "aaa-111"

    def test_multiple_reports_sorted(self, tmp_path: Path) -> None:
        sched = ContinuousScheduler(
            config=_make_config(),
            history_dir=tmp_path / "history",
        )
        r1 = _make_report(run_id="first")
        r2 = _make_report(run_id="second")
        sched._save_report(r1)
        sched._save_report(r2)

        loaded = sched.get_history()
        assert len(loaded) == 2

    def test_empty_history(self, tmp_path: Path) -> None:
        sched = ContinuousScheduler(
            config=_make_config(),
            history_dir=tmp_path / "nonexistent",
        )
        assert sched.get_history() == []

    def test_corrupt_file_skipped(self, tmp_path: Path) -> None:
        history_dir = tmp_path / "history"
        history_dir.mkdir(parents=True)
        (history_dir / "bad.json").write_text("not-json", encoding="utf-8")

        sched = ContinuousScheduler(
            config=_make_config(),
            history_dir=history_dir,
        )
        assert sched.get_history() == []


# ---------------------------------------------------------------------------
# Regression detection
# ---------------------------------------------------------------------------


class TestRegressionDetection:
    def test_no_regressions_when_identical(self) -> None:
        results = [_make_test_result("ASI01-001", Verdict.SAFE)]
        prev = _make_report(safe=1, results=results)
        curr = _make_report(safe=1, results=results)

        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)
        assert regs == []

    def test_verdict_regression_safe_to_vulnerable(self) -> None:
        prev = _make_report(
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
            risk_score=10.0,
        )
        curr = _make_report(
            vulnerable=1,
            results=[_make_test_result("ASI01-001", Verdict.VULNERABLE)],
            risk_score=10.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        verdict_regs = [r for r in regs if r["type"] == "verdict_regression"]
        assert len(verdict_regs) == 1
        assert verdict_regs[0]["scenario_id"] == "ASI01-001"
        assert verdict_regs[0]["current_verdict"] == "VULNERABLE"
        assert verdict_regs[0]["previous_verdict"] == "SAFE"

    def test_safe_to_refusal_echo_regression(self) -> None:
        prev = _make_report(
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
            risk_score=5.0,
        )
        curr = _make_report(
            results=[_make_test_result("ASI01-001", Verdict.REFUSAL_ECHO)],
            risk_score=5.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        echo_regs = [r for r in regs if r["type"] == "refusal_echo_regression"]
        assert len(echo_regs) == 1

    def test_new_vulnerability_detected(self) -> None:
        prev = _make_report(
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
            risk_score=5.0,
        )
        curr = _make_report(
            vulnerable=1,
            safe=1,
            results=[
                _make_test_result("ASI01-001", Verdict.SAFE),
                _make_test_result("ASI01-002", Verdict.VULNERABLE),
            ],
            risk_score=5.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        new_regs = [r for r in regs if r["type"] == "new_vulnerability"]
        assert len(new_regs) == 1
        assert new_regs[0]["scenario_id"] == "ASI01-002"

    def test_risk_score_increase(self) -> None:
        prev = _make_report(risk_score=10.0, results=[])
        curr = _make_report(risk_score=25.0, results=[])

        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        score_regs = [r for r in regs if r["type"] == "risk_score_increase"]
        assert len(score_regs) == 1
        assert score_regs[0]["current_risk_score"] == 25.0
        assert score_regs[0]["previous_risk_score"] == 10.0

    def test_risk_score_decrease_not_flagged(self) -> None:
        prev = _make_report(risk_score=30.0, results=[])
        curr = _make_report(risk_score=10.0, results=[])

        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)
        assert regs == []

    def test_tool_poisoning_regression(self) -> None:
        prev = _make_report(
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
            risk_score=5.0,
        )
        curr = _make_report(
            vulnerable=1,
            results=[_make_test_result("ASI01-001", Verdict.TOOL_POISONING)],
            risk_score=5.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        verdict_regs = [r for r in regs if r["type"] == "verdict_regression"]
        assert len(verdict_regs) == 1
        assert verdict_regs[0]["current_verdict"] == "TOOL_POISONING"

    def test_vulnerable_to_safe_not_regression(self) -> None:
        """Improvement should not be flagged as regression."""
        prev = _make_report(
            vulnerable=1,
            results=[_make_test_result("ASI01-001", Verdict.VULNERABLE)],
            risk_score=20.0,
        )
        curr = _make_report(
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
            risk_score=5.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)
        assert regs == []

    def test_multiple_regressions_combined(self) -> None:
        prev = _make_report(
            safe=2,
            results=[
                _make_test_result("ASI01-001", Verdict.SAFE),
                _make_test_result("ASI01-002", Verdict.SAFE),
            ],
            risk_score=5.0,
        )
        curr = _make_report(
            vulnerable=2,
            results=[
                _make_test_result("ASI01-001", Verdict.VULNERABLE),
                _make_test_result("ASI01-002", Verdict.SCHEMA_POISONING),
            ],
            risk_score=30.0,
        )
        sched = ContinuousScheduler(config=_make_config())
        regs = sched.detect_regressions(curr, prev)

        types = {r["type"] for r in regs}
        assert "verdict_regression" in types
        assert "risk_score_increase" in types
        assert len(regs) == 3  # 2 verdict + 1 risk score


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


class TestRunOnce:
    @pytest.mark.asyncio
    async def test_run_once_saves_report(self, tmp_path: Path) -> None:
        report = _make_report(run_id="test-run-once")

        with patch("aastf.scheduler.Runner") as MockRunner:
            instance = MockRunner.return_value
            instance.run = AsyncMock(return_value=report)

            sched = ContinuousScheduler(
                config=_make_config(),
                history_dir=tmp_path / "history",
            )
            result = await sched.run_once()

        assert result.run_id == "test-run-once"
        history = sched.get_history()
        assert len(history) == 1

    @pytest.mark.asyncio
    async def test_run_once_detects_regressions(self, tmp_path: Path) -> None:
        prev_report = _make_report(
            run_id="prev",
            safe=1,
            results=[_make_test_result("ASI01-001", Verdict.SAFE)],
        )
        curr_report = _make_report(
            run_id="curr",
            vulnerable=1,
            results=[_make_test_result("ASI01-001", Verdict.VULNERABLE)],
        )

        sched = ContinuousScheduler(
            config=_make_config(),
            history_dir=tmp_path / "history",
        )
        # Pre-seed history with previous report
        sched._save_report(prev_report)

        with patch("aastf.scheduler.Runner") as MockRunner:
            instance = MockRunner.return_value
            instance.run = AsyncMock(return_value=curr_report)

            result = await sched.run_once()

        assert result.run_id == "curr"
        assert len(sched.get_history()) == 2


# ---------------------------------------------------------------------------
# Webhook
# ---------------------------------------------------------------------------


class TestWebhook:
    @pytest.mark.asyncio
    async def test_webhook_post_called(self, tmp_path: Path) -> None:
        report = _make_report(run_id="webhook-test")

        with (
            patch("aastf.scheduler.Runner") as MockRunner,
            patch("aastf.scheduler.urllib.request.urlopen") as mock_urlopen,
        ):
            instance = MockRunner.return_value
            instance.run = AsyncMock(return_value=report)

            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            sched = ContinuousScheduler(
                config=_make_config(),
                history_dir=tmp_path / "history",
                webhook_url="https://example.com/hook",
            )
            await sched.run_once()

        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert req.full_url == "https://example.com/hook"
        assert req.method == "POST"

        body = json.loads(req.data.decode("utf-8"))
        assert body["event"] == "aastf_scan_complete"
        assert body["run_id"] == "webhook-test"

    @pytest.mark.asyncio
    async def test_no_webhook_when_url_none(self, tmp_path: Path) -> None:
        report = _make_report()

        with (
            patch("aastf.scheduler.Runner") as MockRunner,
            patch("aastf.scheduler.urllib.request.urlopen") as mock_urlopen,
        ):
            instance = MockRunner.return_value
            instance.run = AsyncMock(return_value=report)

            sched = ContinuousScheduler(
                config=_make_config(),
                history_dir=tmp_path / "history",
            )
            await sched.run_once()

        mock_urlopen.assert_not_called()


# ---------------------------------------------------------------------------
# SARIF push
# ---------------------------------------------------------------------------


class TestSARIFPush:
    @pytest.mark.asyncio
    async def test_sarif_push_called(self, tmp_path: Path) -> None:
        report = _make_report(run_id="sarif-test")

        with (
            patch("aastf.scheduler.Runner") as MockRunner,
            patch("aastf.scheduler.urllib.request.urlopen") as mock_urlopen,
            patch.object(ContinuousScheduler, "_get_git_sha", return_value="abc123"),
            patch.object(ContinuousScheduler, "_get_git_ref", return_value="refs/heads/main"),
        ):
            instance = MockRunner.return_value
            instance.run = AsyncMock(return_value=report)

            mock_resp = MagicMock()
            mock_resp.status = 202
            mock_resp.__enter__ = MagicMock(return_value=mock_resp)
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            sched = ContinuousScheduler(
                config=_make_config(),
                history_dir=tmp_path / "history",
                sarif_endpoint="https://api.github.com/repos/org/repo/code-scanning/sarifs",
            )
            await sched.run_once()

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        body = json.loads(req.data.decode("utf-8"))
        assert body["commit_sha"] == "abc123"
        assert body["ref"] == "refs/heads/main"
        assert "sarif" in body


# ---------------------------------------------------------------------------
# start / stop lifecycle
# ---------------------------------------------------------------------------


class TestStartStop:
    @pytest.mark.asyncio
    async def test_stop_halts_loop(self, tmp_path: Path) -> None:
        report = _make_report()
        call_count = 0

        async def mock_run():
            nonlocal call_count
            call_count += 1
            return report

        with patch("aastf.scheduler.Runner") as MockRunner:
            instance = MockRunner.return_value
            instance.run = mock_run

            sched = ContinuousScheduler(
                config=_make_config(),
                interval_seconds=1,
                history_dir=tmp_path / "history",
            )

            async def stop_after_delay():
                await asyncio.sleep(0.3)
                await sched.stop()

            await asyncio.gather(
                sched.start(),
                stop_after_delay(),
            )

        # Should have run at least once before stopping
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_stop_before_start(self) -> None:
        sched = ContinuousScheduler(config=_make_config())
        # Should not raise
        await sched.stop()

    @pytest.mark.asyncio
    async def test_scan_error_does_not_crash_loop(self, tmp_path: Path) -> None:
        call_count = 0

        async def mock_run():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("Simulated failure")
            return _make_report()

        with patch("aastf.scheduler.Runner") as MockRunner:
            instance = MockRunner.return_value
            instance.run = mock_run

            sched = ContinuousScheduler(
                config=_make_config(),
                interval_seconds=1,
                history_dir=tmp_path / "history",
            )

            async def stop_after_delay():
                await asyncio.sleep(2.5)
                await sched.stop()

            await asyncio.gather(
                sched.start(),
                stop_after_delay(),
            )

        # Should have recovered and run at least twice
        assert call_count >= 2


# ---------------------------------------------------------------------------
# CLI flag parsing (integration-light)
# ---------------------------------------------------------------------------


class TestCLIFlags:
    def test_parse_interval_for_cli(self) -> None:
        """Ensure CLI-style interval strings parse correctly."""
        assert parse_interval("24h") == 86400
        assert parse_interval("1h") == 3600
        assert parse_interval("30m") == 1800
