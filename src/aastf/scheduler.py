"""Continuous mode scheduler — runs AASTF scans on a recurring interval.

Stores results in `.aastf/history/`, detects regressions between runs,
and optionally pushes results to a webhook URL or GitHub Code Scanning API (SARIF).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .cache import ResponseCache
from .models.config import FrameworkConfig
from .models.result import VULNERABLE_VERDICTS, ScanReport, Verdict
from .reporting.json_reporter import JSONReporter
from .reporting.sarif_reporter import SARIFReporter
from .runner import Runner

logger = logging.getLogger(__name__)

_INTERVAL_RE = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_interval(value: str) -> int:
    """Parse a human-friendly interval string like '24h', '1h30m', '45s' to seconds.

    Raises ValueError if the format is invalid or result is zero.
    """
    value = value.strip()
    # Plain integer → treat as seconds
    if value.isdigit():
        secs = int(value)
        if secs <= 0:
            raise ValueError(f"Interval must be positive, got {secs}")
        return secs

    m = _INTERVAL_RE.match(value)
    if not m or not any(m.groups()):
        raise ValueError(
            f"Invalid interval {value!r}. "
            "Use format like '24h', '1h30m', '90s', or a plain integer (seconds)."
        )
    hours = int(m.group(1) or 0)
    minutes = int(m.group(2) or 0)
    seconds = int(m.group(3) or 0)
    total = hours * 3600 + minutes * 60 + seconds
    if total <= 0:
        raise ValueError(f"Interval must be positive, got {total}s from {value!r}")
    return total


class ContinuousScheduler:
    """Schedules recurring AASTF scans with regression detection and webhook output."""

    def __init__(
        self,
        config: FrameworkConfig,
        interval_seconds: int = 86400,
        history_dir: Path | None = None,
        webhook_url: str | None = None,
        sarif_endpoint: str | None = None,
    ) -> None:
        self._config = config
        self._interval = interval_seconds
        self._history_dir = (history_dir or Path(".aastf/history")).resolve()
        self._webhook_url = webhook_url
        self._sarif_endpoint = sarif_endpoint
        self._running = False
        self._stop_event: asyncio.Event | None = None
        self._json_reporter = JSONReporter()
        self._sarif_reporter = SARIFReporter()

    # ------------------------------------------------------------------ public

    @property
    def history_dir(self) -> Path:
        return self._history_dir

    @property
    def interval(self) -> int:
        return self._interval

    async def run_once(self) -> ScanReport:
        """Execute a single scan, persist to history, detect regressions, push outputs."""
        runner = Runner(self._config, cache=ResponseCache(enabled=False))
        report = await runner.run()

        # Persist
        self._save_report(report)

        # Regression detection
        history = self.get_history()
        regressions: list[dict[str, Any]] = []
        if len(history) >= 2:
            previous = history[-2]
            regressions = self.detect_regressions(current=report, previous=previous)
            if regressions:
                logger.warning(
                    "Detected %d regression(s) compared to previous run %s",
                    len(regressions),
                    previous.run_id,
                )

        # Webhook
        if self._webhook_url:
            await self._post_webhook(report, regressions)

        # SARIF push
        if self._sarif_endpoint:
            await self._push_sarif(report)

        return report

    async def start(self) -> None:
        """Run scans in a loop at the configured interval. Blocks until stop() is called."""
        self._running = True
        self._stop_event = asyncio.Event()
        logger.info(
            "Continuous scheduler started — interval=%ds, history=%s",
            self._interval,
            self._history_dir,
        )
        while self._running:
            try:
                await self.run_once()
            except Exception:
                logger.exception("Scan failed during continuous run")

            # Wait for interval or stop signal
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=self._interval,
                )
                # If wait_for returned without timeout, stop was requested
                break
            except asyncio.TimeoutError:
                # Interval elapsed — run next scan
                continue

        logger.info("Continuous scheduler stopped.")

    async def stop(self) -> None:
        """Signal the scheduler to stop after the current scan completes."""
        self._running = False
        if self._stop_event is not None:
            self._stop_event.set()

    def get_history(self) -> list[ScanReport]:
        """Load all previous scan reports from history directory, sorted by timestamp."""
        if not self._history_dir.exists():
            return []

        reports: list[ScanReport] = []
        for path in sorted(self._history_dir.glob("*.json")):
            try:
                data = path.read_text(encoding="utf-8")
                reports.append(ScanReport.model_validate_json(data))
            except Exception:
                logger.warning("Failed to load history file %s", path, exc_info=True)
        return reports

    def detect_regressions(
        self,
        current: ScanReport,
        previous: ScanReport,
    ) -> list[dict[str, Any]]:
        """Compare current and previous scan reports, return list of regressions.

        A regression is defined as:
        - A scenario that was SAFE in the previous run but is now VULNERABLE
          (or any attack-success verdict).
        - A newly introduced finding not present in the previous run.
        - An increase in overall risk score.
        """
        regressions: list[dict[str, Any]] = []

        # Canonical behavioural-compromise set (includes MCP + multi-agent
        # verdicts) so a SAFE→compromise regression is detected for all of them.
        _ATTACK_VERDICTS = VULNERABLE_VERDICTS

        # Build lookup: scenario_id -> verdict for previous run
        prev_verdicts: dict[str, Verdict] = {}
        for result in previous.results:
            prev_verdicts[result.scenario_id] = result.verdict

        # Check each current result against previous
        for result in current.results:
            prev_verdict = prev_verdicts.get(result.scenario_id)

            if prev_verdict is None and result.verdict in _ATTACK_VERDICTS:
                # New scenario that immediately shows as vulnerable
                regressions.append({
                    "type": "new_vulnerability",
                    "scenario_id": result.scenario_id,
                    "scenario_name": result.scenario_name,
                    "current_verdict": result.verdict.value,
                    "previous_verdict": None,
                    "message": (
                        f"New scenario {result.scenario_id} is {result.verdict.value}"
                    ),
                })
            elif prev_verdict == Verdict.SAFE and result.verdict in _ATTACK_VERDICTS:
                regressions.append({
                    "type": "verdict_regression",
                    "scenario_id": result.scenario_id,
                    "scenario_name": result.scenario_name,
                    "current_verdict": result.verdict.value,
                    "previous_verdict": prev_verdict.value,
                    "message": (
                        f"{result.scenario_id} regressed: "
                        f"{prev_verdict.value} -> {result.verdict.value}"
                    ),
                })
            elif (
                prev_verdict == Verdict.SAFE
                and result.verdict == Verdict.REFUSAL_ECHO
            ):
                regressions.append({
                    "type": "refusal_echo_regression",
                    "scenario_id": result.scenario_id,
                    "scenario_name": result.scenario_name,
                    "current_verdict": result.verdict.value,
                    "previous_verdict": prev_verdict.value,
                    "message": (
                        f"{result.scenario_id} regressed to REFUSAL_ECHO: "
                        f"agent now leaks payload details in refusal"
                    ),
                })

        # Overall risk score increase
        if current.overall_risk_score > previous.overall_risk_score:
            regressions.append({
                "type": "risk_score_increase",
                "scenario_id": None,
                "scenario_name": None,
                "current_verdict": None,
                "previous_verdict": None,
                "current_risk_score": current.overall_risk_score,
                "previous_risk_score": previous.overall_risk_score,
                "message": (
                    f"Overall risk score increased: "
                    f"{previous.overall_risk_score} -> {current.overall_risk_score}"
                ),
            })

        return regressions

    # ----------------------------------------------------------------- private

    def _save_report(self, report: ScanReport) -> Path:
        """Persist a scan report to the history directory."""
        self._history_dir.mkdir(parents=True, exist_ok=True)
        ts = report.generated_at.strftime("%Y%m%dT%H%M%S")
        filename = f"scan-{ts}-{report.run_id[:8]}.json"
        path = self._history_dir / filename
        path.write_text(
            self._json_reporter.generate(report),
            encoding="utf-8",
        )
        logger.info("Saved scan report to %s", path)
        return path

    async def _post_webhook(
        self,
        report: ScanReport,
        regressions: list[dict[str, Any]],
    ) -> None:
        """POST scan results to the configured webhook URL."""
        if not self._webhook_url:
            return

        payload = {
            "event": "aastf_scan_complete",
            "run_id": report.run_id,
            "generated_at": report.generated_at.isoformat(),
            "aastf_version": report.aastf_version,
            "adapter": report.adapter,
            "total_scenarios": report.total_scenarios,
            "vulnerable": report.vulnerable,
            "safe": report.safe,
            "errors": report.errors,
            "overall_risk_score": report.overall_risk_score,
            "eu_ai_act_readiness": report.eu_ai_act_readiness,
            "vulnerability_rate": report.vulnerability_rate,
            "regressions": regressions,
            "findings_count": len(report.findings),
        }

        body = json.dumps(payload).encode("utf-8")

        def _do_post() -> int:
            req = urllib.request.Request(
                self._webhook_url,  # type: ignore[arg-type]
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"aastf/{report.aastf_version}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.status  # type: ignore[return-value]
            except urllib.error.URLError as e:
                logger.error("Webhook POST failed: %s", e)
                return 0

        loop = asyncio.get_running_loop()
        status = await loop.run_in_executor(None, _do_post)
        if status and 200 <= status < 300:
            logger.info("Webhook POST to %s succeeded (HTTP %d)", self._webhook_url, status)
        else:
            logger.warning("Webhook POST to %s returned HTTP %d", self._webhook_url, status)

    async def _push_sarif(self, report: ScanReport) -> None:
        """Push SARIF results to GitHub Code Scanning API."""
        if not self._sarif_endpoint:
            return

        import base64
        import gzip

        sarif_json = self._sarif_reporter.generate_json(report)
        compressed = gzip.compress(sarif_json.encode("utf-8"))
        sarif_b64 = base64.b64encode(compressed).decode("ascii")

        payload = json.dumps({
            "commit_sha": self._get_git_sha(),
            "ref": self._get_git_ref(),
            "sarif": sarif_b64,
        }).encode("utf-8")

        def _do_push() -> int:
            req = urllib.request.Request(
                self._sarif_endpoint,  # type: ignore[arg-type]
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"aastf/{report.aastf_version}",
                },
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.status  # type: ignore[return-value]
            except urllib.error.URLError as e:
                logger.error("SARIF push failed: %s", e)
                return 0

        loop = asyncio.get_running_loop()
        status = await loop.run_in_executor(None, _do_push)
        if status and 200 <= status < 300:
            logger.info("SARIF push to %s succeeded (HTTP %d)", self._sarif_endpoint, status)
        else:
            logger.warning("SARIF push to %s returned HTTP %d", self._sarif_endpoint, status)

    @staticmethod
    def _get_git_sha() -> str:
        """Best-effort: read current git commit SHA."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except Exception:
            return "unknown"

    @staticmethod
    def _get_git_ref() -> str:
        """Best-effort: read current git ref."""
        import subprocess

        try:
            result = subprocess.run(
                ["git", "symbolic-ref", "HEAD"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else "refs/heads/main"
        except Exception:
            return "refs/heads/main"
