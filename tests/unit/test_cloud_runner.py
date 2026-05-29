"""Tests for aastf.cloud_runner — 20+ tests for config, manifests, and cost estimation."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aastf.cloud_runner import (
    CloudRunner,
    CloudRunnerConfig,
    HelmValues,
    _parse_memory_gib,
)

# ---------------------------------------------------------------------------
# CloudRunnerConfig model tests
# ---------------------------------------------------------------------------


class TestCloudRunnerConfig:
    def test_defaults(self):
        c = CloudRunnerConfig()
        assert c.image == "ghcr.io/anonymousaak/aastf:latest"
        assert c.timeout == 1800
        assert c.memory_limit == "2Gi"
        assert c.cpu_limit == "2"
        assert c.namespace == "aastf"

    def test_custom(self):
        c = CloudRunnerConfig(
            image="custom:v1", timeout=600,
            memory_limit="4Gi", cpu_limit="4",
            namespace="prod",
        )
        assert c.image == "custom:v1"
        assert c.timeout == 600

    def test_invalid_timeout(self):
        with pytest.raises(ValidationError):
            CloudRunnerConfig(timeout=0)


# ---------------------------------------------------------------------------
# HelmValues model tests
# ---------------------------------------------------------------------------


class TestHelmValues:
    def test_defaults(self):
        h = HelmValues()
        assert h.replicaCount == 1
        assert h.image == {}

    def test_invalid_replicas(self):
        with pytest.raises(ValidationError):
            HelmValues(replicaCount=0)

    def test_custom(self):
        h = HelmValues(
            replicaCount=3,
            image={"repository": "test", "tag": "v1"},
            resources={"limits": {"cpu": "4"}},
            config={"timeout": 300},
        )
        assert h.replicaCount == 3
        assert h.image["tag"] == "v1"


# ---------------------------------------------------------------------------
# CloudRunner tests
# ---------------------------------------------------------------------------


class TestCloudRunner:
    def test_default_config(self):
        runner = CloudRunner()
        assert runner.config.image == "ghcr.io/anonymousaak/aastf:latest"

    def test_custom_config(self):
        cfg = CloudRunnerConfig(image="test:v2", timeout=300)
        runner = CloudRunner(config=cfg)
        assert runner.config.timeout == 300

    def test_generate_dockerfile(self):
        runner = CloudRunner()
        df = runner.generate_dockerfile()
        assert "FROM python:3.12-slim" in df
        assert "ENTRYPOINT" in df
        assert "HEALTHCHECK" in df
        assert "pip install" in df
        assert "USER aastf" in df

    def test_generate_helm_values_structure(self):
        runner = CloudRunner()
        vals = runner.generate_helm_values()
        assert "replicaCount" in vals
        assert "image" in vals
        assert "resources" in vals
        assert vals["image"]["repository"] == "ghcr.io/anonymousaak/aastf"
        assert vals["image"]["tag"] == "latest"

    def test_generate_helm_values_resources(self):
        runner = CloudRunner(
            config=CloudRunnerConfig(cpu_limit="4", memory_limit="8Gi"),
        )
        vals = runner.generate_helm_values()
        assert vals["resources"]["limits"]["cpu"] == "4"
        assert vals["resources"]["limits"]["memory"] == "8Gi"

    def test_generate_k8s_job_structure(self):
        runner = CloudRunner()
        job = runner.generate_k8s_job({"run_id": "test-123"})
        assert job["apiVersion"] == "batch/v1"
        assert job["kind"] == "Job"
        assert job["metadata"]["name"] == "aastf-scan-test-123"
        assert job["metadata"]["namespace"] == "aastf"

    def test_generate_k8s_job_container(self):
        runner = CloudRunner()
        job = runner.generate_k8s_job({"run_id": "abc"})
        containers = job["spec"]["template"]["spec"]["containers"]
        assert len(containers) == 1
        assert containers[0]["name"] == "aastf-scanner"
        assert containers[0]["image"] == "ghcr.io/anonymousaak/aastf:latest"

    def test_generate_k8s_job_timeout(self):
        runner = CloudRunner(config=CloudRunnerConfig(timeout=600))
        job = runner.generate_k8s_job({"run_id": "x"})
        assert job["spec"]["activeDeadlineSeconds"] == 600

    def test_generate_k8s_job_config_env(self):
        runner = CloudRunner()
        scan_cfg = {"run_id": "t", "adapter": "langgraph"}
        job = runner.generate_k8s_job(scan_cfg)
        env = job["spec"]["template"]["spec"]["containers"][0]["env"]
        config_env = [e for e in env if e["name"] == "AASTF_SCAN_CONFIG"]
        assert len(config_env) == 1
        parsed = json.loads(config_env[0]["value"])
        assert parsed["adapter"] == "langgraph"

    def test_generate_k8s_job_default_run_id(self):
        runner = CloudRunner()
        job = runner.generate_k8s_job({})
        assert job["metadata"]["name"] == "aastf-scan-default"

    def test_generate_github_webhook_handler(self):
        runner = CloudRunner()
        code = runner.generate_github_webhook_handler()
        assert "AastfWebhookHandler" in code
        assert "do_POST" in code
        assert "X-Hub-Signature-256" in code
        assert "_verify_signature" in code
        assert "_trigger_scan" in code

    def test_estimated_cost_basic(self):
        runner = CloudRunner()
        cost = runner.estimated_cost(100)
        assert cost["scenarios"] == 100
        assert cost["estimated_cost_usd"] > 0
        assert cost["estimated_duration_seconds"] > 0
        assert "assumptions" in cost

    def test_estimated_cost_scales(self):
        runner = CloudRunner()
        c100 = runner.estimated_cost(100)
        c1000 = runner.estimated_cost(1000)
        assert c1000["estimated_cost_usd"] > c100["estimated_cost_usd"]
        assert c1000["estimated_duration_seconds"] > c100["estimated_duration_seconds"]

    def test_estimated_cost_zero_scenarios(self):
        runner = CloudRunner()
        cost = runner.estimated_cost(0)
        # Still has startup overhead
        assert cost["estimated_duration_seconds"] > 0
        assert cost["estimated_cost_usd"] > 0

    def test_estimated_cost_custom_resources(self):
        runner = CloudRunner(
            config=CloudRunnerConfig(cpu_limit="4", memory_limit="8Gi"),
        )
        cost = runner.estimated_cost(100)
        # More resources = higher cost
        default_cost = CloudRunner().estimated_cost(100)
        assert cost["estimated_cost_usd"] > default_cost["estimated_cost_usd"]


# ---------------------------------------------------------------------------
# Helper tests
# ---------------------------------------------------------------------------


class TestParseMemoryGib:
    def test_gi(self):
        assert _parse_memory_gib("2Gi") == 2.0

    def test_mi(self):
        assert abs(_parse_memory_gib("512Mi") - 0.5) < 0.01

    def test_ki(self):
        result = _parse_memory_gib("1048576Ki")
        assert abs(result - 1.0) < 0.01

    def test_fallback(self):
        assert _parse_memory_gib("not_a_number") == 2.0
