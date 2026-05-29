"""Tests for the n8n workflow security scanning adapter."""

from __future__ import annotations

import pytest

from aastf.harness.adapters.n8n import N8nHarness, N8nWorkflow

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_workflow() -> N8nWorkflow:
    return N8nWorkflow(id="wf-empty", name="Empty Workflow")


@pytest.fixture()
def simple_workflow() -> N8nWorkflow:
    return N8nWorkflow(
        id="wf-1",
        name="Simple Webhook Flow",
        nodes=[
            {"type": "n8n-nodes-base.webhook", "name": "Webhook Trigger", "position": [100, 200]},
            {"type": "n8n-nodes-base.httpRequest", "name": "HTTP Request", "position": [300, 200]},
            {"type": "n8n-nodes-base.set", "name": "Set Data", "position": [500, 200]},
        ],
        connections={"Webhook Trigger": {"main": [[{"node": "HTTP Request"}]]}},
        active=True,
    )


@pytest.fixture()
def credential_workflow() -> N8nWorkflow:
    return N8nWorkflow(
        id="wf-cred",
        name="Credential Flow",
        nodes=[
            {"type": "n8n-nodes-base.postgres", "name": "DB Query",
             "credentials": {"postgres": {"id": "1", "name": "prod-db"}}},
            {"type": "n8n-nodes-base.openAi", "name": "OpenAI",
             "credentials": {"openai": {"id": "2", "name": "openai-key"}}},
        ],
    )


@pytest.fixture()
def secret_workflow() -> N8nWorkflow:
    return N8nWorkflow(
        id="wf-secret",
        name="Secret Leak",
        nodes=[
            {"type": "n8n-nodes-base.httpRequest", "name": "API Call",
             "parameters": {"url": "https://api.example.com", "headerParameters": {"api_key": "sk-abcdefghij1234567890abcdefghij1234567890"}}},
        ],
    )


@pytest.fixture()
def expression_workflow() -> N8nWorkflow:
    return N8nWorkflow(
        id="wf-expr",
        name="Expression Flow",
        nodes=[
            {"type": "n8n-nodes-base.set", "name": "Set", "parameters": {"value": "={{$json.body.name}}"}},
            {"type": "n8n-nodes-base.function", "name": "Func", "parameters": {"code": "$input.all()"}},
        ],
    )


# ---------------------------------------------------------------------------
# N8nWorkflow model tests
# ---------------------------------------------------------------------------


class TestN8nWorkflowModel:
    def test_default_values(self):
        wf = N8nWorkflow()
        assert wf.id == ""
        assert wf.name == ""
        assert wf.nodes == []
        assert wf.connections == {}
        assert wf.active is False

    def test_from_dict(self):
        wf = N8nWorkflow(id="x", name="Test", active=True)
        assert wf.id == "x"
        assert wf.active is True

    def test_nodes_are_list_of_dict(self, simple_workflow: N8nWorkflow):
        assert isinstance(simple_workflow.nodes, list)
        assert all(isinstance(n, dict) for n in simple_workflow.nodes)


# ---------------------------------------------------------------------------
# extract_tools
# ---------------------------------------------------------------------------


class TestExtractTools:
    def test_empty_workflow(self, empty_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=empty_workflow)
        assert harness.extract_tools() == []

    def test_returns_unique_types(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        tools = harness.extract_tools()
        assert len(tools) == 3
        assert "n8n-nodes-base.webhook" in tools

    def test_deduplicates(self):
        wf = N8nWorkflow(nodes=[
            {"type": "n8n-nodes-base.set", "name": "A"},
            {"type": "n8n-nodes-base.set", "name": "B"},
        ])
        harness = N8nHarness(workflow=wf)
        assert harness.extract_tools() == ["n8n-nodes-base.set"]

    def test_skips_empty_type(self):
        wf = N8nWorkflow(nodes=[{"type": "", "name": "X"}, {"name": "Y"}])
        harness = N8nHarness(workflow=wf)
        assert harness.extract_tools() == []

    def test_accepts_explicit_workflow(self, empty_workflow: N8nWorkflow, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=empty_workflow)
        tools = harness.extract_tools(simple_workflow)
        assert len(tools) == 3


# ---------------------------------------------------------------------------
# detect_injection_points
# ---------------------------------------------------------------------------


class TestDetectInjectionPoints:
    def test_empty_workflow(self, empty_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=empty_workflow)
        assert harness.detect_injection_points() == []

    def test_finds_webhook(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        points = harness.detect_injection_points()
        types = [p["node_type"] for p in points]
        assert "n8n-nodes-base.webhook" in types

    def test_finds_http_request(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        points = harness.detect_injection_points()
        types = [p["node_type"] for p in points]
        assert "n8n-nodes-base.httpRequest" in types

    def test_finds_expression_nodes(self, expression_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=expression_workflow)
        points = harness.detect_injection_points()
        dynamic = [p for p in points if p["risk"] == "dynamic_expression"]
        assert len(dynamic) >= 1

    def test_returns_node_name(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        points = harness.detect_injection_points()
        names = [p["node_name"] for p in points]
        assert "Webhook Trigger" in names


# ---------------------------------------------------------------------------
# detect_sensitive_nodes
# ---------------------------------------------------------------------------


class TestDetectSensitiveNodes:
    def test_empty_workflow(self, empty_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=empty_workflow)
        assert harness.detect_sensitive_nodes() == []

    def test_finds_credential_nodes(self, credential_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=credential_workflow)
        sensitive = harness.detect_sensitive_nodes()
        assert len(sensitive) == 2

    def test_credential_reasons(self, credential_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=credential_workflow)
        sensitive = harness.detect_sensitive_nodes()
        for s in sensitive:
            assert "credential_type" in s["reasons"]
            assert "has_credentials" in s["reasons"]

    def test_finds_hardcoded_secret(self, secret_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=secret_workflow)
        sensitive = harness.detect_sensitive_nodes()
        assert len(sensitive) >= 1
        reasons_flat = [r for s in sensitive for r in s["reasons"]]
        assert "hardcoded_secret" in reasons_flat

    def test_no_false_positive_on_safe_node(self):
        wf = N8nWorkflow(nodes=[{"type": "n8n-nodes-base.set", "name": "Safe"}])
        harness = N8nHarness(workflow=wf)
        assert harness.detect_sensitive_nodes() == []


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


class TestAnalyze:
    def test_empty_analysis(self, empty_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=empty_workflow)
        result = harness.analyze()
        assert result["risk_score"] == 0.0
        assert result["total_nodes"] == 0

    def test_simple_analysis_keys(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        result = harness.analyze()
        assert "workflow_id" in result
        assert "workflow_name" in result
        assert "tool_types" in result
        assert "injection_points" in result
        assert "sensitive_nodes" in result
        assert "risk_score" in result

    def test_active_bonus(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        active_result = harness.analyze()
        simple_workflow.active = False
        inactive_result = harness.analyze()
        assert active_result["risk_score"] > inactive_result["risk_score"]

    def test_risk_score_capped_at_100(self):
        nodes = [
            {"type": "n8n-nodes-base.webhook", "name": f"W{i}",
             "credentials": {"x": {}}, "parameters": {"api_key": "sk-abcdefghij1234567890abcd"}}
            for i in range(20)
        ]
        wf = N8nWorkflow(nodes=nodes, active=True)
        harness = N8nHarness(workflow=wf)
        result = harness.analyze()
        assert result["risk_score"] <= 100.0

    def test_analysis_reflects_workflow_id(self, simple_workflow: N8nWorkflow):
        harness = N8nHarness(workflow=simple_workflow)
        result = harness.analyze()
        assert result["workflow_id"] == "wf-1"
        assert result["workflow_name"] == "Simple Webhook Flow"
