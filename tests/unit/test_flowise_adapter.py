"""Tests for the Flowise chain security scanning adapter."""

from __future__ import annotations

import pytest

from aastf.harness.adapters.flowise import FlowiseChain, FlowiseHarness

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_chain() -> FlowiseChain:
    return FlowiseChain(id="ch-empty", name="Empty Chain")


@pytest.fixture()
def simple_chain() -> FlowiseChain:
    return FlowiseChain(
        id="ch-1",
        name="Simple QA Chain",
        nodes=[
            {"id": "n1", "type": "chatOpenAI", "label": "ChatOpenAI", "category": "ChatModels",
             "credential": {"openai": "key-1"}},
            {"id": "n2", "type": "conversationChain", "label": "ConversationChain", "category": "Chains"},
            {"id": "n3", "type": "bufferMemory", "label": "Buffer Memory", "category": "Memory"},
        ],
        edges=[
            {"source": "n1", "target": "n2"},
            {"source": "n3", "target": "n2"},
        ],
    )


@pytest.fixture()
def db_chain() -> FlowiseChain:
    return FlowiseChain(
        id="ch-db",
        name="SQL Chain",
        nodes=[
            {"id": "d1", "type": "sqlDatabaseChain", "label": "SQL DB Chain", "category": "Chains",
             "credential": {"postgres": "pg-1"}},
            {"id": "d2", "type": "postgres", "label": "Postgres",
             "data": {"connectionString": "postgres://user:password12345678@host/db"}},
        ],
        edges=[{"source": "d2", "target": "d1"}],
    )


@pytest.fixture()
def template_chain() -> FlowiseChain:
    return FlowiseChain(
        id="ch-tpl",
        name="Template Chain",
        nodes=[
            {"id": "t1", "type": "promptTemplate", "label": "Prompt",
             "data": {"template": "Answer the {input} question"}},
            {"id": "t2", "type": "llmChain", "label": "LLM Chain", "category": "Chains"},
        ],
        edges=[{"source": "t1", "target": "t2"}],
    )


@pytest.fixture()
def secret_chain() -> FlowiseChain:
    return FlowiseChain(
        id="ch-sec",
        name="Secret Chain",
        nodes=[
            {"id": "s1", "type": "chatOpenAI", "label": "OpenAI",
             "data": {"api_key": "sk-abcdefghij1234567890abcdefghij1234567890"}},
        ],
    )


# ---------------------------------------------------------------------------
# FlowiseChain model tests
# ---------------------------------------------------------------------------


class TestFlowiseChainModel:
    def test_default_values(self):
        ch = FlowiseChain()
        assert ch.id == ""
        assert ch.name == ""
        assert ch.nodes == []
        assert ch.edges == []

    def test_from_dict(self):
        ch = FlowiseChain(id="x", name="Test")
        assert ch.id == "x"
        assert ch.name == "Test"

    def test_nodes_and_edges(self, simple_chain: FlowiseChain):
        assert len(simple_chain.nodes) == 3
        assert len(simple_chain.edges) == 2


# ---------------------------------------------------------------------------
# extract_tools
# ---------------------------------------------------------------------------


class TestExtractTools:
    def test_empty_chain(self, empty_chain: FlowiseChain):
        harness = FlowiseHarness(chain=empty_chain)
        assert harness.extract_tools() == []

    def test_returns_unique_types(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        tools = harness.extract_tools()
        assert len(tools) == 3
        assert "chatOpenAI" in tools

    def test_deduplicates(self):
        ch = FlowiseChain(nodes=[
            {"id": "a", "type": "chatOpenAI"},
            {"id": "b", "type": "chatOpenAI"},
        ])
        harness = FlowiseHarness(chain=ch)
        assert harness.extract_tools() == ["chatOpenAI"]

    def test_falls_back_to_name(self):
        ch = FlowiseChain(nodes=[{"id": "a", "name": "customNode"}])
        harness = FlowiseHarness(chain=ch)
        assert harness.extract_tools() == ["customNode"]

    def test_accepts_explicit_chain(self, empty_chain: FlowiseChain, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=empty_chain)
        tools = harness.extract_tools(simple_chain)
        assert len(tools) == 3


# ---------------------------------------------------------------------------
# detect_injection_points
# ---------------------------------------------------------------------------


class TestDetectInjectionPoints:
    def test_empty_chain(self, empty_chain: FlowiseChain):
        harness = FlowiseHarness(chain=empty_chain)
        assert harness.detect_injection_points() == []

    def test_finds_input_node_types(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        points = harness.detect_injection_points()
        types = [p["node_type"] for p in points]
        assert "chatOpenAI" in types
        assert "conversationChain" in types

    def test_finds_input_categories(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        points = harness.detect_injection_points()
        all_reasons = [r for p in points for r in p["reasons"]]
        assert "input_category" in all_reasons

    def test_finds_template_variables(self, template_chain: FlowiseChain):
        harness = FlowiseHarness(chain=template_chain)
        points = harness.detect_injection_points()
        tpl_points = [p for p in points if "template_variable" in p["reasons"]]
        assert len(tpl_points) >= 1

    def test_returns_node_id(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        points = harness.detect_injection_points()
        assert all("node_id" in p for p in points)


# ---------------------------------------------------------------------------
# detect_sensitive_nodes
# ---------------------------------------------------------------------------


class TestDetectSensitiveNodes:
    def test_empty_chain(self, empty_chain: FlowiseChain):
        harness = FlowiseHarness(chain=empty_chain)
        assert harness.detect_sensitive_nodes() == []

    def test_finds_credential_types(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        sensitive = harness.detect_sensitive_nodes()
        assert len(sensitive) >= 1
        first = sensitive[0]
        assert "credential_type" in first["reasons"]

    def test_finds_has_credential(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        sensitive = harness.detect_sensitive_nodes()
        cred_nodes = [s for s in sensitive if "has_credential" in s["reasons"]]
        assert len(cred_nodes) >= 1

    def test_finds_hardcoded_secret(self, secret_chain: FlowiseChain):
        harness = FlowiseHarness(chain=secret_chain)
        sensitive = harness.detect_sensitive_nodes()
        reasons_flat = [r for s in sensitive for r in s["reasons"]]
        assert "hardcoded_secret" in reasons_flat

    def test_db_credentials(self, db_chain: FlowiseChain):
        harness = FlowiseHarness(chain=db_chain)
        sensitive = harness.detect_sensitive_nodes()
        assert len(sensitive) >= 1

    def test_no_false_positive_on_safe_node(self):
        ch = FlowiseChain(nodes=[{"id": "x", "type": "promptTemplate", "label": "Safe"}])
        harness = FlowiseHarness(chain=ch)
        assert harness.detect_sensitive_nodes() == []


# ---------------------------------------------------------------------------
# analyze
# ---------------------------------------------------------------------------


class TestAnalyze:
    def test_empty_analysis(self, empty_chain: FlowiseChain):
        harness = FlowiseHarness(chain=empty_chain)
        result = harness.analyze()
        assert result["risk_score"] == 0.0
        assert result["total_nodes"] == 0

    def test_analysis_keys(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        result = harness.analyze()
        expected_keys = {"chain_id", "chain_name", "total_nodes", "total_edges",
                         "tool_types", "injection_points", "sensitive_nodes",
                         "connected_risk", "risk_score"}
        assert expected_keys.issubset(result.keys())

    def test_connected_risk_detected(self, simple_chain: FlowiseChain):
        """chatOpenAI (injection + sensitive) connects to conversationChain — but the overlap itself is the key."""
        harness = FlowiseHarness(chain=simple_chain)
        result = harness.analyze()
        # n1 (chatOpenAI) is both injection point and sensitive, and connects to n2
        assert result["risk_score"] > 0

    def test_risk_score_capped_at_100(self):
        nodes = [
            {"id": f"n{i}", "type": "chatOpenAI", "category": "ChatModels",
             "credential": {"x": "y"}, "data": {"api_key": "sk-abcdefghij1234567890abcd"}}
            for i in range(20)
        ]
        edges = [{"source": f"n{i}", "target": f"n{i + 1}"} for i in range(19)]
        ch = FlowiseChain(nodes=nodes, edges=edges)
        harness = FlowiseHarness(chain=ch)
        result = harness.analyze()
        assert result["risk_score"] <= 100.0

    def test_analysis_reflects_chain_id(self, simple_chain: FlowiseChain):
        harness = FlowiseHarness(chain=simple_chain)
        result = harness.analyze()
        assert result["chain_id"] == "ch-1"
        assert result["chain_name"] == "Simple QA Chain"
