"""Tests for the blast-radius reporter and visualization."""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.blast_radius import (
    BlastRadiusAnalyzer,
    BlastRadiusReport,
    FaultInjectionResult,
    PropagationStep,
)
from aastf.harness.multi_agent import AgentEdge, AgentNode, TopologyConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agents(n: int) -> list[AgentNode]:
    """Create *n* worker agents with sequential IDs."""
    return [
        AgentNode(
            id=f"agent-{i}",
            role="worker" if i > 0 else "orchestrator",
            adapter="openai_agents",
            agent_factory="tests.fake_factory",
        )
        for i in range(n)
    ]


def _linear_topology(agents: list[AgentNode]) -> TopologyConfig:
    """A -> B -> C chain."""
    edges = [
        AgentEdge(source=agents[i].id, target=agents[i + 1].id)
        for i in range(len(agents) - 1)
    ]
    return TopologyConfig(
        name="linear",
        topology_type="hub_and_spoke",
        agents=agents,
        edges=edges,
    )


def _hub_spoke_topology() -> TopologyConfig:
    hub = AgentNode(id="hub", role="orchestrator", adapter="openai_agents", agent_factory="f")
    spokes = [
        AgentNode(id=f"spoke-{i}", role="worker", adapter="openai_agents", agent_factory="f")
        for i in range(4)
    ]
    agents = [hub, *spokes]
    edges = [AgentEdge(source="hub", target=s.id) for s in spokes]
    return TopologyConfig(name="hs", topology_type="hub_and_spoke", agents=agents, edges=edges)


# ---------------------------------------------------------------------------
# No-spread scenario
# ---------------------------------------------------------------------------


class TestNoSpread:
    """No agents affected beyond injection point."""

    def test_blast_radius_zero(self) -> None:
        agents = _make_agents(4)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="test-001",
            affected_agents=[],
            max_depth=0,
            max_breadth=0,
            severity_amplification=1.0,
            cascade_detected=False,
            verdict="safe",
        )
        analyzer = BlastRadiusAnalyzer(result, topo)
        report = analyzer.compute()

        assert report.affected_agents == 0
        assert report.blast_radius_pct == 0.0
        assert report.compound_risk_score == 0.0
        assert report.risk_level == "low"

    def test_single_agent_affected(self) -> None:
        agents = _make_agents(5)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="test-002",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
            verdict="vulnerable",
        )
        analyzer = BlastRadiusAnalyzer(result, topo)
        report = analyzer.compute()

        assert report.affected_agents == 1
        assert report.blast_radius_pct == 20.0
        assert report.injection_point == "agent-0"


# ---------------------------------------------------------------------------
# Partial spread
# ---------------------------------------------------------------------------


class TestPartialSpread:
    """Some agents contaminated, others safe."""

    def test_partial_blast_radius(self) -> None:
        agents = _make_agents(4)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="test-003",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
                PropagationStep(hop=1, source="agent-1", target="agent-2", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1", "agent-2"],
            max_depth=2,
            max_breadth=1,
            severity_amplification=1.5,
            cascade_detected=True,
            verdict="vulnerable",
        )
        analyzer = BlastRadiusAnalyzer(result, topo)
        report = analyzer.compute()

        assert report.affected_agents == 3
        assert report.blast_radius_pct == 75.0
        assert report.max_propagation_depth == 2
        assert report.propagation_breadth == 1
        assert report.injection_point == "agent-0"

    def test_per_agent_impact_correctness(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="test-004",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
            verdict="vulnerable",
        )
        analyzer = BlastRadiusAnalyzer(result, topo)
        report = analyzer.compute()

        assert report.per_agent_impact["agent-0"].affected is True
        assert report.per_agent_impact["agent-0"].severity_at_agent == "critical"
        assert report.per_agent_impact["agent-1"].affected is True
        assert report.per_agent_impact["agent-1"].hops_from_injection == 1
        assert report.per_agent_impact["agent-2"].affected is False
        assert report.per_agent_impact["agent-2"].severity_at_agent == "none"


# ---------------------------------------------------------------------------
# Full spread
# ---------------------------------------------------------------------------


class TestFullSpread:
    """All agents contaminated."""

    def test_full_blast_radius(self) -> None:
        topo = _hub_spoke_topology()
        all_ids = [a.id for a in topo.agents]
        steps = [
            PropagationStep(hop=0, source="hub", target=f"spoke-{i}", contaminated=True)
            for i in range(4)
        ]
        result = FaultInjectionResult(
            scenario_id="test-005",
            propagation=steps,
            affected_agents=all_ids,
            max_depth=1,
            max_breadth=4,
            severity_amplification=2.0,
            cascade_detected=True,
            verdict="vulnerable",
        )
        analyzer = BlastRadiusAnalyzer(result, topo)
        report = analyzer.compute()

        assert report.affected_agents == 5
        assert report.blast_radius_pct == 100.0
        assert report.propagation_breadth == 4


# ---------------------------------------------------------------------------
# Compound risk score ranges
# ---------------------------------------------------------------------------


class TestCompoundRiskScore:
    """Verify compound risk score bounds and calculation."""

    def test_zero_when_no_affected(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="t",
            affected_agents=[],
            max_depth=0,
            max_breadth=0,
        )
        report = BlastRadiusAnalyzer(result, topo).compute()
        assert report.compound_risk_score == 0.0

    def test_capped_at_100(self) -> None:
        agents = _make_agents(2)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="t",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1"],
            max_depth=50,
            max_breadth=50,
            severity_amplification=10.0,
        )
        report = BlastRadiusAnalyzer(result, topo).compute()
        assert report.compound_risk_score <= 100.0

    def test_score_increases_with_depth(self) -> None:
        agents = _make_agents(4)
        topo = _linear_topology(agents)

        r_shallow = FaultInjectionResult(
            scenario_id="t",
            propagation=[PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True)],
            affected_agents=["agent-0", "agent-1"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        r_deep = FaultInjectionResult(
            scenario_id="t",
            propagation=[PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True)],
            affected_agents=["agent-0", "agent-1"],
            max_depth=5,
            max_breadth=1,
            severity_amplification=1.0,
        )
        s1 = BlastRadiusAnalyzer(r_shallow, topo).compute().compound_risk_score
        s2 = BlastRadiusAnalyzer(r_deep, topo).compute().compound_risk_score
        assert s2 > s1


# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------


class TestRiskLevelThresholds:
    """Validate risk level categorization."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (0.0, "low"),
            (10.0, "low"),
            (24.9, "low"),
            (25.0, "medium"),
            (49.9, "medium"),
            (50.0, "high"),
            (74.9, "high"),
            (75.0, "critical"),
            (100.0, "critical"),
        ],
    )
    def test_thresholds(self, score: float, expected: str) -> None:
        assert BlastRadiusAnalyzer._risk_level(score) == expected


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------


class TestHtmlGeneration:
    """HTML output is written and contains expected elements."""

    def test_html_file_created(self, tmp_path: Path) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="html-test",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        out = tmp_path / "report.html"
        BlastRadiusAnalyzer(result, topo).to_html(out)

        assert out.exists()
        content = out.read_text(encoding="utf-8")
        assert "<svg" in content
        assert "Blast Radius Report" in content

    def test_html_contains_agent_ids(self, tmp_path: Path) -> None:
        agents = _make_agents(2)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="html-ids",
            affected_agents=["agent-0"],
            max_depth=0,
            max_breadth=0,
        )
        out = tmp_path / "sub" / "report.html"
        BlastRadiusAnalyzer(result, topo).to_html(out)

        content = out.read_text(encoding="utf-8")
        assert "agent-0" in content
        assert "agent-1" in content

    def test_html_no_external_deps(self, tmp_path: Path) -> None:
        agents = _make_agents(2)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(scenario_id="t", affected_agents=[])
        out = tmp_path / "report.html"
        BlastRadiusAnalyzer(result, topo).to_html(out)

        content = out.read_text(encoding="utf-8")
        # No external stylesheet or script references
        assert 'href="http' not in content
        assert 'src="http' not in content


# ---------------------------------------------------------------------------
# Console output
# ---------------------------------------------------------------------------


class TestConsoleOutput:
    """Console text summary format."""

    def test_console_contains_header(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="console-test",
            affected_agents=["agent-0"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        text = BlastRadiusAnalyzer(result, topo).to_console()

        assert "Blast Radius Report" in text
        assert "Injection Point" in text
        assert "Risk Level" in text

    def test_console_shows_affected_markers(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="c",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        text = BlastRadiusAnalyzer(result, topo).to_console()

        assert "[X] agent-0" in text
        assert "[X] agent-1" in text
        assert "[ ] agent-2" in text


# ---------------------------------------------------------------------------
# JSON serialization
# ---------------------------------------------------------------------------


class TestJsonSerialization:
    """to_json returns a valid, complete dict."""

    def test_json_keys(self) -> None:
        agents = _make_agents(2)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="json-test",
            affected_agents=["agent-0"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        data = BlastRadiusAnalyzer(result, topo).to_json()

        assert "injection_point" in data
        assert "total_agents" in data
        assert "affected_agents" in data
        assert "blast_radius_pct" in data
        assert "compound_risk_score" in data
        assert "risk_level" in data
        assert "propagation_graph" in data
        assert "per_agent_impact" in data

    def test_json_roundtrip(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="rt",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0", "agent-1"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        data = BlastRadiusAnalyzer(result, topo).to_json()
        # Verify it can be loaded back into the model
        report = BlastRadiusReport(**data)
        assert report.affected_agents == 2
        assert report.blast_radius_pct == 66.67


# ---------------------------------------------------------------------------
# Per-agent impact mapping
# ---------------------------------------------------------------------------


class TestPerAgentImpactMapping:
    """Detailed per-agent impact checks."""

    def test_all_agents_present(self) -> None:
        agents = _make_agents(5)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="pa",
            affected_agents=["agent-0"],
            max_depth=0,
            max_breadth=0,
        )
        report = BlastRadiusAnalyzer(result, topo).compute()
        assert len(report.per_agent_impact) == 5
        for i in range(5):
            assert f"agent-{i}" in report.per_agent_impact

    def test_severity_at_injection_point(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(
            scenario_id="sev",
            propagation=[
                PropagationStep(hop=0, source="agent-0", target="agent-1", contaminated=True),
            ],
            affected_agents=["agent-0"],
            max_depth=1,
            max_breadth=1,
            severity_amplification=1.0,
        )
        report = BlastRadiusAnalyzer(result, topo).compute()
        # agent-0 is at hop 0 (injection point) -> critical
        assert report.per_agent_impact["agent-0"].severity_at_agent == "critical"

    def test_severity_decreases_with_hops(self) -> None:
        agents = _make_agents(5)
        topo = _linear_topology(agents)
        all_ids = [a.id for a in agents]
        steps = [
            PropagationStep(hop=i, source=f"agent-{i}", target=f"agent-{i+1}", contaminated=True)
            for i in range(4)
        ]
        result = FaultInjectionResult(
            scenario_id="sev-dec",
            propagation=steps,
            affected_agents=all_ids,
            max_depth=4,
            max_breadth=1,
            severity_amplification=1.0,
        )
        report = BlastRadiusAnalyzer(result, topo).compute()

        severities = [
            report.per_agent_impact[f"agent-{i}"].severity_at_agent for i in range(5)
        ]
        # critical, high, medium, low, low
        assert severities[0] == "critical"
        assert severities[1] == "high"
        assert severities[2] == "medium"
        assert severities[3] in ("low",)
        assert severities[4] in ("low",)

    def test_roles_preserved(self) -> None:
        agents = _make_agents(3)
        topo = _linear_topology(agents)
        result = FaultInjectionResult(scenario_id="r", affected_agents=[])
        report = BlastRadiusAnalyzer(result, topo).compute()
        assert report.per_agent_impact["agent-0"].role == "orchestrator"
        assert report.per_agent_impact["agent-1"].role == "worker"
