"""Tests for multi-agent topology DSL parsing and validation.

The topology DSL allows users to define agent communication graphs
via YAML. Supported topology types: hub_and_spoke, ring,
fully_connected, hierarchical.

Expected module: src/aastf/models/topology.py
"""

from __future__ import annotations

import pytest
import yaml

topology = pytest.importorskip(
    "aastf.models.topology",
    reason="aastf.models.topology not yet implemented (parallel agent)",
)
from aastf.models.topology import (  # noqa: E402
    TopologyType,
    parse_topology_yaml,
)

# ------------------------------------------------------------------ fixtures


def _hub_spoke_yaml() -> str:
    return yaml.dump({
        "topology": {
            "type": "hub_and_spoke",
            "agents": [
                {"id": "orchestrator", "role": "coordinator"},
                {"id": "worker_a", "role": "researcher"},
                {"id": "worker_b", "role": "writer"},
            ],
            "edges": [
                {"from": "orchestrator", "to": "worker_a"},
                {"from": "orchestrator", "to": "worker_b"},
            ],
        }
    })


def _ring_yaml() -> str:
    return yaml.dump({
        "topology": {
            "type": "ring",
            "agents": [
                {"id": "agent_1", "role": "planner"},
                {"id": "agent_2", "role": "executor"},
                {"id": "agent_3", "role": "reviewer"},
            ],
            "edges": [
                {"from": "agent_1", "to": "agent_2"},
                {"from": "agent_2", "to": "agent_3"},
                {"from": "agent_3", "to": "agent_1"},
            ],
        }
    })


def _fully_connected_yaml() -> str:
    return yaml.dump({
        "topology": {
            "type": "fully_connected",
            "agents": [
                {"id": "a", "role": "peer"},
                {"id": "b", "role": "peer"},
                {"id": "c", "role": "peer"},
            ],
            "edges": [
                {"from": "a", "to": "b"},
                {"from": "a", "to": "c"},
                {"from": "b", "to": "a"},
                {"from": "b", "to": "c"},
                {"from": "c", "to": "a"},
                {"from": "c", "to": "b"},
            ],
        }
    })


def _hierarchical_yaml() -> str:
    return yaml.dump({
        "topology": {
            "type": "hierarchical",
            "agents": [
                {"id": "root", "role": "supervisor"},
                {"id": "mid_a", "role": "team_lead"},
                {"id": "mid_b", "role": "team_lead"},
                {"id": "leaf_1", "role": "worker"},
                {"id": "leaf_2", "role": "worker"},
            ],
            "edges": [
                {"from": "root", "to": "mid_a"},
                {"from": "root", "to": "mid_b"},
                {"from": "mid_a", "to": "leaf_1"},
                {"from": "mid_b", "to": "leaf_2"},
            ],
        }
    })


# ------------------------------------------------------------------ happy-path


class TestParseValidTopologies:
    def test_hub_and_spoke(self):
        config = parse_topology_yaml(_hub_spoke_yaml())
        assert config.type == TopologyType.HUB_AND_SPOKE
        assert len(config.agents) == 3
        assert len(config.edges) == 2
        ids = {a.id for a in config.agents}
        assert ids == {"orchestrator", "worker_a", "worker_b"}

    def test_ring(self):
        config = parse_topology_yaml(_ring_yaml())
        assert config.type == TopologyType.RING
        assert len(config.agents) == 3
        assert len(config.edges) == 3
        # Ring: every agent appears exactly once as source and once as target
        sources = [e.from_agent for e in config.edges]
        targets = [e.to_agent for e in config.edges]
        assert sorted(sources) == sorted(targets)

    def test_fully_connected(self):
        config = parse_topology_yaml(_fully_connected_yaml())
        assert config.type == TopologyType.FULLY_CONNECTED
        assert len(config.agents) == 3
        # 3 agents fully connected = 3 * 2 = 6 edges
        assert len(config.edges) == 6

    def test_hierarchical(self):
        config = parse_topology_yaml(_hierarchical_yaml())
        assert config.type == TopologyType.HIERARCHICAL
        assert len(config.agents) == 5
        assert len(config.edges) == 4

    def test_agent_node_properties(self):
        config = parse_topology_yaml(_hub_spoke_yaml())
        orchestrator = next(a for a in config.agents if a.id == "orchestrator")
        assert orchestrator.role == "coordinator"

    def test_edge_properties(self):
        config = parse_topology_yaml(_hub_spoke_yaml())
        edge = config.edges[0]
        assert hasattr(edge, "from_agent")
        assert hasattr(edge, "to_agent")


# ------------------------------------------------------------------ rejection / validation


class TestRejectInvalidTopologies:
    def test_missing_type_field(self):
        bad_yaml = yaml.dump({
            "topology": {
                "agents": [{"id": "a", "role": "worker"}],
                "edges": [],
            }
        })
        with pytest.raises((ValueError, KeyError)):
            parse_topology_yaml(bad_yaml)

    def test_missing_agents_field(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "ring",
                "edges": [],
            }
        })
        with pytest.raises((ValueError, KeyError)):
            parse_topology_yaml(bad_yaml)

    def test_missing_edges_field(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "ring",
                "agents": [{"id": "a", "role": "worker"}],
            }
        })
        with pytest.raises((ValueError, KeyError)):
            parse_topology_yaml(bad_yaml)

    def test_agent_missing_id(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "ring",
                "agents": [{"role": "worker"}],
                "edges": [],
            }
        })
        with pytest.raises((ValueError, KeyError)):
            parse_topology_yaml(bad_yaml)

    def test_invalid_topology_type(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "star_mesh_quantum",
                "agents": [{"id": "a", "role": "worker"}],
                "edges": [],
            }
        })
        with pytest.raises(ValueError):
            parse_topology_yaml(bad_yaml)

    def test_duplicate_agent_ids(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "hub_and_spoke",
                "agents": [
                    {"id": "agent_x", "role": "worker"},
                    {"id": "agent_x", "role": "manager"},
                ],
                "edges": [],
            }
        })
        with pytest.raises(ValueError, match="[Dd]uplicate"):
            parse_topology_yaml(bad_yaml)

    def test_edge_references_nonexistent_source(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "hub_and_spoke",
                "agents": [
                    {"id": "a", "role": "worker"},
                    {"id": "b", "role": "worker"},
                ],
                "edges": [
                    {"from": "ghost", "to": "a"},
                ],
            }
        })
        with pytest.raises(ValueError, match="ghost"):
            parse_topology_yaml(bad_yaml)

    def test_edge_references_nonexistent_target(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "hub_and_spoke",
                "agents": [
                    {"id": "a", "role": "worker"},
                    {"id": "b", "role": "worker"},
                ],
                "edges": [
                    {"from": "a", "to": "phantom"},
                ],
            }
        })
        with pytest.raises(ValueError, match="phantom"):
            parse_topology_yaml(bad_yaml)

    def test_self_edges_rejected(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "ring",
                "agents": [
                    {"id": "a", "role": "worker"},
                    {"id": "b", "role": "worker"},
                ],
                "edges": [
                    {"from": "a", "to": "a"},
                ],
            }
        })
        with pytest.raises(ValueError, match="[Ss]elf"):
            parse_topology_yaml(bad_yaml)

    def test_empty_agents_list(self):
        bad_yaml = yaml.dump({
            "topology": {
                "type": "ring",
                "agents": [],
                "edges": [],
            }
        })
        with pytest.raises(ValueError):
            parse_topology_yaml(bad_yaml)


# ------------------------------------------------------------------ round-trip


class TestRoundTrip:
    def test_config_to_yaml_to_config(self):
        """Parse YAML, serialize back to YAML, re-parse -- should be identical."""
        original = parse_topology_yaml(_hub_spoke_yaml())

        # Serialize back to a dict matching the expected YAML structure
        serialized = {
            "topology": {
                "type": original.type.value,
                "agents": [
                    {"id": a.id, "role": a.role} for a in original.agents
                ],
                "edges": [
                    {"from": e.from_agent, "to": e.to_agent}
                    for e in original.edges
                ],
            }
        }
        roundtripped = parse_topology_yaml(yaml.dump(serialized))

        assert roundtripped.type == original.type
        assert len(roundtripped.agents) == len(original.agents)
        assert len(roundtripped.edges) == len(original.edges)
        assert {a.id for a in roundtripped.agents} == {a.id for a in original.agents}
        for orig_edge, rt_edge in zip(original.edges, roundtripped.edges, strict=True):
            assert orig_edge.from_agent == rt_edge.from_agent
            assert orig_edge.to_agent == rt_edge.to_agent

    def test_all_topology_types_round_trip(self):
        """Every supported topology type should survive a round-trip."""
        yamls = [
            _hub_spoke_yaml(),
            _ring_yaml(),
            _fully_connected_yaml(),
            _hierarchical_yaml(),
        ]
        for src in yamls:
            original = parse_topology_yaml(src)
            serialized = {
                "topology": {
                    "type": original.type.value,
                    "agents": [
                        {"id": a.id, "role": a.role} for a in original.agents
                    ],
                    "edges": [
                        {"from": e.from_agent, "to": e.to_agent}
                        for e in original.edges
                    ],
                }
            }
            roundtripped = parse_topology_yaml(yaml.dump(serialized))
            assert roundtripped.type == original.type
            assert {a.id for a in roundtripped.agents} == {a.id for a in original.agents}
