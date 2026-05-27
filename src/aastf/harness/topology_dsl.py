"""YAML topology DSL — parse multi-agent topologies from YAML definitions."""

from __future__ import annotations

from pathlib import Path

import yaml

from .multi_agent import AgentEdge, AgentNode, TopologyConfig


def parse_topology(yaml_str: str) -> TopologyConfig:
    """Parse a YAML string into a TopologyConfig."""
    data = yaml.safe_load(yaml_str)
    if not isinstance(data, dict):
        raise ValueError("Topology YAML must be a mapping at the top level")

    agents = [AgentNode(**a) for a in data.get("agents", [])]
    edges = [AgentEdge(**e) for e in data.get("edges", [])]

    return TopologyConfig(
        name=data.get("name", "unnamed_topology"),
        topology_type=data.get("topology_type", "fully_connected"),
        agents=agents,
        edges=edges,
    )


def load_topology(path: Path) -> TopologyConfig:
    """Load a topology from a YAML file on disk."""
    text = path.read_text(encoding="utf-8")
    return parse_topology(text)
