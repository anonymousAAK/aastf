"""Flowise chain security scanning adapter — analyses Flowise chatflow JSON for injection points."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class FlowiseChain(BaseModel):
    """Pydantic model representing a Flowise chatflow export."""

    id: str = ""
    name: str = ""
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


# Node categories that accept external input
_INPUT_CATEGORIES: set[str] = {
    "ChatModels",
    "Embeddings",
    "Memory",
    "Chains",
    "Agents",
    "Tools",
}

# Node types that typically accept user-controlled input
_INPUT_NODE_NAMES: set[str] = {
    "chatOpenAI",
    "chatAnthropic",
    "conversationChain",
    "conversationalRetrievalQAChain",
    "llmChain",
    "apiChain",
    "sqlDatabaseChain",
    "webBrowser",
    "customTool",
    "requestsGet",
    "requestsPost",
}

# Node types that hold credentials / sensitive data
_SENSITIVE_NODE_NAMES: set[str] = {
    "chatOpenAI",
    "chatAnthropic",
    "openAIEmbeddings",
    "pinecone",
    "supabase",
    "postgres",
    "mysql",
    "redis",
    "qdrant",
    "weaviate",
    "milvus",
    "apiChain",
    "sqlDatabaseChain",
}

_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{16,}", re.IGNORECASE),
    re.compile(r"(?:password|passwd|secret)\s*[:=]\s*['\"]?[^\s'\"]{8,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[\w\-\.]{20,}", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
]


class FlowiseHarness:
    """Security scanner for Flowise chatflow definitions."""

    def __init__(self, chain: FlowiseChain) -> None:
        self.chain = chain

    # -- public API ----------------------------------------------------------

    def extract_tools(self, chain: FlowiseChain | None = None) -> list[str]:
        """Return a deduplicated list of node types / names in the chatflow."""
        ch = chain or self.chain
        seen: set[str] = set()
        tools: list[str] = []
        for node in ch.nodes:
            ntype = node.get("type") or node.get("name", "")
            if ntype and ntype not in seen:
                seen.add(ntype)
                tools.append(ntype)
        return tools

    def detect_injection_points(self, chain: FlowiseChain | None = None) -> list[dict[str, Any]]:
        """Find nodes that accept user-controlled or external input."""
        ch = chain or self.chain
        points: list[dict[str, Any]] = []
        for node in ch.nodes:
            ntype = node.get("type") or node.get("name", "")
            category = node.get("category", "")
            reasons: list[str] = []

            if ntype in _INPUT_NODE_NAMES:
                reasons.append("input_node_type")
            if category in _INPUT_CATEGORIES:
                reasons.append("input_category")

            # Check for template variables in node data
            data_str = str(node.get("data", {}))
            if "{input" in data_str or "{{" in data_str or "{question" in data_str:
                reasons.append("template_variable")

            if reasons:
                points.append({
                    "node_id": node.get("id", ""),
                    "node_name": node.get("label") or node.get("name", ntype),
                    "node_type": ntype,
                    "reasons": reasons,
                })
        return points

    def detect_sensitive_nodes(self, chain: FlowiseChain | None = None) -> list[dict[str, Any]]:
        """Find nodes that use credentials or contain potential secrets."""
        ch = chain or self.chain
        sensitive: list[dict[str, Any]] = []
        for node in ch.nodes:
            ntype = node.get("type") or node.get("name", "")
            reasons: list[str] = []

            if ntype in _SENSITIVE_NODE_NAMES:
                reasons.append("credential_type")

            if node.get("credential"):
                reasons.append("has_credential")

            data_str = str(node.get("data", {}))
            for pat in _SECRET_PATTERNS:
                if pat.search(data_str):
                    reasons.append("hardcoded_secret")
                    break

            if reasons:
                sensitive.append({
                    "node_id": node.get("id", ""),
                    "node_name": node.get("label") or node.get("name", ntype),
                    "node_type": ntype,
                    "reasons": reasons,
                })
        return sensitive

    def _build_adjacency(self, chain: FlowiseChain) -> dict[str, list[str]]:
        """Build adjacency list from edges."""
        adj: dict[str, list[str]] = {}
        for edge in chain.edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src and tgt:
                adj.setdefault(src, []).append(tgt)
        return adj

    def analyze(self, chain: FlowiseChain | None = None) -> dict[str, Any]:
        """Run full security analysis and return a summary dict."""
        ch = chain or self.chain
        tools = self.extract_tools(ch)
        injection_points = self.detect_injection_points(ch)
        sensitive_nodes = self.detect_sensitive_nodes(ch)
        adjacency = self._build_adjacency(ch)

        # Check if any injection point connects to a sensitive node
        inj_ids = {p["node_id"] for p in injection_points}
        sens_ids = {s["node_id"] for s in sensitive_nodes}
        connected_risk = False
        for inj_id in inj_ids:
            for downstream in adjacency.get(inj_id, []):
                if downstream in sens_ids:
                    connected_risk = True
                    break

        risk_score = 0.0
        if injection_points:
            risk_score += min(len(injection_points) * 12.0, 40.0)
        if sensitive_nodes:
            risk_score += min(len(sensitive_nodes) * 10.0, 30.0)
        if connected_risk:
            risk_score += 20.0
        risk_score = min(risk_score, 100.0)

        return {
            "chain_id": ch.id,
            "chain_name": ch.name,
            "total_nodes": len(ch.nodes),
            "total_edges": len(ch.edges),
            "tool_types": tools,
            "injection_points": injection_points,
            "sensitive_nodes": sensitive_nodes,
            "connected_risk": connected_risk,
            "risk_score": round(risk_score, 1),
        }
