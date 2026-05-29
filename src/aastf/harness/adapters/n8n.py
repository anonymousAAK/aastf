"""n8n workflow security scanning adapter — analyses n8n workflow JSON for injection points and sensitive nodes."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class N8nWorkflow(BaseModel):
    """Pydantic model representing an n8n workflow export."""

    id: str = ""
    name: str = ""
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    connections: dict[str, Any] = Field(default_factory=dict)
    active: bool = False


# Node types that accept external / user-controlled input
_INPUT_NODE_TYPES: set[str] = {
    "n8n-nodes-base.webhook",
    "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.formTrigger",
    "n8n-nodes-base.emailReadImap",
    "n8n-nodes-base.telegramTrigger",
    "n8n-nodes-base.slackTrigger",
    "n8n-nodes-base.discordTrigger",
    "n8n-nodes-base.chatTrigger",
}

# Node types that typically hold credentials or API keys
_SENSITIVE_NODE_TYPES: set[str] = {
    "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.postgres",
    "n8n-nodes-base.mysql",
    "n8n-nodes-base.mongoDb",
    "n8n-nodes-base.redis",
    "n8n-nodes-base.aws",
    "n8n-nodes-base.openAi",
    "n8n-nodes-base.slack",
    "n8n-nodes-base.gmail",
    "n8n-nodes-base.stripe",
    "n8n-nodes-base.ssh",
    "n8n-nodes-base.ftp",
}

# Patterns that suggest hardcoded secrets in node parameters
_SECRET_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?[\w\-]{16,}", re.IGNORECASE),
    re.compile(r"(?:password|passwd|secret)\s*[:=]\s*['\"]?[^\s'\"]{8,}", re.IGNORECASE),
    re.compile(r"Bearer\s+[\w\-\.]{20,}", re.IGNORECASE),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),
]


class N8nHarness:
    """Security scanner for n8n workflow definitions."""

    def __init__(self, workflow: N8nWorkflow) -> None:
        self.workflow = workflow

    # -- public API ----------------------------------------------------------

    def extract_tools(self, workflow: N8nWorkflow | None = None) -> list[str]:
        """Return a deduplicated list of node types used in the workflow."""
        wf = workflow or self.workflow
        seen: set[str] = set()
        tools: list[str] = []
        for node in wf.nodes:
            ntype = node.get("type", "")
            if ntype and ntype not in seen:
                seen.add(ntype)
                tools.append(ntype)
        return tools

    def detect_injection_points(self, workflow: N8nWorkflow | None = None) -> list[dict[str, Any]]:
        """Find nodes that accept user-controlled input."""
        wf = workflow or self.workflow
        points: list[dict[str, Any]] = []
        for node in wf.nodes:
            ntype = node.get("type", "")
            if ntype in _INPUT_NODE_TYPES:
                points.append({
                    "node_name": node.get("name", ntype),
                    "node_type": ntype,
                    "risk": "accepts_external_input",
                    "position": node.get("position"),
                })
            # Also flag expression-based parameters that reference $input or $json
            params_str = str(node.get("parameters", {}))
            if "{{" in params_str or "$input" in params_str or "$json" in params_str:
                points.append({
                    "node_name": node.get("name", ntype),
                    "node_type": ntype,
                    "risk": "dynamic_expression",
                    "position": node.get("position"),
                })
        return points

    def detect_sensitive_nodes(self, workflow: N8nWorkflow | None = None) -> list[dict[str, Any]]:
        """Find nodes that use credentials or contain potential secrets."""
        wf = workflow or self.workflow
        sensitive: list[dict[str, Any]] = []
        for node in wf.nodes:
            ntype = node.get("type", "")
            reasons: list[str] = []

            if ntype in _SENSITIVE_NODE_TYPES:
                reasons.append("credential_type")

            if node.get("credentials"):
                reasons.append("has_credentials")

            params_str = str(node.get("parameters", {}))
            for pat in _SECRET_PATTERNS:
                if pat.search(params_str):
                    reasons.append("hardcoded_secret")
                    break

            if reasons:
                sensitive.append({
                    "node_name": node.get("name", ntype),
                    "node_type": ntype,
                    "reasons": reasons,
                    "position": node.get("position"),
                })
        return sensitive

    def analyze(self, workflow: N8nWorkflow | None = None) -> dict[str, Any]:
        """Run full security analysis and return a summary dict."""
        wf = workflow or self.workflow
        tools = self.extract_tools(wf)
        injection_points = self.detect_injection_points(wf)
        sensitive_nodes = self.detect_sensitive_nodes(wf)

        risk_score = 0.0
        if injection_points:
            risk_score += min(len(injection_points) * 15.0, 40.0)
        if sensitive_nodes:
            risk_score += min(len(sensitive_nodes) * 10.0, 30.0)
        # Bonus risk if injection feeds into sensitive node
        inj_names = {p["node_name"] for p in injection_points}
        sens_names = {s["node_name"] for s in sensitive_nodes}
        if inj_names & sens_names:
            risk_score += 20.0
        # Active workflow bonus
        if wf.active:
            risk_score += 10.0
        risk_score = min(risk_score, 100.0)

        return {
            "workflow_id": wf.id,
            "workflow_name": wf.name,
            "active": wf.active,
            "total_nodes": len(wf.nodes),
            "tool_types": tools,
            "injection_points": injection_points,
            "sensitive_nodes": sensitive_nodes,
            "risk_score": round(risk_score, 1),
        }
