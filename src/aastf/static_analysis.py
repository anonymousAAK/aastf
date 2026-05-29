"""Static analysis companion — scans Python source for agentic security anti-patterns."""

from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .models.scenario import ASICategory, Severity

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class StaticFinding(BaseModel):
    """A single static-analysis finding."""

    file_path: str
    line_number: int
    column: int = 0
    rule_id: str
    message: str
    severity: Severity
    category: ASICategory
    fix_suggestion: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9\-_]{16,})['"]""", re.IGNORECASE),
     "Hardcoded API key detected"),
    (re.compile(r"""(?:password|passwd|secret|token)\s*[:=]\s*['"]([^\s'"]{8,})['"]""", re.IGNORECASE),
     "Hardcoded password/secret detected"),
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI API key detected"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token detected"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID detected"),
    (re.compile(r"""Bearer\s+['"]?[A-Za-z0-9\-_.]{20,}"""), "Hardcoded Bearer token detected"),
]

_UNSAFE_TOOL_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\beval\s*\("), "eval() call detected — potential code injection",
     "Use ast.literal_eval() or a sandboxed interpreter"),
    (re.compile(r"\bexec\s*\("), "exec() call detected — potential code injection",
     "Avoid exec(); use structured dispatch instead"),
    (re.compile(r"\bos\.system\s*\("), "os.system() call — potential command injection",
     "Use subprocess.run() with shell=False"),
    (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
     "subprocess with shell=True — potential command injection",
     "Use shell=False and pass args as a list"),
    (re.compile(r"pickle\.loads?\s*\("), "pickle.load/loads — potential deserialization attack",
     "Use json or a safe serializer instead of pickle"),
    (re.compile(r"yaml\.(?:load|unsafe_load)\s*\((?![^)]*Loader)"),
     "yaml.load without SafeLoader — potential code execution",
     "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"),
    (re.compile(r"__import__\s*\("), "Dynamic import via __import__() — potential supply chain risk",
     "Use importlib with validated module names"),
]

_MISSING_AUTH_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"@app\.(?:route|get|post|put|delete|patch)\s*\((?!.*auth)(?!.*login)(?!.*public)", re.IGNORECASE),
     "HTTP endpoint without apparent authentication",
     "Add authentication middleware or decorator"),
    (re.compile(r"\.run\(\s*(?:host\s*=\s*['\"]0\.0\.0\.0|debug\s*=\s*True)"),
     "Server binding to 0.0.0.0 or debug=True in production",
     "Bind to 127.0.0.1 and disable debug in production"),
    (re.compile(r"CORS\(\s*app\s*(?:,\s*resources\s*=\s*['\"]\/\*)?(?:\s*\)|\s*,\s*origins\s*=\s*['\"]?\*)"),
     "Overly permissive CORS configuration",
     "Restrict CORS origins to specific domains"),
]

_MCP_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"(?:mcp|McpServer|MCPServer)\s*\("),
     "MCP server instantiation — verify tool sandboxing",
     "Ensure all MCP tools are sandboxed and validated"),
    (re.compile(r"tool_description\s*=\s*.*(?:\bsudo\b|\broot\b|\badmin\b)", re.IGNORECASE),
     "MCP tool with privileged description — potential tool poisoning",
     "Remove privilege-escalation keywords from tool descriptions"),
    (re.compile(r"server\.add_tool\s*\(|@server\.tool"),
     "MCP tool registration — verify input validation",
     "Add input schema validation to MCP tool handlers"),
]


# ---------------------------------------------------------------------------
# StaticAnalyzer
# ---------------------------------------------------------------------------


class StaticAnalyzer:
    """Scans Python source files for agentic security anti-patterns."""

    def scan_file(self, path: Path) -> list[StaticFinding]:
        """Scan a single Python file and return findings."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        path_str = str(path)
        findings: list[StaticFinding] = []
        findings.extend(self.detect_hardcoded_secrets(content, path_str))
        findings.extend(self.detect_unsafe_tool_calls(content, path_str))
        findings.extend(self.detect_missing_auth(content, path_str))
        findings.extend(self.detect_mcp_servers(content, path_str))
        return findings

    def scan_directory(self, path: Path, patterns: list[str] | None = None) -> list[StaticFinding]:
        """Recursively scan a directory for Python files matching glob patterns."""
        if patterns is None:
            patterns = ["**/*.py"]
        findings: list[StaticFinding] = []
        for pat in patterns:
            for fpath in path.glob(pat):
                if fpath.is_file():
                    findings.extend(self.scan_file(fpath))
        return findings

    def detect_hardcoded_secrets(self, content: str, path: str) -> list[StaticFinding]:
        """Detect hardcoded API keys, passwords, and tokens."""
        findings: list[StaticFinding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat, msg in _SECRET_PATTERNS:
                match = pat.search(line)
                if match:
                    findings.append(StaticFinding(
                        file_path=path,
                        line_number=line_num,
                        column=match.start(),
                        rule_id="SEC001",
                        message=msg,
                        severity=Severity.CRITICAL,
                        category=ASICategory.ASI04,
                        fix_suggestion="Move secrets to environment variables or a secrets manager",
                    ))
        return findings

    def detect_unsafe_tool_calls(self, content: str, path: str) -> list[StaticFinding]:
        """Detect eval(), exec(), os.system() and other dangerous calls."""
        findings: list[StaticFinding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat, msg, fix in _UNSAFE_TOOL_PATTERNS:
                match = pat.search(line)
                if match:
                    findings.append(StaticFinding(
                        file_path=path,
                        line_number=line_num,
                        column=match.start(),
                        rule_id="SEC002",
                        message=msg,
                        severity=Severity.HIGH,
                        category=ASICategory.ASI05,
                        fix_suggestion=fix,
                    ))
        return findings

    def detect_missing_auth(self, content: str, path: str) -> list[StaticFinding]:
        """Detect HTTP endpoints without authentication and insecure server config."""
        findings: list[StaticFinding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat, msg, fix in _MISSING_AUTH_PATTERNS:
                match = pat.search(line)
                if match:
                    findings.append(StaticFinding(
                        file_path=path,
                        line_number=line_num,
                        column=match.start(),
                        rule_id="SEC003",
                        message=msg,
                        severity=Severity.MEDIUM,
                        category=ASICategory.ASI03,
                        fix_suggestion=fix,
                    ))
        return findings

    def detect_mcp_servers(self, content: str, path: str) -> list[StaticFinding]:
        """Detect MCP server patterns and verify tool sandboxing."""
        findings: list[StaticFinding] = []
        for line_num, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pat, msg, fix in _MCP_PATTERNS:
                match = pat.search(line)
                if match:
                    findings.append(StaticFinding(
                        file_path=path,
                        line_number=line_num,
                        column=match.start(),
                        rule_id="SEC004",
                        message=msg,
                        severity=Severity.MEDIUM,
                        category=ASICategory.ASI02,
                        fix_suggestion=fix,
                    ))
        return findings


# ---------------------------------------------------------------------------
# WorkflowVisualizer
# ---------------------------------------------------------------------------


class WorkflowVisualizer:
    """Renders node/edge graphs as SVG or Mermaid diagrams."""

    def render_topology(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
        """Render an SVG graph from nodes and edges.

        Each node dict should have at minimum 'id' and optionally 'label'.
        Each edge dict should have 'source' and 'target'.
        """
        if not nodes:
            return '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="50"><text x="10" y="30">No nodes</text></svg>'

        node_ids = [n.get("id", f"n{i}") for i, n in enumerate(nodes)]
        node_labels = [html.escape(str(n.get("label", n.get("id", f"n{i}")))) for i, n in enumerate(nodes)]

        # Layout: simple horizontal placement
        spacing_x = 200
        y_center = 100
        radius = 40
        width = max(spacing_x * len(nodes), 400)
        height = 250

        parts: list[str] = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        ]
        parts.append('<defs><marker id="arrow" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">'
                     '<polygon points="0 0, 10 3.5, 0 7" fill="#333"/></marker></defs>')

        # Positions
        positions: dict[str, tuple[int, int]] = {}
        for i, nid in enumerate(node_ids):
            x = spacing_x // 2 + i * spacing_x
            positions[nid] = (x, y_center)

        # Draw edges
        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            if src in positions and tgt in positions:
                x1, y1 = positions[src]
                x2, y2 = positions[tgt]
                parts.append(
                    f'<line x1="{x1 + radius}" y1="{y1}" x2="{x2 - radius}" y2="{y2}" '
                    f'stroke="#333" stroke-width="2" marker-end="url(#arrow)"/>'
                )

        # Draw nodes
        for i, nid in enumerate(node_ids):
            x, y = positions[nid]
            parts.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="#4A90D9" stroke="#333" stroke-width="2"/>')
            parts.append(f'<text x="{x}" y="{y + 5}" text-anchor="middle" fill="white" font-size="12">'
                         f'{node_labels[i]}</text>')

        parts.append("</svg>")
        return "\n".join(parts)

    def render_mermaid(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> str:
        """Render a Mermaid flowchart diagram from nodes and edges."""
        lines: list[str] = ["graph LR"]

        for i, node in enumerate(nodes):
            nid = node.get("id", f"n{i}")
            label = node.get("label", node.get("id", f"n{i}"))
            lines.append(f"    {nid}[{label}]")

        for edge in edges:
            src = edge.get("source", "")
            tgt = edge.get("target", "")
            edge_label = edge.get("label", "")
            if src and tgt:
                if edge_label:
                    lines.append(f"    {src} -->|{edge_label}| {tgt}")
                else:
                    lines.append(f"    {src} --> {tgt}")

        return "\n".join(lines)
