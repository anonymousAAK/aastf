"""Tests for the static analysis companion module."""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.models.scenario import ASICategory, Severity
from aastf.static_analysis import StaticAnalyzer, StaticFinding, WorkflowVisualizer

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer()


@pytest.fixture()
def visualizer() -> WorkflowVisualizer:
    return WorkflowVisualizer()


# ---------------------------------------------------------------------------
# StaticFinding model
# ---------------------------------------------------------------------------


class TestStaticFindingModel:
    def test_basic_creation(self):
        f = StaticFinding(
            file_path="test.py",
            line_number=10,
            column=5,
            rule_id="SEC001",
            message="Test finding",
            severity=Severity.HIGH,
            category=ASICategory.ASI01,
        )
        assert f.file_path == "test.py"
        assert f.line_number == 10
        assert f.fix_suggestion is None

    def test_with_fix_suggestion(self):
        f = StaticFinding(
            file_path="test.py",
            line_number=1,
            rule_id="SEC001",
            message="Test",
            severity=Severity.LOW,
            category=ASICategory.ASI01,
            fix_suggestion="Fix this",
        )
        assert f.fix_suggestion == "Fix this"

    def test_timestamp_set(self):
        f = StaticFinding(
            file_path="test.py",
            line_number=1,
            rule_id="SEC001",
            message="Test",
            severity=Severity.LOW,
            category=ASICategory.ASI01,
        )
        assert f.timestamp is not None

    def test_default_column(self):
        f = StaticFinding(
            file_path="test.py",
            line_number=1,
            rule_id="SEC001",
            message="Test",
            severity=Severity.LOW,
            category=ASICategory.ASI01,
        )
        assert f.column == 0


# ---------------------------------------------------------------------------
# detect_hardcoded_secrets
# ---------------------------------------------------------------------------


class TestDetectHardcodedSecrets:
    def test_finds_api_key(self, analyzer: StaticAnalyzer):
        code = 'api_key = "ABCDEFGHIJKLMNOP1234"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].rule_id == "SEC001"
        assert findings[0].severity == Severity.CRITICAL

    def test_finds_openai_key(self, analyzer: StaticAnalyzer):
        code = 'key = "sk-abcdefghijklmnopqrstuvwxyz"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1

    def test_finds_github_token(self, analyzer: StaticAnalyzer):
        code = 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1

    def test_finds_aws_key(self, analyzer: StaticAnalyzer):
        code = 'key = "AKIAIOSFODNN7EXAMPLE"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1

    def test_skips_comments(self, analyzer: StaticAnalyzer):
        code = '# api_key = "ABCDEFGHIJKLMNOP1234"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) == 0

    def test_no_false_positive_on_short_value(self, analyzer: StaticAnalyzer):
        code = 'api_key = "short"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) == 0

    def test_category_is_asi04(self, analyzer: StaticAnalyzer):
        code = 'password = "supersecretpassword123"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].category == ASICategory.ASI04

    def test_fix_suggestion_present(self, analyzer: StaticAnalyzer):
        code = 'secret = "mysecretvalue123456"'
        findings = analyzer.detect_hardcoded_secrets(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].fix_suggestion is not None


# ---------------------------------------------------------------------------
# detect_unsafe_tool_calls
# ---------------------------------------------------------------------------


class TestDetectUnsafeToolCalls:
    def test_finds_eval(self, analyzer: StaticAnalyzer):
        code = 'result = eval(user_input)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1
        assert "eval" in findings[0].message

    def test_finds_exec(self, analyzer: StaticAnalyzer):
        code = 'exec(code_string)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_finds_os_system(self, analyzer: StaticAnalyzer):
        code = 'os.system("rm -rf /")'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_finds_subprocess_shell(self, analyzer: StaticAnalyzer):
        code = 'subprocess.run(cmd, shell=True)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_finds_pickle(self, analyzer: StaticAnalyzer):
        code = 'data = pickle.loads(payload)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_finds_yaml_unsafe_load(self, analyzer: StaticAnalyzer):
        code = 'data = yaml.load(text)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_finds_dunder_import(self, analyzer: StaticAnalyzer):
        code = 'mod = __import__(module_name)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) >= 1

    def test_severity_is_high(self, analyzer: StaticAnalyzer):
        code = 'eval(x)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert findings[0].severity == Severity.HIGH

    def test_category_is_asi05(self, analyzer: StaticAnalyzer):
        code = 'exec(x)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert findings[0].category == ASICategory.ASI05

    def test_skips_comments(self, analyzer: StaticAnalyzer):
        code = '# eval(user_input)'
        findings = analyzer.detect_unsafe_tool_calls(code, "test.py")
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# detect_missing_auth
# ---------------------------------------------------------------------------


class TestDetectMissingAuth:
    def test_finds_unauthed_route(self, analyzer: StaticAnalyzer):
        code = '@app.route("/data")'
        findings = analyzer.detect_missing_auth(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].rule_id == "SEC003"

    def test_finds_debug_mode(self, analyzer: StaticAnalyzer):
        code = 'app.run(debug=True)'
        findings = analyzer.detect_missing_auth(code, "test.py")
        assert len(findings) >= 1

    def test_severity_is_medium(self, analyzer: StaticAnalyzer):
        code = '@app.get("/items")'
        findings = analyzer.detect_missing_auth(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].severity == Severity.MEDIUM

    def test_category_is_asi03(self, analyzer: StaticAnalyzer):
        code = '@app.post("/submit")'
        findings = analyzer.detect_missing_auth(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].category == ASICategory.ASI03


# ---------------------------------------------------------------------------
# detect_mcp_servers
# ---------------------------------------------------------------------------


class TestDetectMCPServers:
    def test_finds_mcp_server_instantiation(self, analyzer: StaticAnalyzer):
        code = 'server = McpServer("tools")'
        findings = analyzer.detect_mcp_servers(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].rule_id == "SEC004"

    def test_finds_tool_registration(self, analyzer: StaticAnalyzer):
        code = 'server.add_tool(my_tool)'
        findings = analyzer.detect_mcp_servers(code, "test.py")
        assert len(findings) >= 1

    def test_finds_tool_decorator(self, analyzer: StaticAnalyzer):
        code = '@server.tool\ndef my_tool(): pass'
        findings = analyzer.detect_mcp_servers(code, "test.py")
        assert len(findings) >= 1

    def test_category_is_asi02(self, analyzer: StaticAnalyzer):
        code = 'server = MCPServer()'
        findings = analyzer.detect_mcp_servers(code, "test.py")
        assert len(findings) >= 1
        assert findings[0].category == ASICategory.ASI02


# ---------------------------------------------------------------------------
# scan_file
# ---------------------------------------------------------------------------


class TestScanFile:
    def test_scan_nonexistent_file(self, analyzer: StaticAnalyzer, tmp_path: Path):
        findings = analyzer.scan_file(tmp_path / "nope.py")
        assert findings == []

    def test_scan_clean_file(self, analyzer: StaticAnalyzer, tmp_path: Path):
        f = tmp_path / "clean.py"
        f.write_text("x = 1\ny = 2\n", encoding="utf-8")
        findings = analyzer.scan_file(f)
        assert findings == []

    def test_scan_file_with_findings(self, analyzer: StaticAnalyzer, tmp_path: Path):
        f = tmp_path / "bad.py"
        f.write_text('api_key = "ABCDEFGHIJKLMNOP1234"\nresult = eval(x)\n', encoding="utf-8")
        findings = analyzer.scan_file(f)
        assert len(findings) >= 2


# ---------------------------------------------------------------------------
# scan_directory
# ---------------------------------------------------------------------------


class TestScanDirectory:
    def test_scan_empty_directory(self, analyzer: StaticAnalyzer, tmp_path: Path):
        findings = analyzer.scan_directory(tmp_path)
        assert findings == []

    def test_scan_directory_with_files(self, analyzer: StaticAnalyzer, tmp_path: Path):
        (tmp_path / "a.py").write_text('eval(x)\n', encoding="utf-8")
        (tmp_path / "b.py").write_text('exec(y)\n', encoding="utf-8")
        findings = analyzer.scan_directory(tmp_path)
        assert len(findings) >= 2

    def test_scan_directory_custom_patterns(self, analyzer: StaticAnalyzer, tmp_path: Path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "code.py").write_text('eval(x)\n', encoding="utf-8")
        (tmp_path / "top.py").write_text('exec(y)\n', encoding="utf-8")
        findings = analyzer.scan_directory(tmp_path, patterns=["sub/*.py"])
        assert len(findings) >= 1
        assert all("sub" in f.file_path for f in findings)


# ---------------------------------------------------------------------------
# WorkflowVisualizer — render_topology (SVG)
# ---------------------------------------------------------------------------


class TestRenderTopology:
    def test_empty_nodes(self, visualizer: WorkflowVisualizer):
        svg = visualizer.render_topology([], [])
        assert "<svg" in svg
        assert "No nodes" in svg

    def test_single_node(self, visualizer: WorkflowVisualizer):
        svg = visualizer.render_topology([{"id": "a", "label": "Node A"}], [])
        assert "<svg" in svg
        assert "<circle" in svg
        assert "Node A" in svg

    def test_edge_renders_line(self, visualizer: WorkflowVisualizer):
        nodes = [{"id": "a", "label": "A"}, {"id": "b", "label": "B"}]
        edges = [{"source": "a", "target": "b"}]
        svg = visualizer.render_topology(nodes, edges)
        assert "<line" in svg

    def test_html_escaping(self, visualizer: WorkflowVisualizer):
        nodes = [{"id": "a", "label": "<script>alert(1)</script>"}]
        svg = visualizer.render_topology(nodes, [])
        assert "<script>" not in svg
        assert "&lt;script&gt;" in svg


# ---------------------------------------------------------------------------
# WorkflowVisualizer — render_mermaid
# ---------------------------------------------------------------------------


class TestRenderMermaid:
    def test_empty_graph(self, visualizer: WorkflowVisualizer):
        md = visualizer.render_mermaid([], [])
        assert md.startswith("graph LR")

    def test_nodes_rendered(self, visualizer: WorkflowVisualizer):
        nodes = [{"id": "a", "label": "Alpha"}, {"id": "b", "label": "Beta"}]
        md = visualizer.render_mermaid(nodes, [])
        assert "a[Alpha]" in md
        assert "b[Beta]" in md

    def test_edges_rendered(self, visualizer: WorkflowVisualizer):
        nodes = [{"id": "a"}, {"id": "b"}]
        edges = [{"source": "a", "target": "b"}]
        md = visualizer.render_mermaid(nodes, edges)
        assert "a --> b" in md

    def test_labeled_edges(self, visualizer: WorkflowVisualizer):
        nodes = [{"id": "a"}, {"id": "b"}]
        edges = [{"source": "a", "target": "b", "label": "feeds"}]
        md = visualizer.render_mermaid(nodes, edges)
        assert "a -->|feeds| b" in md
