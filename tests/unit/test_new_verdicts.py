"""Tests for new MCP-specific verdict types."""
from aastf.models.result import Verdict


def test_tool_poisoning_verdict_exists():
    assert Verdict.TOOL_POISONING == "TOOL_POISONING"


def test_schema_poisoning_verdict_exists():
    assert Verdict.SCHEMA_POISONING == "SCHEMA_POISONING"


def test_preference_manipulation_verdict_exists():
    assert Verdict.PREFERENCE_MANIPULATION == "PREFERENCE_MANIPULATION"


def test_all_verdicts_are_strings():
    for v in Verdict:
        assert isinstance(v.value, str)
