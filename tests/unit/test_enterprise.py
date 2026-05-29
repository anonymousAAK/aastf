"""Tests for aastf.enterprise — conformity packs, config, scenario authoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from aastf.enterprise import (
    ConformityPack,
    EnterpriseConfig,
    ScenarioAuthoringUI,
)

# ── ConformityPack ──────────────────────────────────────────────────────────

class TestConformityPack:
    def test_eu_ai_act_pack(self):
        pack = ConformityPack.for_framework("eu_ai_act")
        assert pack.framework == "eu_ai_act"
        assert len(pack.articles) > 0
        assert "scan_report" in pack.evidence_types

    def test_nist_pack(self):
        pack = ConformityPack.for_framework("nist_ai_rmf")
        assert pack.framework == "nist_ai_rmf"
        assert any("GOVERN" in a for a in pack.articles)

    def test_iso_pack(self):
        pack = ConformityPack.for_framework("iso_42001")
        assert len(pack.articles) > 0

    def test_singapore_pack(self):
        pack = ConformityPack.for_framework("singapore_imda")
        assert "governance_report" in pack.evidence_types

    def test_unknown_framework_empty(self):
        pack = ConformityPack.for_framework("unknown_framework")
        assert pack.articles == []
        assert pack.evidence_types == []

    def test_generated_at_populated(self):
        pack = ConformityPack.for_framework("eu_ai_act")
        assert pack.generated_at is not None

    def test_manual_construction(self):
        pack = ConformityPack(
            framework="custom",
            articles=["A1"],
            evidence_types=["report"],
        )
        assert pack.framework == "custom"


# ── EnterpriseConfig ────────────────────────────────────────────────────────

class TestEnterpriseConfig:
    def test_defaults(self):
        cfg = EnterpriseConfig()
        assert cfg.on_prem is False
        assert cfg.custom_scenarios_dir is None
        assert cfg.support_tier == "standard"
        assert cfg.conformity_frameworks == []

    def test_on_prem_flag(self):
        cfg = EnterpriseConfig(on_prem=True)
        assert cfg.on_prem is True

    def test_custom_scenarios_dir(self):
        cfg = EnterpriseConfig(custom_scenarios_dir=Path("/opt/scenarios"))
        assert cfg.custom_scenarios_dir == Path("/opt/scenarios")

    def test_conformity_packs_generation(self):
        cfg = EnterpriseConfig(
            conformity_frameworks=["eu_ai_act", "nist_ai_rmf"],
        )
        packs = cfg.conformity_packs()
        assert len(packs) == 2
        assert packs[0].framework == "eu_ai_act"
        assert packs[1].framework == "nist_ai_rmf"

    def test_conformity_packs_empty(self):
        cfg = EnterpriseConfig()
        assert cfg.conformity_packs() == []

    def test_support_tier_custom(self):
        cfg = EnterpriseConfig(support_tier="premium")
        assert cfg.support_tier == "premium"


# ── ScenarioAuthoringUI ────────────────────────────────────────────────────

class TestScenarioAuthoringUI:
    @pytest.fixture()
    def ui(self):
        return ScenarioAuthoringUI()

    def test_valid_yaml(self, ui):
        content = """\
id: ASI01-100
name: Test scenario
category: ASI01
severity: HIGH
description: A test.
attack:
  type: prompt_injection
  payload: "test"
evaluator:
  strategy: substring
  forbidden:
    - "bad"
"""
        errors = ui.validate_yaml(content)
        assert errors == []

    def test_missing_keys(self, ui):
        content = "id: ASI01-100\nname: test\n"
        errors = ui.validate_yaml(content)
        assert any("Missing required keys" in e for e in errors)

    def test_invalid_yaml_syntax(self, ui):
        content = ":\n  bad: [yaml\n"
        errors = ui.validate_yaml(content)
        assert any("YAML parse error" in e for e in errors)

    def test_non_mapping_top_level(self, ui):
        content = "- item1\n- item2\n"
        errors = ui.validate_yaml(content)
        assert any("mapping" in e for e in errors)

    def test_invalid_severity(self, ui):
        content = """\
id: ASI01-100
name: test
category: ASI01
severity: EXTREME
description: x
attack:
  type: x
  payload: y
evaluator:
  strategy: z
"""
        errors = ui.validate_yaml(content)
        assert any("severity" in e.lower() for e in errors)

    def test_attack_missing_type(self, ui):
        content = """\
id: ASI01-100
name: test
category: ASI01
severity: HIGH
description: x
attack:
  payload: y
evaluator:
  strategy: z
"""
        errors = ui.validate_yaml(content)
        assert any("attack.type" in e for e in errors)

    def test_evaluator_missing_strategy(self, ui):
        content = """\
id: ASI01-100
name: test
category: ASI01
severity: HIGH
description: x
attack:
  type: x
  payload: y
evaluator:
  forbidden:
    - bad
"""
        errors = ui.validate_yaml(content)
        assert any("evaluator.strategy" in e for e in errors)

    def test_preview_valid(self, ui):
        content = """\
id: ASI01-100
name: Test
category: ASI01
severity: HIGH
description: A test.
attack:
  type: prompt_injection
  payload: "test"
evaluator:
  strategy: substring
"""
        result = ui.preview(content)
        assert result["id"] == "ASI01-100"
        assert result["valid"] is True
        assert result["attack_type"] == "prompt_injection"

    def test_preview_invalid(self, ui):
        result = ui.preview("not: valid: yaml: [")
        assert "error" in result

    def test_preview_non_mapping(self, ui):
        result = ui.preview("- list\n")
        assert "error" in result

    def test_template_prompt_injection(self, ui):
        t = ui.template("prompt_injection")
        assert "ASI01" in t
        assert "prompt_injection" in t

    def test_template_tool_misuse(self, ui):
        t = ui.template("tool_misuse")
        assert "ASI02" in t

    def test_template_memory_attack(self, ui):
        t = ui.template("memory_attack")
        assert "ASI06" in t

    def test_template_default_fallback(self, ui):
        t = ui.template("unknown_category")
        assert "ASI01-NEW" in t

    def test_invalid_id_format(self, ui):
        content = """\
id: BADID
name: test
category: ASI01
severity: HIGH
description: x
attack:
  type: x
  payload: y
evaluator:
  strategy: z
"""
        errors = ui.validate_yaml(content)
        assert any("Invalid scenario ID" in e for e in errors)
