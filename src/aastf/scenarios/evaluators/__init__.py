"""Evaluator registry — maps ASI categories to evaluator instances."""

from __future__ import annotations

from ...models.scenario import ASICategory
from .base import AbstractEvaluator
from .cascading import CascadingFailureEvaluator
from .composite import _CompositeEvaluator
from .goal_hijack import GoalHijackEvaluator
from .inter_agent import InterAgentEvaluator
from .mcp import MCPEvaluator as MCPEvaluator
from .memory_poisoning import MemoryPoisoningEvaluator
from .multi_agent import MultiAgentEvaluator
from .privilege_escalation import PrivilegeEscalationEvaluator
from .rce import RCEEvaluator
from .refusal_detector import (
    RefusalDetector as RefusalDetector,
)
from .refusal_detector import (
    classify_with_refusal_check as classify_with_refusal_check,
)
from .refusal_detector import (
    default_refusal_detector as default_refusal_detector,
)
from .rogue_agent import RogueAgentEvaluator
from .supply_chain import SupplyChainEvaluator
from .tool_misuse import ToolMisuseEvaluator
from .trust_exploit import TrustExploitEvaluator

_REGISTRY: dict[ASICategory, AbstractEvaluator] = {
    ASICategory.ASI01: GoalHijackEvaluator(),
    ASICategory.ASI02: ToolMisuseEvaluator(),
    ASICategory.ASI03: PrivilegeEscalationEvaluator(),
    ASICategory.ASI04: SupplyChainEvaluator(),
    ASICategory.ASI05: RCEEvaluator(),
    ASICategory.ASI06: MemoryPoisoningEvaluator(),
    ASICategory.ASI07: InterAgentEvaluator(),
    ASICategory.ASI08: CascadingFailureEvaluator(),
    ASICategory.ASI09: TrustExploitEvaluator(),
    ASICategory.ASI10: RogueAgentEvaluator(),
}


# Specialised evaluators selected by scenario-ID prefix rather than ASI category
# (MCP / multi-agent scenarios declare an ASI category for taxonomy purposes but
# need their own detection on top). Each is composed with the category evaluator
# so the baseline checks always run and routing here never loses detection.
_mcp_evaluator = MCPEvaluator()
_multi_agent_evaluator = MultiAgentEvaluator()


def get_evaluator(category: ASICategory) -> AbstractEvaluator | None:
    """Return the base evaluator registered for an ASI category."""
    return _REGISTRY.get(category)


def get_evaluator_for(scenario) -> AbstractEvaluator | None:
    """Select an evaluator for a scenario.

    MCP scenarios use the MCP evaluator (tool/schema poisoning) and MAS/A2A
    scenarios use the multi-agent evaluator (propagation/collusion/watchdog),
    each falling back to the ASI-category evaluator when no specialised pattern
    fires. All other scenarios route by category.
    """
    base = _REGISTRY.get(scenario.category)
    sid = str(scenario.id).upper()
    if sid.startswith("MCP"):
        return _CompositeEvaluator(_mcp_evaluator, base)
    if sid.startswith(("MAS", "A2A")):
        return _CompositeEvaluator(_multi_agent_evaluator, base)
    return base


def all_categories_covered() -> bool:
    return all(cat in _REGISTRY for cat in ASICategory)
