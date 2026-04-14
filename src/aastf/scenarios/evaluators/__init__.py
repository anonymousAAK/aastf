"""Evaluator registry — maps ASI categories to evaluator instances."""

from __future__ import annotations

from ...models.scenario import ASICategory
from .base import AbstractEvaluator
from .cascading import CascadingFailureEvaluator
from .goal_hijack import GoalHijackEvaluator
from .inter_agent import InterAgentEvaluator
from .memory_poisoning import MemoryPoisoningEvaluator
from .privilege_escalation import PrivilegeEscalationEvaluator
from .rce import RCEEvaluator
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


def get_evaluator(category: ASICategory) -> AbstractEvaluator | None:
    return _REGISTRY.get(category)


def all_categories_covered() -> bool:
    return all(cat in _REGISTRY for cat in ASICategory)
