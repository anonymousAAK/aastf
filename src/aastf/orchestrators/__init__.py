"""Multi-turn attack orchestrators for automated escalation strategies."""

from __future__ import annotations

from .base import BaseOrchestrator, OrchestrationResult, Turn
from .crescendo import CrescendoOrchestrator
from .pair import PAIROrchestrator
from .tap import TAPOrchestrator

__all__ = [
    "BaseOrchestrator",
    "CrescendoOrchestrator",
    "OrchestrationResult",
    "PAIROrchestrator",
    "TAPOrchestrator",
    "Turn",
]
