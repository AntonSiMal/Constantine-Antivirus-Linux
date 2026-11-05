"""
Constantine Antivirus - Root Facade for Central Event Manager (event_manager.py)
Permite 'import event_manager' de forma directa y transparente.
"""
from core.engine.event_manager import (
    ConstantineEventManager,
    SecurityDecisionEngine,
    EventCorrelation,
    SecurityVerdict,
    SecurityAction,
    EventSource,
    EventType,
    SecurityEvent,
    PillarAnalysisResult,
    CorrelatedVerdict,
    ARCHITECTURE_RULES,
    get_default_event_manager
)

__all__ = [
    "ConstantineEventManager",
    "SecurityDecisionEngine",
    "EventCorrelation",
    "SecurityVerdict",
    "SecurityAction",
    "EventSource",
    "EventType",
    "SecurityEvent",
    "PillarAnalysisResult",
    "CorrelatedVerdict",
    "ARCHITECTURE_RULES",
    "get_default_event_manager"
]
