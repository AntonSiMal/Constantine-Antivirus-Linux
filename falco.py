"""
Fachada nativa de integración con Falco para Constantine Antivirus.
"""
from core.engine.falco_monitor import FalcoMonitor, FalcoRule, FalcoAlert

__all__ = ["FalcoMonitor", "FalcoRule", "FalcoAlert"]
