"""
Fachada nativa de integración con Sigma para Constantine Antivirus.
"""
from core.engine.sigma_engine import SigmaEngine, SigmaRule, SigmaMatch

__all__ = ["SigmaEngine", "SigmaRule", "SigmaMatch"]
