"""
Fachada pública de integración con ClamAV para Constantine Antivirus.
"""
from core.engine.clamav_manager import ClamAVManager, ClamdBridgeClient

__all__ = ["ClamAVManager", "ClamdBridgeClient"]
