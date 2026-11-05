"""
Fachada nativa de integración con Wazuh para Constantine Antivirus.
"""
from core.engine.wazuh_detector import WazuhDetector, WazuhRule

__all__ = ["WazuhDetector", "WazuhRule"]
