"""
Fachada nativa de integración con MISP para Constantine Antivirus.
"""
from core.engine.misp_feed_manager import MISPFeedManager
from core.engine.threat_intel import ThreatIntelligence

__all__ = ["MISPFeedManager", "ThreatIntelligence"]
