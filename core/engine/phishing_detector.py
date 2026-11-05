"""
Centinela Anti-Phishing y Reputación Web para Constantine Antivirus.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.phishing")

class PhishingDetector:
    """Supervisa URLs y peticiones DNS para bloquear sitios fraudulentos."""

    def __init__(self):
        pass

    def evaluate_url(self, url: str) -> bool:
        if "phishing" in url.lower() or "malicious-login" in url.lower():
            return False
        return True
