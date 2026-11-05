"""
Registro de Salud y Estado Operativo de Subsistemas para Constantine Antivirus.
"""
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.health")

class SubsystemHealthRegistry:
    """Registra y audita el estado operativo en tiempo real de todos los componentes."""

    def __init__(self):
        self.subsystems: Dict[str, Dict[str, Any]] = {}

    def register(self, name: str, status: str = "ACTIVE", details: str = ""):
        self.subsystems[name] = {"status": status, "details": details}

    def get_overall_posture(self) -> Dict[str, Any]:
        has_error = any(s["status"] == "ERROR" for s in self.subsystems.values())
        has_degraded = any(s["status"] == "DEGRADED" for s in self.subsystems.values())
        posture = "ERROR" if has_error else ("DEGRADED" if has_degraded else "HEALTHY")
        return {
            "posture": posture,
            "subsystems": self.subsystems
        }
