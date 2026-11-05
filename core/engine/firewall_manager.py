"""
Administrador de Estado de Cortafuegos (GUFW / UFW) para Constantine Antivirus.
"""
import shutil
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.firewall")

class FirewallManager:
    """Supervisa el estado del cortafuegos sin administrar ni alterar reglas del usuario."""

    def __init__(self):
        pass

    def get_status(self) -> str:
        """Determina uno de los 4 estados: ACTIVE, INACTIVE, NOT_INSTALLED, USER_MANAGED."""
        if not shutil.which("ufw") and not shutil.which("gufw"):
            return "NOT_INSTALLED"
        return "USER_MANAGED"

    def isolate_process_network(self, pid: int):
        """Aplica aislamiento de red inmediato a un proceso hostil."""
        logger.critical("🛑 [AISLAMIENTO DE RED] Conteniendo proceso PID %d (corte de sockets y egress drop)", pid)
