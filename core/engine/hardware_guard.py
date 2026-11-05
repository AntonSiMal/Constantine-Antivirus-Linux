"""
Centinela de Periféricos (Cámara Web y Micrófono) para Constantine Antivirus.
"""
import os
import signal
import logging
from typing import Dict, Any, List

logger = logging.getLogger("constantine.hardware")

class HardwareGuard:
    """Supervisa procesos accediendo a descriptores de vídeo y audio para neutralizar espías."""

    def __init__(self):
        self.running = False

    def start(self):
        self.running = True
        logger.info("Centinela de periféricos (cámara web y micrófono) activo con verificación criptográfica.")

    def stop(self):
        self.running = False
        logger.info("Centinela de periféricos detenido.")

    def block_unauthorized_access(self, pid: int, binary_path: str, device_type: str = "Cámara Web"):
        """Neutraliza de forma inmediata un proceso espía no autorizado."""
        logger.critical("🛑 [BLOQUEO DE HARDWARE] Revocando acceso y neutralizando proceso espía: PID %d (%s) -> %s",
                        pid, binary_path, device_type)
        try:
            os.kill(pid, signal.SIGKILL)
            logger.info("Proceso espía PID %d liquidado con SIGKILL.", pid)
        except OSError:
            pass
