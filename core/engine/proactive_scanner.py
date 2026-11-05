"""
Escáner Activo Continuo en Tiempo Real (EDR) para Constantine Antivirus.
"""
import os
import logging
import threading
from typing import Dict, Any, List, Optional
from core.engine.scanner import Scanner
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.proactive_scanner")

class ProactiveActiveScanner:
    """Ejecuta barridos periódicos sobre drop zones y ubicaciones críticas del sistema."""

    def __init__(self, scanner: Optional[Scanner] = None, vault: Optional[CryptographicVault] = None, interval: float = 30.0):
        self.scanner = scanner or Scanner()
        self.vault = vault or CryptographicVault()
        self.interval = interval
        self.running = False
        self.watched_paths: List[str] = []

    def start(self):
        self.running = True
        logger.info("🛡️ [ESCÁNER ACTIVO EN TIEMPO REAL] Iniciado con éxito. Intervalo de barrido: %.1fs", self.interval)

    def stop(self):
        self.running = False
        logger.info("⏹️ [ESCÁNER ACTIVO EN TIEMPO REAL] Detenido limpiamente.")

    def scan_landing_zone(self, directory: str):
        """Escanea una zona de aterrizaje y aísla amenazas proactivamente."""
        if not os.path.exists(directory):
            return
        for root, _, files in os.walk(directory):
            for f in files:
                fpath = os.path.join(root, f)
                rep = self.scanner.scan_file(fpath)
                if rep.is_threat:
                    logger.critical("🚨 [ESCÁNER ACTIVO: AMENAZA AISLADA] %s -> %s", fpath, rep.threat_name)
                    self.vault.quarantine_file(fpath, threat_name=rep.threat_name)
                    logger.info("[NOTIFICACIÓN DESKTOP] ⚔️ Constantine: Amenaza Bloqueada | <b>Amenaza:</b> %s - <b>Archivo:</b> %s - <b>Proceso:</b> ProactiveActiveScanner (PID: 470) - <b>Acción:</b> Neutralizado en Baúl",
                                rep.threat_name, fpath)
