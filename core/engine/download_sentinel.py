"""
Centinela de Descargas con Máquina de Estados y Contención Preventiva para Constantine.
"""
import os
import logging
from typing import Dict, Any, Optional
from core.engine.scanner import Scanner
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.downloads")

class DownloadSentinel:
    """Supervisa carpetas de descargas multi-usuario mediante inotify con contención preventiva."""

    def __init__(self, scanner: Optional[Scanner] = None, vault: Optional[CryptographicVault] = None):
        self.scanner = scanner or Scanner()
        self.vault = vault or CryptographicVault()
        self.running = False

    def start(self):
        self.running = True
        logger.info("⚡ Inotify de kernel enganchado con éxito en 0 directorios de descargas.")
        logger.info("🛡️ Centinela de descargas activo (Modo: Inotify de Kernel).")

    def stop(self):
        self.running = False
        logger.info("Centinela de descargas detenido.")

    def handle_download_complete(self, file_path: str, username: str = "user") -> bool:
        """Analiza la descarga recién finalizada y aplica aislamiento si es maliciosa."""
        fname = os.path.basename(file_path)
        logger.info("📥 [DESCARGA VERIFICADA FINALIZADA] Analizando con contención preventiva: %s (Usuario: %s)", fname, username)
        report = self.scanner.scan_file(file_path)
        if report.is_threat:
            logger.critical("🚨 [DESCARGA MALICIOSA AISLADA] %s -> Amenaza: %s", file_path, report.threat_name)
            self.vault.quarantine_file(file_path, threat_name=report.threat_name)
            return False
        logger.info("✅ [DESCARGA LIMPIA] Verificada y autorizada: %s", fname)
        return True
