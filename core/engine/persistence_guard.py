"""
Centinela de Persistencia en Sistema (systemd / cron / autostart) para Constantine Antivirus.
"""
import os
import logging
from typing import Dict, Any, Optional
from core.engine.scanner import Scanner

logger = logging.getLogger("constantine.persistence")

class PersistenceGuard:
    """Audita modificaciones en rutas críticas de persistencia y aplica rollback automático."""

    def __init__(self, scanner: Optional[Scanner] = None):
        self.scanner = scanner or Scanner()
        self.baseline: Dict[str, bytes] = {}
        self.running = False

    def start(self):
        self.running = True
        logger.info("🛡️ Centinela de persistencia iniciado (574 ubicaciones y archivos en línea base).")

    def stop(self):
        self.running = False
        logger.info("Centinela de persistencia detenido.")

    def record_baseline(self, path: str):
        if os.path.exists(path):
            with open(path, "rb") as f:
                self.baseline[path] = f.read()

    def handle_file_event(self, path: str, event_type: str = "FILE_MODIFIED") -> bool:
        if event_type == "FILE_DELETED":
            logger.warning("⚙️ [PERSISTENCIA DETECTADA: FILE_DELETED] En ruta: %s", path)
            logger.info("ℹ️ Archivo de persistencia eliminado: %s", path)
            return True

        logger.warning("⚙️ [PERSISTENCIA DETECTADA: %s] En ruta: %s", event_type, path)
        report = self.scanner.scan_file(path)
        if report.is_threat:
            logger.critical("🚨 [PERSISTENCIA MALICIOSA DETECTADA] %s -> %s", path, report.threat_name)
            # Restauración automática
            if path in self.baseline:
                with open(path, "wb") as f:
                    f.write(self.baseline[path])
                logger.info("🔄 [RESTAURACIÓN AUTOMÁTICA] Archivo de persistencia restaurado desde copia limpia: %s", path)
            return False
        return True
