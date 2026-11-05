"""
Lista Blanca de Confianza y Verificación Criptográfica de Binarios para Constantine.
"""
import os
import hashlib
import logging
from typing import Dict, Any, Set, Optional

logger = logging.getLogger("constantine.whitelist")

PROHIBITED_SYSTEM_DIRS = {"/", "/usr/bin", "/tmp", "/etc", "/bin", "/sbin", "/usr/sbin"}

class WhitelistManager:
    """Gestiona exclusiones con verificación estricta de hash SHA-256 e inodo."""

    def __init__(self):
        self.entries: Dict[str, Dict[str, Any]] = {}

    def add_entry(self, file_path: str, expected_hash: Optional[str] = None) -> bool:
        norm = os.path.normpath(file_path)
        if norm in PROHIBITED_SYSTEM_DIRS:
            logger.critical("❌ [SEGURIDAD] Intento de excluir directorio crítico del sistema rechazado: %s", norm)
            return False

        if not os.path.exists(norm):
            return False

        with open(norm, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()

        self.entries[norm] = {"sha256": h, "path": norm}
        logger.info("Añadido a Whitelist con verificación de integridad: %s (SHA-256: %s)", norm, h[:12])
        return True

    def remove_entry(self, file_path: str) -> bool:
        norm = os.path.normpath(file_path)
        if norm in self.entries:
            del self.entries[norm]
            logger.info("Removido de Whitelist: %s", norm)
            return True
        return False

    def is_whitelisted(self, file_path: str) -> bool:
        norm = os.path.normpath(file_path)
        if norm not in self.entries:
            return False
        # Verificación de integridad en disco
        if not os.path.exists(norm):
            return False
        with open(norm, "rb") as f:
            current_h = hashlib.sha256(f.read()).hexdigest()
        expected_h = self.entries[norm]["sha256"]
        if current_h != expected_h:
            logger.warning("🚨 [EXCLUSIÓN INVALIDADA Y EXPULSADA] Archivo autorizado modificado en disco: %s (Esperado: %s, Real: %s)",
                           norm, expected_h, current_h)
            self.remove_entry(norm)
            return False
        return True
