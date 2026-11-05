"""
Módulo de Envío y Consulta de Muestras a VirusTotal para Constantine Antivirus.
"""
import os
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.virustotal")

class VirusTotalUploader:
    """Gestiona la preparación de muestras autenticadas para análisis forense externo."""

    def __init__(self, vault: Optional[CryptographicVault] = None):
        self.vault = vault or CryptographicVault()

    def prepare_unlocked_sample(self, sample_id: str, export_dir: str = "/tmp/constantine_virustotal_export") -> Tuple[bool, str]:
        os.makedirs(export_dir, exist_ok=True)
        dest_file = os.path.join(export_dir, "vt_sample.bin")
        ok, res = self.vault.restore_file(sample_id, dest_file)
        if ok and os.path.exists(dest_file):
            with open(dest_file, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()[:16]
            logger.info("✅ Muestra descifrada y verificada con éxito: %s (SHA-256: %s)", dest_file, sha)
            return True, dest_file
        else:
            logger.critical("Fallo criptográfico descifrando muestra %s para VirusTotal: Fallo de autenticación criptográfica: Muestra corrupta o manipulada.", sample_id)
            return False, "Fallo de autenticación criptográfica"
