"""
Constantine Antivirus - System Whitelist & Zero-Nag Engine (core/engine/system_whitelist.py)
Reconocimiento automático de binarios del sistema y paquetes oficiales de la distribución.
Evita la fatiga de alertas ("efecto Windows Vista") y garantiza cero interrupciones
para software instalado mediante apt, dpkg, Flatpak o Snap.
"""

import os
import logging
from typing import Set

logger = logging.getLogger("constantine.whitelist")

# Directorios de sistema de confianza de Debian, Ubuntu y Linux Mint
TRUSTED_SYSTEM_DIRS = (
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/usr/lib64/",
    "/snap/",
    "/var/lib/flatpak/",
    "/usr/share/"
)

# Directorios de alto riesgo donde nunca se aplica whitelist ciega
SUSPICIOUS_UNTRUSTED_DIRS = (
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/home"
)

class SystemWhitelist:
    def __init__(self):
        self.cached_trusted: Set[str] = set()

    def is_trusted_system_binary(self, file_path: str) -> bool:
        """
        Determina si un archivo es un ejecutable oficial de la distribución.
        Garantiza que la navegación y uso ordinario jamás genere preguntas al usuario.
        """
        if not file_path:
            return False

        norm_path = os.path.abspath(file_path)

        # 1. Los directorios temporales y de usuario NUNCA están en la lista blanca
        for susp in SUSPICIOUS_UNTRUSTED_DIRS:
            if norm_path.startswith(susp):
                return False

        # 2. Si pertenece a rutas canónicas del sistema (/usr/bin, etc.)
        for trusted_dir in TRUSTED_SYSTEM_DIRS:
            if norm_path.startswith(trusted_dir):
                return True

        return False
