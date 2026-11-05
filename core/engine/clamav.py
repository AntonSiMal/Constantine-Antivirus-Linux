"""
Constantine Antivirus - ClamAV Subsystem Unified Facade (core/engine/clamav.py)
Expone la interfaz unificada del motor ClamAV para análisis de archivos, firmas y control de acceso:
1. Reexportación de componentes centrales:
   - ClamAVManager: Orquestador integral (clamd, freshclam, clamonacc, archivos comprimidos).
   - ClamAVDaemonClient: Cliente IPC nativo de baja latencia con el socket Unix de clamd.
   - ClamAVSignatureImporter: Parser de bases CVD/CLD, firmas HSB (SHA-256) y PDB (anti-phishing).
2. Funciones de conveniencia de nivel superior:
   - scan_file(path, timeout=3.0): Analiza un archivo en disco con clamd.
   - scan_stream(stream, timeout=3.0): Analiza un flujo en memoria o descriptor.
   - is_available(): Consulta disponibilidad rápida de clamd vía PING.
   - get_version(): Retorna la versión oficial de ClamAV y la base de firmas.
   - update_signatures(): Ejecuta freshclam y sincronización local.
   - coordinate_on_access(interceptor): Coordina exclusiones mutuas para evitar deadlocks fanotify.
3. Registro transparente en sys.modules:
   - Permite 'import clamav' en el ecosistema de Constantine sin dependencias externas.
"""

from __future__ import annotations

import sys
from typing import Optional, Tuple, Dict, Any

from core.engine.clamav_bridge import ClamAVDaemonClient
from core.engine.clamav_importer import ClamAVSignatureImporter
from core.engine.clamav_manager import ClamAVManager

# Instancia singleton predeterminada para uso directo
_default_manager: Optional[ClamAVManager] = None


def get_default_manager() -> ClamAVManager:
    """Retorna la instancia global compartida de ClamAVManager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = ClamAVManager(auto_start_daemon=False)
    return _default_manager


def is_available() -> bool:
    """Verifica si el demonio local clamd está en ejecución y disponible."""
    return get_default_manager().is_engine_available()


def get_version() -> Optional[str]:
    """Obtiene la cadena de versión oficial de ClamAV y fecha de base de firmas."""
    return get_default_manager().get_engine_version()


def scan_file(file_path: str, timeout: float = 3.0) -> Tuple[bool, Optional[str], str]:
    """
    Analiza un archivo en disco utilizando clamd y ArchiveSentinel.
    Retorna (is_infected, threat_name, details).
    """
    return get_default_manager().scan_file(file_path, timeout=timeout)


def scan_stream(data_or_fd, timeout: float = 3.0) -> Tuple[bool, Optional[str], str]:
    """Analiza datos en memoria o descriptor abierto mediante clamd zINSTREAM."""
    return get_default_manager().scan_stream(data_or_fd, timeout=timeout)


def update_signatures(timeout: int = 60) -> Dict[str, Any]:
    """Ejecuta la actualización de firmas mediante freshclam y sincroniza bases locales."""
    return get_default_manager().update_signatures(timeout=timeout)


def coordinate_on_access(interceptor) -> Dict[str, Any]:
    """Coordina políticas On-Access entre fanotify y clamd/clamonacc para evitar deadlocks."""
    return get_default_manager().coordinate_on_access_protection(interceptor)


# Registrar este módulo en sys.modules bajo el nombre canónico 'clamav'
# si aún no ha sido importado desde otra librería externa
if "clamav" not in sys.modules:
    sys.modules["clamav"] = sys.modules[__name__]

__all__ = [
    "ClamAVManager",
    "ClamAVDaemonClient",
    "ClamAVSignatureImporter",
    "get_default_manager",
    "is_available",
    "get_version",
    "scan_file",
    "scan_stream",
    "update_signatures",
    "coordinate_on_access",
]
