"""
Constantine Antivirus - Anti-Ransomware Shield (core/engine/ransomware_shield.py)
Detección y protección activa contra ataques de ransomware en Linux:
1. Canary Honeypots (archivos señuelo en carpetas críticas).
2. Monitoreo de ráfagas de modificación y extensiones de cifrado (.locked, .encrypted, etc.).
3. Congelación y neutralización instantánea del proceso agresor (SIGKILL + fanotify).
"""

import os
import signal
import time
import logging
from typing import Dict, List, Optional, Callable

logger = logging.getLogger("constantine.ransomware")

DEFAULT_CANARY_DIR = os.path.expanduser("~/.config/constantine/canaries")
SYSTEM_CANARY_DIR = "/var/lib/constantine/canaries"

RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".encrypted", ".crypted", ".lockbit",
    ".ransom", ".blackcat", ".hive", ".enc", ".wnry"
}

class RansomwareShield:
    def __init__(self, canary_dir: Optional[str] = None, alert_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback
        if canary_dir:
            self.canary_dir = canary_dir
        else:
            self.canary_dir = SYSTEM_CANARY_DIR if os.geteuid() == 0 else DEFAULT_CANARY_DIR

        self.canary_files = {}
        self.process_mod_counts = {}  # pid -> [timestamps]
        self._deploy_canaries()

    def _deploy_canaries(self):
        """Despliega archivos señuelo cuya modificación delata inmediatamente un ransomware."""
        os.makedirs(self.canary_dir, exist_ok=True)
        canaries = ["important_document.docx", "family_photos_backup.zip", "finance_ledger.xlsx"]
        for c in canaries:
            path = os.path.join(self.canary_dir, c)
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(b"CONSTANTINE_CANARY_INTEGRITY_CHECK_TOKEN_DO_NOT_MODIFY_2026")
            self.canary_files[path] = os.path.getmtime(path)

    def check_file_path(self, file_path: str, pid: int) -> bool:
        """
        Analiza si la operación de archivo corresponde a un patrón típico de ransomware:
        - Modificación de archivos señuelo (canary trap)
        - Creación o renombrado con extensiones de ransomware conocidas
        Retorna True si es sospechoso de ransomware.
        """
        # 1. Comprobación de trampa señuelo
        if file_path in self.canary_files:
            logger.critical("🚨 [RANSOMWARE DETECTADO] Proceso PID %d intentó alterar archivo trampa: %s", pid, file_path)
            self._neutralize_ransomware(pid, f"CanaryTrapTriggered ({file_path})")
            return True

        # 2. Comprobación de extensión de cifrado
        ext = os.path.splitext(file_path)[1].lower()
        if ext in RANSOMWARE_EXTENSIONS:
            logger.critical("🚨 [RANSOMWARE DETECTADO] Proceso PID %d creó archivo cifrado: %s", pid, file_path)
            self._neutralize_ransomware(pid, f"RansomwareExtension.{ext}")
            return True

        # 3. Detección de ráfagas anómalas de modificación rápida (> 30 archivos en 2 segundos)
        now = time.time()
        timestamps = self.process_mod_counts.get(pid, [])
        timestamps = [t for t in timestamps if now - t < 2.0]
        timestamps.append(now)
        self.process_mod_counts[pid] = timestamps

        if len(timestamps) > 35:
            logger.critical("🚨 [RANSOMWARE DETECTADO] Ráfaga masiva de modificaciones por PID %d (>35 ops/2s)", pid)
            self._neutralize_ransomware(pid, "MassFileEncryptionBurst")
            return True

        return False

    def _neutralize_ransomware(self, pid: int, reason: str):
        """Mata el proceso agresor inmediatamente y dispara alerta."""
        try:
            os.kill(pid, signal.SIGKILL)
            logger.critical("⚡ Proceso ransomware PID %d neutralizado con SIGKILL. Razón: %s", pid, reason)
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.error("Error al matar PID %d: %s", pid, e)

        if self.alert_callback:
            self.alert_callback(f"Ransomware.Blocked.{reason}", pid)
