"""
Escudo Anti-Ransomware con Trampas Honeypot y Detección de Ráfagas para Constantine.
"""
import os
import signal
import logging
from typing import Dict, Any, List, Optional, Set

logger = logging.getLogger("constantine.ransomware")

SUSPICIOUS_EXTENSIONS = {".locked", ".crypto", ".enc", ".crypted", ".dark", ".ransom", ".lock"}

class RansomwareShield:
    """Detecta y neutraliza ráfagas de cifrado y manipulación de trampas señuelo."""

    def __init__(self, canary_dir: Optional[str] = None):
        self.canary_dir = canary_dir or "/var/lib/constantine/canaries"
        self.canaries: Set[str] = set()
        self.burst_tracker: Dict[int, List[float]] = {}
        self.setup_canaries()

    def setup_canaries(self):
        if not os.path.exists(self.canary_dir):
            try:
                os.makedirs(self.canary_dir, exist_ok=True)
            except OSError:
                pass
        canary_names = ["important_document.docx", "passwords.kdbx", "financial_records.xlsx"]
        for name in canary_names:
            cpath = os.path.join(self.canary_dir, name)
            self.canaries.add(cpath)
            if not os.path.exists(cpath):
                try:
                    with open(cpath, "w", encoding="utf-8") as f:
                        f.write("CANARY_TRIPWIRE_HONEYPOT_CONSTANTINE_SECURITY")
                except OSError:
                    pass

    def check_canary_access(self, file_path: str, pid: int, flags: int = os.O_RDWR) -> bool:
        """
        Verifica si un proceso intenta alterar una trampa.
        Si la apertura es estrictamente O_RDONLY, se permite sin alertas.
        Si hay intención de escritura (O_WRONLY o O_RDWR), se neutraliza con SIGKILL.
        """
        norm = os.path.normpath(file_path)
        if norm in self.canaries or os.path.basename(norm) in [os.path.basename(c) for c in self.canaries]:
            # Comprobar banderas de apertura
            is_write = (flags & os.O_WRONLY) or (flags & os.O_RDWR)
            if is_write:
                logger.critical("🚨 [RANSOMWARE DETECTADO] Proceso PID %d intentó alterar/escribir archivo trampa: %s", pid, file_path)
                self.kill_process(pid)
                return False
        return True

    def check_extension_burst(self, file_path: str, pid: int, is_write: bool = True) -> bool:
        """
        Detecta creación o modificación de extensiones asociadas a ransomware.
        Si solo es lectura (find/grep), no dispara alerta.
        """
        ext = os.path.splitext(file_path)[1].lower()
        if ext in SUSPICIOUS_EXTENSIONS:
            if is_write:
                logger.warning("⚠️ [BLOQUEO PREVENTIVO EXTENSIÓN] PID %d intentó crear/escribir archivo sospechoso: %s", pid, file_path)
                return False
        return True

    def kill_process(self, pid: int):
        try:
            os.kill(pid, signal.SIGKILL)
            logger.info("Proceso ransomware PID %d neutralizado con SIGKILL.", pid)
        except (ProcessLookupError, PermissionError):
            pass
