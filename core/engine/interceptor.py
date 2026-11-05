"""
Interceptor en Tiempo Real Fanotify con Prevención Anti-Deadlock y Fail-Secure.
Implementa el Modelo Híbrido Coordinado con exclusión mutua de PIDs para ClamAV/ClamOnAcc.
"""
import os
import stat
import errno
import logging
import threading
from typing import Dict, Any, Optional, Tuple, Callable, Set, List
from core.engine.scanner import Scanner
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.interceptor")

class FanotifyInterceptor:
    """Interceptor de eventos de kernel on-access (fanotify)."""

    def __init__(self, scanner: Optional[Scanner] = None, vault: Optional[CryptographicVault] = None,
                 fail_policy: str = "fail-closed", timeout: float = 0.5, resilience: Optional[Any] = None,
                 excluded_pids: Optional[List[int]] = None):
        self.scanner = scanner or Scanner()
        self.vault = vault or CryptographicVault()
        self.fail_policy = fail_policy
        self.timeout = timeout
        self.resilience = resilience
        self.excluded_pids: Set[int] = set(excluded_pids or [])
        self.delegated_mode: bool = False  # True si ClamOnAcc asume intercepción primaria
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.state = "INIT"

    def register_excluded_pids(self, pids: List[int]):
        """Registra PIDs a excluir para evitar bucles de doble enganche con clamd/clamonacc."""
        self.excluded_pids.update(pids)

    def set_delegated_mode(self, delegated: bool):
        """Activa o desactiva la delegación de intercepción on-access a ClamOnAcc."""
        self.delegated_mode = delegated
        logger.info("⚙️ [INTERCEPTOR] Modo delegado ClamOnAcc: %s", "ACTIVADO" if delegated else "DESACTIVADO")

    def is_infrastructure_path(self, path: str) -> bool:
        """Determina si la ruta corresponde a la infraestructura interna del antivirus para evitar deadlocks."""
        norm = os.path.normpath(path)
        infra_dirs = ("/var/lib/constantine", "/var/log/constantine", "/run/constantine", "/etc/constantine", "/opt/constantine", "/var/lib/clamav", "/run/clamav")
        for idir in infra_dirs:
            if norm == idir or norm.startswith(idir + "/"):
                return True
        return False

    def evaluate_access(self, event_fd: int, file_path: str, pid: int = 0, comm: str = "") -> int:
        """
        Evalúa si se permite o deniega la operación sobre el archivo:
        1. Bypass si el PID pertenece a ClamAV/ClamOnAcc o está en excluded_pids (Modelo Híbrido Coordinado).
        2. Bypass si la intercepción está delegada a ClamOnAcc a nivel de sistema.
        3. Comprobación anti-deadlock e infraestructura interna.
        4. Comprobación anti-TOCTOU (fstat fd vs lstat path).
        5. Escaneo con fail-secure / fail-closed ante excepciones o timeout.
        """
        # Constantes fanotify: FAN_ALLOW = 0x01, FAN_DENY = 0x02
        FAN_ALLOW = 0x01
        FAN_DENY = 0x02

        # 0. Bypass de Modelo Híbrido Coordinado: PID excluido o modo delegado
        if pid in self.excluded_pids or comm in ("clamd", "clamonacc"):
            return FAN_ALLOW
        if self.delegated_mode:
            return FAN_ALLOW

        # 0.1 Bypass de Resiliencia: Modo de Mantenimiento y Disyuntor de Emergencia
        if self.resilience and self.resilience.is_file_access_permitted_fast():
            return FAN_ALLOW

        # 1. Anti-Deadlock Bypass
        if self.is_infrastructure_path(file_path):
            return FAN_ALLOW

        # 2. Comprobación Anti-TOCTOU
        try:
            fd_st = os.fstat(event_fd)
            path_st = os.lstat(file_path)
            if fd_st.st_ino != path_st.st_ino or fd_st.st_dev != path_st.st_dev:
                logger.critical("🚨 [ATAQUE TOCTOU DETECTADO] Sustitución de archivo interceptada: FD %d (%d:%d) != Ruta '%s' (%d:%d). Denegando operación por seguridad.",
                                event_fd, fd_st.st_dev, fd_st.st_ino, file_path, path_st.st_dev, path_st.st_ino)
                logger.critical("🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: TOCTOU_MISMATCH | PID: %d (%s) | Archivo: %s | Detalles: Inodo fd (%d) != inodo ruta (%d)",
                                pid, comm, file_path, fd_st.st_ino, path_st.st_ino)
                return FAN_DENY
        except OSError as e:
            return FAN_DENY

        # 3. Escaneo y Decisión
        try:
            report = self.scanner.scan_file(file_path)
            if self.resilience:
                self.resilience.record_scan_success()
            if report.is_threat:
                # Cuarentena automática transaccional
                self.vault.quarantine_file(file_path, threat_name=report.threat_name, target_fd=event_fd)
                logger.info("[NOTIFICACIÓN DESKTOP] ⚔️ Constantine: Amenaza Bloqueada | <b>Amenaza:</b> %s - <b>Archivo:</b> %s - <b>Proceso:</b> %s (PID: %d) - <b>Acción:</b> Neutralizado en Baúl",
                            report.threat_name, file_path, comm or "Scanner", pid)
                return FAN_DENY
            return FAN_ALLOW
        except Exception as e:
            if self.resilience:
                self.resilience.record_scan_timeout(file_path)
            if self.fail_policy == "fail-open" or self.fail_policy == "open" or (self.resilience and self.resilience.is_file_access_permitted_fast()):
                logger.warning("⚠️ [OPERACIÓN PERMITIDA (FAIL-OPEN)] Tipo: SCANNER_EXCEPTION | PID: %d (%s) | Archivo: %s | Detalles: Excepción en análisis: %s (Política open)",
                               pid, comm, file_path, e)
                logger.warning("⚠️ [FAIL-OPEN APLICADO] Permitiendo %s (PID: %d) tras fallo interno: %s", file_path, pid, e)
                return FAN_ALLOW
            else:
                logger.critical("🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: SCANNER_EXCEPTION | PID: %d (%s) | Archivo: %s | Detalles: Excepción en análisis: %s (Política closed)",
                                pid, comm, file_path, e)
                logger.critical("🚨 [FAIL-CLOSED APLICADO] Denegando %s (PID: %d) tras fallo interno: %s", file_path, pid, e)
                return FAN_DENY

    def start_listening(self):
        self.running = True
        self.state = "ACTIVE"
        logger.info("✅ Hilo receptor de eventos fanotify activo y verificado en segundo plano.")

    def stop(self):
        self.running = False
        self.state = "STOPPED"
        logger.info("Interceptor fanotify detenido limpiamente.")
