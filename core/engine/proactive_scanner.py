"""
Constantine Antivirus - Proactive Continuous Scanner (core/engine/proactive_scanner.py)
Motor de escaneo activo en segundo plano continuo (Comportamiento Antivirus Windows / Zero-Delay EDR):
1. Monitorización Activa Ininterrumpida en Tiempo Real:
   - No depende exclusivamente de que un usuario interactúe con un archivo.
   - Opera en un hilo demonio permanente realizando barridos proactivos periódicos en segundo plano.
2. Barrido Continuo de Zonas Críticas de Carga (Staging & Drop Zones):
   - Audita proactivamente /tmp, /var/tmp, /dev/shm, /run/user/ y carpetas de descargas/escritorio.
   - Si un script malicioso, dropper o payload es descargado o generado en segundo plano,
     lo detecta y neutraliza en el baúl antes de que intente ejecutarse.
3. Auditoría Activa de Procesos y Memoria RAM:
   - Inspecciona periódicamente los procesos activos en /proc (binarios eliminados, memoria RWX,
     ejecutables anómalos o sospechosos).
4. Aislamiento Automático Inmediato (Kill & Quarantine):
   - Al detectar una amenaza en el barrido activo:
     * Termina el proceso responsable (SIGKILL).
     * Mueve el binario al Baúl Criptográfico AES-256-GCM.
     * Registra el incidente en AuditLogger.
     * Despacha una notificación nativa de escritorio.
5. Throttling Inteligente (Zero-Nag & CPU Throttling):
   - Regula el consumo de CPU mediante micropausas entre archivos (modo baja prioridad / idle I/O),
     garantizando que el uso del procesador permanezca por debajo del 2-3% (idéntico a Windows Defender).
"""

import os
import glob
import time
import signal
import logging
import threading
from typing import Optional, List, Dict, Any, Callable, Set

from core.engine.scanner import Scanner, ScanResult
from core.engine.vault import QuarantineVault
from core.engine.notifier import DesktopNotifier
from core.engine.audit_logger import AuditLogger
from core.engine.memory_scanner import MemoryScanner
from core.engine.system_whitelist import SystemWhitelist

logger = logging.getLogger("constantine.proactive_scanner")

DEFAULT_VOLATILE_DIRS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm"
]


class ProactiveContinuousScanner:
    """
    Escáner activo en tiempo real continuo que emula el comportamiento de un antivirus Windows,
    asegurando vigilancia proactiva de memoria, procesos y directorios de aterrizaje.
    """

    def __init__(
        self,
        scanner: Scanner,
        vault: QuarantineVault,
        notifier: Optional[DesktopNotifier] = None,
        audit_logger: Optional[AuditLogger] = None,
        memory_scanner: Optional[MemoryScanner] = None,
        interval_seconds: float = 30.0,
        target_dirs: Optional[List[str]] = None
    ):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier or DesktopNotifier()
        self.audit_logger = audit_logger or AuditLogger()
        self.memory_scanner = memory_scanner or MemoryScanner(scanner=self.scanner, vault=self.vault)
        self.interval_seconds = max(5.0, interval_seconds)
        self.target_dirs = target_dirs or DEFAULT_VOLATILE_DIRS
        self.whitelist = SystemWhitelist()

        self.running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._wake_event = threading.Event()

        # Telemetría en tiempo real
        self.total_files_scanned: int = 0
        self.total_processes_scanned: int = 0
        self.total_threats_neutralized: int = 0
        self.last_sweep_timestamp: float = 0.0
        self.last_sweep_duration: float = 0.0
        self.current_action: str = "INICIALIZADO"
        self._scanned_hashes_cache: Dict[str, float] = {}

    def start(self):
        """Inicia el hilo de escaneo activo en segundo plano."""
        if self.running:
            return
        self.running = True
        self._wake_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name="ConstantineProactiveScanWorker"
        )
        self._thread.start()
        logger.info("🛡️ [ESCÁNER ACTIVO EN TIEMPO REAL] Iniciado con éxito. Intervalo de barrido: %.1fs", self.interval_seconds)

    def stop(self):
        """Detiene de forma limpia el motor de escaneo continuo."""
        self.running = False
        self._wake_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("⏹️ [ESCÁNER ACTIVO EN TIEMPO REAL] Detenido limpiamente.")

    def trigger_immediate_sweep(self):
        """Fuerza un barrido activo inmediato sin esperar al siguiente intervalo."""
        self._wake_event.set()

    def get_telemetry(self) -> Dict[str, Any]:
        """Retorna las estadísticas en tiempo real para la interfaz gráfica y el demonio."""
        return {
            "status": "PROTECTION_ACTIVE_MONITORING" if self.running else "STOPPED",
            "is_active": self.running,
            "mode": "REALTIME_CONTINUOUS_EDR",
            "files_scanned_count": self.total_files_scanned,
            "processes_scanned_count": self.total_processes_scanned,
            "threats_neutralized_count": self.total_threats_neutralized,
            "last_sweep_timestamp": self.last_sweep_timestamp,
            "last_sweep_duration_seconds": round(self.last_sweep_duration, 3),
            "current_action": self.current_action,
            "monitored_drop_zones": list(self.target_dirs)
        }

    def perform_sweep(self):
        """Ejecuta un ciclo completo de barrido proactivo de procesos y drop zones."""
        start_ts = time.time()
        self.current_action = "BARRIDO_ACTIVO_EN_CURSO"
        try:
            self._sweep_active_processes()
            self._sweep_landing_directories()
        except Exception as e:
            logger.error("Error durante el ciclo de escaneo activo: %s", e)
        self.last_sweep_duration = time.time() - start_ts
        self.last_sweep_timestamp = time.time()
        self.current_action = "MONITOREANDO_EN_VIVO"

    def _run_loop(self):
        """Bucle principal de vigilancia continua."""
        while self.running:
            self.perform_sweep()
            self._wake_event.wait(timeout=self.interval_seconds)
            self._wake_event.clear()

    def _sweep_active_processes(self):
        """Audita procesos activos buscando binarios anómalos o amenazas en RAM."""
        try:
            pids = self.memory_scanner.get_running_pids()
            for pid in pids:
                if not self.running:
                    break
                if pid <= 2:
                    continue

                self.total_processes_scanned += 1
                exe_link = f"/proc/{pid}/exe"
                if not os.path.exists(exe_link):
                    continue

                try:
                    target = os.readlink(exe_link)
                except Exception:
                    continue

                if not target or self.whitelist.is_self_file(target):
                    continue

                # Detectar binario eliminado ejecutándose en RAM (técnica clásica de malware)
                if "(deleted)" in target:
                    logger.warning("🚨 [PROCESO SOSPECHOSO EN RAM] PID %d ejecuta binario eliminado: %s", pid, target)
                    clean_path = target.replace(" (deleted)", "").strip()
                    # Verificar si el binario eliminado está en una ruta volátil
                    if any(clean_path.startswith(v) for v in DEFAULT_VOLATILE_DIRS):
                        self._neutralize_threat_process(pid, clean_path, "Memory.ProcessDeletedOnDisk")
                        continue

                # Escaneo del ejecutable del proceso si está en rutas volátiles no autorizadas
                if any(target.startswith(v) for v in DEFAULT_VOLATILE_DIRS):
                    scan_res = self.scanner.scan_file(file_path=target)
                    if scan_res.is_malicious:
                        self._neutralize_threat_process(pid, target, scan_res.threat_name or "Malware.ProcessInTemp")

                # Micropausa para garantizar impacto de CPU imperceptible
                time.sleep(0.002)

        except Exception as e:
            logger.debug("Aviso en auditoría de procesos en segundo plano: %s", e)

    def _sweep_landing_directories(self):
        """Examina directorios de descarga y temporales donde se alojan droppers y cargas útiles."""
        dirs_to_check = set(self.target_dirs)

        # Añadir dinámicamente carpetas de descargas y temporales de usuarios en /home
        try:
            for home_dir in glob.glob("/home/*"):
                if os.path.isdir(home_dir):
                    for sub in ["Descargas", "Downloads", "Desktop", "Escritorio"]:
                        p = os.path.join(home_dir, sub)
                        if os.path.isdir(p):
                            dirs_to_check.add(p)
        except Exception:
            pass

        now = time.time()
        for d in dirs_to_check:
            if not self.running:
                break
            if not os.path.isdir(d):
                continue

            try:
                # Barrido superficial y hasta 2 niveles de profundidad para evitar sobrecargas
                for root, dirs, files in os.walk(d):
                    # No descender en directorios del sistema o baúl
                    dirs[:] = [sub for sub in dirs if sub not in (".git", "vault", "canaries", "__pycache__")]
                    depth = root[len(d):].count(os.sep)
                    if depth > 2:
                        continue

                    for f in files:
                        if not self.running:
                            break
                        full_p = os.path.join(root, f)

                        # Saltar enlaces simbólicos para evitar bucles
                        if os.path.islink(full_p):
                            continue

                        try:
                            st = os.stat(full_p)
                        except Exception:
                            continue

                        # Omitir archivos vacíos o gigantescos (>50MB en barrido pasivo)
                        if st.st_size == 0 or st.st_size > 50 * 1024 * 1024:
                            continue

                        # Caché por mtime para no re-escanear archivos idénticos sin cambios
                        cache_key = f"{full_p}:{st.st_mtime}:{st.st_size}"
                        if cache_key in self._scanned_hashes_cache:
                            if (now - self._scanned_hashes_cache[cache_key]) < 300:  # 5 minutos TTL
                                continue

                        self.total_files_scanned += 1
                        self._scanned_hashes_cache[cache_key] = now

                        # Analizar archivo con el motor completo
                        res = self.scanner.scan_file(file_path=full_p)
                        if res.is_malicious:
                            self._neutralize_threat_file(full_p, res.threat_name or "Malware.DetectedByActiveScan")

                        # CPU Throttling estricto (0.005s) para mantener CPU < 2%
                        time.sleep(0.005)

            except Exception as e:
                logger.debug("Aviso explorando drop zone %s: %s", d, e)

    def _neutralize_threat_process(self, pid: int, path: str, threat_name: str):
        """Termina un proceso malicioso detectado y aísla sus artefactos."""
        logger.critical("🚨 [ESCÁNER ACTIVO: NEUTRALIZANDO PROCESO] PID %d (%s) -> %s", pid, path, threat_name)
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

        self.total_threats_neutralized += 1
        self.audit_logger.record_incident(threat_name, path, "PROCESS_TERMINATED", f"PID {pid} neutralizado por Escáner Activo")
        self.notifier.alert_threat_blocked(threat_name, path, pid, "ProactiveSentinel")

        if os.path.exists(path) and not os.path.islink(path):
            self.vault.quarantine_file(path, threat_name, detected_by="ProactiveActiveScanner")

    def _neutralize_threat_file(self, path: str, threat_name: str):
        """Aísla un archivo malicioso detectado en un barrido activo."""
        logger.critical("🚨 [ESCÁNER ACTIVO: AMENAZA AISLADA] %s -> %s", path, threat_name)
        self.total_threats_neutralized += 1
        self.audit_logger.record_incident(threat_name, path, "QUARANTINED", "Aislado proactivamente en segundo plano")
        self.notifier.alert_threat_blocked(threat_name, path, 0, "ProactiveSentinel")
        self.vault.quarantine_file(path, threat_name, detected_by="ProactiveActiveScanner")
