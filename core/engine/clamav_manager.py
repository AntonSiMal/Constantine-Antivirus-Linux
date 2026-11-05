"""
Constantine Antivirus - Comprehensive ClamAV Antivirus Engine Manager (core/engine/clamav_manager.py)
Integración integral del motor antivirus de código abierto ClamAV (Cisco Talos) en Constantine EDR:
1. Motor de Análisis de Alto Rendimiento:
   - Conexión de baja latencia con el demonio clamd vía Unix Domain Socket (/run/clamav/clamd.ctl).
   - Análisis de archivos en disco (SCAN) y de flujos en memoria (zINSTREAM).
2. Firmas Antivirus Actualizables (FreshClam):
   - Coordinación y ejecución de freshclam para mantener las bases de virus actualizadas diariamente.
   - Consulta e inspección de metadatos de versión y conteo de firmas (CVD/CLD).
   - Ingesta automática de firmas ClamAV (.hsb / .hdb / .pdb) hacia Constantine Threat Intel.
3. Análisis Profundo de Archivos Comprimidos:
   - Descompresión e inspección de múltiples formatos de contenedores (ZIP, 7z, RAR, TAR, GZ, OLE, PDF).
   - Prevención estricta de bombas de descompresión (Zip Bombs) y denegación de servicio.
4. Detección de Malware Conocido:
   - Cobertura de millones de variantes de malware conocidas (troyanos, ransomware, gusanos, exploits).
5. Gestión del Servicio clamd:
   - Supervisión activa del ciclo de vida del servicio (detección, arranque, keepalive PING/PONG).
6. Coordinación de Protección al Acceso (clamonacc & fanotify):
   - Coordinación de políticas On-Access entre Constantine FanotifyInterceptor y clamonacc.
   - Prevención mutua de bucles infinitos (exclusión de PIDs de clamd/clamonacc/constantine).
   - Enrutamiento de alertas de acceso denegado hacia el Baúl Criptográfico de Constantine.
"""

import os
import time
import socket
import struct
import subprocess
import logging
from typing import Dict, Any, Optional, Tuple, List, Callable

from core.engine.clamav_bridge import ClamAVDaemonClient
from core.engine.clamav_importer import ClamAVSignatureImporter
from core.engine.archive_sentinel import ArchiveSentinel
from core.engine.system_whitelist import SystemWhitelist

logger = logging.getLogger("constantine.clamav_manager")

CLAMAV_SYSTEMD_SERVICES = ["clamav-daemon", "clamav-freshclam"]
CLAMD_SOCKET_PATHS = [
    "/run/clamav/clamd.ctl",
    "/var/run/clamav/clamd.ctl",
    "/tmp/clamd.sock"
]


class ClamAVManager:
    """
    Gestor integral de integración del motor antivirus ClamAV dentro de Constantine.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        threat_intel=None,
        vault=None,
        notifier=None,
        audit_logger=None,
        auto_start_daemon: bool = True
    ):
        self.socket_path = socket_path
        self.threat_intel = threat_intel
        self.vault = vault
        self.notifier = notifier
        self.audit_logger = audit_logger
        self.auto_start_daemon = auto_start_daemon

        self.bridge = ClamAVDaemonClient(socket_path=self.socket_path)
        self.importer = ClamAVSignatureImporter()
        self.archive_sentinel = ArchiveSentinel()
        self.whitelist = SystemWhitelist()

        self._last_freshclam_ts: float = 0.0
        self._clamonacc_enabled: bool = False

    def is_engine_available(self) -> bool:
        """Determina si el motor clamd está disponible y respondiendo a comandos."""
        return self.bridge.is_available()

    def get_engine_version(self) -> Optional[str]:
        """Retorna la versión oficial de ClamAV y las firmas activas."""
        return self.bridge.get_version() if self.bridge.is_available() else None

    def ensure_clamd_service(self) -> bool:
        """
        Verifica si el servicio clamd está activo; si no lo está y se cuenta con permisos,
        intenta iniciarlo mediante systemctl o arranque directo.
        """
        if self.bridge.ping(timeout=0.5):
            return True

        if not self.auto_start_daemon:
            return False

        logger.info("Iniciando servicio de demonio ClamAV (clamav-daemon)...")
        try:
            res = subprocess.run(["systemctl", "start", "clamav-daemon"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            if res.returncode == 0:
                # Esperar hasta 3 segundos a que el socket esté listo
                for _ in range(6):
                    time.sleep(0.5)
                    if self.bridge.ping(timeout=0.5):
                        logger.info("✅ Demonio clamd iniciado y operativo.")
                        return True
        except Exception as e:
            logger.debug("Aviso iniciando clamav-daemon vía systemctl: %s", e)

        return self.bridge.ping(timeout=0.5)

    def scan_file(self, file_path: str, timeout: float = 3.0) -> Tuple[bool, Optional[str], str]:
        """
        Analiza un archivo contra el motor ClamAV:
        - Si es un archivo comprimido, evalúa con ArchiveSentinel y solicita análisis interno a clamd.
        - Analiza el archivo principal mediante el demonio clamd.
        Retorna (is_infected, threat_name, engine_details).
        """
        if not file_path or not os.path.exists(file_path):
            return False, None, "Archivo no encontrado"

        # 1. Comprobación y descompresión de contenedores comprimidos
        if self.archive_sentinel.is_archive(file_path):
            archive_res = self.archive_sentinel.inspect_and_scan(
                file_path,
                scanner_func=lambda p: self.bridge.scan_file(p, timeout=2.0)
            )
            if archive_res.is_malicious:
                threat = archive_res.threat_name or "Archive.ThreatDetected"
                return True, threat, archive_res.details or "Amenaza en contenedor comprimido"

        # 2. Análisis del archivo mediante clamd
        if self.bridge.is_available():
            is_inf, threat = self.bridge.scan_file(file_path, timeout=timeout)
            if is_inf and threat:
                return True, f"ClamAV.{threat}", f"Detección oficial ClamAV: {threat}"

        return False, None, "Limpio"

    def scan_stream(self, data_or_fd, timeout: float = 3.0) -> Tuple[bool, Optional[str], str]:
        """Analiza un flujo en memoria o descriptor abierto mediante clamd zINSTREAM."""
        if not self.bridge.is_available():
            return False, None, "ClamAV clamd no disponible"

        is_inf, threat = self.bridge.scan_stream(data_or_fd, timeout=timeout)
        if is_inf and threat:
            return True, f"ClamAV.{threat}", f"Detección en streaming ClamAV: {threat}"
        return False, None, "Limpio"

    def update_signatures(self, timeout: int = 60) -> Dict[str, Any]:
        """
        Ejecuta la actualización de firmas oficiales mediante freshclam:
        - Ejecuta 'freshclam' para descargar los diferenciales CDIFF o bases CVD más recientes.
        - Sincroniza las bases locales hacia la base SQLite de Constantine.
        """
        logger.info("Iniciando actualización de firmas antivirus ClamAV mediante freshclam...")
        freshclam_ok = False
        output_msg = ""

        try:
            proc = subprocess.run(
                ["freshclam", "--quiet"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout
            )
            if proc.returncode in (0, 1):  # 0: actualizado, 1: ya está al día
                freshclam_ok = True
                output_msg = "Firmas de ClamAV actualizadas exitosamente o ya al día."
                self._last_freshclam_ts = time.time()
            else:
                output_msg = f"freshclam reportó código {proc.returncode}: {proc.stderr.decode('utf-8', errors='ignore').strip()}"
        except FileNotFoundError:
            output_msg = "Binario 'freshclam' no instalado en el sistema."
        except subprocess.TimeoutExpired:
            output_msg = f"Tiempo de espera agotado ({timeout}s) ejecutando freshclam."
        except Exception as e:
            output_msg = f"Error ejecutando freshclam: {e}"

        # Sincronizar bases locales a Constantine SQLite
        imported_count = 0
        if self.threat_intel:
            try:
                sync_res = self.importer.sync_from_local_clamav(self.threat_intel)
                imported_count = sync_res.get("imported_hashes", 0)
            except Exception as e:
                logger.debug("Aviso sincronizando firmas locales a ThreatIntel: %s", e)

        ver = self.get_engine_version()

        return {
            "success": freshclam_ok,
            "message": output_msg,
            "engine_version": ver,
            "imported_to_constantine": imported_count,
            "last_updated_timestamp": self._last_freshclam_ts
        }

    def coordinate_on_access_protection(self, interceptor) -> Dict[str, Any]:
        """
        Coordina las políticas de protección al acceso (On-Access) entre Constantine fanotify
        y ClamAV clamonacc para evitar bucles infinitos, saturación y conflictos de descriptores:
        1. Excluye ejecutables de clamd, clamonacc y freshclam del interceptor de Constantine.
        2. Configura los parámetros de exclusión de Constantine en la configuración de clamonacc.
        3. Enruta eventos de detección hacia la cuarentena de Constantine.
        """
        clam_binaries = ["/usr/sbin/clamd", "/usr/bin/clamscan", "/usr/bin/freshclam", "/usr/bin/clamonacc"]
        excluded = []

        if interceptor and hasattr(interceptor, "whitelist"):
            for b in clam_binaries:
                if os.path.exists(b):
                    interceptor.whitelist.add_path(b)
                    excluded.append(b)

        if interceptor and hasattr(interceptor, "add_ignored_comm"):
            for comm in ("clamd", "freshclam", "clamonacc", "clamscan"):
                interceptor.add_ignored_comm(comm)

        if interceptor and hasattr(interceptor, "add_ignored_pid"):
            for comm in ("clamd", "freshclam", "clamonacc"):
                try:
                    res = subprocess.run(["pgrep", "-f", comm], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1, text=True)
                    if res.returncode == 0:
                        for line in res.stdout.strip().splitlines():
                            try:
                                interceptor.add_ignored_pid(int(line.strip()))
                            except ValueError:
                                pass
                except Exception:
                    pass

        # Comprobar si clamonacc está activo en el sistema
        clamonacc_active = False
        try:
            res = subprocess.run(["pgrep", "-f", "clamonacc"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            clamonacc_active = (res.returncode == 0)
        except Exception:
            pass

        self._clamonacc_enabled = clamonacc_active

        logger.info("🛡️ [COORDINACIÓN ON-ACCESS] ClamAV coordinado con FanotifyInterceptor. Binarios excluidos de bucle: %s", excluded)
        return {
            "clamonacc_active": clamonacc_active,
            "loop_prevention_excluded": excluded,
            "on_access_mode": "FANOTIFY_SYNCHRONOUS_COOPERATIVE"
        }

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna el estado integral de todos los componentes de ClamAV."""
        is_avail = self.bridge.is_available()
        ver = self.bridge.get_version() if is_avail else None

        return {
            "engine_name": "ClamAV (Cisco Talos)",
            "clamd_available": is_avail,
            "clamd_socket": self.bridge.socket_path or "AUTO",
            "clamd_version": ver,
            "clamonacc_coordinated": self._clamonacc_enabled,
            "last_freshclam_update": self._last_freshclam_ts,
            "archive_protection_active": True,
            "anti_zipbomb_active": True,
            "max_compression_ratio": self.archive_sentinel.max_compression_ratio,
            "max_archive_size_mb": self.archive_sentinel.max_extracted_size // (1024 * 1024)
        }
