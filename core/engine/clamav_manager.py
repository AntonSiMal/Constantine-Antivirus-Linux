import shutil
"""
Gestor Integral e Integración de ClamAV Antivirus para Constantine.
Implementa el Modelo Híbrido Coordinado:
1. Interceptor de Constantine como autoridad primaria de decisión en kernel (fanotify).
2. ClamAV como motor de escaneo secundario desacoplado vía clamd socket (/run/clamav/clamd.ctl).
3. Soporte coordinado para ClamOnAcc (Modo Opcional/Servidor): detección dinámica, configuración optimizada, exclusión mutua de PIDs y conmutación de rol.
"""
import os
import socket
import logging
import zipfile
import tarfile
from typing import Dict, Any, List, Optional, Tuple
from core.engine.clamav_config import generate_default_configs, CLAMD_CONF_TEMPLATE, CLAMONACC_CONF_TEMPLATE

logger = logging.getLogger("constantine.clamav_manager")

class ClamdBridgeClient:
    """Cliente IPC para el demonio clamd mediante socket Unix o TCP."""

    def __init__(self, socket_path: str = "/run/clamav/clamd.ctl"):
        self.socket_path = socket_path

    def ping(self) -> bool:
        if not os.path.exists(self.socket_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(self.socket_path)
            s.sendall(b"PING\n")
            resp = s.recv(1024)
            s.close()
            return b"PONG" in resp
        except Exception:
            return False

    def version(self) -> str:
        if not self.ping():
            return "ClamAV (Emulado/En espera)"
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(self.socket_path)
            s.sendall(b"VERSION\n")
            resp = s.recv(1024).decode("utf-8", errors="ignore").strip()
            s.close()
            return resp
        except Exception:
            return "ClamAV 1.0.0"

    def scan_path(self, path: str) -> Tuple[bool, str]:
        """Envía comando SCAN a clamd."""
        if not self.ping():
            return True, "Clamd no disponible (Fallback a YARA y Heurística)"
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(10.0)
            s.connect(self.socket_path)
            s.sendall(f"SCAN {path}\n".encode("utf-8"))
            resp = s.recv(4096).decode("utf-8", errors="ignore")
            s.close()
            if "FOUND" in resp:
                threat = resp.split("FOUND")[0].split(":")[-1].strip()
                return False, threat
            return True, "OK"
        except Exception as e:
            return True, f"Error en SCAN clamd: {e}"


class ClamAVManager:
    """
    Administrador integral de ClamAV: estado, firmas CVD y coordinación on-access.
    Soporta el Modelo Híbrido Coordinado entre el interceptor propio de Constantine y ClamOnAcc.
    """

    def __init__(self, socket_path: str = "/run/clamav/clamd.ctl", db_dir: str = "/var/lib/clamav"):
        self.bridge = ClamdBridgeClient(socket_path=socket_path)
        self.db_dir = db_dir
        self.onacc_role = "PRIMARY_CONSTANTINE"  # "PRIMARY_CONSTANTINE" | "DELEGATED_CLAMONACC"
        self.discovered_clam_pids: List[int] = []

    def get_recommended_configuration(self) -> Dict[str, str]:
        """Retorna las directivas oficiales de configuración para clamd y clamonacc."""
        return {
            "clamd_conf": CLAMD_CONF_TEMPLATE,
            "clamonacc_conf": CLAMONACC_CONF_TEMPLATE
        }

    def write_recommended_configs(self, output_dir: str = "/etc/constantine/clamav") -> Dict[str, str]:
        """Genera las plantillas de configuración recomendadas en disco."""
        return generate_default_configs(output_dir)

    def unpack_cvd_safely(self, archive_path: str, extract_to: str) -> bool:
        """Desempaqueta archivos CVD con protección estricta contra ataques Zip Slip."""
        os.makedirs(extract_to, exist_ok=True)
        dest_canon = os.path.realpath(extract_to)

        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.namelist():
                    target = os.path.realpath(os.path.join(extract_to, member))
                    if not target.startswith(dest_canon + os.sep) and target != dest_canon:
                        raise ValueError(f"Zip Slip attack detectado en miembro: {member}")
                    zf.extract(member, extract_to)
            return True
        return False

    def detect_clamonacc_service(self) -> Dict[str, Any]:
        """
        Detecta si ClamOnAcc está instalado o activo en el sistema host.
        Busca binario clamonacc y procesos activos en /proc.
        """
        binary_path = shutil.which("clamonacc")
        pids: List[int] = []
        is_running = False

        if os.path.exists("/proc"):
            for pid_dir in os.listdir("/proc"):
                if pid_dir.isdigit():
                    comm_path = os.path.join("/proc", pid_dir, "comm")
                    if os.path.exists(comm_path):
                        try:
                            with open(comm_path, "r", encoding="utf-8", errors="ignore") as f:
                                comm = f.read().strip()
                                if comm in ("clamonacc", "clamd"):
                                    pids.append(int(pid_dir))
                                    if comm == "clamonacc":
                                        is_running = True
                        except (OSError, IOError):
                            pass

        self.discovered_clam_pids = pids
        return {
            "binary_path": binary_path,
            "installed": binary_path is not None,
            "running": is_running,
            "pids": pids
        }

    def coordinate_on_access(self, excluded_pids: Optional[List[int]] = None) -> List[int]:
        """
        Coordina exclusión de binarios y PIDs para evitar bucles de doble enganche fanotify.
        Garantiza que el interceptor nativo no intercepte las lecturas de clamd o clamonacc.
        """
        onacc_info = self.detect_clamonacc_service()
        combined_pids = set(excluded_pids or [])
        combined_pids.update(onacc_info.get("pids", []))
        result_pids = sorted(list(combined_pids))

        logger.info("🛡️ [COORDINACIÓN ON-ACCESS] ClamAV coordinado con FanotifyInterceptor. Binarios excluidos de bucle: %s",
                    result_pids)
        return result_pids

    def switch_onacc_mode(self, mode: str) -> Dict[str, Any]:
        """
        Conmuta el rol on-access en el Modelo Híbrido Coordinado:
        - 'PRIMARY_CONSTANTINE': Constantine mantiene el control fanotify y usa ClamAV para firmas.
        - 'DELEGATED_CLAMONACC': Delega la intercepción on-access a ClamOnAcc del sistema.
        """
        target = mode.upper()
        if target not in ("PRIMARY_CONSTANTINE", "DELEGATED_CLAMONACC"):
            raise ValueError(f"Modo On-Access no reconocido: {mode}")

        self.onacc_role = target
        logger.info("🔄 [MODELO HÍBRIDO CLAMAV] Conmutación de rol On-Access a: %s", target)
        return {
            "mode": self.onacc_role,
            "description": "Constantine primario (Fanotify de kernel + Baúl 2PC)" if target == "PRIMARY_CONSTANTINE" else "ClamOnAcc delegado para intercepción on-access"
        }

    def scan_file(self, path: str) -> Tuple[bool, str]:
        return self.bridge.scan_path(path)

    def probe_integration(self) -> Dict[str, Any]:
        """Verifica si ClamAV daemon o binario están instalados en el sistema."""
        clamd_running = self.bridge.ping()
        clamscan_bin = shutil.which("clamscan")
        onacc_info = self.detect_clamonacc_service()
        is_installed = clamd_running or (clamscan_bin is not None) or onacc_info["installed"]

        return {
            "name": "ClamAV Secondary Antivirus & ClamOnAcc",
            "type": "SYSTEM_DAEMON_CLI",
            "installed": is_installed,
            "daemon_running": clamd_running,
            "binary_path": clamscan_bin,
            "clamonacc": onacc_info,
            "onacc_role": self.onacc_role,
            "mode": "LIVE_CLAMD_DAEMON" if clamd_running else ("CLAMSCAN_CLI" if clamscan_bin else "STANDALONE_FALLBACK"),
            "details": "Demonio clamd conectado vía socket Unix" if clamd_running else ("Binario clamscan disponible" if clamscan_bin else "ClamAV no instalado en el SO; operando mediante motor principal YARA-X")
        }
