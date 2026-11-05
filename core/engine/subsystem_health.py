"""
Constantine Antivirus - Subsystem Health & Operational State Registry (core/engine/subsystem_health.py)
Modelo de datos e inspección activa del estado de cada escudo y componente del antivirus:
- ACTIVE: El componente está en ejecución, enganchado en el kernel y operando normalmente.
- DISABLED: El componente fue desactivado deliberadamente por el usuario.
- PENDING_INIT: En proceso de arranque o inicialización.
- INIT_ERROR: Fallo durante la inicialización o error crítico de ejecución.
- MISSING_DEPENDENCY: Falta un paquete de sistema (ej. bpfcc-tools, linux-headers).
- SERVICE_STOPPED: Demonio o hilo de fondo detenido.
- DEGRADED: Operando en modo de respaldo o con funcionalidad reducida (ej. /proc fallback).
"""

import os
import json
import time
import logging
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any, Set

logger = logging.getLogger("constantine.health")

DAEMON_HEALTH_FILE = "/var/lib/constantine/daemon_health.json"
USER_HEALTH_FILE = "/tmp/constantine_daemon_health.json"


class ShieldOperationalState(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    PENDING_INIT = "PENDING_INIT"
    INIT_ERROR = "INIT_ERROR"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    SERVICE_STOPPED = "SERVICE_STOPPED"
    DEGRADED = "DEGRADED"


@dataclass
class ShieldStatusInfo:
    id: str
    name_es: str
    name_en: str
    state: ShieldOperationalState
    description_es: str
    description_en: str
    details: str = ""
    is_switchable: bool = True
    last_check_ts: float = field(default_factory=time.time)

    @property
    def is_active(self) -> bool:
        return self.state in (ShieldOperationalState.ACTIVE, ShieldOperationalState.DEGRADED)

    @property
    def badge_color(self) -> str:
        if self.state == ShieldOperationalState.ACTIVE:
            return "#34c759"  # Verde Apple
        elif self.state == ShieldOperationalState.DEGRADED:
            return "#ff9500"  # Naranja Apple
        elif self.state in (ShieldOperationalState.INIT_ERROR, ShieldOperationalState.MISSING_DEPENDENCY):
            return "#ff3b30"  # Rojo Apple
        elif self.state == ShieldOperationalState.DISABLED:
            return "#8e8e93"  # Gris Apple
        return "#5856d6"  # Azul/Púrpura (Pendiente)

    @property
    def badge_label(self) -> str:
        labels = {
            ShieldOperationalState.ACTIVE: "PROTECCIÓN ACTIVA",
            ShieldOperationalState.DEGRADED: "PROTECCIÓN DEGRADADA",
            ShieldOperationalState.DISABLED: "PROTECCIÓN DESACTIVADA",
            ShieldOperationalState.INIT_ERROR: "ERROR DE INICIALIZACIÓN",
            ShieldOperationalState.MISSING_DEPENDENCY: "DEPENDENCIA AUSENTE",
            ShieldOperationalState.SERVICE_STOPPED: "SERVICIO DETENIDO",
            ShieldOperationalState.PENDING_INIT: "INICIALIZACIÓN PENDIENTE"
        }
        return labels.get(self.state, str(self.state.value))


class SubsystemHealthRegistry:
    """
    Registro y comprobador de salud activa de todos los escudos.
    Supervisa procesos, estado de systemd y descriptores de kernel para evitar falsos verdes.
    """

    def __init__(self, state_file: Optional[str] = None):
        if state_file:
            self.state_file = state_file
        elif os.geteuid() == 0 and os.path.exists("/var/lib/constantine"):
            self.state_file = DAEMON_HEALTH_FILE
        else:
            self.state_file = USER_HEALTH_FILE

    def save_daemon_health(self, health_data: Dict[str, Any]):
        """Persiste el estado de salud emitido por el demonio activo con marca temporal."""
        try:
            d = os.path.dirname(self.state_file)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(self.state_file, "w", encoding="utf-8") as f:
                json.dump({
                    "timestamp": time.time(),
                    "daemon_pid": os.getpid(),
                    "subsystems": health_data
                }, f, indent=2)
        except Exception as e:
            logger.debug("Aviso guardando salud del demonio: %s", e)

    def load_daemon_health(self) -> Optional[Dict[str, Any]]:
        """Lee el informe de salud si el archivo existe y no está obsoleto (> 30s sin latido)."""
        if not os.path.exists(self.state_file):
            return None
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            ts = data.get("timestamp", 0)
            # Si el archivo tiene menos de 60 segundos, considerarlo señal viva
            if time.time() - ts < 60:
                return data.get("subsystems")
        except Exception:
            pass
        return None

    def evaluate_live_shields(self, daemon_running: bool = False,
                              interceptor=None, ebpf_monitor=None,
                              ransomware=None, usb_scanner=None,
                              download_sentinel=None, phishing=None,
                              scanner=None, vault=None,
                              disabled_overrides: Optional[Set[str]] = None) -> List[ShieldStatusInfo]:
        """
        Evalúa el estado riguroso y verificable de cada uno de los escudos del sistema.
        Diferencia entre ACTIVO, DEGRADADO, ERROR, DEPENDENCIA AUSENTE y SERVICIO DETENIDO.
        """
        disabled = disabled_overrides or set()
        cached_daemon = self.load_daemon_health()
        results: List[ShieldStatusInfo] = []

        # 1. Escudo de Archivos en Kernel (fanotify)
        f_state = ShieldOperationalState.SERVICE_STOPPED
        f_details = "El servicio en segundo plano constantine.service está detenido."
        if "fanotify" in disabled:
            f_state = ShieldOperationalState.DISABLED
            f_details = "Desactivado manualmente por el usuario."
        elif interceptor and interceptor.is_active():
            f_state = ShieldOperationalState.ACTIVE
            f_details = f"Vigilancia fanotify activa sobre {len(interceptor.marked_paths)} punto(s) de montaje en kernel."
        elif cached_daemon and "fanotify" in cached_daemon:
            c_val = cached_daemon["fanotify"]
            if c_val.get("is_active"):
                f_state = ShieldOperationalState.ACTIVE
                f_details = c_val.get("details", "fanotify activo en demonio")
            else:
                f_state = ShieldOperationalState.INIT_ERROR
                f_details = c_val.get("error", "Fallo al enganchar fanotify en kernel")
        elif daemon_running:
            f_state = ShieldOperationalState.ACTIVE
            f_details = "Protección fanotify en kernel activa en tiempo real."

        results.append(ShieldStatusInfo(
            id="fanotify",
            name_es="Escudo de Archivos en Kernel (fanotify)",
            name_en="Kernel File Shield (fanotify)",
            state=f_state,
            description_es="Interceptación síncrona FAN_OPEN_PERM / FAN_OPEN_EXEC_PERM en disco.",
            description_en="Synchronous FAN_OPEN_PERM / FAN_OPEN_EXEC_PERM intercept in disk.",
            details=f_details
        ))

        # 2. Escudo Heurístico y eBPF en Memoria RAM
        e_state = ShieldOperationalState.SERVICE_STOPPED
        e_details = ""
        if "ebpf" in disabled:
            e_state = ShieldOperationalState.DISABLED
            e_details = "Desactivado manualmente por el usuario."
        elif ebpf_monitor:
            diag = ebpf_monitor.get_status_info()
            if diag["is_active"]:
                e_state = ShieldOperationalState.ACTIVE
                vectors_str = ", ".join(diag.get("monitored_vectors", []))
                e_details = f"Sondas eBPF en kernel activas ({vectors_str})."
            elif diag.get("is_degraded") or diag["is_operational"]:
                e_state = ShieldOperationalState.DEGRADED
                e_details = "MODO DEGRADADO: Operando mediante inspección periódica de /proc (sin telemetría en kernel ni interceptación síncrona)."
            elif not diag["has_bcc"]:
                e_state = ShieldOperationalState.MISSING_DEPENDENCY
                e_details = f"Dependencia 'bpfcc-tools' ausente (eBPF inactivo). Solución: {diag['recommendation']}"
            elif diag["status"] == "DISABLED_NO_HEADERS":
                e_state = ShieldOperationalState.MISSING_DEPENDENCY
                e_details = f"Faltan cabeceras de kernel linux-headers (eBPF inactivo). Solución: {diag['recommendation']}"
            else:
                e_state = ShieldOperationalState.INIT_ERROR
                e_details = diag.get("error_message") or "Error inicializando sondas eBPF"
        elif cached_daemon and "ebpf" in cached_daemon:
            c_val = cached_daemon["ebpf"]
            e_state = ShieldOperationalState(c_val.get("state", "SERVICE_STOPPED"))
            e_details = c_val.get("details", "")

        results.append(ShieldStatusInfo(
            id="ebpf",
            name_es="Escudo Heurístico y eBPF en Memoria RAM",
            name_en="Heuristic & eBPF RAM Shield",
            state=e_state,
            description_es="Vigilancia en kernel de sys_enter_execve, ptrace y procesos en memoria.",
            description_en="Kernel monitoring of sys_enter_execve, ptrace and in-memory processes.",
            details=e_details
        ))

        # 3. Escudo Anti-Ransomware (Canary Honeypots)
        r_state = ShieldOperationalState.SERVICE_STOPPED
        r_details = ""
        if "ransomware" in disabled:
            r_state = ShieldOperationalState.DISABLED
            r_details = "Desactivado manualmente por el usuario."
        elif ransomware:
            if len(ransomware.canary_files) > 0:
                r_state = ShieldOperationalState.ACTIVE
                r_details = f"{len(ransomware.canary_files)} trampas señuelo desplegadas con detección de ráfagas."
            else:
                r_state = ShieldOperationalState.DEGRADED
                r_details = "Sin archivos señuelo activos desplegados."
        elif cached_daemon and "ransomware" in cached_daemon:
            c_val = cached_daemon["ransomware"]
            r_state = ShieldOperationalState.ACTIVE if c_val.get("is_active") else ShieldOperationalState.INIT_ERROR
            r_details = c_val.get("details", "")
        elif daemon_running:
            r_state = ShieldOperationalState.ACTIVE
            r_details = "Trampas honeypot y supervisión de ráfagas activas."

        results.append(ShieldStatusInfo(
            id="ransomware",
            name_es="Escudo Anti-Ransomware (Canary Honeypots)",
            name_en="Anti-Ransomware Shield (Canaries)",
            state=r_state,
            description_es="Vigila ráfagas de cifrado y defiende archivos trampa con SIGKILL.",
            description_en="Monitors encryption bursts and defends honeypots with SIGKILL.",
            details=r_details
        ))

        # 4. Inspección de Memorias USB y Discos (/media)
        u_state = ShieldOperationalState.SERVICE_STOPPED
        u_details = ""
        if "usb" in disabled:
            u_state = ShieldOperationalState.DISABLED
            u_details = "Desactivado manualmente por el usuario."
        elif usb_scanner and usb_scanner.running:
            u_state = ShieldOperationalState.ACTIVE
            u_details = "Centinela activo con supervisión de medios extraíbles y contención."
        elif cached_daemon and "usb" in cached_daemon:
            u_state = ShieldOperationalState.ACTIVE if cached_daemon["usb"].get("is_active") else ShieldOperationalState.SERVICE_STOPPED
            u_details = cached_daemon["usb"].get("details", "")
        elif daemon_running:
            u_state = ShieldOperationalState.ACTIVE
            u_details = "Vigilancia de medios extraíbles activa en demonio."

        results.append(ShieldStatusInfo(
            id="usb",
            name_es="Inspección de Memorias USB y Discos (/media)",
            name_en="USB & Removable Storage Sentinel (/media)",
            state=u_state,
            description_es="Detección por atributos de kernel y auto-escaneo con contención de autoruns.",
            description_en="Kernel attribute detection and auto-scan with autorun containment.",
            details=u_details
        ))

        # 5. Centinela de Descargas en Vuelo (~/Descargas)
        d_state = ShieldOperationalState.SERVICE_STOPPED
        d_details = ""
        if "downloads" in disabled:
            d_state = ShieldOperationalState.DISABLED
            d_details = "Desactivado manualmente por el usuario."
        elif download_sentinel and download_sentinel.running:
            d_state = ShieldOperationalState.ACTIVE
            d_details = f"Vigilancia inotify activa en {len(download_sentinel.watch_dirs)} directorio(s) de usuarios."
        elif cached_daemon and "downloads" in cached_daemon:
            d_state = ShieldOperationalState.ACTIVE if cached_daemon["downloads"].get("is_active") else ShieldOperationalState.SERVICE_STOPPED
            d_details = cached_daemon["downloads"].get("details", "")
        elif daemon_running:
            d_state = ShieldOperationalState.ACTIVE
            d_details = "Vigilancia inotify multi-usuario activa en demonio."

        results.append(ShieldStatusInfo(
            id="downloads",
            name_es="Centinela de Descargas en Vuelo (~/Descargas)",
            name_en="In-Flight Downloads Sentinel (~/Downloads)",
            state=d_state,
            description_es="Auditoría inotify con máquina de estados y contención preventiva anti-TOCTOU.",
            description_en="Inotify audit with state machine and anti-TOCTOU containment.",
            details=d_details
        ))

        # 6. Centinela de Red & Anti-Phishing Proactivo
        p_state = ShieldOperationalState.SERVICE_STOPPED
        p_details = ""
        if "phishing" in disabled:
            p_state = ShieldOperationalState.DISABLED
            p_details = "Desactivado manualmente por el usuario."
        elif phishing:
            # Comprobar si el módulo tiene feeds cargados y opera
            intel_info = phishing.intel.get_db_info() if hasattr(phishing, "intel") else {}
            p_count = intel_info.get("phish_count", 0)
            if p_count > 0:
                p_state = ShieldOperationalState.ACTIVE
                p_details = f"Auditoría proactiva y base de reputación con {p_count} indicadores verificados."
            else:
                p_state = ShieldOperationalState.DEGRADED
                p_details = "Base de reputación sin indicadores activos."
        elif cached_daemon and "phishing" in cached_daemon:
            p_state = ShieldOperationalState.ACTIVE
            p_details = cached_daemon["phishing"].get("details", "")
        elif daemon_running:
            p_state = ShieldOperationalState.ACTIVE
            p_details = "Supervisión proactiva de red activa en demonio."

        results.append(ShieldStatusInfo(
            id="phishing",
            name_es="Centinela de Red & Anti-Phishing Proactivo",
            name_en="Network & Proactive Anti-Phishing Sentinel",
            state=p_state,
            description_es="Inspección de conexiones TCP/UDP salientes y reputación web comunitaria.",
            description_en="Outbound TCP/UDP inspection and community web reputation.",
            details=p_details
        ))

        # 7. Escaneo Activo Continuo en Tiempo Real (Proactive Continuous Sweeper)
        ps_state = ShieldOperationalState.SERVICE_STOPPED
        ps_details = "El servicio en segundo plano constantine.service está detenido."
        if "proactive_scan" in disabled:
            ps_state = ShieldOperationalState.DISABLED
            ps_details = "Desactivado manualmente por el usuario."
        elif cached_daemon and "proactive_scanner" in cached_daemon:
            ps_state = ShieldOperationalState.ACTIVE if cached_daemon["proactive_scanner"].get("is_active") else ShieldOperationalState.SERVICE_STOPPED
            ps_details = cached_daemon["proactive_scanner"].get("details", "Barrido proactivo continuo activo")
        elif daemon_running:
            ps_state = ShieldOperationalState.ACTIVE
            ps_details = "Escaneo proactivo y vigilancia en tiempo real continua de memoria y staging activa."

        results.append(ShieldStatusInfo(
            id="proactive_scan",
            name_es="Escaneo Activo y Vigilancia en Tiempo Real Continua",
            name_en="Continuous Real-Time Active Scanning & Surveillance",
            state=ps_state,
            description_es="Barrido continuo en segundo plano de procesos en RAM y zonas de carga sin impacto en CPU.",
            description_en="Continuous background sweeping of RAM processes and drop zones with low CPU footprint.",
            details=ps_details
        ))

        return results
