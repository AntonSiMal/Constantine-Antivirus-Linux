"""
Constantine Antivirus - Tetragon Kernel Observability & Runtime Enforcement (core/engine/tetragon.py)
Integración nativa con Cilium Tetragon para observabilidad profunda de kernel y aplicación de políticas en tiempo de ejecución:

ARQUITECTURA DE ENFORCEMENT & OBSERVABILIDAD TETRAGON (P0):
1. Observabilidad Profunda de Kernel basada en eBPF:
   - Supervisión de ciclo de vida de procesos (sys_enter_execve, credentials, namespaces).
   - Acceso y modificación de archivos (sys_enter_openat, sys_enter_unlinkat, sys_enter_rename, truncate).
   - Conexiones de red y sockets (sys_enter_connect, tcp_connect, egress hacia C2).
   - Comportamientos anómalos y escaladas de privilegios.
2. Distinción Crítica de Enforcement en Kernel:
   - Sigkill: Terminación asíncrona del proceso atacante. Advertencia: SIGKILL por sí solo
     NO garantiza que una escritura no se haya completado en disco antes de la entrega de la señal.
   - Override (argError: -13 / -EACCES): Anulación inmediata del resultado de la llamada al sistema
     directamente en la capa del kernel de Linux, impidiendo que la operación física (escritura/ejecución)
     llegue a completarse.
   - Coexistencia Fail-Secure con fanotify: Coordinación con Interceptor (FAN_DENY) y Baúl Criptográfico
     (QuarantineVault) para garantizar aislamiento transaccional completo.
3. Operación Autónoma fuera de Kubernetes:
   - Despliegue administrado por systemd (tetragon.service).
   - Políticas locales YAML en /etc/tetragon/tetragon.tp.d/ y /opt/constantine/core/policies/tetragon/.
   - Comunicación mediante socket Unix (/var/run/tetragon/tetragon.sock), CLI tetra y registros JSON.
4. Degradación Elegante y Alta Disponibilidad:
   - Si el servicio Tetragon no está instalado o se detiene, Constantine se degrada de forma transparente
     hacia BCC eBPF / BPF LSM y el centinela heurístico /proc en ebpf_monitor.py.
5. Registro Transparente en sys.modules:
   - Permite 'import tetragon' de manera nativa en todo el ecosistema Constantine.
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import logging
import threading
import subprocess
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("constantine.tetragon")

# Constantes de Rutas del Ecosistema Tetragon
TETRAGON_SOCKET_PATH = "/var/run/tetragon/tetragon.sock"
TETRAGON_LOG_PATH = "/var/log/tetragon/tetragon.log"
TETRAGON_DEFAULT_POLICY_DIR = "/etc/tetragon/tetragon.tp.d"
CONSTANTINE_POLICY_DIR = "/opt/constantine/core/policies/tetragon"
LOCAL_DEV_POLICY_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "policies", "tetragon")


class TetragonEventType(str, Enum):
    """Tipos de eventos soportados por Cilium Tetragon."""
    PROCESS_EXEC = "PROCESS_EXEC"
    PROCESS_EXIT = "PROCESS_EXIT"
    PROCESS_KPROBE = "PROCESS_KPROBE"
    PROCESS_TRACEPOINT = "PROCESS_TRACEPOINT"
    FILE_ACCESS = "FILE_ACCESS"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    UNKNOWN = "UNKNOWN"


@dataclass
class TetragonEvent:
    """Representación normalizada de un evento capturado por Tetragon en el kernel."""
    event_type: TetragonEventType
    timestamp: float
    process_pid: int
    process_binary: str
    process_arguments: str = ""
    process_uid: int = 0
    parent_pid: int = 0
    parent_binary: str = ""
    kprobe_function: Optional[str] = None
    target_path: Optional[str] = None
    action_taken: Optional[str] = None  # Sigkill, Override, Post, Notify
    error_override: Optional[int] = None  # -13 (-EACCES)
    network_destination: Optional[str] = None
    policy_name: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TetragonEvent":
        """Parsea un diccionario JSON emitido por 'tetra getevents' o tetragon.log."""
        ts = time.time()
        time_str = data.get("time")
        if time_str:
            try:
                # Intento de parsear ISO timestamp si está presente
                pass
            except Exception:
                pass

        # Determinar tipo de evento
        event_type = TetragonEventType.UNKNOWN
        kprobe_fn = None
        target_p = None
        action = None
        err_override = None
        net_dst = None
        pol_name = None

        proc_info = data.get("process_exec", {}).get("process", {})
        parent_info = data.get("process_exec", {}).get("parent", {})

        if "process_exec" in data:
            event_type = TetragonEventType.PROCESS_EXEC
        elif "process_exit" in data:
            event_type = TetragonEventType.PROCESS_EXIT
            proc_info = data.get("process_exit", {}).get("process", {})
            parent_info = data.get("process_exit", {}).get("parent", {})
        elif "process_kprobe" in data:
            event_type = TetragonEventType.PROCESS_KPROBE
            pk = data["process_kprobe"]
            proc_info = pk.get("process", {})
            parent_info = pk.get("parent", {})
            kprobe_fn = pk.get("function_name")
            pol_name = pk.get("policy_name")
            action = pk.get("action")

            # Extraer argumentos de kprobe
            args = pk.get("args", [])
            for arg in args:
                if isinstance(arg, dict):
                    if "string_arg" in arg:
                        val = arg["string_arg"]
                        if val.startswith("/") or "." in val:
                            target_p = val
                    elif "sock_arg" in arg:
                        sock = arg["sock_arg"]
                        daddr = sock.get("daddr")
                        dport = sock.get("dport")
                        if daddr and dport:
                            net_dst = f"{daddr}:{dport}"
                            event_type = TetragonEventType.NETWORK_CONNECT

            # Verificar si se aplicó Override o Sigkill
            if action:
                action_str = str(action).upper()
                if "OVERRIDE" in action_str:
                    err_override = -13
                if "SIGKILL" in action_str:
                    action = "SIGKILL"

        pid = int(proc_info.get("pid", 0) or 0)
        binary = proc_info.get("binary", "") or ""
        arguments = proc_info.get("arguments", "") or ""
        uid = int(proc_info.get("uid", 0) or 0)
        ppid = int(parent_info.get("pid", 0) or 0)
        pbin = parent_info.get("binary", "") or ""

        return cls(
            event_type=event_type,
            timestamp=ts,
            process_pid=pid,
            process_binary=binary,
            process_arguments=arguments,
            process_uid=uid,
            parent_pid=ppid,
            parent_binary=pbin,
            kprobe_function=kprobe_fn,
            target_path=target_p,
            action_taken=action,
            error_override=err_override,
            network_destination=net_dst,
            policy_name=pol_name,
            raw_data=data
        )


class TetragonPolicy:
    """Gestor y validador de políticas de trazado TracingPolicy de Tetragon."""

    def __init__(self, raw_yaml: str, file_path: Optional[str] = None):
        self.raw_yaml = raw_yaml
        self.file_path = file_path
        self.parsed_doc: Dict[str, Any] = {}
        self._parse()

    def _parse(self) -> None:
        if HAS_YAML:
            try:
                self.parsed_doc = yaml.safe_load(self.raw_yaml) or {}
            except Exception as e:
                logger.error("Error parseando política YAML de Tetragon: %s", e)
                self.parsed_doc = {}
        else:
            # Fallback simple si no hay PyYAML
            self.parsed_doc = {"spec": {}}

    @property
    def name(self) -> str:
        metadata = self.parsed_doc.get("metadata", {})
        return metadata.get("name", "unnamed-policy")

    @property
    def kind(self) -> str:
        return self.parsed_doc.get("kind", "TracingPolicy")

    def validate(self) -> Tuple[bool, str]:
        """Valida la estructura formal de un TracingPolicy de Tetragon."""
        if not self.parsed_doc:
            return False, "Documento YAML vacío o inválido"
        if self.parsed_doc.get("apiVersion") != "cilium.io/v1alpha1":
            return False, "apiVersion debe ser cilium.io/v1alpha1"
        if self.kind not in ("TracingPolicy", "TracingPolicyNamespaced"):
            return False, f"Tipo de política no soportado: {self.kind}"
        if "spec" not in self.parsed_doc:
            return False, "La política carece de la sección 'spec'"
        return True, "Política válida"

    def has_override_enforcement(self) -> bool:
        """Verifica si la política implementa Override de llamada al sistema (-EACCES)."""
        spec = self.parsed_doc.get("spec", {})
        kprobes = spec.get("kprobes", [])
        for kp in kprobes:
            selectors = kp.get("selectors", [])
            for sel in selectors:
                actions = sel.get("matchActions", [])
                for act in actions:
                    if isinstance(act, dict) and act.get("action") == "Override":
                        return True
                    elif isinstance(act, str) and act.lower() == "override":
                        return True
        return False

    def has_sigkill_action(self) -> bool:
        """Verifica si la política aplica terminación de proceso mediante Sigkill."""
        spec = self.parsed_doc.get("spec", {})
        kprobes = spec.get("kprobes", [])
        for kp in kprobes:
            selectors = kp.get("selectors", [])
            for sel in selectors:
                actions = sel.get("matchActions", [])
                for act in actions:
                    if isinstance(act, dict) and act.get("action") == "Sigkill":
                        return True
                    elif isinstance(act, str) and act.lower() == "sigkill":
                        return True
        return False


class TetragonClient:
    """Cliente para interactuar con el demonio local de Tetragon vía socket Unix o CLI."""

    def __init__(self, socket_path: str = TETRAGON_SOCKET_PATH, log_path: str = TETRAGON_LOG_PATH):
        self.socket_path = socket_path
        self.log_path = log_path
        self._tetra_binary = shutil.which("tetra")

    def is_daemon_running(self) -> bool:
        """Comprueba si el socket de Tetragon o el servicio systemd están activos."""
        if os.path.exists(self.socket_path):
            return True
        # Comprobar estado vía systemctl si no hay socket directo
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "--quiet", "tetragon"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Comprobar si existe proceso tetragon en /proc
        try:
            for pid_dir in os.listdir("/proc"):
                if pid_dir.isdigit():
                    cmdline_path = os.path.join("/proc", pid_dir, "cmdline")
                    if os.path.exists(cmdline_path):
                        with open(cmdline_path, "rb") as f:
                            content = f.read()
                            if b"tetragon" in content:
                                return True
        except Exception:
            pass

        return False

    def get_version(self) -> Optional[str]:
        """Obtiene la versión de Tetragon instalada en el host."""
        if self._tetra_binary:
            try:
                res = subprocess.run(
                    [self._tetra_binary, "version"],
                    capture_output=True,
                    text=True,
                    timeout=2.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip().split("\n")[0]
            except Exception:
                pass
        return None

    def list_loaded_policies(self) -> List[Dict[str, Any]]:
        """Lista las políticas activas en el motor Tetragon."""
        policies = []
        if self._tetra_binary and self.is_daemon_running():
            try:
                res = subprocess.run(
                    [self._tetra_binary, "tracingpolicy", "list", "-o", "json"],
                    capture_output=True,
                    text=True,
                    timeout=3.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    if isinstance(data, list):
                        return data
                    elif isinstance(data, dict):
                        return [data]
            except Exception:
                pass

        # Fallback: Listar políticas presentes en el directorio de configuración
        for pdir in (TETRAGON_DEFAULT_POLICY_DIR, CONSTANTINE_POLICY_DIR, LOCAL_DEV_POLICY_DIR):
            if os.path.exists(pdir):
                for fname in sorted(os.listdir(pdir)):
                    if fname.endswith((".yaml", ".yml")):
                        fpath = os.path.join(pdir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                pol = TetragonPolicy(f.read(), file_path=fpath)
                                valid, _ = pol.validate()
                                if valid:
                                    policies.append({
                                        "name": pol.name,
                                        "file": fpath,
                                        "has_override": pol.has_override_enforcement(),
                                        "has_sigkill": pol.has_sigkill_action(),
                                        "status": "CONFIGURED"
                                    })
                        except Exception:
                            pass
        return policies

    def load_policy_file(self, policy_path: str) -> Tuple[bool, str]:
        """Carga una política TracingPolicy en Tetragon en caliente."""
        if not os.path.exists(policy_path):
            return False, f"Archivo de política no existe: {policy_path}"

        if self._tetra_binary and self.is_daemon_running():
            try:
                res = subprocess.run(
                    [self._tetra_binary, "tracingpolicy", "load", policy_path],
                    capture_output=True,
                    text=True,
                    timeout=5.0
                )
                if res.returncode == 0:
                    return True, "Política cargada exitosamente mediante tetra CLI"
                return False, f"Fallo al cargar política: {res.stderr.strip()}"
            except Exception as e:
                return False, f"Error ejecutando tetra load: {e}"

        # Si el demonio no está ejecutándose con CLI, instalar en directorio de políticas systemd
        target_dir = TETRAGON_DEFAULT_POLICY_DIR
        try:
            if os.path.exists(target_dir) and os.access(target_dir, os.W_OK):
                dst = os.path.join(target_dir, os.path.basename(policy_path))
                shutil.copy2(policy_path, dst)
                return True, f"Política desplegada en {dst} (pendiente de recarga por systemd)"
        except Exception as e:
            return False, f"No se pudo copiar política a {target_dir}: {e}"

        return False, "Tetragon CLI o directorio de políticas no accesible"


class TetragonManager:
    """
    Orquestador Central de Tetragon en Constantine EDR.
    Coordina la observabilidad de llamadas al sistema, enforcement de kernel y mediación con el baúl.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        vault=None,
        firewall=None,
        auto_enforce: bool = True
    ):
        self.alert_callback = alert_callback
        self.vault = vault
        self.firewall = firewall
        self.auto_enforce = auto_enforce

        self.client = TetragonClient()
        self.running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.events_processed = 0
        self.blocked_operations = 0
        self.intercepted_kills = 0
        self.recent_events: List[TetragonEvent] = []
        self._lock = threading.Lock()

        # Rutas de políticas locales
        self.policy_dirs = [
            CONSTANTINE_POLICY_DIR,
            LOCAL_DEV_POLICY_DIR,
            TETRAGON_DEFAULT_POLICY_DIR
        ]

    def is_engine_available(self) -> bool:
        """Determina si Tetragon está instalado y operativo en el host."""
        return self.client.is_daemon_running()

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna información detallada del estado operativo de Tetragon."""
        is_avail = self.is_engine_available()
        version = self.client.get_version() or "No disponible"
        policies = self.client.list_loaded_policies()
        return {
            "available": is_avail,
            "version": version,
            "running": self.running,
            "policies_count": len(policies),
            "policies": policies,
            "events_processed": self.events_processed,
            "blocked_operations": self.blocked_operations,
            "intercepted_kills": self.intercepted_kills,
            "runtime_enforcement": "KERNEL_OVERRIDE_AND_SIGKILL"
        }

    def deploy_policies(self) -> int:
        """Despliega las políticas TracingPolicy de Constantine en el directorio de Tetragon."""
        deployed_count = 0
        src_dir = None
        for cand in (CONSTANTINE_POLICY_DIR, LOCAL_DEV_POLICY_DIR):
            if os.path.exists(cand):
                src_dir = cand
                break

        if not src_dir:
            logger.debug("No se encontró directorio fuente de políticas Tetragon.")
            return 0

        target_dir = TETRAGON_DEFAULT_POLICY_DIR
        try:
            if not os.path.exists(target_dir) and os.geteuid() == 0:
                os.makedirs(target_dir, exist_ok=True)
        except Exception:
            pass

        for fname in os.listdir(src_dir):
            if fname.endswith((".yaml", ".yml")):
                src_path = os.path.join(src_dir, fname)
                success, _ = self.client.load_policy_file(src_path)
                if success:
                    deployed_count += 1
        return deployed_count

    def start(self) -> bool:
        """Inicia el recolector de eventos y centinela de políticas Tetragon."""
        if self.running:
            return True

        if not self.is_engine_available():
            logger.info("ℹ️ Demonio Tetragon no detectado en el host. Operando en modo degradado transparente.")
            return False

        self._stop_event.clear()
        self.running = True
        self._worker_thread = threading.Thread(
            target=self._event_collector_loop,
            name="Constantine-Tetragon-Collector",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("🛡️ Subsistema Tetragon EDR iniciado: Enlace con kernel activo.")
        return True

    def stop(self) -> None:
        """Detiene el hilo de eventos de Tetragon."""
        self.running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("🛑 Subsistema Tetragon EDR detenido.")

    def _event_collector_loop(self) -> None:
        """Bucle consumidor que procesa eventos de Tetragon."""
        # Se prioriza leer de tetra CLI si está disponible
        tetra_bin = self.client._tetra_binary
        if tetra_bin:
            try:
                proc = subprocess.Popen(
                    [tetra_bin, "getevents", "-o", "json"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    bufsize=1
                )
                while self.running and not self._stop_event.is_set():
                    line = proc.stdout.readline()
                    if not line:
                        if proc.poll() is not None:
                            break
                        time.sleep(0.1)
                        continue
                    try:
                        data = json.loads(line)
                        event = TetragonEvent.from_dict(data)
                        self.process_kernel_event(event)
                    except Exception:
                        pass
                proc.terminate()
                return
            except Exception as e:
                logger.debug("No se pudo conectar a tetra getevents: %s", e)

        # Fallback: Seguir el archivo de registro JSON de Tetragon
        log_file = self.client.log_path
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while self.running and not self._stop_event.is_set():
                        line = f.readline()
                        if not line:
                            time.sleep(0.2)
                            continue
                        try:
                            data = json.loads(line)
                            event = TetragonEvent.from_dict(data)
                            self.process_kernel_event(event)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug("Error leyendo log de Tetragon: %s", e)

    def process_kernel_event(self, event: TetragonEvent) -> None:
        """
        Procesa y correlaciona un evento de Tetragon:
        Aplica la diferenciación entre terminación de proceso (SIGKILL) y anulación
        de llamada al sistema (OVERRIDE -13), coordinando con el baúl y cortafuegos.
        """
        with self._lock:
            self.events_processed += 1
            self.recent_events.append(event)
            if len(self.recent_events) > 100:
                self.recent_events.pop(0)

        is_threat = False
        threat_desc = ""

        if event.action_taken == "SIGKILL":
            self.intercepted_kills += 1
            is_threat = True
            threat_desc = f"Tetragon ejecutó SIGKILL sobre PID {event.process_pid} ({event.process_binary})"

        if event.error_override is not None:
            self.blocked_operations += 1
            is_threat = True
            threat_desc += f" | Operación en kernel ANULADA mediante Override: {event.error_override}"

        # Detección heurística de reverse shell si no vino con acción directa
        if event.process_arguments and any(fl in event.process_arguments for fl in ("-e /bin/sh", "-e /bin/bash", "bash -i", "0>&1")):
            is_threat = True
            threat_desc = f"Posible Reverse Shell detectada por Tetragon: {event.process_arguments}"

        if is_threat:
            logger.warning("🚨 [TETRAGON ENFORCEMENT] %s", threat_desc)

            # Notificar al callback de alertas si está configurado
            if self.alert_callback:
                try:
                    self.alert_callback({
                        "source": "TETRAGON_KERNEL_EBPF",
                        "pid": event.process_pid,
                        "binary": event.process_binary,
                        "arguments": event.process_arguments,
                        "target_path": event.target_path,
                        "action": event.action_taken or "OVERRIDE_ENFORCE",
                        "description": threat_desc,
                        "timestamp": event.timestamp
                    })
                except Exception as e:
                    logger.error("Error en callback de alerta Tetragon: %s", e)

            # Si hay un objetivo en disco afectado y se dispone de baúl, aislar
            if event.target_path and os.path.exists(event.target_path) and self.vault:
                try:
                    self.vault.quarantine_file(
                        file_path=event.target_path,
                        reason=f"Tetragon EDR: Intento malicioso interceptado ({threat_desc})"
                    )
                except Exception as e:
                    logger.error("Error aislando archivo objetivo de Tetragon en el baúl: %s", e)


# Instancia singleton predeterminada
_default_tetragon_manager: Optional[TetragonManager] = None


def get_default_manager() -> TetragonManager:
    """Retorna la instancia global compartida de TetragonManager."""
    global _default_tetragon_manager
    if _default_tetragon_manager is None:
        _default_tetragon_manager = TetragonManager()
    return _default_tetragon_manager


def is_available() -> bool:
    """Comprueba si el subsistema Tetragon está disponible en el host."""
    return get_default_manager().is_engine_available()


def get_version() -> Optional[str]:
    """Obtiene la versión del subsistema Tetragon."""
    return get_default_manager().client.get_version()


def load_policy(policy_path: str) -> bool:
    """Carga una política TracingPolicy de Tetragon."""
    success, msg = get_default_manager().client.load_policy_file(policy_path)
    if not success:
        logger.warning("No se pudo cargar política Tetragon: %s", msg)
    return success


def list_policies() -> List[Dict[str, Any]]:
    """Lista las políticas TracingPolicy disponibles en Tetragon."""
    return get_default_manager().client.list_loaded_policies()


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import tetragon' nativo)
# =============================================================================
if "tetragon" not in sys.modules:
    sys.modules["tetragon"] = sys.modules[__name__]
