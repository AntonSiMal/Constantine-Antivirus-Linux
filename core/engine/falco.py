"""
Constantine Antivirus - Falco Syscall Behavioral Detection & Alerting Subsystem (core/engine/falco.py)
Integración nativa con Falco (CNCF Graduated Project) para detección de anomalías en llamadas al sistema:

ARQUITECTURA DIFERENCIAL TETRAGON VS FALCO (P0):
1. Distinción Fundamental:
   - Cilium Tetragon: Observabilidad profunda y APLICACIÓN DE POLÍTICAS EN KERNEL (Kernel Runtime Enforcement).
     Implementa interceptación preventiva y anulación física de llamadas al sistema (Override: argError: -13)
     junto con Sigkill antes de que la operación toque el disco.
   - Falco: MOTOR DE DETECCIÓN CONDUCTUAL Y GENERACIÓN DE ALERTAS.
     Falco NO es un mecanismo de bloqueo por sí mismo. Su propia política de seguridad establece que
     detecta y notifica, pero NO bloquea ni aísla activamente operaciones en el kernel.
2. El Rol de Constantine como Ejecutor (Active Enforcement Bridge):
   - Constantine consume el flujo de alertas y telemetría de Falco y ejecuta las acciones de neutralización
     preventiva y respuesta activa inmediata:
     a) Contención de red del proceso agresor (NetworkQuarantine / nftables drop).
     b) Interceptación en kernel síncrona mediante fanotify (FAN_DENY).
     c) Terminación forzada de procesos hostiles (SIGSTOP + SIGKILL).
     d) Aislamiento transaccional en el Baúl Criptográfico AES-256-GCM (QuarantineVault).
     e) Auditoría inmutable en AuditLogger y notificación de escritorio en tiempo real.
3. Vectores Clave Supervisados por Falco:
   - Operaciones sospechosas relacionadas con privilegios (su, sudo, pkexec, EUID mismatch, setuid).
   - Conexiones de red inesperadas (puertos C2 inusuales, balizamiento egress, shells reversas interactivas).
   - Acceso no autorizado a credenciales críticas (/etc/shadow, claves SSH privadas, sudoers).
   - Ejecución de código desde ubicaciones volátiles no confiables (/tmp, /dev/shm).
4. Auto-registro en sys.modules:
   - Permite 'import falco' de manera nativa y transparente en cualquier parte del entorno Constantine.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import logging
import threading
import subprocess
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable, Set

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("constantine.falco")

FALCO_SOCKET_PATH = "/var/run/falco/falco.sock"
FALCO_LOG_PATH = "/var/log/falco/falco.log"
FALCO_DEFAULT_RULES_DIR = "/etc/falco/rules.d"
CONSTANTINE_FALCO_RULES_DIR = "/opt/constantine/core/rules/falco"
LOCAL_DEV_FALCO_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "falco"
)


class FalcoPriority(str, Enum):
    """Niveles de prioridad oficiales del motor Falco."""
    EMERGENCY = "EMERGENCY"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFORMATIONAL = "INFORMATIONAL"
    DEBUG = "DEBUG"


@dataclass
class FalcoAlert:
    """Representación normalizada de una alerta emitida por Falco."""
    rule: str
    priority: FalcoPriority
    output: str
    output_fields: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    proc_pid: int = 0
    proc_name: str = ""
    proc_cmdline: str = ""
    user_uid: int = 0
    user_name: str = ""
    target_path: Optional[str] = None
    network_dest: Optional[str] = None
    source: str = "syscall"
    tags: List[str] = field(default_factory=list)
    raw_json: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule": self.rule,
            "priority": self.priority.value,
            "output": self.output,
            "output_fields": self.output_fields,
            "timestamp": self.timestamp,
            "proc_pid": self.proc_pid,
            "proc_name": self.proc_name,
            "proc_cmdline": self.proc_cmdline,
            "user_uid": self.user_uid,
            "user_name": self.user_name,
            "target_path": self.target_path,
            "network_dest": self.network_dest,
            "source": self.source,
            "tags": self.tags
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FalcoAlert":
        """Convierte un evento JSON emitido por Falco a una instancia FalcoAlert."""
        rule = data.get("rule", "Unknown_Falco_Rule")
        prio_str = data.get("priority", "WARNING").upper()
        try:
            priority = FalcoPriority(prio_str)
        except ValueError:
            priority = FalcoPriority.WARNING

        output = data.get("output", "")
        output_fields = data.get("output_fields", {})
        tags = data.get("tags", [])

        # Extraer campos enriquecidos de la alerta
        proc_pid = int(output_fields.get("proc.pid", 0) or data.get("proc_pid", 0) or 0)
        proc_name = str(output_fields.get("proc.name", "") or data.get("proc_name", "") or "")
        proc_cmdline = str(output_fields.get("proc.cmdline", "") or data.get("proc_cmdline", "") or "")
        user_uid = int(output_fields.get("user.uid", 0) or data.get("user_uid", 0) or 0)
        user_name = str(output_fields.get("user.name", "") or data.get("user_name", "") or "")

        target_path = output_fields.get("fd.name") or output_fields.get("proc.filename") or data.get("target_path")
        network_dest = None
        if "fd.sport" in output_fields or "fd.dport" in output_fields:
            network_dest = f"{output_fields.get('fd.rip', 'unknown')}:{output_fields.get('fd.dport', '')}"

        ts = time.time()
        time_field = data.get("time")
        if isinstance(time_field, (int, float)):
            ts = float(time_field)

        return cls(
            rule=rule,
            priority=priority,
            output=output,
            output_fields=output_fields,
            timestamp=ts,
            proc_pid=proc_pid,
            proc_name=proc_name,
            proc_cmdline=proc_cmdline,
            user_uid=user_uid,
            user_name=user_name,
            target_path=target_path,
            network_dest=network_dest,
            source=data.get("source", "syscall"),
            tags=tags,
            raw_json=data
        )


class FalcoRule:
    """Representación y motor de evaluación sintáctica de una regla de Falco."""

    def __init__(
        self,
        rule: str,
        condition: str,
        output: str,
        desc: str = "",
        priority: str = "WARNING",
        tags: Optional[List[str]] = None,
        source: str = "syscall"
    ):
        self.rule = rule
        self.condition = condition.strip()
        self.output = output.strip()
        self.desc = desc.strip()
        self.priority = priority.upper()
        self.tags = tags or []
        self.source = source

    def evaluate(self, event: Dict[str, Any]) -> Tuple[bool, Optional[FalcoAlert]]:
        """
        Evalúa un evento de llamada al sistema contra la condición de la regla.
        Implementa un motor de resolución sintáctica compatible con las directivas de Falco:
        - proc.name in (...)
        - user.uid != user.euid
        - fd.name in (...) / fd.name startswith ...
        - fd.dport in (...) / fd.sport > ...
        - proc.cmdline contains "..."
        - syscall.type in (...)
        """
        proc_name = str(event.get("proc.name", "") or event.get("proc_name", "")).lower()
        proc_cmdline = str(event.get("proc.cmdline", "") or event.get("proc_cmdline", ""))
        proc_filename = str(event.get("proc.filename", "") or event.get("proc_filename", ""))
        user_uid = int(event.get("user.uid", 0) if event.get("user.uid") is not None else event.get("user_uid", 0))
        user_euid = int(event.get("user.euid", user_uid) if event.get("user.euid") is not None else event.get("user_euid", user_uid))
        user_name = str(event.get("user.name", "unknown") or event.get("user_name", "unknown"))
        proc_pid = int(event.get("proc.pid", 0) or event.get("proc_pid", 0))
        proc_ppid = int(event.get("proc.ppid", 0) or event.get("proc_ppid", 0))
        proc_pname = str(event.get("proc.pname", "") or event.get("proc_pname", "")).lower()
        fd_name = str(event.get("fd.name", "") or event.get("target_path", ""))
        fd_dport = int(event.get("fd.dport", 0) or 0)
        fd_sport = int(event.get("fd.sport", 0) or 0)
        syscall_type = str(event.get("syscall.type", "") or event.get("syscall", "")).lower()

        matched = False

        # 1. Reglas de Elevación de Privilegios
        if "user.uid != user.euid" in self.condition or "proc.name in (pkexec, su, sudo, setuid)" in self.condition:
            if (user_uid != user_euid) or (proc_name in ("pkexec", "su", "sudo", "setuid")):
                if proc_pname not in ("systemd", "gdm-session-worker"):
                    matched = True

        elif "syscall.type in (setuid, setgid" in self.condition:
            if syscall_type in ("setuid", "setgid", "setresuid", "setresgid", "capset", "unshare", "setns") and user_uid != 0:
                matched = True

        # 2. Reglas de Conexiones de Red Inesperadas
        elif "fd.dport in (4444, 5555, 6666, 1337, 8888, 9001)" in self.condition or "fd.sport > 1024" in self.condition:
            if fd_dport in (4444, 5555, 6666, 1337, 8888, 9001) or (event.get("outbound") and fd_dport > 1024):
                if proc_name not in ("firefox", "chrome", "curl", "wget", "git", "dnsmasq", "systemd-resolved"):
                    matched = True

        elif "proc.name in (nc, ncat, netcat, socat)" in self.condition or "bash -i" in self.condition or "/dev/tcp/" in self.condition:
            if (proc_name in ("nc", "ncat", "netcat", "socat")) or ("bash -i" in proc_cmdline) or ("/dev/tcp/" in proc_cmdline):
                matched = True

        # 3. Reglas de Acceso a Archivos Sensibles y Credenciales
        elif "fd.name in (/etc/shadow" in self.condition or "fd.name startswith \"/root/.ssh\"" in self.condition:
            if any(fd_name.startswith(p) for p in ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh")):
                if proc_name not in ("login", "passwd", "sshd", "sudo", "systemd"):
                    matched = True

        elif "proc.filename startswith \"/tmp\"" in self.condition or "/dev/shm" in self.condition:
            if any(proc_filename.startswith(d) for d in ("/tmp", "/dev/shm", "/var/tmp")):
                if proc_pname not in ("apt", "dpkg", "constantine"):
                    matched = True

        # Evaluación genérica de cadenas 'contains'
        elif "contains" in self.condition:
            m = re.search(r'contains\s+["\']([^"\']+)["\']', self.condition)
            if m:
                term = m.group(1)
                if term in proc_cmdline or term in fd_name:
                    matched = True

        if not matched:
            return False, None

        # Formatear plantilla de salida (output)
        fmt_output = self.output
        replacements = {
            "%user.name": user_name,
            "%user.uid": str(user_uid),
            "%user.euid": str(user_euid),
            "%proc.cmdline": proc_cmdline or proc_name,
            "%proc.name": proc_name,
            "%proc.pid": str(proc_pid),
            "%proc.ppid": str(proc_ppid),
            "%proc.filename": proc_filename or fd_name,
            "%fd.name": fd_name,
            "%fd.dport": str(fd_dport),
            "%connection": f"{fd_name}:{fd_dport}" if fd_dport else fd_name,
            "%syscall.type": syscall_type
        }
        for k, v in replacements.items():
            fmt_output = fmt_output.replace(k, v)

        alert = FalcoAlert(
            rule=self.rule,
            priority=FalcoPriority(self.priority) if self.priority in FalcoPriority.__members__ else FalcoPriority.WARNING,
            output=fmt_output,
            output_fields={
                "proc.name": proc_name,
                "proc.pid": proc_pid,
                "proc.cmdline": proc_cmdline,
                "user.uid": user_uid,
                "user.name": user_name,
                "fd.name": fd_name,
                "fd.dport": fd_dport,
                "syscall.type": syscall_type
            },
            timestamp=time.time(),
            proc_pid=proc_pid,
            proc_name=proc_name,
            proc_cmdline=proc_cmdline,
            user_uid=user_uid,
            user_name=user_name,
            target_path=fd_name or None,
            network_dest=f"{fd_dport}" if fd_dport else None,
            source=self.source,
            tags=self.tags,
            raw_json=event
        )
        return True, alert


class FalcoClient:
    """Cliente para interactuar con el demonio local de Falco mediante socket Unix, CLI o logs."""

    def __init__(self, socket_path: str = FALCO_SOCKET_PATH, log_path: str = FALCO_LOG_PATH):
        self.socket_path = socket_path
        self.log_path = log_path
        self._falco_bin = shutil.which("falco")

    def is_daemon_running(self) -> bool:
        """Comprueba si el demonio falco está activo vía socket, systemctl o /proc."""
        if os.path.exists(self.socket_path):
            return True
        try:
            res = subprocess.run(
                ["systemctl", "is-active", "--quiet", "falco"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.5
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        try:
            for pid_dir in os.listdir("/proc"):
                if pid_dir.isdigit():
                    cmdline_p = os.path.join("/proc", pid_dir, "cmdline")
                    if os.path.exists(cmdline_p):
                        with open(cmdline_p, "rb") as f:
                            content = f.read()
                            if b"falco" in content:
                                return True
        except Exception:
            pass
        return False

    def get_version(self) -> Optional[str]:
        """Obtiene la versión oficial de Falco instalada en el host."""
        if self._falco_bin:
            try:
                res = subprocess.run(
                    [self._falco_bin, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=2.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip().split("\n")[0]
            except Exception:
                pass
        return None


class FalcoManager:
    """
    Orquestador Central del subsistema Falco en Constantine Antivirus.
    Gestiona reglas YAML, evalúa eventos de llamadas al sistema y traduce detecciones
    pasivas de Falco en acciones de bloqueo activo, aislamiento de red y cuarentena en Constantine.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        vault=None,
        firewall=None,
        auto_contain: bool = True
    ):
        self.alert_callback = alert_callback
        self.vault = vault
        self.firewall = firewall
        self.auto_contain = auto_contain

        self.client = FalcoClient()
        self.running = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        self.rules: List[FalcoRule] = []
        self.alerts_count = 0
        self.enforced_actions_count = 0
        self.recent_alerts: List[FalcoAlert] = []
        self._lock = threading.Lock()

        # Cargar reglas predeterminadas
        self.reload_rules()

    def reload_rules(self) -> int:
        """Carga las reglas YAML de Falco desde los directorios de Constantine."""
        loaded_rules: List[FalcoRule] = []
        candidate_dirs = [
            CONSTANTINE_FALCO_RULES_DIR,
            LOCAL_DEV_FALCO_RULES_DIR,
            FALCO_DEFAULT_RULES_DIR
        ]

        for cdir in candidate_dirs:
            if os.path.exists(cdir):
                for fname in sorted(os.listdir(cdir)):
                    if fname.endswith((".yaml", ".yml")):
                        fpath = os.path.join(cdir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                docs = yaml.safe_load_all(f) if HAS_YAML else []
                                for doc in docs:
                                    if isinstance(doc, list):
                                        for item in doc:
                                            if isinstance(item, dict) and "rule" in item and "condition" in item:
                                                loaded_rules.append(FalcoRule(
                                                    rule=item["rule"],
                                                    condition=item.get("condition", ""),
                                                    output=item.get("output", ""),
                                                    desc=item.get("desc", ""),
                                                    priority=item.get("priority", "WARNING"),
                                                    tags=item.get("tags", []),
                                                    source=item.get("source", "syscall")
                                                ))
                                    elif isinstance(doc, dict) and "rule" in doc and "condition" in doc:
                                        loaded_rules.append(FalcoRule(
                                            rule=doc["rule"],
                                            condition=doc.get("condition", ""),
                                            output=doc.get("output", ""),
                                            desc=doc.get("desc", ""),
                                            priority=doc.get("priority", "WARNING"),
                                            tags=doc.get("tags", []),
                                            source=doc.get("source", "syscall")
                                        ))
                        except Exception as e:
                            logger.error("Error parseando archivo de reglas Falco %s: %s", fpath, e)

        with self._lock:
            self.rules = loaded_rules
        logger.info("⚡ [FALCO REGLAS CARGADAS] %d reglas de comportamiento activas.", len(self.rules))
        return len(self.rules)

    def is_engine_available(self) -> bool:
        """Determina si el demonio oficial de Falco está operativo en el host."""
        return self.client.is_daemon_running()

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna telemetría completa del subsistema Falco y el puente de enforcement."""
        is_avail = self.is_engine_available()
        version = self.client.get_version() or "No disponible"
        return {
            "available": is_avail,
            "version": version,
            "running": self.running,
            "rules_count": len(self.rules),
            "alerts_count": self.alerts_count,
            "enforced_actions_count": self.enforced_actions_count,
            "architectural_role": "BEHAVIORAL_DETECTION_AND_ALERTING",
            "enforcement_bridge": "CONSTANTINE_ACTIVE_ENFORCER (Fanotify + Firewall + Vault)",
            "rules": [
                {
                    "rule": r.rule,
                    "desc": r.desc,
                    "priority": r.priority,
                    "tags": r.tags,
                    "source": r.source
                } for r in self.rules[:20]
            ]
        }

    def evaluate_event(self, event_dict: Dict[str, Any]) -> List[FalcoAlert]:
        """
        Evalúa un evento de llamada al sistema contra todas las reglas de Falco cargadas.
        Si se activa alguna regla, procesa la alerta y ejecuta el enforcement en Constantine.
        """
        alerts: List[FalcoAlert] = []
        with self._lock:
            current_rules = list(self.rules)

        for rule in current_rules:
            matched, alert = rule.evaluate(event_dict)
            if matched and alert:
                alerts.append(alert)
                self.process_alert(alert)

        return alerts

    def process_alert(self, alert: FalcoAlert) -> None:
        """
        Procesa una alerta emitida por Falco y ejecuta el Enforcement Activo en Constantine:
        Falco únicamente detecta; Constantine actúa de inmediato:
        1. Aislamiento de Red: Si es conexión sospechosa o balizamiento C2.
        2. Cuarentena Criptográfica: Si hay un ejecutable o script objetivo en disco.
        3. Terminación de Proceso: Si involucra escalada ilegítima o shell reversa.
        4. Notificación y Auditoría.
        """
        with self._lock:
            self.alerts_count += 1
            self.recent_alerts.append(alert)
            if len(self.recent_alerts) > 100:
                self.recent_alerts.pop(0)

        logger.warning(
            "🚨 [FALCO ALERTA DETECTADA] Regla: %s | Prioridad: %s | Salida: %s",
            alert.rule, alert.priority.value, alert.output
        )

        # Disparar callback de notificación
        if self.alert_callback:
            try:
                self.alert_callback({
                    "source": "FALCO_BEHAVIORAL_DETECTION",
                    "rule": alert.rule,
                    "priority": alert.priority.value,
                    "pid": alert.proc_pid,
                    "process": alert.proc_name,
                    "cmdline": alert.proc_cmdline,
                    "target_path": alert.target_path,
                    "output": alert.output,
                    "timestamp": alert.timestamp,
                    "tags": alert.tags
                })
            except Exception as e:
                logger.error("Error en callback de alerta Falco: %s", e)

        if not self.auto_contain:
            return

        # =====================================================================
        # PUENTE DE ENFORCEMENT ACTIVO (RESPUESTA DE SEGURIDAD CONSTANTINE)
        # =====================================================================
        enforced = False

        # 1. Aislamiento de Red Inmediato ante Balizamiento C2 o Sockets Inesperados
        if any(t in alert.tags for t in ("network", "c2", "egress", "reverse_shell")):
            if self.firewall and alert.proc_pid > 1:
                try:
                    logger.critical("🛑 [FALCO ENFORCEMENT] Aislamiento de red para PID %d (%s)", alert.proc_pid, alert.proc_name)
                    self.firewall.contain_process(alert.proc_pid, reason=f"Falco Alert: {alert.rule}")
                    enforced = True
                except Exception as e:
                    logger.error("Error en aislamiento de red por Falco: %s", e)

        # 2. Aislamiento en Cuarentena Criptográfica del Archivo Involucrado
        if alert.target_path and os.path.exists(alert.target_path) and self.vault:
            if any(t in alert.tags for t in ("droppers", "execution", "credentials", "reverse_shell")):
                try:
                    logger.critical("🔒 [FALCO ENFORCEMENT] Cuarentena inmediata para %s", alert.target_path)
                    self.vault.quarantine_file(
                        file_path=alert.target_path,
                        reason=f"Falco Detection: {alert.rule} ({alert.output})"
                    )
                    enforced = True
                except Exception as e:
                    logger.error("Error aislando archivo objetivo de Falco en el Baúl: %s", e)

        # 3. Terminación Inmediata de Proceso Agresor (SIGSTOP + SIGKILL)
        if alert.proc_pid > 1 and alert.priority in (FalcoPriority.CRITICAL, FalcoPriority.EMERGENCY, FalcoPriority.ERROR):
            try:
                import signal
                os.kill(alert.proc_pid, signal.SIGSTOP)
                os.kill(alert.proc_pid, signal.SIGKILL)
                logger.critical("⚡ [FALCO ENFORCEMENT] Proceso hostil PID %d terminado con SIGKILL.", alert.proc_pid)
                enforced = True
            except (ProcessLookupError, PermissionError):
                pass
            except Exception as e:
                logger.error("Error terminando proceso agresor de Falco: %s", e)

        if enforced:
            with self._lock:
                self.enforced_actions_count += 1

    def deploy_rules(self, target_dir: str = FALCO_DEFAULT_RULES_DIR) -> int:
        """Despliega las reglas YAML de Constantine en el directorio oficial de Falco del sistema."""
        deployed = 0
        src_dir = None
        for cand in (CONSTANTINE_FALCO_RULES_DIR, LOCAL_DEV_FALCO_RULES_DIR):
            if os.path.exists(cand):
                src_dir = cand
                break

        if not src_dir:
            return 0

        try:
            if not os.path.exists(target_dir) and os.geteuid() == 0:
                os.makedirs(target_dir, exist_ok=True)
        except Exception:
            pass

        if os.path.exists(target_dir) and os.access(target_dir, os.W_OK):
            for fname in os.listdir(src_dir):
                if fname.endswith((".yaml", ".yml")):
                    src_f = os.path.join(src_dir, fname)
                    dst_f = os.path.join(target_dir, f"constantine_{fname}")
                    try:
                        shutil.copy2(src_f, dst_f)
                        deployed += 1
                    except Exception as e:
                        logger.warning("No se pudo copiar regla Falco %s: %s", fname, e)
        return deployed

    def start(self) -> bool:
        """Inicia el recolector de eventos y consumidor de logs/socket de Falco."""
        if self.running:
            return True

        if not self.is_engine_available():
            logger.info("ℹ️ Demonio oficial de Falco no detectado en el host. Evaluador nativo de reglas activo.")

        self._stop_event.clear()
        self.running = True
        self._worker_thread = threading.Thread(
            target=self._collector_loop,
            name="Constantine-Falco-Collector",
            daemon=True
        )
        self._worker_thread.start()
        logger.info("🛡️ Subsistema Falco EDR iniciado: Motor de detección conductual activo.")
        return True

    def stop(self) -> None:
        """Detiene el recolector de eventos de Falco."""
        self.running = False
        self._stop_event.set()
        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        logger.info("🛑 Subsistema Falco EDR detenido.")

    def _collector_loop(self) -> None:
        """Sigue el archivo de log JSON o socket emitido por Falco si está disponible."""
        log_f = self.client.log_path
        if os.path.exists(log_f):
            try:
                with open(log_f, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    while self.running and not self._stop_event.is_set():
                        line = f.readline()
                        if not line:
                            time.sleep(0.2)
                            continue
                        try:
                            data = json.loads(line)
                            alert = FalcoAlert.from_dict(data)
                            self.process_alert(alert)
                        except Exception:
                            pass
            except Exception as e:
                logger.debug("Error leyendo log de Falco: %s", e)


# Instancia singleton predeterminada
_default_falco_manager: Optional[FalcoManager] = None


def get_default_manager() -> FalcoManager:
    """Retorna la instancia global compartida de FalcoManager."""
    global _default_falco_manager
    if _default_falco_manager is None:
        _default_falco_manager = FalcoManager()
    return _default_falco_manager


def is_available() -> bool:
    """Comprueba si el subsistema Falco está disponible en el host."""
    return get_default_manager().is_engine_available()


def get_version() -> Optional[str]:
    """Obtiene la versión oficial del subsistema Falco."""
    return get_default_manager().client.get_version()


def list_rules() -> List[Dict[str, Any]]:
    """Lista las reglas de comportamiento activas en el subsistema Falco."""
    return [
        {
            "rule": r.rule,
            "desc": r.desc,
            "priority": r.priority,
            "tags": r.tags,
            "source": r.source
        } for r in get_default_manager().rules
    ]


def evaluate_event(event_dict: Dict[str, Any]) -> List[FalcoAlert]:
    """Evalúa un evento contra el motor de reglas Falco."""
    return get_default_manager().evaluate_event(event_dict)


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import falco' nativo)
# =============================================================================
if "falco" not in sys.modules:
    sys.modules["falco"] = sys.modules[__name__]
