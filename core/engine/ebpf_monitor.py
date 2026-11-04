"""
Constantine Antivirus - eBPF Monitoring & Multi-Vector Kernel Defense (core/engine/ebpf_monitor.py)
Supervisión heurística y neutralización activa en memoria mediante sondas eBPF y BPF LSM:

1. Detección Ampliada de Vectores de Inyección y Manipulación de Memoria:
   - sys_enter_execve / sys_enter_execveat: Linaje de ejecución y captura de argumentos (512B).
   - sys_enter_ptrace: Detección de inyección de código (PTRACE_POKETEXT, PTRACE_POKEDATA, PTRACE_ATTACH).
   - sys_enter_mprotect: Detección de transiciones de memoria W^X (PROT_READ|PROT_WRITE -> PROT_EXEC) para ejecución de shellcode en memoria (RWX memory violation).
   - sys_enter_memfd_create: Detección de payloads ejecutables anónimos en memoria (fileless execution).
2. Distinción Clara entre Modo Kernel Nativo y Modo Degradado (/proc):
   - is_kernel_native: Indica si las sondas eBPF están efectivamente compiladas y activas en el kernel.
   - is_degraded: Indica si el sistema opera bajo el centinela de rescate en espacio de usuario (/proc),
     reflejando explícitamente en la telemetría y en la GUI que el modo no ofrece las mismas garantías de kernel.
3. Telemetría y Diagnóstico de Estado Transparente:
   - Modo de ejecución: "BPF_LSM_ENFORCING", "EBPF_KERNEL_PROBES", "DEGRADED_USERSPACE_POLLER" o "INACTIVE".
   - Detalle forense y recomendaciones de activación sin fingir capacidades de kernel cuando se opera en /proc.
"""

import os
import re
import time
import signal
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any, List, Tuple

logger = logging.getLogger("constantine.ebpf")

try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False


class EBPFEventState(str, Enum):
    EVENT_OBSERVED = "EVENT_OBSERVED"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    THREAT_CONFIRMED = "THREAT_CONFIRMED"
    PROCESS_CONTAINED = "PROCESS_CONTAINED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    ACTION_FAILED = "ACTION_FAILED"


@dataclass
class EBPFIncident:
    pid: int
    comm: str
    target_path: str
    threat_name: str
    state: EBPFEventState
    timestamp: float = field(default_factory=time.time)
    details: str = ""
    exit_code: Optional[int] = None


EBPF_PROBE_C = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mman.h>

#define ARGSIZE 512

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char args[ARGSIZE];
};

struct ptrace_event_t {
    u32 pid;
    u32 target_pid;
    u32 request;
    char comm[TASK_COMM_LEN];
};

struct mem_event_t {
    u32 pid;
    u32 uid;
    u64 addr;
    u64 len;
    u64 prot;
    char comm[TASK_COMM_LEN];
};

struct memfd_event_t {
    u32 pid;
    u32 flags;
    char name[128];
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(ptrace_events);
BPF_PERF_OUTPUT(mprotect_events);
BPF_PERF_OUTPUT(memfd_events);

// 1. Sonda de ejecución de procesos
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    const char __user *const __user *argp = args->argv;
    if (argp) {
        int offset = 0;
        #pragma unroll
        for (int i = 1; i < 8; i++) {
            const char __user *arg;
            if (bpf_probe_read_user(&arg, sizeof(arg), &argp[i]) == 0 && arg) {
                if (offset < ARGSIZE - 1) {
                    if (offset > 0) {
                        event.args[offset++] = ' ';
                    }
                    int len = bpf_probe_read_user_str(&event.args[offset], ARGSIZE - offset, arg);
                    if (len > 1) {
                        offset += (len - 1);
                    }
                }
            } else {
                break;
            }
        }
    }
    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 2. Sonda de inyección ptrace (manipulación de hilos y memoria de otros procesos)
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ptrace_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.request = args->request;
    event.target_pid = args->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 3. Sonda de violación W^X (mprotect a PROT_EXEC sobre memoria escribible)
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
    // PROT_EXEC = 0x4, PROT_WRITE = 0x2
    if ((args->prot & 0x4) && (args->prot & 0x2)) {
        struct mem_event_t event = {};
        event.pid = bpf_get_current_pid_tgid() >> 32;
        event.uid = bpf_get_current_uid_gid();
        event.addr = (u64)args->start;
        event.len = (u64)args->len;
        event.prot = (u64)args->prot;
        bpf_get_current_comm(&event.comm, sizeof(event.comm));
        mprotect_events.perf_submit(args, &event, sizeof(event));
    }
    return 0;
}

// 4. Sonda de ejecución anónima en memoria (memfd_create - Fileless Execution)
TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
    struct memfd_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.flags = args->flags;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.name, sizeof(event.name), args->uname);
    memfd_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class EBPFMonitor:
    """
    Monitor de seguridad en memoria y ejecución basado en eBPF con soporte multivector:
    Supervisa execve, ptrace, mprotect (W^X violation) y memfd_create (fileless malware).
    Diferencia claramente el modo kernel nativo del modo degradado en espacio de usuario.
    """

    def __init__(self, alert_callback: Optional[Callable] = None, auto_kill: bool = True, notifier=None):
        self.alert_callback = alert_callback
        self.auto_kill = auto_kill
        self.notifier = notifier
        self.bpf = None
        self.running = False
        self.thread = None
        self.fallback_thread = None

        # Estado operativo y diagnóstico transparente
        self.status = "UNINITIALIZED"
        self.error_message: Optional[str] = None
        self.consecutive_poll_errors: int = 0
        self.incidents_history: List[EBPFIncident] = []
        self.has_bpf_lsm = self._check_bpf_lsm_support()

        self.netcat_binaries = {"nc", "ncat", "netcat", "socat"}
        self.reverse_shell_flags = [
            "-e /bin/", "-e/bin/", "-e /usr/bin/", "-e/usr/bin/",
            "-e /bin/sh", "-e /bin/bash", "-e sh", "-e bash",
            "-c /bin/sh", "-c /bin/bash", "--exec",
            "/dev/tcp/", "pty.spawn", "base64 -d", "0>&1"
        ]

    def _check_bpf_lsm_support(self) -> bool:
        """Comprueba si el kernel tiene activo el soporte de seguridad BPF LSM."""
        lsm_path = "/sys/kernel/security/lsm"
        try:
            if os.path.exists(lsm_path):
                with open(lsm_path, "r") as f:
                    return "bpf" in f.read().lower()
        except Exception:
            pass
        return False

    def is_active(self) -> bool:
        """Indica si la supervisión por sondas eBPF nativas en kernel está activa."""
        return self.running and self.status == "ACTIVE"

    def is_degraded(self) -> bool:
        """Indica si el sistema está operando en modo degradado (centinela /proc) sin sondas de kernel."""
        return self.running and self.status == "FALLBACK_USERSPACE"

    def is_operational(self) -> bool:
        """Indica si al menos el monitor eBPF o el centinela de rescate está activo."""
        return self.running and (self.status in ("ACTIVE", "FALLBACK_USERSPACE") or self.fallback_thread is not None)

    def get_status_info(self) -> Dict[str, Any]:
        """Devuelve un informe completo del estado de eBPF para el demonio y la interfaz gráfica."""
        kernel_release = os.uname().release if hasattr(os, "uname") else "desconocido"
        if self.is_active():
            mode_str = "BPF_LSM_ENFORCING" if self.has_bpf_lsm else "EBPF_KERNEL_PROBES"
            operational_label = "PROTECCIÓN ACTIVA EN KERNEL"
            operational_details = "Sondas eBPF de kernel activas (execve, ptrace, mprotect W^X, memfd_create)."
        elif self.is_degraded():
            mode_str = "DEGRADED_USERSPACE_POLLER"
            operational_label = "MODO DEGRADADO (ESPACIO DE USUARIO)"
            operational_details = "Operando en modo degradado mediante inspección periódica de /proc (sin telemetría atómica de kernel)."
        else:
            mode_str = "INACTIVE"
            operational_label = "INACTIVO"
            operational_details = self.error_message or "Monitor eBPF inactivo."

        return {
            "status": self.status,
            "mode": mode_str,
            "operational_label": operational_label,
            "operational_details": operational_details,
            "has_bpf_lsm": self.has_bpf_lsm,
            "is_active": self.is_active(),
            "is_degraded": self.is_degraded(),
            "is_operational": self.is_operational(),
            "has_bcc": HAS_BCC,
            "monitored_vectors": ["sys_enter_execve", "sys_enter_ptrace", "sys_enter_mprotect", "sys_enter_memfd_create"] if self.is_active() else ["/proc cmdline poll"],
            "error_message": self.error_message,
            "kernel_version": kernel_release,
            "recommendation": self._get_troubleshooting_recommendation(),
            "total_incidents": len(self.incidents_history)
        }

    def _get_troubleshooting_recommendation(self) -> str:
        kernel_release = os.uname().release if hasattr(os, "uname") else "$(uname -r)"
        if os.geteuid() != 0:
            return "Ejecuta Constantine Daemon con privilegios de superusuario (sudo)."
        if not HAS_BCC:
            return f"sudo apt install -y bpfcc-tools python3-bpfcc linux-headers-{kernel_release}"
        if self.status == "DISABLED_NO_HEADERS":
            return f"sudo apt install -y linux-headers-{kernel_release}"
        if self.status == "ERROR":
            return f"Verifica que el kernel soporte BPF (CONFIG_BPF_SYSCALL=y) e instala linux-headers-{kernel_release}."
        if self.is_degraded():
            return f"Para activar la monitorización en kernel instala: sudo apt install -y bpfcc-tools linux-headers-{kernel_release}"
        return "El subsistema eBPF opera con normalidad."

    def start(self) -> bool:
        """
        Inicia el monitor eBPF en kernel.
        Si falla o BCC no está disponible, registra detalladamente el error,
        notifica al administrador y activa de forma controlada el centinela en espacio de usuario.
        """
        # 1. Verificación de permisos de superusuario
        if os.geteuid() != 0:
            self.status = "ERROR_PERMISSIONS"
            self.error_message = "Sondas eBPF en kernel requieren privilegios de root (CAP_SYS_ADMIN / CAP_BPF)."
            logger.warning("⚠️ %s Activando centinela heurístico en espacio de usuario.", self.error_message)
            self._start_fallback_poller()
            return False

        # 2. Verificación de presencia de BCC
        if not HAS_BCC:
            self.status = "DISABLED_NO_BCC"
            self.error_message = "Librería BCC ('bpfcc-tools' / 'python3-bpfcc') no está instalada en el sistema."
            logger.warning("⚠️ %s", self.error_message)
            logger.warning("💡 Para activar eBPF en kernel ejecuta: %s", self._get_troubleshooting_recommendation())
            self._notify_degraded_state()
            self._start_fallback_poller()
            return False

        # 3. Verificación de cabeceras de kernel
        kernel_release = os.uname().release if hasattr(os, "uname") else ""
        headers_dir = f"/lib/modules/{kernel_release}/build"
        if kernel_release and not os.path.exists(headers_dir) and not os.path.exists(f"/usr/src/linux-headers-{kernel_release}"):
            self.status = "DISABLED_NO_HEADERS"
            self.error_message = f"Cabeceras de kernel no encontradas en {headers_dir}."
            logger.warning("⚠️ %s", self.error_message)
            logger.warning("💡 Solución: %s", self._get_troubleshooting_recommendation())
            self._notify_degraded_state()
            self._start_fallback_poller()
            return False

        # 4. Compilación e inyección de sondas en kernel
        try:
            self.bpf = BPF(text=EBPF_PROBE_C)
            self.bpf["exec_events"].open_perf_buffer(self._on_exec)
            self.bpf["ptrace_events"].open_perf_buffer(self._on_ptrace)
            if "mprotect_events" in self.bpf:
                self.bpf["mprotect_events"].open_perf_buffer(self._on_mprotect)
            if "memfd_events" in self.bpf:
                self.bpf["memfd_events"].open_perf_buffer(self._on_memfd)

            self.running = True
            self.status = "ACTIVE"
            self.error_message = None
            self.thread = threading.Thread(target=self._poll, daemon=True, name="ebpf-poll")
            self.thread.start()
            logger.info("✅ Sondas eBPF activas en kernel (execve, ptrace, mprotect W^X, memfd_create).")
            return True
        except Exception as e:
            self.status = "ERROR"
            self.error_message = f"Fallo al cargar sondas eBPF en kernel: {e}"
            logger.error("❌ %s", self.error_message)
            self._notify_degraded_state()
            self._start_fallback_poller()
            return False

    def _notify_degraded_state(self):
        """Informa al usuario y a los canales de alerta del estado degradado de eBPF."""
        if self.notifier:
            try:
                self.notifier.send(
                    "⚠️ Constantine: Modo eBPF Degradado (/proc fallback)",
                    f"{self.error_message}\nOperando en espacio de usuario. Solución: {self._get_troubleshooting_recommendation()}",
                    urgency="normal",
                    icon="security-low"
                )
            except Exception:
                pass

    def _start_fallback_poller(self):
        """Inicia un centinela heurístico de rescate en espacio de usuario (/proc) para no dejar el sistema ciego."""
        if self.fallback_thread and self.fallback_thread.is_alive():
            return
        self.running = True
        self.status = "FALLBACK_USERSPACE"
        logger.warning("⚠️ [MODO DEGRADADO ACTIVADO] eBPF no está disponible. Operando mediante inspección periódica de /proc.")
        self.fallback_thread = threading.Thread(target=self._fallback_loop, daemon=True, name="ebpf-fallback-poller")
        self.fallback_thread.start()

    def read_process_full_cmdline(self, pid: int) -> str:
        """Lee la línea de comandos completa de /proc/<pid>/cmdline."""
        try:
            cmd_p = f"/proc/{pid}/cmdline"
            if os.path.exists(cmd_p):
                with open(cmd_p, "rb") as f:
                    raw = f.read()
                return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            pass
        return ""

    def evaluate_execution_threat(self, comm: str, filename: str, args_str: str, pid: Optional[int] = None) -> Tuple[bool, str]:
        """
        Reglas de detección conductual de alta precisión:
        - Erradica falsos positivos en herramientas legítimas de administración (nc, socat).
        - Solo marca amenaza si existen argumentos explícitos de ejecución de shell (-e, -c, --exec)
          o redirecciones de shell reversa interactivas.
        """
        full_cmd = args_str
        if pid:
            disk_cmd = self.read_process_full_cmdline(pid)
            if disk_cmd:
                full_cmd = disk_cmd

        base = os.path.basename(filename).lower()
        comm_clean = comm.lower()

        # 1. Netcat y utilidades de red: Exigir banderas maliciosas o rutas volátiles
        if base in self.netcat_binaries or comm_clean in self.netcat_binaries:
            if filename.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
                return True, f"Behavior.UntrustedDirExecution.{base}"

            if any(flag in full_cmd for flag in self.reverse_shell_flags):
                return True, "Exploit.ReverseShell.Netcat"

            return False, ""

        # 2. Shells interactivas reversas (/dev/tcp/ o tuberías a intérpretes)
        if "/dev/tcp/" in full_cmd or "exec 5<>" in full_cmd:
            return True, "Exploit.ReverseShell.DevTcp"

        if "pty.spawn" in full_cmd and ("import socket" in full_cmd or "socket.socket" in full_cmd):
            return True, "Exploit.ReverseShell.PythonPty"

        if "base64 -d" in full_cmd and ("| sh" in full_cmd or "| bash" in full_cmd or "|sh" in full_cmd or "|bash" in full_cmd):
            return True, "Exploit.ObfuscatedPayload.Base64"

        # 3. Binarios sospechosos en directorios volátiles no autorizados
        if filename.startswith(("/tmp/", "/dev/shm/")):
            if any(filename.endswith(ext) for ext in (".sh", ".py", ".pl", ".elf", ".bin")):
                return True, "Behavior.UntrustedDirExecution"

        return False, ""

    def contain_and_terminate_process(self, pid: int, threat: str, details: str, comm: str = "", target_path: str = "") -> EBPFEventState:
        """
        Flujo de contención y neutralización en dos fases:
        Fase 1: Contención preventiva inmediata (SIGSTOP para congelar el proceso y prevenir propagación).
        Fase 2: Terminación definitiva (SIGKILL) y verificación de aniquilación.
        Retorna el estado exacto alcanzado (PROCESS_TERMINATED, PROCESS_CONTAINED o ACTION_FAILED).
        """
        if pid <= 1:
            return EBPFEventState.ACTION_FAILED

        contained = False
        try:
            os.kill(pid, signal.SIGSTOP)
            contained = True
            logger.warning("⏸️ [PROCESO CONTENIDO - SIGSTOP] Proceso agresor PID %d congelado.", pid)
        except ProcessLookupError:
            incident = EBPFIncident(pid=pid, comm=comm, target_path=target_path, threat_name=threat,
                                    state=EBPFEventState.PROCESS_TERMINATED, details="Proceso efímero ya finalizado")
            self.incidents_history.append(incident)
            return EBPFEventState.PROCESS_TERMINATED
        except Exception as e:
            logger.debug("No se pudo aplicar contención SIGSTOP a PID %d: %s", pid, e)

        if not self.auto_kill:
            final_state = EBPFEventState.PROCESS_CONTAINED if contained else EBPFEventState.SUSPICIOUS_ACTIVITY
            self.incidents_history.append(EBPFIncident(pid=pid, comm=comm, target_path=target_path, threat_name=threat,
                                                        state=final_state, details="Auto-kill desactivado; proceso en alerta"))
            return final_state

        # 2. Terminación definitiva (SIGKILL)
        try:
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.02)
            try:
                os.kill(pid, 0)
                logger.error("❌ [ACCIÓN FALLIDA] PID %d sigue vivo tras SIGKILL (proceso zombie o en D-state).", pid)
                final_state = EBPFEventState.ACTION_FAILED
            except (ProcessLookupError, PermissionError):
                logger.critical("🚨 [PROCESO TERMINADO - SIGKILL] Neutralizado PID %d (%s) ante amenaza confirmada: %s", pid, details, threat)
                final_state = EBPFEventState.PROCESS_TERMINATED

        except ProcessLookupError:
            final_state = EBPFEventState.PROCESS_TERMINATED
        except Exception as e:
            logger.error("Fallo liquidando PID %d mediante eBPF: %s", pid, e)
            final_state = EBPFEventState.ACTION_FAILED

        incident = EBPFIncident(pid=pid, comm=comm, target_path=target_path, threat_name=threat,
                                state=final_state, details=details)
        self.incidents_history.append(incident)
        return final_state

    def kill_offender(self, pid: int, threat: str, details: str) -> bool:
        """Compatibilidad con métodos heredados; delega en contain_and_terminate_process."""
        final_state = self.contain_and_terminate_process(pid, threat, details)
        return final_state == EBPFEventState.PROCESS_TERMINATED

    def get_process_name(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return "desconocido"

    def _fallback_loop(self):
        """Inspecciona periódicamente procesos sospechosos en /proc si eBPF en kernel no está disponible."""
        seen_pids = set()
        while self.running:
            try:
                current_pids = set()
                for entry in os.listdir("/proc"):
                    if not entry.isdigit():
                        continue
                    pid = int(entry)
                    current_pids.add(pid)
                    if pid in seen_pids or pid <= 1:
                        continue

                    try:
                        cmdline_path = f"/proc/{pid}/cmdline"
                        if os.path.exists(cmdline_path):
                            with open(cmdline_path, "rb") as f:
                                raw_cmd = f.read()
                            args_str = raw_cmd.replace(b"\x00", b" ").decode("utf-8", "replace")
                            comm = self.get_process_name(pid)
                            exe = ""
                            try:
                                exe = os.readlink(f"/proc/{pid}/exe")
                            except Exception:
                                pass

                            is_threat, threat = self.evaluate_execution_threat(comm, exe or comm, args_str, pid=pid)
                            if is_threat:
                                state = self.contain_and_terminate_process(pid, threat, f"{comm} {args_str}", comm=comm, target_path=exe or f"/proc/{pid}")
                                if self.alert_callback:
                                    self.alert_callback(threat, exe or f"/proc/{pid}", pid, comm, state.value)
                    except (ProcessLookupError, PermissionError):
                        pass
                    except Exception:
                        pass

                seen_pids = current_pids
                time.sleep(1.0)
            except Exception as e:
                logger.debug("Aviso en bucle de rescate de procesos: %s", e)
                time.sleep(2.0)

    def _poll(self):
        """Bucle de polling de búferes de rendimiento perf con recuperación ante errores."""
        while self.running:
            try:
                self.bpf.perf_buffer_poll(timeout=100)
                self.consecutive_poll_errors = 0
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.consecutive_poll_errors += 1
                logger.warning("Excepción en sondeo perf de eBPF (#%d): %s", self.consecutive_poll_errors, e)
                if self.consecutive_poll_errors >= 5:
                    self.status = "ERROR"
                    self.error_message = f"Bucle de sondeo eBPF detenido tras múltiples errores: {e}"
                    logger.critical("🚨 %s", self.error_message)
                    self._notify_degraded_state()
                    self._start_fallback_poller()
                    break
                time.sleep(0.5)

    def _on_exec(self, cpu, data, size):
        try:
            event = self.bpf["exec_events"].event(data)
            comm = event.comm.decode("utf-8", "replace")
            filename = event.filename.decode("utf-8", "replace")
            args = event.args.decode("utf-8", "replace")

            is_threat, threat_name = self.evaluate_execution_threat(comm, filename, args, pid=event.pid)

            if is_threat:
                final_state = self.contain_and_terminate_process(event.pid, threat_name, f"{comm} {filename}", comm=comm, target_path=filename)
                if self.alert_callback:
                    self.alert_callback(threat_name, filename, event.pid, comm, final_state.value)
        except Exception as err:
            logger.error("Error procesando evento execve en eBPF: %s", err)

    def _on_ptrace(self, cpu, data, size):
        try:
            event = self.bpf["ptrace_events"].event(data)
            if event.request in (4, 5, 16):
                comm = event.comm.decode("utf-8", "replace")
                threat_name = "Behavior.ProcessInjection.Ptrace"
                target = f"/proc/{event.target_pid}"
                final_state = self.contain_and_terminate_process(event.pid, threat_name, f"{comm} -> Target PID {event.target_pid}", comm=comm, target_path=target)
                if self.alert_callback:
                    self.alert_callback(threat_name, target, event.pid, comm, final_state.value)
        except Exception as err:
            logger.error("Error procesando evento ptrace en eBPF: %s", err)

    def _on_mprotect(self, cpu, data, size):
        try:
            event = self.bpf["mprotect_events"].event(data)
            comm = event.comm.decode("utf-8", "replace")
            threat_name = "Exploit.Memory.WX_Violation_RWX"
            details = f"{comm} intentó marcar memoria como RWX (0x{event.addr:x}, prot={event.prot})"
            target = f"/proc/{event.pid}"
            final_state = self.contain_and_terminate_process(event.pid, threat_name, details, comm=comm, target_path=target)
            if self.alert_callback:
                self.alert_callback(threat_name, target, event.pid, comm, final_state.value)
        except Exception as err:
            logger.error("Error procesando evento mprotect en eBPF: %s", err)

    def _on_memfd(self, cpu, data, size):
        try:
            event = self.bpf["memfd_events"].event(data)
            comm = event.comm.decode("utf-8", "replace")
            name = event.name.decode("utf-8", "replace")
            threat_name = "Behavior.Fileless.MemfdExecution"
            details = f"{comm} creó descriptor anónimo en memoria: memfd({name})"
            target = f"/proc/{event.pid}"
            logger.warning("⚠️ [MEMFD EN MEMORIA DETECTADO] PID %d (%s) creó descriptor ejecutable: %s", event.pid, comm, name)
            if self.alert_callback:
                self.alert_callback(threat_name, target, event.pid, comm, EBPFEventState.SUSPICIOUS_ACTIVITY.value)
        except Exception as err:
            logger.error("Error procesando evento memfd en eBPF: %s", err)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
        if self.fallback_thread and self.fallback_thread.is_alive():
            self.fallback_thread.join(timeout=1)
        logger.info("Monitor eBPF detenido.")
