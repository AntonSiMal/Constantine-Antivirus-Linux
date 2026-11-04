"""
Constantine Antivirus - eBPF Monitoring & Active Prevention Engine (core/engine/ebpf_monitor.py)
Supervisión heurística y neutralización activa en memoria mediante sondas eBPF (BCC):
- Rastrea sys_enter_execve y sys_enter_ptrace en tiempo real.
- Detecta reverse shells (/dev/tcp, nc -e), binarios LOLBins, droppers y ataques de inyección.
- CICLO DE VIDA DE EVENTOS CON ESTADOS ESTRICTOS:
    * EVENT_OBSERVED: Evento de llamada al sistema capturado en el búfer.
    * SUSPICIOUS_ACTIVITY: Comportamiento anómalo o argumentos sospechosos.
    * THREAT_CONFIRMED: Amenaza confirmada que viola las políticas de seguridad.
    * PROCESS_CONTAINED: Aislamiento preventivo del proceso (corte de red / pausa SIGSTOP).
    * PROCESS_TERMINATED: Proceso liquidado exitosamente mediante SIGKILL.
    * ACTION_FAILED: Fallo en la neutralización o proceso inaccesible.
- Registro forense honesto: No se reporta 'BLOQUEADO' salvo confirmación verificada de terminación.
"""
import os
import time
import signal
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any, List

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

#define ARGSIZE 128

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

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(ptrace_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.ppid = task->real_parent->tgid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    const char __user *const __user *argp = args->argv;
    const char __user *first_arg;
    if (argp && bpf_probe_read_user(&first_arg, sizeof(first_arg), &argp[1]) == 0 && first_arg) {
        bpf_probe_read_user_str(&event.args, sizeof(event.args), first_arg);
    }
    exec_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ptrace_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.request = args->request;
    event.target_pid = args->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""


class EBPFMonitor:
    def __init__(self, alert_callback: Optional[Callable] = None, auto_kill: bool = True, notifier=None):
        self.alert_callback = alert_callback
        self.auto_kill = auto_kill
        self.notifier = notifier
        self.bpf = None
        self.running = False
        self.thread = None
        self.fallback_thread = None

        # Estado operativo y diagnóstico
        self.status = "UNINITIALIZED"
        self.error_message: Optional[str] = None
        self.consecutive_poll_errors: int = 0
        self.incidents_history: List[EBPFIncident] = []

        self.suspicious_binaries = {"nc", "ncat", "netcat", "socat", "xmrig"}
        self.suspicious_args = ["/dev/tcp/", "-e /bin/sh", "-e /bin/bash", "--exec", "pty.spawn", "base64 -d"]

    def is_active(self) -> bool:
        """Indica si la supervisión por sondas eBPF en kernel está activa."""
        return self.running and self.status == "ACTIVE"

    def is_operational(self) -> bool:
        """Indica si al menos el monitor eBPF o el centinela de rescate está activo."""
        return self.running and (self.status in ("ACTIVE", "FALLBACK_USERSPACE") or self.fallback_thread is not None)

    def get_status_info(self) -> Dict[str, Any]:
        """Devuelve un informe completo del estado de eBPF para el demonio y la interfaz gráfica."""
        kernel_release = os.uname().release if hasattr(os, "uname") else "desconocido"
        return {
            "status": self.status,
            "is_active": self.is_active(),
            "is_operational": self.is_operational(),
            "has_bcc": HAS_BCC,
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
            self.running = True
            self.status = "ACTIVE"
            self.error_message = None
            self.thread = threading.Thread(target=self._poll, daemon=True, name="ebpf-poll")
            self.thread.start()
            logger.info("✅ Sondas eBPF (sys_enter_execve / sys_enter_ptrace) activas con neutralización y trazabilidad de estados.")
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
                    "⚠️ Constantine: eBPF en Modo Compatible",
                    f"{self.error_message}\nActiva eBPF con: {self._get_troubleshooting_recommendation()}",
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
        logger.info("🛡️ Activando Centinela Heurístico de Rescate en espacio de usuario (/proc) como respaldo a eBPF.")
        self.fallback_thread = threading.Thread(target=self._fallback_loop, daemon=True, name="ebpf-fallback-poller")
        self.fallback_thread.start()

    def contain_and_terminate_process(self, pid: int, threat: str, details: str, comm: str = "", target_path: str = "") -> EBPFEventState:
        """
        Flujo de contención y neutralización en dos fases:
        Fase 1: Contención preventiva inmediata (SIGSTOP para congelar el proceso y prevenir propagación).
        Fase 2: Terminación definitiva (SIGKILL) y verificación de aniquilación.
        Retorna el estado exacto alcanzado (PROCESS_TERMINATED, PROCESS_CONTAINED o ACTION_FAILED).
        """
        if pid <= 1:
            return EBPFEventState.ACTION_FAILED

        # 1. Contención preventiva (SIGSTOP)
        contained = False
        try:
            os.kill(pid, signal.SIGSTOP)
            contained = True
            logger.warning("⏸️ [PROCESO CONTENIDO - SIGSTOP] Proceso agresor PID %d congelado.", pid)
        except ProcessLookupError:
            # Proceso ya terminó
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
            # Verificar si el proceso efectivamente murió
            time.sleep(0.02)
            try:
                os.kill(pid, 0)
                # Si sigue respondiendo a signal 0 tras SIGKILL, acción fallida
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

                            if any(arg in args_str for arg in self.suspicious_args):
                                threat = "Exploit.ReverseShell.Payload"
                                state = self.contain_and_terminate_process(pid, threat, f"{comm} {args_str}", comm=comm, target_path=f"/proc/{pid}")
                                if self.alert_callback:
                                    self.alert_callback(threat, f"/proc/{pid}", pid, comm, state.value)
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
            base = os.path.basename(filename)

            # Estado 1: Evento observado
            # self.incidents_history.append(EBPFIncident(pid=event.pid, comm=comm, target_path=filename,
            #                                            threat_name="", state=EBPFEventState.EVENT_OBSERVED))

            is_threat = False
            threat_name = ""

            # Estado 2 / 3: Análisis de sospecha y confirmación
            if any(p in args for p in self.suspicious_args):
                is_threat = True
                threat_name = "Exploit.ReverseShell.Payload"
            elif base in self.suspicious_binaries and (filename.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")) or "nc" in base):
                is_threat = True
                threat_name = f"Behavior.SuspiciousTool.{base}"
            elif filename.startswith(("/tmp/", "/dev/shm/")) and any(ext in filename for ext in (".sh", ".py", ".pl", ".elf")):
                is_threat = True
                threat_name = "Behavior.UntrustedDirExecution"

            if is_threat:
                # Transición: Proceso Contenido -> Terminado o Fallido
                final_state = self.contain_and_terminate_process(event.pid, threat_name, f"{comm} {filename}", comm=comm, target_path=filename)
                if self.alert_callback:
                    self.alert_callback(threat_name, filename, event.pid, comm, final_state.value)
        except Exception as err:
            logger.error("Error procesando evento execve en eBPF: %s", err)

    def _on_ptrace(self, cpu, data, size):
        try:
            event = self.bpf["ptrace_events"].event(data)
            # PTRACE_POKETEXT (4), PTRACE_POKEDATA (5), PTRACE_ATTACH (16)
            if event.request in (4, 5, 16):
                comm = event.comm.decode("utf-8", "replace")
                threat_name = "Behavior.ProcessInjection.Ptrace"
                target = f"/proc/{event.target_pid}"
                final_state = self.contain_and_terminate_process(event.pid, threat_name, f"{comm} -> Target PID {event.target_pid}", comm=comm, target_path=target)
                if self.alert_callback:
                    self.alert_callback(threat_name, target, event.pid, comm, final_state.value)
        except Exception as err:
            logger.error("Error procesando evento ptrace en eBPF: %s", err)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
        if self.fallback_thread and self.fallback_thread.is_alive():
            self.fallback_thread.join(timeout=1)
        logger.info("Monitor eBPF detenido.")
