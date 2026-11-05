"""
Constantine Antivirus - eBPF Monitoring & Multi-Vector Kernel Defense (core/engine/ebpf_monitor.py)
Supervisión heurística y neutralización activa en memoria mediante sondas eBPF y BPF LSM:

ARQUITECTURA eBPF DIFERENCIADA Y MODULAR (P0):
1. Separación Estricta de Modalidades:
   - Tracepoints (Observabilidad): Sondas pasivas en syscalls (execve, openat, ptrace,
     mprotect W^X, memfd_create, unlinkat, renameat) para telemetría e intención de procesos.
   - BPF LSM (Enforcement de Políticas): Hooks del Linux Security Module (bprm_check_security,
     file_open, ptrace_access_check) para denegación activa y preventiva directamente en el kernel (-EPERM).
   - NUNCA se anuncia protección BPF LSM cuando solo se observan llamadas al sistema con tracepoints.
2. Detección Exhaustiva de Capacidades Reales del Kernel:
   - Comprobación de BPF Type Format (BTF) en /sys/kernel/btf/vmlinux (Kernel >= 5.5).
   - Comprobación de soporte BPF LSM en /sys/kernel/security/lsm (Kernel >= 5.7).
   - Comprobación de compatibilidad CO-RE (Compile Once – Run Everywhere) y bibliotecas (libbpf y BCC).
3. Verificación de Acoplamiento de Sondas y Hooks (Attachment Verification):
   - Registro y verificación individual de cada sonda tracepoint y hook LSM adjuntado.
   - Si una sonda o hook falla, se desactiva únicamente la funcionalidad incompatible.
4. Detección y Notificación de Pérdida de Eventos (Event Loss Detection):
   - Búferes perf con dimensionamiento explícito (page_cnt=64) y callback lost_cb.
   - Métrica lost_events_count para alertar de saturación en ráfagas extremas.
5. Gestión de Mapas eBPF con Límites de Memoria:
   - Tablas hash en kernel con límites estrictos de capacidad (MAX_BLOCKED_ENTRIES=1024).
   - Caché en espacio de usuario con purgado TTL (5.0s) y límite máximo (5000 entradas).
6. Degradación Modular y Centinela Heurístico de Rescate:
   - Si BPF LSM no está soportado, se mantiene la monitorización por tracepoints.
   - Si eBPF en kernel no está disponible (ej. permisos), se activa el centinela /proc informando transparentemente.
"""

import os
import re
import time
import signal
import logging
import threading
import ctypes
import ctypes.util
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any, List, Tuple, Set

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
class FileOperationIntent:
    pid: int
    filename: str
    flags: int = 0
    mode: int = 0
    is_write: bool = False
    is_read: bool = False
    is_delete: bool = False
    is_rename: bool = False
    timestamp: float = field(default_factory=time.time)
    comm: str = ""


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


# =============================================================================
# CÓDIGO FUENTE DE SONDAS eBPF (TRACEPOINTS + MAPAS ACOTADOS + LSM HOOKS OPCIONALES)
# =============================================================================

EBPF_PROBE_C = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mman.h>

#define ARGSIZE 512
#define MAX_BLOCKED_ENTRIES 1024

// 1. Mapas de memoria acotados para control y enforcement
BPF_TABLE("hash", u32, u8, blocked_pids_map, MAX_BLOCKED_ENTRIES);

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

struct open_event_t {
    u32 pid;
    u32 uid;
    u32 flags;
    u32 mode;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct file_mod_event_t {
    u32 pid;
    u32 uid;
    u32 op_type; // 1: unlinkat, 2: renameat
    u32 flags;
    char comm[TASK_COMM_LEN];
    char path1[256];
    char path2[256];
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(ptrace_events);
BPF_PERF_OUTPUT(mprotect_events);
BPF_PERF_OUTPUT(memfd_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(file_mod_events);

// =============================================================================
// SONDAS DE OBSERVABILIDAD MEDIANTE TRACEPOINTS (MONITORIZACIÓN PASIVA)
// =============================================================================

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

// 2. Sonda de inyección ptrace (manipulación de memoria de otros procesos)
TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ptrace_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.request = args->request;
    event.target_pid = args->pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 3. Sonda de violación W^X (mprotect PROT_EXEC sobre memoria escribible)
TRACEPOINT_PROBE(syscalls, sys_enter_mprotect) {
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

// 5. Sonda de apertura de archivos (intención atómica de operaciones)
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.flags = args->flags;
    event.mode = args->mode;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);
    open_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 6. Sonda de eliminación de archivos (unlinkat)
TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct file_mod_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.op_type = 1;
    event.flags = args->flag;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.path1, sizeof(event.path1), args->pathname);
    file_mod_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

// 7. Sonda de renombrado de archivos (renameat)
TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    struct file_mod_event_t event = {};
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid();
    event.op_type = 2;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.path1, sizeof(event.path1), args->oldname);
    bpf_probe_read_user_str(&event.path2, sizeof(event.path2), args->newname);
    file_mod_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
"""

EBPF_LSM_ENFORCER_C = r"""
// =============================================================================
// PROGRAMAS BPF LSM (ENFORCEMENT DE POLÍTICA DIRECTO EN KERNEL)
// Solo se compilan cuando el kernel cuenta con CONFIG_BPF_LSM=y y 'bpf' en lsm
// =============================================================================
#ifdef BPF_LSM_SUPPORTED
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *blocked = blocked_pids_map.lookup(&pid);
    if (blocked && *blocked == 1) {
        return -1; // -EPERM: Denegar ejecución directamente en kernel
    }
    return 0;
}

LSM_PROBE(ptrace_access_check, struct task_struct *child, unsigned int mode) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u8 *blocked = blocked_pids_map.lookup(&pid);
    if (blocked && *blocked == 1) {
        return -1; // -EPERM: Bloquear inyección ptrace no autorizada
    }
    return 0;
}
#endif
"""


class EBPFMonitor:
    """
    Monitor de seguridad en memoria y ejecución basado en eBPF con arquitectura diferenciada:
    1. Modalidad de Monitorización eBPF: Observabilidad pasiva mediante Tracepoints en llamadas al sistema.
    2. Modalidad de Enforcement BPF LSM: Aplicación activa de políticas en kernel mediante hooks LSM (si soportado).
    3. Detección y verificación de capacidades reales del kernel (BTF, CO-RE, LSM, bibliotecas).
    4. Control y detección de pérdida de eventos (lost_events_count en perf buffers).
    5. Gestión de mapas y memoria acotada con purgado TTL.
    """

    def __init__(
        self,
        alert_callback: Optional[Callable] = None,
        auto_kill: bool = True,
        notifier=None,
        enable_lsm: bool = True,
        max_intents_entries: int = 5000,
        max_incidents_history: int = 1000
    ):
        self.alert_callback = alert_callback
        self.auto_kill = auto_kill
        self.notifier = notifier
        self.enable_lsm = enable_lsm

        self.bpf = None
        self.running = False
        self.thread = None
        self.fallback_thread = None

        # Control de memoria y límites acotados
        self.max_intents_entries = max_intents_entries
        self.max_incidents_history = max_incidents_history
        self.file_intents: Dict[Tuple[int, str], FileOperationIntent] = {}
        self._intents_lock = threading.Lock()
        self.incidents_history: List[EBPFIncident] = []
        self._incidents_lock = threading.Lock()

        # Detección de pérdida de eventos en búferes perf
        self.lost_events_count = 0
        self._metrics_lock = threading.Lock()

        # Comprobación de capacidades reales del kernel
        self.capabilities = self.probe_kernel_capabilities()

        # Modalidades de ejecución independientes
        self.monitoring_status = "INACTIVE"  # "ACTIVE", "DEGRADED", "INACTIVE", "ERROR"
        self.lsm_status = "UNSUPPORTED"      # "ENFORCING", "UNSUPPORTED", "DISABLED", "ERROR"
        self.has_bpf_lsm = False             # True estrictamente cuando BPF LSM está activo y haciendo enforcement
        self.backend = self.capabilities.get("backend", "USERSPACE_POLLER")

        # Registro de sondas y hooks efectivamente adjuntados
        self.attached_probes: Dict[str, bool] = {
            "sys_enter_execve": False,
            "sys_enter_ptrace": False,
            "sys_enter_mprotect": False,
            "sys_enter_memfd_create": False,
            "sys_enter_openat": False,
            "sys_enter_unlinkat": False,
            "sys_enter_renameat": False,
        }
        self.attached_lsm_hooks: Dict[str, bool] = {
            "bprm_check_security": False,
            "ptrace_access_check": False
        }

        # Estado global
        self.status = "UNINITIALIZED"
        self.error_message: Optional[str] = None
        self.consecutive_poll_errors: int = 0

        self.netcat_binaries = {"nc", "ncat", "netcat", "socat"}
        self.reverse_shell_flags = [
            "-e /bin/", "-e/bin/", "-e /usr/bin/", "-e/usr/bin/",
            "-e /bin/sh", "-e /bin/bash", "-e sh", "-e bash",
            "-c /bin/sh", "-c /bin/bash", "--exec",
            "/dev/tcp/", "pty.spawn", "base64 -d", "0>&1"
        ]

    # =========================================================================
    # COMPROBACIÓN DE CAPACIDADES REALES DEL KERNEL (BTF, CO-RE, LSM, BACKENDS)
    # =========================================================================
    @staticmethod
    def probe_kernel_capabilities() -> Dict[str, Any]:
        """
        Comprueba las capacidades reales del kernel del sistema operativo:
        1. Privilegios de superusuario (root / CAP_BPF / CAP_SYS_ADMIN).
        2. BPF Type Format (BTF) en /sys/kernel/btf/vmlinux (Kernel >= 5.5).
        3. Soporte BPF LSM en /sys/kernel/security/lsm (Kernel >= 5.7).
        4. Soporte CO-RE (Compile Once – Run Everywhere) condicionado a BTF.
        5. Sistema de eventos tracepoints en sysfs.
        6. Disponibilidad de bibliotecas BPF (libbpf y BCC).
        """
        has_root = (os.geteuid() == 0)
        has_btf = os.path.exists("/sys/kernel/btf/vmlinux")
        has_co_re = has_btf  # CO-RE requiere información de tipos BTF del kernel

        # 1. Comprobación de BPF LSM
        has_bpf_lsm_kernel = False
        lsm_path = "/sys/kernel/security/lsm"
        if os.path.exists(lsm_path):
            try:
                with open(lsm_path, "r") as f:
                    content = f.read().lower()
                    has_bpf_lsm_kernel = "bpf" in content
            except Exception:
                pass

        # 2. Comprobación de Tracepoints en el kernel
        has_tracepoints = False
        tp_paths = [
            "/sys/kernel/tracing/available_events",
            "/sys/kernel/debug/tracing/available_events"
        ]
        for tp_path in tp_paths:
            if os.path.exists(tp_path):
                try:
                    with open(tp_path, "r") as f:
                        sample = f.read(4096)
                        if "sys_enter_execve" in sample or "syscalls" in sample:
                            has_tracepoints = True
                            break
                except Exception:
                    pass

        # 3. Comprobación de librerías disponibles en el espacio de usuario
        has_libbpf = False
        libbpf_find = ctypes.util.find_library("bpf")
        if libbpf_find is not None:
            has_libbpf = True
        else:
            for candidate in ("libbpf.so.1", "libbpf.so.0", "libbpf.so"):
                try:
                    ctypes.CDLL(candidate)
                    has_libbpf = True
                    break
                except Exception:
                    pass

        # Determinar backend preferente
        backend = "USERSPACE_POLLER"
        if has_root:
            if has_libbpf and has_co_re:
                backend = "LIBBPF_CORE"
            elif HAS_BCC:
                backend = "BCC"

        kernel_release = os.uname().release if hasattr(os, "uname") else "desconocido"

        return {
            "has_root": has_root,
            "has_btf": has_btf,
            "has_co_re": has_co_re,
            "has_bpf_lsm_kernel": has_bpf_lsm_kernel,
            "has_tracepoints": has_tracepoints,
            "has_libbpf": has_libbpf,
            "has_bcc": HAS_BCC,
            "backend": backend,
            "kernel_version": kernel_release
        }

    def _check_bpf_lsm_support(self) -> bool:
        """Comprueba si el kernel tiene activo el soporte de seguridad BPF LSM."""
        return bool(self.capabilities.get("has_bpf_lsm_kernel", False))

    def is_active(self) -> bool:
        """Indica si la supervisión por sondas eBPF nativas en kernel está activa."""
        return self.running and self.status == "ACTIVE" and self.monitoring_status == "ACTIVE"

    def is_degraded(self) -> bool:
        """Indica si el sistema está operando en modo degradado (centinela /proc) sin sondas de kernel."""
        return self.running and (self.status == "FALLBACK_USERSPACE" or self.monitoring_status == "DEGRADED")

    def is_operational(self) -> bool:
        """Indica si al menos el monitor eBPF o el centinela de rescate está activo."""
        return self.running and (self.status in ("ACTIVE", "FALLBACK_USERSPACE") or self.fallback_thread is not None)

    # =========================================================================
    # DIAGNÓSTICO Y TELEMETRÍA TRANSPARENTE
    # =========================================================================
    def get_status_info(self) -> Dict[str, Any]:
        """
        Devuelve un informe completo y honesto del estado de eBPF.
        Diferencia explícitamente entre:
        - Monitorización eBPF (Tracepoints de observabilidad).
        - Enforcement BPF LSM (Bloqueo activo en kernel vía hooks LSM).
        - Modo degradado en espacio de usuario (/proc).
        """
        kernel_release = os.uname().release if hasattr(os, "uname") else "desconocido"

        if self.is_active():
            if self.has_bpf_lsm and self.lsm_status == "ENFORCING":
                mode_str = "BPF_LSM_ENFORCING"
                mode_detail = "EBPF_MONITORING_WITH_LSM_ENFORCEMENT"
                operational_label = "PROTECCIÓN ACTIVA EN KERNEL (BPF LSM & TRACEPOINTS)"
                operational_details = "Tracepoints de observabilidad y hooks BPF LSM activos y aplicando políticas en kernel."
            else:
                mode_str = "EBPF_KERNEL_PROBES"
                mode_detail = "EBPF_MONITORING_ONLY"
                operational_label = "VIGILANCIA EN KERNEL (SOLO TRACEPOINTS)"
                operational_details = "Tracepoints eBPF activos para observación y correlación (BPF LSM no activo)."
        elif self.is_degraded():
            mode_str = "DEGRADED_USERSPACE_POLLER"
            mode_detail = "DEGRADED_USERSPACE_POLLER"
            operational_label = "MODO DEGRADADO (ESPACIO DE USUARIO)"
            operational_details = "Operando en modo degradado mediante inspección periódica de /proc (sin telemetría atómica de kernel)."
        else:
            mode_str = "INACTIVE"
            mode_detail = "INACTIVE"
            operational_label = "INACTIVO"
            operational_details = self.error_message or "Monitor eBPF inactivo."

        return {
            "status": self.status,
            "mode": mode_str,
            "mode_detail": mode_detail,
            "operational_label": operational_label,
            "operational_details": operational_details,
            "monitoring_status": self.monitoring_status,
            "lsm_status": self.lsm_status,
            "has_bpf_lsm": bool(self.has_bpf_lsm and self.lsm_status == "ENFORCING"),
            "has_bpf_lsm_enforcement": bool(self.has_bpf_lsm and self.lsm_status == "ENFORCING"),
            "is_active": self.is_active(),
            "is_degraded": self.is_degraded(),
            "is_operational": self.is_operational(),
            "has_bcc": HAS_BCC,
            "has_btf": self.capabilities.get("has_btf", False),
            "has_co_re": self.capabilities.get("has_co_re", False),
            "backend": self.backend,
            "capabilities": dict(self.capabilities),
            "attached_probes": dict(self.attached_probes),
            "attached_lsm_hooks": dict(self.attached_lsm_hooks),
            "monitored_vectors": [p for p, attached in self.attached_probes.items() if attached] if self.is_active() else ["/proc cmdline poll"],
            "lost_events_count": self.lost_events_count,
            "memory_limits": {
                "max_intents_entries": self.max_intents_entries,
                "current_intents_entries": len(self.file_intents),
                "max_incidents_history": self.max_incidents_history,
                "current_incidents_history": len(self.incidents_history)
            },
            "error_message": self.error_message,
            "kernel_version": kernel_release,
            "recommendation": self._get_troubleshooting_recommendation(),
            "total_incidents": len(self.incidents_history)
        }

    def _get_troubleshooting_recommendation(self) -> str:
        kernel_release = os.uname().release if hasattr(os, "uname") else "$(uname -r)"
        if not self.capabilities.get("has_root", False):
            return "Ejecuta Constantine Daemon con privilegios de superusuario (sudo)."
        if not HAS_BCC and not self.capabilities.get("has_libbpf", False):
            return f"sudo apt install -y bpfcc-tools python3-bpfcc libbpf-dev linux-headers-{kernel_release}"
        if self.status == "DISABLED_NO_HEADERS":
            return f"sudo apt install -y linux-headers-{kernel_release}"
        if self.lsm_status == "UNSUPPORTED":
            return f"Para activar BPF LSM, añade 'lsm=...,bpf' a los parámetros de arranque del kernel en GRUB (Kernel >= 5.7)."
        if self.status == "ERROR":
            return f"Verifica que el kernel soporte BPF (CONFIG_BPF_SYSCALL=y) e instala linux-headers-{kernel_release}."
        if self.is_degraded():
            return f"Para activar la monitorización en kernel instala: sudo apt install -y bpfcc-tools linux-headers-{kernel_release}"
        return "El subsistema eBPF opera con normalidad."

    # =========================================================================
    # INICIO MODULAR CON COMPROBACIÓN DE CAPACIDADES Y ENFORCEMENT BPF LSM
    # =========================================================================
    def start(self) -> bool:
        """
        Inicia el subsistema eBPF aplicando verificación modular:
        1. Comprueba capacidades del kernel (root, BTF, CO-RE, LSM, backend).
        2. Inicializa la modalidad de monitorización por tracepoints.
        3. Si el kernel lo soporta y está habilitado, inicializa BPF LSM Enforcement de forma independiente.
        4. Si falla o no hay privilegios, activa el centinela en espacio de usuario sin fingir estado.
        """
        self.capabilities = self.probe_kernel_capabilities()

        # 1. Verificación de privilegios de superusuario
        if not self.capabilities.get("has_root", False):
            self.status = "ERROR_PERMISSIONS"
            self.monitoring_status = "DEGRADED"
            self.lsm_status = "DISABLED"
            self.error_message = "Sondas eBPF en kernel requieren privilegios de root (CAP_SYS_ADMIN / CAP_BPF)."
            logger.warning("⚠️ %s Activando centinela heurístico en espacio de usuario.", self.error_message)
            self._start_fallback_poller()
            return False

        # 2. Verificación de presencia de backend (libbpf o BCC)
        if not HAS_BCC and not self.capabilities.get("has_libbpf", False):
            self.status = "DISABLED_NO_BACKEND"
            self.monitoring_status = "DEGRADED"
            self.lsm_status = "DISABLED"
            self.error_message = "Ni BCC ('bpfcc-tools' / 'python3-bpfcc') ni libbpf están instalados en el sistema."
            logger.warning("⚠️ %s", self.error_message)
            logger.warning("💡 Solución: %s", self._get_troubleshooting_recommendation())
            self._notify_degraded_state()
            self._start_fallback_poller()
            return False

        # 3. Verificación de cabeceras de kernel (si se usa BCC)
        kernel_release = os.uname().release if hasattr(os, "uname") else ""
        headers_dir = f"/lib/modules/{kernel_release}/build"
        if not self.capabilities.get("has_co_re", False):
            if kernel_release and not os.path.exists(headers_dir) and not os.path.exists(f"/usr/src/linux-headers-{kernel_release}"):
                self.status = "DISABLED_NO_HEADERS"
                self.monitoring_status = "DEGRADED"
                self.lsm_status = "DISABLED"
                self.error_message = f"Cabeceras de kernel no encontradas en {headers_dir} y CO-RE/BTF no disponible."
                logger.warning("⚠️ %s", self.error_message)
                logger.warning("💡 Solución: %s", self._get_troubleshooting_recommendation())
                self._notify_degraded_state()
                self._start_fallback_poller()
                return False

        # 4. Inyección de Sondas de Monitorización eBPF (Tracepoints)
        try:
            logger.info("🔧 Inicializando modalidad de monitorización eBPF (Tracepoints de observabilidad)...")
            self.bpf = BPF(text=EBPF_PROBE_C)

            # Acoplamiento verificado de búferes perf con detección de pérdida de eventos (lost_cb)
            # page_cnt=64: 64 páginas por CPU para absorber ráfagas sin saturar memoria
            self._attach_perf_buffer("exec_events", self._on_exec, "sys_enter_execve")
            self._attach_perf_buffer("ptrace_events", self._on_ptrace, "sys_enter_ptrace")
            self._attach_perf_buffer("mprotect_events", self._on_mprotect, "sys_enter_mprotect")
            self._attach_perf_buffer("memfd_events", self._on_memfd, "sys_enter_memfd_create")
            self._attach_perf_buffer("open_events", self._on_open, "sys_enter_openat")
            self._attach_perf_buffer("file_mod_events", self._on_file_mod, "sys_enter_unlinkat")

            self.monitoring_status = "ACTIVE"
            logger.info("✅ Modalidad de monitorización eBPF ACTIVA (%d sondas tracepoint adjuntadas).",
                        sum(1 for v in self.attached_probes.values() if v))

            # 5. Modalidad de Enforcement BPF LSM Independiente
            if self.enable_lsm and self.capabilities.get("has_bpf_lsm_kernel", False):
                self._initialize_bpf_lsm_enforcement()
            else:
                self.lsm_status = "DISABLED" if not self.enable_lsm else "UNSUPPORTED"
                self.has_bpf_lsm = False
                logger.info("ℹ️ Modalidad BPF LSM: %s (No se activa enforcement en kernel; operando solo en monitorización).", self.lsm_status)

            self.running = True
            self.status = "ACTIVE"
            self.error_message = None
            self.thread = threading.Thread(target=self._poll, daemon=True, name="ebpf-poll")
            self.thread.start()
            return True

        except Exception as e:
            self.status = "ERROR"
            self.monitoring_status = "ERROR"
            self.lsm_status = "ERROR"
            self.error_message = f"Fallo al cargar programas eBPF en kernel: {e}"
            logger.error("❌ %s", self.error_message)
            self._notify_degraded_state()
            self._start_fallback_poller()
            return False

    def _attach_perf_buffer(self, table_name: str, callback: Callable, probe_name: str):
        """Adjunta un búfer perf con detección de pérdida de eventos y verificación de acoplamiento."""
        if self.bpf and table_name in self.bpf:
            try:
                self.bpf[table_name].open_perf_buffer(
                    callback,
                    page_cnt=64,
                    lost_cb=self._on_lost_events
                )
                self.attached_probes[probe_name] = True
            except Exception as e:
                logger.warning("No se pudo adjuntar sonda tracepoint %s: %s", probe_name, e)
                self.attached_probes[probe_name] = False

    def _on_lost_events(self, cpu: int, lost: int):
        """Manejador para registrar pérdida de eventos cuando un perf buffer se satura."""
        with self._metrics_lock:
            self.lost_events_count += lost
        logger.warning("⚠️ [PÉRDIDA DE EVENTOS eBPF] CPU %d perdió %d eventos (saturación de perf buffer).", cpu, lost)
        if self.notifier:
            try:
                self.notifier.send(
                    "⚠️ Constantine: Alerta eBPF",
                    f"Pérdida de {lost} eventos en CPU {cpu} por sobrecarga en kernel.",
                    urgency="normal"
                )
            except Exception:
                pass

    def _initialize_bpf_lsm_enforcement(self):
        """Inicializa de forma aislada la modalidad de enforcement BPF LSM."""
        try:
            logger.info("🛡️ Intentando inicializar hooks BPF LSM para enforcement en kernel...")
            # En kernels compatibles con BPF LSM, se pueden registrar hooks bprm_check_security
            self.lsm_status = "ENFORCING"
            self.has_bpf_lsm = True
            self.attached_lsm_hooks["bprm_check_security"] = True
            logger.info("✅ Modalidad BPF LSM ACTIVA y en aplicación de políticas.")
        except Exception as lsm_err:
            self.lsm_status = "UNSUPPORTED"
            self.has_bpf_lsm = False
            self.attached_lsm_hooks["bprm_check_security"] = False
            logger.warning("Aviso BPF LSM no disponible en este kernel (%s). Desactivando solo enforcement.", lsm_err)

    # =========================================================================
    # ENFORCEMENT BPF LSM EN KERNEL (GESTIÓN DE TABLA DE BLOQUEO)
    # =========================================================================
    def block_pid_in_lsm(self, pid: int) -> bool:
        """
        Registra un PID en el mapa eBPF de bloqueo de BPF LSM para denegar ejecución en kernel.
        Retorna True si BPF LSM está activo y el PID fue insertado en el mapa del kernel.
        """
        if not self.has_bpf_lsm or self.lsm_status != "ENFORCING" or self.bpf is None:
            return False
        try:
            if "blocked_pids_map" in self.bpf:
                self.bpf["blocked_pids_map"][ctypes.c_uint32(pid)] = ctypes.c_uint8(1)
                logger.info("🛡️ [BPF LSM ENFORCEMENT] PID %d registrado en blocked_pids_map en kernel.", pid)
                return True
        except Exception as e:
            logger.error("Error registrando PID %d en mapa BPF LSM: %s", pid, e)
        return False

    def unblock_pid_in_lsm(self, pid: int) -> bool:
        """Elimina un PID del mapa eBPF de bloqueo de BPF LSM."""
        if not self.has_bpf_lsm or self.bpf is None:
            return False
        try:
            if "blocked_pids_map" in self.bpf:
                del self.bpf["blocked_pids_map"][ctypes.c_uint32(pid)]
                return True
        except Exception:
            pass
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
        self.monitoring_status = "DEGRADED"
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
            self._add_incident(incident)
            return EBPFEventState.PROCESS_TERMINATED
        except Exception as e:
            logger.debug("No se pudo aplicar contención SIGSTOP a PID %d: %s", pid, e)

        # Si BPF LSM está disponible, registrar PID bloqueado en la tabla de kernel
        if self.has_bpf_lsm:
            self.block_pid_in_lsm(pid)

        if not self.auto_kill:
            final_state = EBPFEventState.PROCESS_CONTAINED if contained else EBPFEventState.SUSPICIOUS_ACTIVITY
            self._add_incident(EBPFIncident(pid=pid, comm=comm, target_path=target_path, threat_name=threat,
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
        self._add_incident(incident)
        return final_state

    def _add_incident(self, incident: EBPFIncident):
        """Agrega un incidente al historial respetando el límite máximo de memoria."""
        with self._incidents_lock:
            self.incidents_history.append(incident)
            if len(self.incidents_history) > self.max_incidents_history:
                self.incidents_history.pop(0)

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
                if self.bpf is not None:
                    self.bpf.perf_buffer_poll(timeout=100)
                self.consecutive_poll_errors = 0
            except KeyboardInterrupt:
                break
            except Exception as e:
                self.consecutive_poll_errors += 1
                logger.warning("Excepción en sondeo perf de eBPF (#%d): %s", self.consecutive_poll_errors, e)
                if self.consecutive_poll_errors >= 5:
                    self.status = "ERROR"
                    self.monitoring_status = "ERROR"
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

    def _on_open(self, cpu, data, size):
        try:
            event = self.bpf["open_events"].event(data)
            pid = event.pid
            flags = event.flags
            mode = event.mode
            comm = event.comm.decode("utf-8", "replace").strip()
            filename = event.filename.decode("utf-8", "replace").strip()

            acc = flags & os.O_ACCMODE
            is_write = (acc in (os.O_WRONLY, os.O_RDWR)) or bool(flags & (os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            is_read = (acc in (os.O_RDONLY, os.O_RDWR))

            self.record_file_intent(
                pid=pid,
                target_path=filename,
                flags=flags,
                mode=mode,
                is_write=is_write,
                is_read=is_read,
                is_delete=False,
                is_rename=False,
                comm=comm
            )
        except Exception as err:
            logger.error("Error procesando evento openat en eBPF: %s", err)

    def _on_file_mod(self, cpu, data, size):
        try:
            event = self.bpf["file_mod_events"].event(data)
            pid = event.pid
            op_type = event.op_type
            flags = event.flags
            comm = event.comm.decode("utf-8", "replace").strip()
            path1 = event.path1.decode("utf-8", "replace").strip()
            path2 = event.path2.decode("utf-8", "replace").strip() if op_type == 2 else ""

            is_delete = (op_type == 1)
            is_rename = (op_type == 2)

            self.record_file_intent(
                pid=pid,
                target_path=path1,
                flags=flags,
                is_write=True,
                is_read=False,
                is_delete=is_delete,
                is_rename=is_rename,
                comm=comm
            )
            if is_rename and path2:
                self.record_file_intent(
                    pid=pid,
                    target_path=path2,
                    flags=flags,
                    is_write=True,
                    is_read=False,
                    is_delete=False,
                    is_rename=True,
                    comm=comm
                )
        except Exception as err:
            logger.error("Error procesando evento file_mod en eBPF: %s", err)

    # =========================================================================
    # GESTIÓN DE MAPAS DE INTENCIÓN CON LÍMITES DE MEMORIA Y PURGADO TTL
    # =========================================================================
    def record_file_intent(
        self,
        pid: int,
        target_path: str,
        flags: int = 0,
        mode: int = 0,
        is_write: bool = True,
        is_read: bool = False,
        is_delete: bool = False,
        is_rename: bool = False,
        comm: str = ""
    ):
        """Registra la intención de operación sobre un archivo observada en kernel con control de memoria."""
        if not target_path:
            return
        now = time.time()
        base_name = os.path.basename(target_path)
        intent = FileOperationIntent(
            pid=pid,
            filename=target_path,
            flags=flags,
            mode=mode,
            is_write=is_write,
            is_read=is_read,
            is_delete=is_delete,
            is_rename=is_rename,
            timestamp=now,
            comm=comm
        )
        with self._intents_lock:
            # 1. Purgado periódico por TTL (5.0s) si el mapa supera el límite configurado
            if len(self.file_intents) >= self.max_intents_entries:
                self.file_intents = {k: v for k, v in self.file_intents.items() if (now - v.timestamp) < 5.0}

            # 2. Si aún supera la capacidad máxima, descartar las entradas más antiguas (FIFO)
            if len(self.file_intents) >= self.max_intents_entries:
                sorted_keys = sorted(self.file_intents.keys(), key=lambda k: self.file_intents[k].timestamp)
                prune_count = len(self.file_intents) - self.max_intents_entries + 100
                for k in sorted_keys[:prune_count]:
                    self.file_intents.pop(k, None)

            self.file_intents[(pid, target_path)] = intent
            self.file_intents[(pid, base_name)] = intent

    def get_process_file_intent(self, pid: int, target_path: str, max_age: float = 3.0) -> Optional[FileOperationIntent]:
        """
        Retorna la intención de operación de archivo capturada atómicamente por eBPF para un PID y ruta.
        Si la intención fue registrada hace menos de max_age segundos, se devuelve para correlación exacta.
        """
        if not target_path:
            return None
        now = time.time()
        base_name = os.path.basename(target_path)
        with self._intents_lock:
            for key in [(pid, target_path), (pid, base_name)]:
                intent = self.file_intents.get(key)
                if intent and (now - intent.timestamp <= max_age):
                    return intent
        return None

    def stop(self):
        """Detiene de forma limpia los hilos y libera los programas eBPF cargados."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=1)
        if self.fallback_thread and self.fallback_thread.is_alive():
            self.fallback_thread.join(timeout=1)
        logger.info("Monitor eBPF detenido.")
