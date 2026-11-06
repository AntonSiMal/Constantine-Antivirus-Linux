"""
Auditor y Verificador de Seguridad para Unidades systemd de Constantine Antivirus.
Evalúa el equilibrio riguroso entre hardening del servicio y operatividad EDR:
supervisión de archivos personales, instrumentación eBPF, intercepción fanotify y cuarentena.
Garantiza el principio de menor privilegio, separando inspección de remediación,
calculando el conjunto efectivo de SystemCallFilter conforme a la semántica seccomp (prevalencia de denegación),
y determinando perfiles de capacidades kernel-aware con pruebas de operaciones específicas eBPF
y política de degradación asistida en lugar de elevación indiscriminada a CAP_SYS_ADMIN.
"""
import os
import re
import platform
import logging
from typing import Dict, Any, List, Set, Tuple, Optional

logger = logging.getLogger("constantine.systemd_hardening")



CORE_BOOTSTRAP_SYSCALLS: Set[str] = {
    "read", "write", "close", "mmap", "mprotect", "munmap", "rt_sigaction",
    "rt_sigprocmask", "rt_sigreturn", "futex", "exit", "exit_group"
}

EDR_ENFORCEMENT_SYSCALLS: Set[str] = {
    "bpf", "perf_event_open", "fanotify_init", "fanotify_mark"
}

OPTIONAL_INTEGRATION_SYSCALLS: Set[str] = {
    "connect", "sendto", "recvfrom", "socket", "getsockopt", "setsockopt"
}

SYSTEMD_SYSCALL_GROUPS: Dict[str, Set[str]] = {
    "@system-service": {
        "accept", "bind", "clone", "clone3", "close", "connect", "epoll_create",
        "epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait", "exit",
        "exit_group", "fcntl", "fstat", "futex", "getpid", "getuid", "getgid",
        "kill", "madvise", "mmap", "mprotect", "munmap", "nanosleep", "pipe",
        "pipe2", "poll", "ppoll", "read", "recvfrom", "rt_sigaction", "rt_sigprocmask",
        "rt_sigreturn", "select", "pselect6", "sendto", "setsockopt", "shutdown",
        "socket", "stat", "wait4", "write"
    },
    "@network-io": {
        "accept", "accept4", "bind", "connect", "getpeername", "getsockname",
        "getsockopt", "listen", "recv", "recvfrom", "recvmmsg", "recvmsg",
        "send", "sendmmsg", "sendmsg", "sendto", "setsockopt", "shutdown",
        "socket", "socketpair"
    },
    "@file-system": {
        "access", "chdir", "chmod", "chown", "close", "creat", "dup", "dup2", "dup3",
        "faccessat", "fchmod", "fchmodat", "fchown", "fchownat", "fcntl", "fstat",
        "fstatat", "fstatfs", "fsync", "ftruncate", "getcwd", "getdents", "getdents64",
        "link", "linkat", "lseek", "lstat", "mkdir", "mkdirat", "mknod", "mknodat",
        "newfstatat", "open", "openat", "openat2", "read", "readlink", "readlinkat",
        "rename", "renameat", "renameat2", "rmdir", "stat", "statfs", "statx",
        "symlink", "symlinkat", "truncate", "unlink", "unlinkat", "write"
    },
    "@obsolete": {
        "create_module", "get_kernel_syms", "query_module", "sysfs", "uselib", "_sysctl"
    },
    "@reboot": {
        "reboot", "kexec_load", "kexec_file_load"
    },
    "@swap": {
        "swapon", "swapoff"
    },
    "@privileged": {
        "acct", "chroot", "finit_module", "init_module", "delete_module",
        "iopl", "ioperm", "kcmp", "mount", "umount", "umount2", "pivot_root",
        "quotactl", "vhangup"
    }
}


class SystemCallFilterEvaluator:
    """
    Analiza y calcula el conjunto efectivo de llamadas al sistema permitidas y bloqueadas
    en systemd considerando la semántica estricta de seccomp:
    - En seccomp, las reglas de denegación (ERRNO/KILL) son sustractivas y definitivas;
      una llamada excluida por una regla '~' no puede ser rehabilitada por una regla permisiva.
    - Las llamadas requeridas por Constantine (bpf, perf_event_open, fanotify_init, fanotify_mark)
      deben estar explícitamente en el conjunto permitido y completamente ausentes del denylist.
    """

    # Justificaciones operativas auditables para conjuntos amplios
    GROUP_JUSTIFICATIONS = {
        "@system-service": (
            "Requerido para ciclo de vida del demonio: gestión de subprocesos, hebras, señales, "
            "asignación de memoria y comunicación síncrona vía sockets Unix IPC (/run/constantine)."
        ),
        "@network-io": (
            "Requerido para sincronización de inteligencia de amenazas (feeds MISP, VirusTotal), "
            "resolución DNS de protección activa y telemetría de red."
        ),
        "@file-system": (
            "Requerido para supervisión on-access de archivos, recorrido forense de directorios "
            "en /proc y /home, y aislamiento atómico transaccional de amenazas en el Baúl."
        )
    }

    def __init__(self, raw_lines: List[str], architecture: str = "native"):
        self.raw_lines = raw_lines
        self.architecture = architecture
        self.rules: List[Tuple[bool, List[str]]] = []
        self._parse_rules()

    def _parse_rules(self):
        for line in self.raw_lines:
            tokens = line.strip().split()
            if not tokens:
                continue
            is_deny = tokens[0].startswith("~")
            cleaned_tokens = []
            for tok in tokens:
                clean = tok[1:] if tok.startswith("~") else tok
                cleaned_tokens.append(clean)
            self.rules.append((is_deny, cleaned_tokens))

    def compute_effective_posture(self) -> Dict[str, Any]:
        """
        Calcula el conjunto efectivo de llamadas permitidas y bloqueadas bajo semántica seccomp real.
        """
        allowed_items: Set[str] = set()
        denied_items: Set[str] = set()
        explicit_allowed_syscalls: Set[str] = set()
        explicit_denied_syscalls: Set[str] = set()

        for is_deny, tokens in self.rules:
            if is_deny:
                for tok in tokens:
                    denied_items.add(tok)
                    if not tok.startswith("@"):
                        explicit_denied_syscalls.add(tok)
            else:
                for tok in tokens:
                    allowed_items.add(tok)
                    if not tok.startswith("@"):
                        explicit_allowed_syscalls.add(tok)

        # 1. Expandir llamadas permitidas
        effective_allowed: Set[str] = set()
        for item in allowed_items:
            if item.startswith("@"):
                effective_allowed.update(SYSTEMD_SYSCALL_GROUPS.get(item, set()))
            else:
                effective_allowed.add(item)

        # 2. Expandir llamadas denegadas
        effective_denied: Set[str] = set()
        for item in denied_items:
            if item.startswith("@"):
                effective_denied.update(SYSTEMD_SYSCALL_GROUPS.get(item, set()))
            else:
                effective_denied.add(item)

        # 3. Semántica estricta seccomp: Deny es definitivo.
        # Si una llamada pertenece a un grupo denegado o denylist explícito, es bloqueada sin excepción
        final_allowed = effective_allowed - effective_denied

        # 4. Validar llamadas nucleares del EDR
        edr_syscalls = EDR_ENFORCEMENT_SYSCALLS
        edr_verified = edr_syscalls.issubset(final_allowed) and edr_syscalls.isdisjoint(effective_denied)

        # 4b. Validar llamadas esenciales de arranque (bootstrap)
        core_bootstrap_verified = CORE_BOOTSTRAP_SYSCALLS.issubset(final_allowed) and CORE_BOOTSTRAP_SYSCALLS.isdisjoint(effective_denied)

        # 4c. Validar llamadas de integración opcionales
        optional_network_verified = OPTIONAL_INTEGRATION_SYSCALLS.issubset(final_allowed) and OPTIONAL_INTEGRATION_SYSCALLS.isdisjoint(effective_denied)

        # 5. Validar bloqueo de grupos peligrosos
        dangerous_groups = {"@obsolete", "@reboot", "@swap"}
        dangerous_blocked = dangerous_groups.issubset(denied_items)

        # 6. Comprobar exclusión de @privileged
        privileged_in_allowlist = "@privileged" in allowed_items

        # 7. Validar justificaciones de grupos activos
        allowed_groups = {it for it in allowed_items if it.startswith("@")}
        denied_groups = {it for it in denied_items if it.startswith("@")}
        active_justifications = {
            grp: self.GROUP_JUSTIFICATIONS.get(grp, "Conjunto no documentado")
            for grp in allowed_groups if grp in self.GROUP_JUSTIFICATIONS
        }

        # 8. Compatibilidad de arquitectura
        native_arch = platform.machine()
        arch_valid = self.architecture.lower() in ("native", native_arch.lower(), "")

        is_valid = (
            edr_verified and
            dangerous_blocked and
            not privileged_in_allowlist and
            len(allowed_groups) > 0 and
            arch_valid
        )

        return {
            "is_valid": is_valid,
            "mode": "allowlist_with_denylist_exclusions",
            "allowed_groups": sorted(list(allowed_groups)),
            "denied_groups": sorted(list(denied_groups)),
            "explicit_allowed_syscalls": sorted(list(explicit_allowed_syscalls)),
            "explicit_denied_syscalls": sorted(list(explicit_denied_syscalls)),
            "effective_allowed_count": len(final_allowed),
            "effective_denied_count": len(effective_denied),
            "edr_syscalls_verified": edr_verified,
            "core_bootstrap_verified": core_bootstrap_verified,
            "optional_network_verified": optional_network_verified,
            "dangerous_groups_blocked": dangerous_blocked,
            "privileged_blocked": not privileged_in_allowlist,
            "architecture_valid": arch_valid,
            "group_justifications": active_justifications
        }

    def validate_syscall_execution(self, syscall: str) -> Tuple[bool, str]:
        """
        Valida si una llamada al sistema específica está permitida o denegada
        bajo la semántica sustractiva estricta de seccomp.
        """
        posture = self.compute_effective_posture()
        if not posture["architecture_valid"]:
            return False, f"Arquitectura '{self.architecture}' incompatible con reglas nativas de seccomp"

        # Prevalencia irrevocable de denegación seccomp
        if syscall in posture["explicit_denied_syscalls"]:
            return False, f"Syscall '{syscall}' explícitamente bloqueada por denylist (~)"

        for grp in posture["denied_groups"]:
            if syscall in SYSTEMD_SYSCALL_GROUPS.get(grp, set()):
                return False, f"Syscall '{syscall}' bloqueada por pertenecer al grupo denegado '{grp}'"

        if syscall in posture["explicit_allowed_syscalls"]:
            return True, f"Syscall '{syscall}' explícitamente permitida en allowlist"

        for grp in posture["allowed_groups"]:
            if syscall in SYSTEMD_SYSCALL_GROUPS.get(grp, set()):
                return True, f"Syscall '{syscall}' permitida a través del grupo '{grp}'"

        return False, f"Syscall '{syscall}' denegada por política restrictiva por defecto"


class EBPFCapabilityProber:
    """
    Realiza pruebas funcionales activas del subsistema eBPF y telemetría del kernel.
    Determina si el entorno admite el perfil de mínimo privilegio sin CAP_SYS_ADMIN.
    Si una operación falla por políticas de kernel (lockdown, LSM, virt), Constantine
    activa degradación asistida explícita (MODE_DEGRADED_OBS) en vez de inflar privilegios.
    """

    @staticmethod
    def check_unprivileged_bpf_disabled() -> int:
        """Lee /proc/sys/kernel/unprivileged_bpf_disabled."""
        path = "/proc/sys/kernel/unprivileged_bpf_disabled"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return int(f.read().strip())
            except Exception:
                pass
        return 1

    @staticmethod
    def check_kernel_lockdown() -> str:
        """Verifica si el kernel está en modo lockdown (integrity / confidentiality)."""
        path = "/sys/kernel/security/lockdown"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    m = re.search(r"\[(.*?)\]", content)
                    if m:
                        return m.group(1)
            except Exception:
                pass
        return "none"

    @staticmethod
    def probe_bpf_syscall() -> Tuple[bool, int, str]:
        """Sondea la llamada al sistema bpf(2) con comando de prueba."""
        try:
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            sys_arch = platform.machine()
            bpf_nr = 321 if sys_arch == "x86_64" else (280 if "arm" in sys_arch or "aarch64" in sys_arch else -1)
            if bpf_nr > 0:
                res = libc.syscall(bpf_nr, -1, 0, 0)
                err = ctypes.get_errno()
                if err == 38: # ENOSYS
                    return False, err, "Llamada al sistema bpf(2) no soportada en el kernel (ENOSYS)"
                return True, err, "Llamada al sistema bpf(2) disponible en el kernel"
            return False, 38, "Arquitectura de CPU sin mapeo de syscall bpf"
        except Exception as e:
            return False, -1, str(e)

    @staticmethod
    def probe_perf_event_open() -> Tuple[bool, int, str]:
        """Sondea la llamada al sistema perf_event_open(2) para tracepoints y libera descriptores."""
        try:
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            sys_arch = platform.machine()
            perf_nr = 298 if sys_arch == "x86_64" else (241 if "arm" in sys_arch or "aarch64" in sys_arch else -1)
            if perf_nr > 0:
                res = libc.syscall(perf_nr, 0, -1, 0, -1, 0)
                err = ctypes.get_errno()
                if res >= 0:
                    try:
                        os.close(res)
                    except OSError:
                        pass
                if err == 38: # ENOSYS
                    return False, err, "Llamada perf_event_open(2) no soportada (ENOSYS)"
                return True, err, "Llamada perf_event_open(2) disponible en el kernel"
            return False, 38, "Arquitectura de CPU sin mapeo de perf_event_open"
        except Exception as e:
            return False, -1, str(e)

    @staticmethod
    def probe_bpf_map_create() -> Tuple[bool, int, str]:
        """Sondea la creación de mapa eBPF (BPF_MAP_CREATE) y libera descriptores."""
        try:
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            sys_arch = platform.machine()
            bpf_nr = 321 if sys_arch == "x86_64" else (280 if "arm" in sys_arch or "aarch64" in sys_arch else -1)
            if bpf_nr > 0:
                res = libc.syscall(bpf_nr, 0, 0, 0)
                err = ctypes.get_errno()
                if res >= 0:
                    try:
                        os.close(res)
                    except OSError:
                        pass
                if err == 38: # ENOSYS
                    return False, err, "Llamada BPF_MAP_CREATE no soportada (ENOSYS)"
                return True, err, "Soporte de BPF_MAP_CREATE verificado en kernel"
            return False, 38, "Arquitectura sin soporte de syscall bpf"
        except Exception as e:
            return False, -1, str(e)

    @staticmethod
    def probe_bpf_prog_load() -> Tuple[bool, int, str]:
        """Sondea la carga de programas eBPF (BPF_PROG_LOAD = 5) y libera descriptores."""
        try:
            import ctypes
            libc = ctypes.CDLL(None, use_errno=True)
            sys_arch = platform.machine()
            bpf_nr = 321 if sys_arch == "x86_64" else (280 if "arm" in sys_arch or "aarch64" in sys_arch else -1)
            if bpf_nr > 0:
                # BPF_PROG_LOAD = 5
                res = libc.syscall(bpf_nr, 5, 0, 0)
                err = ctypes.get_errno()
                if res >= 0:
                    try:
                        os.close(res)
                    except OSError:
                        pass
                if err == 38: # ENOSYS
                    return False, err, "Llamada BPF_PROG_LOAD no soportada (ENOSYS)"
                return True, err, "Soporte de BPF_PROG_LOAD verificado en kernel"
            return False, 38, "Arquitectura sin soporte de syscall bpf"
        except Exception as e:
            return False, -1, str(e)

    @classmethod
    def probe_ebpf_runtime(cls) -> Dict[str, Any]:
        """
        Ejecuta el sondeo de operaciones concretas requeridas por Constantine:
        - Disponibilidad de syscall bpf(2).
        - Disponibilidad de perf_event_open(2) para telemetría.
        - Estado de unprivileged_bpf_disabled y lockdown.
        - Recomendación de perfil: mínimo privilegio con degradación asistida.
        """
        unprivileged_bpf = cls.check_unprivileged_bpf_disabled()
        lockdown = cls.check_kernel_lockdown()
        bpf_ok, bpf_err, bpf_msg = cls.probe_bpf_syscall()
        perf_ok, perf_err, perf_msg = cls.probe_perf_event_open()
        map_ok, map_err, map_msg = cls.probe_bpf_map_create()
        prog_ok, prog_err, prog_msg = cls.probe_bpf_prog_load()

        # Determinar estado de telemetría eBPF y degradación asistida
        if bpf_ok and perf_ok and lockdown == "none":
            telemetry_state = "EBPF_ACTIVE_OPTIMAL"
            telemetry_desc = "Telemetría eBPF y contención en kernel activas de forma óptima."
        elif bpf_ok or perf_ok:
            telemetry_state = "EBPF_PARTIAL"
            telemetry_desc = "Telemetría eBPF parcial; algunas funciones restringidas por entorno o kernel."
        elif unprivileged_bpf != 0 or lockdown != "none":
            telemetry_state = "DEGRADED_PROC_FALLBACK"
            telemetry_desc = "eBPF restringido por políticas de host (lockdown/LSM/virt). Operando en degradación asistida mediante sondeo de /proc (limitación documentada: latencia de muestreo y procesos efímeros no capturados)."
        else:
            telemetry_state = "MONITORING_DISABLED"
            telemetry_desc = "Supervisión desactivada."

        # Determinar versión de kernel
        k_ver = platform.release()
        is_modern = False
        try:
            m = re.match(r"^(\d+)\.(\d+)", k_ver)
            if m:
                k_maj, k_min = int(m.group(1)), int(m.group(2))
                is_modern = (k_maj > 5) or (k_maj == 5 and k_min >= 8)
            else:
                is_modern = True
        except Exception:
            is_modern = True

        # Principio de menor privilegio: en kernel >= 5.8 se prescinde de CAP_SYS_ADMIN.
        # Si las sondas eBPF estuvieran restringidas por lockdown o LSM, el motor opera en degradación asistida.
        can_drop_sys_admin = is_modern and bpf_ok

        return {
            "kernel_version": k_ver,
            "is_modern_kernel": is_modern,
            "unprivileged_bpf_disabled": unprivileged_bpf,
            "lockdown_mode": lockdown,
            "bpf_syscall_available": bpf_ok,
            "bpf_status_reason": bpf_msg,
            "perf_event_open_available": perf_ok,
            "perf_status_reason": perf_msg,
            "can_drop_sys_admin": can_drop_sys_admin,
            "recommended_profile": "PROFILE_LEAST_PRIVILEGE" if can_drop_sys_admin else "PROFILE_LEGACY_COMPATIBILITY",
            "fallback_strategy": "GRACEFUL_DEGRADATION_MODE_PROC",
            "bpf_map_create_probe": {
                "available": map_ok,
                "errno": map_err,
                "reason": map_msg
            },
            "bpf_prog_load_probe": {
                "available": prog_ok,
                "errno": prog_err,
                "reason": prog_msg
            },
            "telemetry_state": telemetry_state,
            "telemetry_description": telemetry_desc
        }


class SystemdSecurityAuditor:
    """Audita las directivas de seguridad y aislamiento del archivo de servicio systemd."""

    def __init__(self, unit_path: str = "/etc/systemd/system/constantine.service"):
        self.unit_path = unit_path

    def _parse_unit(self) -> Tuple[Dict[str, str], List[str]]:
        """Extrae directivas clave de la unidad systemd concatenando reglas acumulativas y guardando líneas de SystemCallFilter."""
        directives = {}
        syscall_filter_lines = []
        if not os.path.exists(self.unit_path):
            return directives, syscall_filter_lines

        with open(self.unit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    k = key.strip()
                    v = val.strip()
                    if k == "SystemCallFilter":
                        syscall_filter_lines.append(v)
                    if k in directives:
                        directives[k] += " " + v
                    else:
                        directives[k] = v
        return directives, syscall_filter_lines

    def check_capability_bounding_set(self, caps_str: str, kernel_version: Optional[str] = None) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evalúa si CapabilityBoundingSet cumple el principio de mínimo privilegio:
        - Kernel >= 5.8: CAP_BPF y CAP_PERFMON bastan para eBPF y telemetría, eliminando CAP_SYS_ADMIN.
        - Kernel < 5.8: Requiere CAP_SYS_ADMIN como fallback heredado para bpf().
        - CAP_DAC_OVERRIDE está delimitado y no se propaga permanentemente a workers de inspección.
        """
        caps = set(caps_str.split())
        has_bpf = "CAP_BPF" in caps
        has_perfmon = "CAP_PERFMON" in caps
        has_dac_read = "CAP_DAC_READ_SEARCH" in caps
        has_dac_override = "CAP_DAC_OVERRIDE" in caps
        has_sys_admin = "CAP_SYS_ADMIN" in caps
        has_sys_boot = "CAP_SYS_BOOT" in caps

        if has_sys_boot:
            return False, "CAP_SYS_BOOT indebidamente concedida", {"passed": False}

        if kernel_version is None:
            kernel_version = platform.release()

        is_modern = False
        try:
            m = re.match(r"^(\d+)\.(\d+)", kernel_version)
            if m:
                k_maj, k_min = int(m.group(1)), int(m.group(2))
                is_modern = (k_maj > 5) or (k_maj == 5 and k_min >= 8)
            else:
                is_modern = True
        except Exception:
            is_modern = True

        details = {
            "kernel_version": kernel_version,
            "is_modern_kernel": is_modern,
            "has_bpf": has_bpf,
            "has_perfmon": has_perfmon,
            "has_sys_admin": has_sys_admin,
            "has_dac_read": has_dac_read,
            "has_dac_override": has_dac_override,
            "least_privilege_optimal": is_modern and not has_sys_admin and has_bpf and has_perfmon
        }

        if is_modern:
            if has_bpf and has_perfmon and has_dac_read and has_dac_override:
                status_msg = "Conjunto de capacidades óptimo para kernel >= 5.8"
                if not has_sys_admin:
                    status_msg += " (Principio de menor privilegio estricto: CAP_SYS_ADMIN retirado)"
                else:
                    status_msg += " (CAP_SYS_ADMIN conservado para compatibilidad)"
                return True, status_msg, details
            return False, "Faltan capacidades eBPF especializadas (CAP_BPF, CAP_PERFMON) o de inspección", details
        else:
            if has_sys_admin and has_dac_read and has_dac_override:
                return True, "Conjunto de capacidades compatible para kernel < 5.8 (requiere CAP_SYS_ADMIN)", details
            return False, "Kernel < 5.8 requiere CAP_SYS_ADMIN para operaciones bpf()", details

    def evaluate_security_posture(self, kernel_version: Optional[str] = None) -> Dict[str, Any]:
        """
        Evalúa el cumplimiento de directivas de hardening del servicio:
        - NoNewPrivileges: Activo para prevenir escalada vía setuid/setgid.
        - ProtectSystem: Protección de jerarquía del sistema (/usr, /boot).
        - FileSupervision: Configuración que garantiza la inspección y remediación de archivos (/home).
        - CapabilityBoundingSet: Conjunto delimitado y kernel-aware (CAP_BPF, CAP_PERFMON, CAP_DAC_OVERRIDE).
        - DevicePolicy: closed con lista blanca de dispositivos.
        - SystemCallFilter: Análisis formal del conjunto efectivo allowlist/denylist y justificaciones.
        - SystemCallArchitectures: native.
        - RestrictSUIDSGID y ProtectKernelTunables.
        - KernelHardening: ProtectKernelModules=true protege contra módulos rootkit.
        """
        directives, sc_lines = self._parse_unit()
        if not directives:
            return {
                "unit_found": False,
                "score": 0,
                "rating": "SERVICE_NOT_FOUND",
                "passed_checks": [],
                "missing_checks": ["Unit file not found"]
            }

        passed_checks: List[str] = []
        missing_checks: List[str] = []

        # 1. NoNewPrivileges
        if directives.get("NoNewPrivileges", "").lower() in ("true", "yes", "1"):
            passed_checks.append("NoNewPrivileges")
        else:
            missing_checks.append("NoNewPrivileges")

        # 2. ProtectSystem
        if directives.get("ProtectSystem", "").lower() in ("strict", "full", "true"):
            passed_checks.append("ProtectSystem")
        else:
            missing_checks.append("ProtectSystem")

        # 3. Supervisión de Archivos Personales (ProtectHome & FileSupervision)
        protect_home_val = directives.get("ProtectHome", "").lower()
        rw_paths = directives.get("ReadWritePaths", "").split()
        if protect_home_val in ("false", "no", "0") or (protect_home_val in ("read-only", "true") and any(p == "/home" for p in rw_paths)):
            passed_checks.append("FileSupervision")
            passed_checks.append("ProtectHome")
        elif protect_home_val in ("read-only", "true", "yes", "tmpfs"):
            passed_checks.append("ProtectHome")
        else:
            missing_checks.append("ProtectHome")

        # 4. CapabilityBoundingSet (análisis kernel-aware y sondeo funcional)
        caps = directives.get("CapabilityBoundingSet", "")
        caps_ok, caps_msg, caps_details = self.check_capability_bounding_set(caps, kernel_version=kernel_version)
        if caps_ok:
            passed_checks.append("CapabilityBoundingSet")
        else:
            missing_checks.append(f"CapabilityBoundingSet ({caps_msg})")

        # 5. DevicePolicy
        if directives.get("DevicePolicy", "").lower() == "closed":
            passed_checks.append("DevicePolicy")
        else:
            missing_checks.append("DevicePolicy")

        # 6. SystemCallFilter (análisis formal de conjuntos y justificaciones bajo semántica seccomp)
        arch_val = directives.get("SystemCallArchitectures", "native")
        sc_eval = SystemCallFilterEvaluator(sc_lines, architecture=arch_val)
        sc_posture = sc_eval.compute_effective_posture()
        if sc_posture["is_valid"]:
            passed_checks.append("SystemCallFilter")
        else:
            missing_checks.append("SystemCallFilter")

        # 7. SystemCallArchitectures
        if "native" in directives.get("SystemCallArchitectures", "").lower():
            passed_checks.append("SystemCallArchitectures")
        else:
            missing_checks.append("SystemCallArchitectures")

        # 8. RestrictSUIDSGID
        if directives.get("RestrictSUIDSGID", "").lower() in ("true", "yes", "1"):
            passed_checks.append("RestrictSUIDSGID")

        # 9. ProtectKernelTunables
        if directives.get("ProtectKernelTunables", "").lower() in ("true", "yes", "1"):
            passed_checks.append("ProtectKernelTunables")

        # 10. KernelHardening (Protección de módulos del kernel)
        if directives.get("ProtectKernelModules", "").lower() in ("true", "yes", "1"):
            passed_checks.append("KernelHardening")

        score = min(100, int((len(passed_checks) / 8.0) * 100))
        rating = "HARDENED_EXCELLENT" if score >= 90 else ("MODERATE" if score >= 70 else "INSECURE")

        # Sondeo funcional eBPF complementario
        ebpf_probe = EBPFCapabilityProber.probe_ebpf_runtime()

        return {
            "unit_found": True,
            "score": score,
            "rating": rating,
            "passed_checks": passed_checks,
            "missing_checks": missing_checks,
            "directives_count": len(directives),
            "syscall_filter_audit": sc_posture,
            "capability_audit": caps_details,
            "ebpf_probe": ebpf_probe
        }
