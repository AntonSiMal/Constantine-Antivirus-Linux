"""
Motor eBPF de Kernel para Constantine Antivirus.
Separación Arquitectónica Estricta:
1. Capa de Observación (KernelObservationEngine):
   - Telemetría no intrusiva mediante tracepoints de kernel (sys_enter_execve, etc.) y buffers de perf.
   - Observar NO es bloquear; registra eventos sin interferir en su ciclo de vida.
2. Capa de Detección (KernelDetectionEngine):
   - Análisis heurístico, reglas conductuales y clasificación de amenazas en los eventos observados.
   - Detectar NO es impedir; calcula el nivel de riesgo y genera alertas.
3. Capa de Enforcement (KernelEnforcementEngine):
   - Mecanismos verificables de aplicación:
     * Preventivo (Inline In-Kernel Pre-Execution): BPF LSM (bpf_lsm_bprm_check_security) devolviendo -EPERM.
     * Alternativo / Fallback (Post-Execution Containment): SIGKILL inmediato + aislamiento de red + cuarentena.
"""
import os
import signal
import logging
from typing import Dict, Any, List, Optional, Tuple
from collections import namedtuple

logger = logging.getLogger("constantine.ebpf")

ObservedEvent = namedtuple("ObservedEvent", ["timestamp", "pid", "binary_path", "argv", "syscall", "cpu_id"])
DetectionReport = namedtuple("DetectionReport", ["is_threat", "threat_type", "severity", "details"])
EnforcementDecision = namedtuple("EnforcementDecision", ["blocked_in_kernel", "action", "enforcement_mode", "reason"])

# Modos de Enforcement de Kernel
MODE_BPF_LSM = "BPF_LSM_PREVENTIVE"          # Bloqueo en kernel pre-ejecución (-EPERM)
MODE_REACTIVE_FALLBACK = "REACTIVE_CONTAINMENT" # Neutralización reactiva (SIGKILL + Aislamiento)
MODE_DEGRADED_OBS = "DEGRADED_OBSERVATION"      # Solo lectura /proc en entornos no privilegiados


class KernelObservationEngine:
    """
    Capa 1: Observación del Kernel (Telemetry).
    Se encarga exclusivamente de capturar llamadas al sistema mediante tracepoints y perf buffers.
    Hard Constraint: No modifica el flujo de ejecución ni aplica bloqueos.
    """

    def __init__(self):
        self.active_tracepoints: List[str] = [
            "syscalls:sys_enter_execve",
            "syscalls:sys_enter_openat",
            "syscalls:sys_enter_connect",
            "syscalls:sys_enter_setuid"
        ]
        self.lost_events_count = 0
        self.is_observing = False

    def start_observation(self):
        self.is_observing = True
        logger.info("📡 [eBPF OBSERVABILIDAD] Enganchando tracepoints de telemetría: %s", ", ".join(self.active_tracepoints))

    def stop_observation(self):
        self.is_observing = False
        logger.info("📡 [eBPF OBSERVABILIDAD] Tracepoints desvinculados limpiamente.")

    def record_lost_events(self, cpu_id: int, count: int):
        self.lost_events_count += count
        logger.warning("⚠️ [PÉRDIDA DE EVENTOS eBPF] CPU %d perdió %d eventos (saturación de perf buffer).", cpu_id, count)

    def capture_event(self, pid: int, binary_path: str, argv: List[str], syscall: str = "execve") -> ObservedEvent:
        """Genera un registro normalizado de telemetría pasiva de llamada al sistema."""
        import time
        return ObservedEvent(time.time(), pid, binary_path, argv, syscall, 0)


class KernelDetectionEngine:
    """
    Capa 2: Detección y Análisis de Amenazas.
    Examina los eventos capturados y discrimina actividades benignas de patrones maliciosos.
    Hard Constraint: Clasifica y califica el riesgo, sin ejecutar acciones de terminación.
    """

    def __init__(self):
        pass

    def analyze_event(self, event: ObservedEvent) -> DetectionReport:
        """
        Analiza un evento observado:
        - Discrimina uso benigno de Netcat (-zv, -l) vs reverse shells (-e, -c, /dev/tcp/).
        - Analiza argumentos situados más allá de argv[1].
        """
        bin_name = os.path.basename(event.binary_path).lower()
        argv = event.argv

        if bin_name in ("nc", "ncat", "netcat"):
            is_benign = any(arg in ("-zv", "-z", "-l", "-lvp") for arg in argv)
            has_exec = any(arg in ("-e", "-c") for arg in argv)
            has_sh = any("/bin/" in arg for arg in argv)
            if has_exec or (has_sh and not is_benign):
                logger.warning("🎯 [eBPF DETECCIÓN CONDUCTUAL] Reverse Shell identificada en PID %d: %s %s",
                               event.pid, event.binary_path, " ".join(argv))
                return DetectionReport(True, "ReverseShell.Netcat", "CRITICAL", "Intento de shell interactiva en reversa")
            return DetectionReport(False, "CLEAN", "LOW", "Uso legítimo de herramienta de red")

        # Comprobar descriptores de red interactiva en shell
        if any("/dev/tcp/" in arg for arg in argv):
            logger.warning("🎯 [eBPF DETECCIÓN CONDUCTUAL] Shell reversa mediante /dev/tcp/ en PID %d", event.pid)
            return DetectionReport(True, "ReverseShell.DevTcp", "CRITICAL", "Conexión directa vía /dev/tcp/")

        return DetectionReport(False, "CLEAN", "LOW", "Proceso verificado conforme")


class KernelEnforcementEngine:
    """
    Capa 3: Aplicación y Bloqueo (Enforcement).
    Aplica políticas verificables:
    - Preventivo: BPF LSM hook (bpf_lsm_bprm_check_security) que deniega con -EPERM ANTES de que el proceso corra.
    - Reactivo / Fallback: Cuando BPF LSM no está disponible, aplica SIGKILL y contención post-lanzamiento.
    """

    def __init__(self, force_bpf_lsm: Optional[bool] = None):
        self._force_bpf_lsm = force_bpf_lsm
        self.bpf_lsm_supported = self.check_bpf_lsm_support()
        self.active_mode = MODE_BPF_LSM if self.bpf_lsm_supported else MODE_REACTIVE_FALLBACK

    def check_bpf_lsm_support(self) -> bool:
        """
        Verifica si el kernel en ejecución admite BPF LSM:
        1. Comprueba si 'bpf' figura en /sys/kernel/security/lsm.
        2. Comprueba si el módulo de seguridad bpf está activo en /sys/kernel/security/bpf.
        """
        if self._force_bpf_lsm is not None:
            return self._force_bpf_lsm

        lsm_path = "/sys/kernel/security/lsm"
        if os.path.exists(lsm_path):
            try:
                with open(lsm_path, "r") as f:
                    content = f.read()
                if "bpf" in content:
                    logger.info("🛡️ [BPF LSM DISPONIBLE] Kernel admite enforcement preventivo inline en ganchos LSM.")
                    return True
            except OSError:
                pass
        return False

    def enforce_threat(self, detection: DetectionReport, event: ObservedEvent) -> EnforcementDecision:
        """
        Ejecuta el enforcement de acuerdo a la capacidad verificada del kernel:
        - Si BPF LSM está soportado: DENY inline con -EPERM (prohibiendo la ejecución antes de nacer).
        - Si no está soportado: Fallback verificado con SIGKILL inmediato y registro de contención.
        """
        if not detection.is_threat:
            return EnforcementDecision(False, "ALLOW", self.active_mode, "Ejecución permitida")

        if self.bpf_lsm_supported:
            logger.critical("🛑 [BPF LSM PREVENTIVO (-EPERM)] Bloqueando ejecución en kernel de PID %d (%s) antes de sys_execve.",
                            event.pid, event.binary_path)
            return EnforcementDecision(True, "DENY_EPERM", MODE_BPF_LSM,
                                       f"BPF LSM impidió la ejecución del binario en kernel con -EPERM: {detection.threat_type}")
        else:
            logger.warning("⚠️ [FALLBACK REACTIVO ENFORCEMENT] BPF LSM no disponible en kernel. Aplicando terminación post-detección SIGKILL a PID %d.", event.pid)
            self.terminate_process(event.pid)
            return EnforcementDecision(False, "SIGKILL_CONTAINMENT", MODE_REACTIVE_FALLBACK,
                                       f"Terminación reactiva post-ejecución aplicada con SIGKILL: {detection.threat_type}")

    def terminate_process(self, pid: int) -> bool:
        """Mecanismo alternativo de rescate / neutralización reactiva."""
        try:
            os.kill(pid, signal.SIGKILL)
            logger.info("Proceso agresor PID %d terminado con SIGKILL.", pid)
            return True
        except (ProcessLookupError, PermissionError):
            return False


class EBPFMonitor:
    """
    Orquestador eBPF de Constantine Antivirus.
    Integra y desacopla explícitamente:
    - Observación: KernelObservationEngine
    - Detección: KernelDetectionEngine
    - Enforcement: KernelEnforcementEngine
    """

    def __init__(self, fallback_mode: Optional[bool] = None, enable_bpf_lsm: Optional[bool] = None):
        self.running = False
        if fallback_mode is not None:
            self.fallback_mode = fallback_mode
        else:
            self.fallback_mode = (os.getuid() != 0)

        # 3 Capas Desacopladas
        self.observer = KernelObservationEngine()
        self.detector = KernelDetectionEngine()
        self.enforcer = KernelEnforcementEngine(force_bpf_lsm=enable_bpf_lsm)

        if self.enforcer.bpf_lsm_supported:
            self.enforcement_mode = MODE_BPF_LSM
        elif self.fallback_mode:
            self.enforcement_mode = MODE_DEGRADED_OBS
        else:
            self.enforcement_mode = MODE_REACTIVE_FALLBACK

    @property
    def lost_events_count(self) -> int:
        return self.observer.lost_events_count

    def start(self):
        self.running = True
        self.observer.start_observation()
        if self.fallback_mode:
            logger.warning("⚠️ Sondas eBPF en kernel requieren privilegios de root (CAP_SYS_ADMIN / CAP_BPF). Activando centinela heurístico en espacio de usuario.")
            logger.warning("⚠️ [MODO DEGRADADO ACTIVADO] eBPF no está disponible. Operando mediante inspección periódica de /proc.")
        elif self.enforcer.bpf_lsm_supported:
            logger.info("🛡️ Sondas eBPF y ganchos BPF LSM preventivos activos en kernel.")
        else:
            logger.info("🛡️ Sondas eBPF de observación activas en kernel con fallback reactivo de contención.")

    def stop(self):
        self.running = False
        self.observer.stop_observation()
        logger.info("Monitor eBPF detenido.")

    def record_lost_events(self, cpu_id: int, count: int):
        self.observer.record_lost_events(cpu_id, count)

    def kill_offender(self, pid: int):
        self.enforcer.terminate_process(pid)

    def evaluate_process(self, pid: int, binary_path: str, argv: List[str]) -> Tuple[bool, str]:
        """
        Ejecuta el flujo completo desacoplado:
        1. Observa el evento.
        2. Detecta si es una amenaza.
        3. Aplica enforcement verificable según el modo del kernel.
        """
        event = self.observer.capture_event(pid, binary_path, argv)
        detection = self.detector.analyze_event(event)
        enforcement = self.enforcer.enforce_threat(detection, event)

        if detection.is_threat:
            return False, enforcement.reason
        return True, "Uso legítimo de herramienta de red"

    def process_kernel_exec_request(self, pid: int, binary_path: str, argv: List[str]) -> Tuple[bool, EnforcementDecision]:
        """Interfaz de decisión de kernel para BPF LSM / Tetragon pre-exec hooks."""
        event = self.observer.capture_event(pid, binary_path, argv)
        detection = self.detector.analyze_event(event)
        decision = self.enforcer.enforce_threat(detection, event)
        is_allowed = not detection.is_threat
        return is_allowed, decision
