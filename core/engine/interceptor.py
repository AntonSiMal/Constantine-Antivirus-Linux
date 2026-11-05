"""
Constantine Antivirus - Fanotify Kernel Interceptor (core/engine/interceptor.py)
Interceptación síncrona en kernel mediante fanotify (FAN_OPEN_PERM & FAN_OPEN_EXEC_PERM):

ARQUITECTURA DE RESILIENCIA Y ALTA DISPONIBILIDAD (P0 - Anti-Bloqueo de Sistema):
1. Desacoplamiento Productor-Consumidor (Separación de Recepción y Análisis):
   - El hilo principal de sondeo únicamente lee eventos del descriptor fanotify, crea un
     AuthorizationContext y lo despacha de forma no bloqueante a una cola acotada.
   - El análisis de firmas, YARA, heurística y antiransomware se delega a un grupo de
     trabajadores concurrentes (Worker Pool), evitando que un escaneo lento congele el SO.
2. Cola de Trabajo Acotada (Bounded Work Queue) y Detección de Desbordamientos:
   - Capacidad limitada (max_queue_size) para prevenir agotamiento de memoria.
   - Detección inmediata de saturación (queue.Full) y desbordamiento en kernel (FAN_Q_OVERFLOW).
   - Ante saturación, se responde de inmediato aplicando la política de fallo correspondiente.
3. Timeout Estricto por Evento de Autorización (Garantía Cero Colgados):
   - Cada evento cuenta con un temporizador independiente (event_timeout, por defecto 2.0s).
   - Si el escaneo excede el tiempo límite, el temporizador responde al kernel de forma atómica
     y libera el descriptor para que los procesos legítimos del sistema nunca queden en estado D (Uninterruptible Sleep).
4. Garantía Absoluta de Respuesta Única (No Dangling Events):
   - El envío de respuesta a fanotify está protegido por un bloqueo atómico Compare-And-Swap.
   - Se garantiza exactamente una respuesta por evento y cierre seguro del descriptor (os.close).
5. Políticas Diferenciadas y Configurables (Fail-Open vs Fail-Closed):
   - Aperturas/Accesos ordinarios (FAN_OPEN_PERM): Fail-Open por defecto ('open') para preservar
     la disponibilidad y funcionamiento normal del sistema operativo ante averías o sobrecargas.
   - Ejecución de archivos (FAN_OPEN_EXEC_PERM): Fail-Closed por defecto ('closed') para preservar
     la seguridad y bloquear la ejecución de binarios o scripts no verificados.
   - Totalmente configurables vía open_fail_policy y exec_fail_policy.
6. Protección Estricta Anti-TOCTOU (Fijación de Descriptor y Verificación de Inodo):
   - El análisis se realiza fijando el descriptor en el kernel (target_fd=event_fd), impidiendo
     que un atacante sustituya el archivo en disco entre el openat y la decisión.
   - Se valida fstat(event_fd) contra lstat(target_path) para detectar desincronizaciones de inodo/dispositivo.
7. Auditoría y Registro de Operaciones Bloqueadas por Fallos Internos:
   - Registro en memoria e integración con AuditLogger de todas las operaciones afectadas
     por timeouts, desbordamientos o excepciones, diferenciando explícitamente fallos de malware real.
8. Recuperación Automática del Servicio (Self-Healing):
   - Procedimiento recover_service() para restaurar descriptores rotos de fanotify, re-enganchar
     marcas y reiniciar workers sin reiniciar el demonio.
"""
import os
import time
import stat
import queue
import ctypes
import fcntl
import select
import logging
import threading
from typing import Optional, List, Set, Dict, Any
from core.engine.system_whitelist import SystemWhitelist

logger = logging.getLogger("constantine.interceptor")

# Constantes oficiales del kernel de Linux (<linux/fanotify.h>)
FAN_CLASS_CONTENT = 0x00000004
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020

FAN_MARK_ADD = 0x00000001
FAN_MARK_DONT_FOLLOW = 0x00000004
FAN_MARK_ONLYDIR = 0x00000008
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_FILESYSTEM = 0x00000100  # Kernel Linux >= 4.20 para supervisión global de todo el sistema

FAN_OPEN_PERM = 0x00010000        # Autorización síncrona en apertura de archivo
FAN_ACCESS_PERM = 0x00020000      # Autorización síncrona en acceso
FAN_OPEN_EXEC_PERM = 0x00040000   # Autorización síncrona en apertura para ejecución (Linux >= 5.0)

# Alias de compatibilidad hacia atrás
FAN_EXEC_PERM = FAN_OPEN_EXEC_PERM

FAN_Q_OVERFLOW = 0x00004000       # Evento de desbordamiento de cola en kernel
FAN_EVENT_ON_CHILD = 0x08000000   # Notificar eventos de archivos hijos en marcas de directorio

FAN_ALLOW = 0x01
FAN_DENY = 0x02

FAN_EVENT_METADATA_LEN = 24
FAN_NOFD = -1

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class FanotifyEventMetadata(ctypes.Structure):
    _fields_ = [
        ("event_len", ctypes.c_uint32),
        ("vers", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("metadata_len", ctypes.c_uint16),
        ("mask", ctypes.c_uint64),
        ("fd", ctypes.c_int32),
        ("pid", ctypes.c_int32),
    ]

class FanotifyResponse(ctypes.Structure):
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]

# Pseudo-sistemas de archivos no compatibles con fanotify
PSEUDO_FILESYSTEMS = {
    "proc", "sysfs", "devpts", "cgroup", "cgroup2", "pstore",
    "bpf", "autofs", "mqueue", "tracefs", "securityfs", "hugetlbfs",
    "fusectl", "configfs", "ramfs", "debugfs"
}


class AuthorizationContext:
    """
    Contexto atómico y seguro de autorización por evento de Fanotify.
    Garantiza una respuesta única al kernel fanotify, cierre seguro del descriptor
    y resolución mediante timeout si el análisis se demora.
    """
    def __init__(
        self,
        fan_fd: int,
        event_fd: int,
        pid: int,
        mask: int,
        fallback_decision: int,
        event_timeout: float = 2.0,
        on_respond_callback = None
    ):
        self.fan_fd = fan_fd
        self.event_fd = event_fd
        self.pid = pid
        self.mask = mask
        self.fallback_decision = fallback_decision
        self.event_timeout = max(0.01, float(event_timeout))
        self.on_respond_callback = on_respond_callback

        self.enqueue_time = time.monotonic()
        self._lock = threading.Lock()
        self.responded = False
        self.decision: Optional[int] = None
        self.reason: Optional[str] = None
        self.target_path: str = f"<fd:{event_fd}>"
        self.proc_name: str = "desconocido"
        self.timer: Optional[threading.Timer] = None
        self._done_event = threading.Event()

    def start_timer(self):
        """Inicia el temporizador de tiempo límite para evitar que el proceso quede colgado."""
        if self.event_timeout > 0:
            self.timer = threading.Timer(self.event_timeout, self._handle_timeout)
            self.timer.daemon = True
            self.timer.start()

    def _handle_timeout(self):
        """Manejador ejecutado si el análisis no concluye antes del timeout."""
        self.respond(self.fallback_decision, reason="TIMEOUT")

    def respond(self, decision: int, reason: str = "NORMAL") -> bool:
        """
        Envía la respuesta al kernel fanotify exactamente una vez y cierra el descriptor.
        Retorna True si fue esta llamada la que respondió, False si ya había respondido.
        """
        with self._lock:
            if self.responded:
                return False
            self.responded = True
            self.decision = decision
            self.reason = reason

        # Cancelar el temporizador si sigue activo
        if self.timer is not None:
            try:
                self.timer.cancel()
            except Exception:
                pass

        # Escribir la respuesta a fanotify en el kernel
        try:
            if self.fan_fd >= 0 and self.event_fd >= 0:
                resp = FanotifyResponse(fd=self.event_fd, response=decision)
                os.write(self.fan_fd, bytes(resp))
        except Exception as e:
            logger.debug("Aviso escribiendo respuesta fanotify para fd %d: %s", self.event_fd, e)
        finally:
            # Cierre garantizado del descriptor para no agotar FDs en el sistema operativo
            try:
                if self.event_fd >= 0:
                    os.close(self.event_fd)
            except Exception:
                pass

        self._done_event.set()

        if self.on_respond_callback is not None:
            try:
                self.on_respond_callback(self)
            except Exception as cb_err:
                logger.debug("Aviso en on_respond_callback: %s", cb_err)

        return True

    def wait_for_response(self, timeout: Optional[float] = None) -> bool:
        """Espera hasta que el evento haya sido respondido o expire el timeout."""
        return self._done_event.wait(timeout=timeout)


class FanotifyInterceptor:
    def __init__(
        self,
        scanner,
        vault=None,
        notifier=None,
        firewall=None,
        ransomware=None,
        fail_policy: str = "secure",
        open_fail_policy: Optional[str] = None,
        exec_fail_policy: Optional[str] = None,
        event_timeout: float = 2.0,
        max_queue_size: int = 1024,
        num_workers: int = 8,
        ebpf_monitor=None,
        audit_logger=None
    ):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.firewall = firewall
        self.ransomware = ransomware
        self.fail_policy = fail_policy  # Atributo para compatibilidad hacia atrás ('secure', 'safe', 'strict')
        self.ebpf_monitor = ebpf_monitor
        self.audit_logger = audit_logger
        self.whitelist = SystemWhitelist()

        # =========================================================================
        # POLÍTICAS DIFERENCIADAS DE FALLO (Fail-Open vs Fail-Closed)
        # =========================================================================
        # 1. Apertura ordinaria (FAN_OPEN_PERM): Default 'open' (preserva disponibilidad del SO)
        if open_fail_policy is not None:
            self.open_fail_policy = open_fail_policy.lower().strip()
        else:
            self.open_fail_policy = "open" if fail_policy in ("secure", "safe", "hybrid") else "closed"

        # 2. Ejecución de binarios/scripts (FAN_OPEN_EXEC_PERM): Default 'closed' (preserva seguridad estricta)
        if exec_fail_policy is not None:
            self.exec_fail_policy = exec_fail_policy.lower().strip()
        else:
            self.exec_fail_policy = "open" if fail_policy == "safe" else "closed"

        # Concurrencia y cola desacoplada
        self.event_timeout = max(0.01, float(event_timeout))
        self.max_queue_size = max(1, int(max_queue_size))
        self.num_workers = max(1, int(num_workers))

        self.work_queue: queue.Queue = queue.Queue(maxsize=self.max_queue_size)
        self.workers: List[threading.Thread] = []
        self._workers_lock = threading.Lock()

        # Métricas y auditoría de fallos internos
        self.overflow_count = 0        # Desbordamientos de cola en kernel (FAN_Q_OVERFLOW)
        self.queue_overflow_count = 0  # Desbordamientos de cola en espacio de usuario
        self.timeout_count = 0         # Operaciones que alcanzaron timeout
        self.internal_failures: List[Dict[str, Any]] = []
        self.blocked_by_internal_failure: List[Dict[str, Any]] = []
        self._failure_lock = threading.Lock()

        self.fan_fd = -1
        # Separación explícita de estados de ciclo de vida del interceptor
        self.is_initialized: bool = False
        self._is_marked: bool = False
        self.running: bool = False
        self.event_thread: Optional[threading.Thread] = None

        self.marked_paths: Set[str] = set()
        self.active_mounts: Set[str] = set()
        self.kernel_supports_exec_perm = True
        self.mount_watcher_thread: Optional[threading.Thread] = None

        # Exclusión de PIDs y procesos para prevención de deadlock y contención del sistema
        self.ignored_pids: Set[int] = set()
        self.ignored_comm_names: Set[str] = {
            "constantine", "constantine-scan", "clamd", "freshclam", "clamonacc",
            "systemd-journald", "systemd-udevd", "dbus-daemon", "polkitd"
        }

    def get_fallback_decision(self, mask: int) -> int:
        """
        Determina la política de fallo adecuada según el tipo de operación:
        - Ejecución (FAN_OPEN_EXEC_PERM): Aplica exec_fail_policy ('closed' -> FAN_DENY por defecto)
        - Apertura/Lectura ordinaria (FAN_OPEN_PERM): Aplica open_fail_policy ('open' -> FAN_ALLOW por defecto)
        """
        is_exec = bool(mask & FAN_OPEN_EXEC_PERM)
        policy = self.exec_fail_policy if is_exec else self.open_fail_policy
        return FAN_ALLOW if policy == "open" else FAN_DENY

    def set_ebpf_monitor(self, ebpf_monitor):
        """Asigna o actualiza el monitor eBPF para correlación de operaciones en kernel."""
        self.ebpf_monitor = ebpf_monitor

    def add_ignored_pid(self, pid: int):
        """Registra un PID para omisión inmediata en el interceptor de kernel (prevención de auto-intercepción)."""
        if pid and pid > 0:
            self.ignored_pids.add(pid)

    def add_ignored_comm(self, comm_name: str):
        """Registra un nombre de comando para omisión inmediata en el interceptor de kernel."""
        if comm_name:
            self.ignored_comm_names.add(comm_name.strip())

    def initialize(self) -> bool:
        """Inicializa fanotify con cola ilimitada y marcas ilimitadas para prevenir desbordamientos."""
        if os.geteuid() != 0:
            logger.error("Fanotify requiere privilegios de superusuario (root / CAP_SYS_ADMIN).")
            return False

        flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
        event_f_flags = os.O_RDONLY | os.O_CLOEXEC
        try:
            self.fan_fd = libc.fanotify_init(flags, event_f_flags)
            if self.fan_fd < 0:
                flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC
                self.fan_fd = libc.fanotify_init(flags, event_f_flags)

            if self.fan_fd < 0:
                err = ctypes.get_errno()
                logger.error("fanotify_init falló con errno %d (%s)", err, os.strerror(err))
                self.is_initialized = False
                return False

            self.is_initialized = True
            logger.info("✅ fanotify_init exitoso (fd: %d, flags: 0x%08x)", self.fan_fd, flags)
            return True
        except Exception as e:
            logger.error("Excepción en fanotify_init: %s", e)
            self.is_initialized = False
            return False

    @property
    def is_marked(self) -> bool:
        """Indica si el interceptor tiene al menos una ruta o sistema de archivos enganchado."""
        return bool(self._is_marked or len(self.marked_paths) > 0)

    @is_marked.setter
    def is_marked(self, value: bool):
        self._is_marked = bool(value)

    def is_active(self) -> bool:
        """
        Comprueba si el interceptor está activo con descriptor de kernel inicializado y marcas válidas.
        Verifica el estado de inicialización y marcas reales, independientemente de si el hilo de
        eventos ya está ejecutándose o aún está por arrancar.
        """
        initialized = self.is_initialized or (self.fan_fd >= 0)
        has_marks = self.is_marked or len(self.marked_paths) > 0
        return bool(initialized and self.fan_fd >= 0 and has_marks)

    def is_running(self) -> bool:
        """Comprueba si el bucle o hilo receptor de eventos está en ejecución activa y vivo."""
        return bool(self.running and (self.event_thread is None or self.event_thread.is_alive()))

    def start(self) -> bool:
        """
        Inicia el hilo receptor de eventos fanotify y el grupo de trabajadores en segundo plano.
        Verifica que el hilo esté vivo antes de retornar True.
        """
        if self.running and self.event_thread and self.event_thread.is_alive():
            return True

        if not self.is_active():
            logger.error("No se puede iniciar el interceptor: no está inicializado o no tiene marcas activas.")
            return False

        self.running = True
        self._start_workers()

        self.event_thread = threading.Thread(
            target=self.process_events,
            name="fanotify-event-receiver",
            daemon=True
        )
        self.event_thread.start()

        time.sleep(0.05)
        if not self.event_thread.is_alive():
            logger.critical("❌ El hilo receptor de eventos fanotify falló al arrancar.")
            self.running = False
            return False

        logger.info("✅ Hilo receptor de eventos fanotify activo y verificado en segundo plano.")
        return True

    def mark_directory(self, path: str, mark_mount: bool = False, mark_filesystem: bool = False, recursive: bool = True) -> bool:
        """
        Marca un directorio, punto de montaje o sistema de archivos para interceptación síncrona.
        """
        if self.fan_fd < 0:
            logger.error("No se puede marcar %s: descriptor fanotify no inicializado.", path)
            return False

        if not os.path.exists(path):
            try:
                os.makedirs(path, exist_ok=True)
            except Exception as e:
                logger.error("No se pudo crear ruta objetivo %s: %s", path, e)
                return False

        flags = FAN_MARK_ADD
        is_mount_or_fs = False
        if mark_filesystem:
            flags |= FAN_MARK_FILESYSTEM
            is_mount_or_fs = True
        elif mark_mount:
            flags |= FAN_MARK_MOUNT
            is_mount_or_fs = True

        base_perm = FAN_OPEN_PERM | (FAN_OPEN_EXEC_PERM if self.kernel_supports_exec_perm else 0)
        mask = base_perm
        if not is_mount_or_fs:
            mask |= FAN_EVENT_ON_CHILD

        success = self._apply_fanotify_mark(path, flags, mask)

        if success and not is_mount_or_fs and recursive and os.path.isdir(path):
            try:
                for root, dirs, _ in os.walk(path):
                    for d in dirs:
                        sub_path = os.path.join(root, d)
                        self._apply_fanotify_mark(sub_path, flags, mask)
            except Exception as w_err:
                logger.debug("Aviso en recorrido recursivo de %s: %s", path, w_err)

        return success

    def _apply_fanotify_mark(self, path: str, flags: int, mask: int) -> bool:
        path_bytes = path.encode("utf-8")
        ret = libc.fanotify_mark(self.fan_fd, flags, ctypes.c_uint64(mask), -100, path_bytes)
        if ret >= 0:
            self.marked_paths.add(path)
            self.is_marked = True
            logger.info("🎯 Enganchado fanotify en: %s (flags=0x%08x, mask=0x%08x)", path, flags, mask)
            return True

        err = ctypes.get_errno()
        if err == 22 and (mask & FAN_OPEN_EXEC_PERM):
            logger.warning("fanotify_mark con FAN_OPEN_EXEC_PERM devolvió EINVAL. Reintentando con FAN_OPEN_PERM en %s...", path)
            self.kernel_supports_exec_perm = False
            fallback_mask = (mask & ~FAN_OPEN_EXEC_PERM)
            ret = libc.fanotify_mark(self.fan_fd, flags, ctypes.c_uint64(fallback_mask), -100, path_bytes)
            if ret >= 0:
                self.marked_paths.add(path)
                logger.info("🎯 Enganchado fanotify (modo compatible) en: %s (mask=0x%08x)", path, fallback_mask)
                return True
            err = ctypes.get_errno()

        if err in (19, 95):  # ENODEV / EOPNOTSUPP
            logger.debug("Sistema de archivos no compatible con fanotify en %s (errno=%d). Omitiendo.", path, err)
        else:
            logger.error("❌ Fallo en fanotify_mark para %s: errno=%d (%s)", path, err, os.strerror(err))
        return False

    def mark_all_mounts(self) -> int:
        """
        Supervisa todo el sistema de archivos de forma 100% recursiva en / y montajes reales.
        """
        marked = 0
        if self.mark_directory("/", mark_filesystem=True):
            marked += 1
            logger.info("🌐 Supervisión global del sistema de archivos (FAN_MARK_FILESYSTEM) ACTIVA en / (Recursivo Total)")

        current_mounts = self._discover_real_mounts()
        for mp in current_mounts:
            if self.mark_directory(mp, mark_mount=True):
                marked += 1
                self.active_mounts.add(mp)

        marked += self.mark_critical_vectors()
        self._start_mount_watcher()
        logger.info("🛡️ Cobertura global completada: %d puntos de montaje y directorios interceptados activamente.", marked)
        return marked

    def _discover_real_mounts(self) -> Set[str]:
        """Descubre los puntos de montaje activos excluyendo pseudo-sistemas de archivos."""
        mounts = set()
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3:
                        mp, fstype = parts[1], parts[2]
                        if fstype not in PSEUDO_FILESYSTEMS and not mp.startswith(("/proc", "/sys", "/dev")):
                            if os.path.exists(mp):
                                mounts.add(mp)
        except Exception as e:
            logger.warning("Aviso leyendo /proc/mounts: %s", e)
        return mounts

    def _start_mount_watcher(self):
        """Inicia el hilo centinela de montajes en caliente y desmontajes."""
        if self.mount_watcher_thread and self.mount_watcher_thread.is_alive():
            return
        self.mount_watcher_thread = threading.Thread(target=self._mount_watcher_loop, daemon=True, name="fanotify-mount-watcher")
        self.mount_watcher_thread.start()

    def _mount_watcher_loop(self):
        while self.running:
            try:
                current_mounts = self._discover_real_mounts()
                new_mounts = current_mounts - self.active_mounts
                for nmp in new_mounts:
                    logger.info("🔌 Nuevo punto de montaje detectado: %s. Enganchando fanotify en caliente...", nmp)
                    if self.mark_directory(nmp, mark_mount=True):
                        self.active_mounts.add(nmp)

                unmounted = self.active_mounts - current_mounts
                for ump in unmounted:
                    logger.info("⏏️ Punto de montaje desmontado: %s. Limpiando estado.", ump)
                    self.active_mounts.discard(ump)
                    self.marked_paths.discard(ump)

                time.sleep(2.0)
            except Exception as e:
                logger.debug("Aviso en centinela de montajes: %s", e)
                time.sleep(3.0)

    def mark_global_filesystem(self) -> bool:
        """Supervisa el sistema de archivos completo en / a nivel de kernel."""
        return self.mark_all_mounts() > 0

    def mark_critical_vectors(self, extra_paths: Optional[List[str]] = None) -> int:
        """Marca simultáneamente los vectores críticos de ataque y drop de malware."""
        targets = [
            "/tmp", "/dev/shm", "/var/tmp", "/home", "/root",
            "/opt", "/media", "/run/media", "/usr/local", "/etc", "/var/www", "/srv"
        ]
        if extra_paths:
            targets.extend(extra_paths)

        marked_count = 0
        for p in targets:
            if os.path.exists(p):
                if self.mark_directory(p, mark_mount=False, recursive=True):
                    marked_count += 1
        return marked_count

    def get_process_name(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return "desconocido"

    def respond(self, event_fd: int, decision: int):
        """Método de respuesta directa a fanotify (para compatibilidad)."""
        resp = FanotifyResponse(fd=event_fd, response=decision)
        try:
            if self.fan_fd >= 0:
                os.write(self.fan_fd, bytes(resp))
        except Exception as e:
            logger.debug("Error escribiendo respuesta fanotify para fd %d: %s", event_fd, e)

    # =========================================================================
    # GESTIÓN DEL GRUPO DE TRABAJADORES CONCURRENTES (WORKER POOL)
    # =========================================================================
    def _start_workers(self):
        with self._workers_lock:
            self.workers = [w for w in self.workers if w.is_alive()]
            needed = self.num_workers - len(self.workers)
            for i in range(needed):
                w = threading.Thread(
                    target=self._worker_loop,
                    name=f"fanotify-worker-{len(self.workers)}",
                    daemon=True
                )
                w.start()
                self.workers.append(w)

    def _worker_loop(self):
        """Bucle de ejecución de cada hilo trabajador desacoplado."""
        while self.running:
            try:
                ctx = self.work_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                if ctx.responded:
                    # El evento ya fue resuelto (ej. por timeout previo mientras esperaba en cola)
                    continue
                self._evaluate_event(ctx)
            except Exception as e:
                logger.error("Excepción no controlada en hilo trabajador de análisis fanotify: %s", e)
                ctx.respond(ctx.fallback_decision, reason="WORKER_EXCEPTION")
            finally:
                try:
                    self.work_queue.task_done()
                except Exception:
                    pass

    # =========================================================================
    # ANÁLISIS DE EVENTO CON VERIFICACIÓN ANTI-TOCTOU
    # =========================================================================
    def _evaluate_event(self, ctx: AuthorizationContext):
        if ctx.responded:
            return

        # 0. Chequeo de seguridad anti-deadlock por PID o proceso del sistema excluido
        if (self.ignored_pids and ctx.pid in self.ignored_pids) or ctx.pid <= 2:
            ctx.respond(FAN_ALLOW, reason="SELF_OR_SYSTEM_PID")
            return

        target_path = f"<fd:{ctx.event_fd}>"
        proc_name = "desconocido"
        try:
            try:
                target_path = os.readlink(f"/proc/self/fd/{ctx.event_fd}")
            except Exception:
                pass

            ctx.target_path = target_path

            # 0b. Exclusión inmediata de infraestructura propia, bases ClamAV y pseudo-sistemas de archivos
            if target_path and not target_path.startswith("<fd:"):
                norm_p = target_path[:-10] if target_path.endswith(" (deleted)") else target_path
                # Infraestructura de Constantine
                if norm_p.startswith(("/opt/constantine", "/var/lib/constantine", "/var/log/constantine", "/run/constantine", "/etc/constantine")) or ("constantine" in norm_p.lower() and not norm_p.startswith("/tmp")):
                    ctx.respond(FAN_ALLOW, reason="SELF_INFRASTRUCTURE")
                    return
                # Infraestructura y bases de firmas de ClamAV
                if norm_p.startswith(("/var/lib/clamav", "/var/log/clamav", "/run/clamav")):
                    ctx.respond(FAN_ALLOW, reason="CLAMAV_INFRASTRUCTURE")
                    return
                # Pseudo-sistemas de archivos del kernel
                if norm_p.startswith(("/proc", "/sys", "/dev", "/run/systemd")):
                    ctx.respond(FAN_ALLOW, reason="KERNEL_PSEUDO_FS")
                    return

            proc_name = self.get_process_name(ctx.pid)
            ctx.proc_name = proc_name

            # 0c. Exclusión dinámica de procesos del sistema por nombre de comando
            if proc_name in self.ignored_comm_names:
                self.add_ignored_pid(ctx.pid)
                ctx.respond(FAN_ALLOW, reason="IGNORED_COMM")
                return

            # 1. VERIFICACIÓN ANTI-TOCTOU Y VALIDACIÓN DE INODO FIJADO EN KERNEL
            if target_path and not target_path.startswith("<fd:"):
                norm_target_path = target_path[:-10] if target_path.endswith(" (deleted)") else target_path
                # Si el archivo fue borrado entre openat y análisis (ej. ejecución de archivo desvinculado)
                if target_path.endswith(" (deleted)"):
                    is_exec = bool(ctx.mask & FAN_OPEN_EXEC_PERM)
                    if is_exec:
                        logger.critical("🚨 [TOCTOU] Intento de ejecución de binario eliminado en disco: %s (PID: %d)", target_path, ctx.pid)
                        ctx.respond(FAN_DENY, reason="TOCTOU_DELETED_EXEC")
                        return

                try:
                    fd_stat = os.fstat(ctx.event_fd)
                    path_stat = os.lstat(norm_target_path)

                    # Verificar si hubo sustitución de inodo o dispositivo (ataque de carrera/enlace simbólico)
                    if fd_stat.st_dev != path_stat.st_dev or fd_stat.st_ino != path_stat.st_ino:
                        logger.critical(
                            "🚨 [ATAQUE TOCTOU DETECTADO] Sustitución de archivo interceptada: "
                            "FD %d (%d:%d) != Ruta '%s' (%d:%d). Denegando operación por seguridad.",
                            ctx.event_fd, fd_stat.st_dev, fd_stat.st_ino, norm_target_path, path_stat.st_dev, path_stat.st_ino
                        )
                        self._record_internal_failure(
                            event_id=ctx.event_fd,
                            target_path=norm_target_path,
                            pid=ctx.pid,
                            proc_name=proc_name,
                            failure_type="TOCTOU_MISMATCH",
                            decision=FAN_DENY,
                            details=f"Inodo fd ({fd_stat.st_ino}) != inodo ruta ({path_stat.st_ino})"
                        )
                        ctx.respond(FAN_DENY, reason="TOCTOU_MISMATCH")
                        return
                except OSError as st_err:
                    logger.debug("Aviso verificando stat anti-TOCTOU en %s: %s", target_path, st_err)

            # 2. DETERMINACIÓN DE INTENCIÓN DE OPERACIÓN (FAIL-SECURE & eBPF)
            is_write_intent = False
            is_read_intent = False
            is_delete_or_rename = False

            ebpf_intent = None
            if self.ebpf_monitor and hasattr(self.ebpf_monitor, "get_process_file_intent"):
                ebpf_intent = self.ebpf_monitor.get_process_file_intent(ctx.pid, target_path)

            if ebpf_intent:
                is_write_intent = ebpf_intent.is_write
                is_read_intent = ebpf_intent.is_read
                is_delete_or_rename = ebpf_intent.is_delete or ebpf_intent.is_rename
            else:
                proc_exe = ""
                try:
                    proc_exe = os.path.realpath(f"/proc/{ctx.pid}/exe")
                except Exception:
                    pass

                is_whitelisted_proc = self.whitelist.is_trusted_system_binary(proc_exe) if proc_exe else False

                is_canary = False
                if self.ransomware and hasattr(self.ransomware, "is_canary_file"):
                    is_canary = self.ransomware.is_canary_file(target_path)
                elif self.ransomware and hasattr(self.ransomware, "canary_files"):
                    norm_t = os.path.abspath(target_path)
                    is_canary = norm_t in self.ransomware.canary_files

                if is_canary:
                    if is_whitelisted_proc:
                        is_read_intent = True
                        is_write_intent = False
                    else:
                        is_write_intent = True
                        is_read_intent = False
                else:
                    ext = os.path.splitext(target_path)[1].lower()
                    is_ransom_ext = False
                    if self.ransomware and hasattr(self.ransomware, "RANSOMWARE_EXTENSIONS"):
                        is_ransom_ext = ext in self.ransomware.RANSOMWARE_EXTENSIONS

                    if is_ransom_ext and not is_whitelisted_proc:
                        is_write_intent = True
                        is_read_intent = False
                    else:
                        is_read_intent = True
                        is_write_intent = False

            # 3. EVALUACIÓN ANTIRANSOMWARE INTEGRADA (Canary Traps, Extensiones y Ráfagas)
            if self.ransomware and target_path and not target_path.startswith("<fd:"):
                rw_decision = self.ransomware.evaluate_operation(
                    file_path=target_path,
                    pid=ctx.pid,
                    is_write=is_write_intent,
                    is_read=is_read_intent,
                    is_delete_or_rename=is_delete_or_rename,
                    target_fd=ctx.event_fd
                )
                if rw_decision.is_blocked:
                    logger.critical(
                        "🚨 [BLOQUEO FAN_DENY - RANSOMWARE] Interceptada actividad sospechosa por PID %d (%s) en: %s (Razón: %s, Terminar: %s)",
                        ctx.pid, proc_name, target_path, rw_decision.threat_reason, rw_decision.terminate_process
                    )
                    if self.firewall:
                        self.firewall.isolate_pid(ctx.pid, terminate=rw_decision.terminate_process)
                    ctx.respond(FAN_DENY, reason="RANSOMWARE_TRIGGERED")
                    return

            # 4. FILTRO ZERO-NAG DE DISTRIBUCIÓN
            if self.whitelist.is_whitelisted(target_path):
                ctx.respond(FAN_ALLOW, reason="WHITELISTED")
                return

            # 5. ANÁLISIS ESTÁTICO, HEURÍSTICO Y YARA OFICIAL (DESCRIPTORES FIJADOS EN KERNEL)
            scan_res = self.scanner.scan_file(target_fd=ctx.event_fd, file_path=target_path)
            if scan_res.is_malicious:
                logger.warning("🚨 [BLOQUEO FAN_DENY] %s (PID: %d) intentó ejecutar/abrir %s (%s)", proc_name, ctx.pid, target_path, scan_res.threat_name)
                if self.vault and os.path.exists(target_path):
                    self.vault.quarantine_file(target_path, scan_res.threat_name or "Malware", detected_by="FanotifyKernel", target_fd=ctx.event_fd)
                if self.notifier:
                    self.notifier.alert_threat_blocked(scan_res.threat_name or "Malware", target_path, ctx.pid, proc_name)
                if self.firewall:
                    self.firewall.isolate_pid(ctx.pid, terminate=False)
                ctx.respond(FAN_DENY, reason="MALWARE_DETECTED")
            else:
                ctx.respond(FAN_ALLOW, reason="CLEAN")

        except Exception as e:
            # 6. GESTIÓN DIFERENCIADA DE EXCEPCIONES SEGÚN RIESGO (FAIL-OPEN / FAIL-CLOSED)
            fallback = ctx.fallback_decision
            is_exec = bool(ctx.mask & FAN_OPEN_EXEC_PERM)
            policy_name = self.exec_fail_policy if is_exec else self.open_fail_policy

            self._record_internal_failure(
                event_id=ctx.event_fd,
                target_path=target_path,
                pid=ctx.pid,
                proc_name=proc_name,
                failure_type="SCANNER_EXCEPTION",
                decision=fallback,
                details=f"Excepción en análisis: {e} (Política {policy_name})"
            )

            if fallback == FAN_ALLOW:
                logger.warning("⚠️ [FAIL-OPEN APLICADO] Permitiendo %s (PID: %d) tras fallo interno: %s", target_path, ctx.pid, e)
            else:
                logger.critical("🚨 [FAIL-CLOSED APLICADO] Denegando %s (PID: %d) tras fallo interno: %s", target_path, ctx.pid, e)

            ctx.respond(fallback, reason="ANALYSIS_EXCEPTION")

    def process_single_event(self, event_fd: int, pid: int, mask: int = FAN_OPEN_PERM) -> int:
        """
        Procesa un evento de forma desacoplada con temporizador estricto de timeout.
        Ejecuta la evaluación en un hilo separado para que una tarea lenta no bloquee al llamador.
        """
        fallback_decision = self.get_fallback_decision(mask)
        ctx = AuthorizationContext(
            fan_fd=self.fan_fd,
            event_fd=event_fd,
            pid=pid,
            mask=mask,
            fallback_decision=fallback_decision,
            event_timeout=self.event_timeout,
            on_respond_callback=self._on_event_responded
        )
        ctx.start_timer()

        eval_thread = threading.Thread(
            target=self._evaluate_event,
            args=(ctx,),
            daemon=True
        )
        eval_thread.start()

        # Esperar la resolución (sea por fin del escaneo o por disparo del timeout)
        ctx.wait_for_response(timeout=self.event_timeout + 0.1)

        return ctx.decision if ctx.decision is not None else fallback_decision

    def _on_event_responded(self, ctx: AuthorizationContext):
        """Callback invocado cuando un evento es resuelto para alimentar métricas y auditoría."""
        if ctx.reason == "TIMEOUT":
            self.timeout_count += 1
            self._record_internal_failure(
                event_id=ctx.event_fd,
                target_path=ctx.target_path,
                pid=ctx.pid,
                proc_name=ctx.proc_name,
                failure_type="TIMEOUT",
                decision=ctx.decision if ctx.decision is not None else ctx.fallback_decision,
                details=f"Tiempo de análisis superó el umbral de {self.event_timeout:.2f}s."
            )
        elif ctx.reason == "QUEUE_OVERFLOW":
            pass
        elif ctx.reason in ("WORKER_EXCEPTION", "TOCTOU_DELETED_EXEC"):
            self._record_internal_failure(
                event_id=ctx.event_fd,
                target_path=ctx.target_path,
                pid=ctx.pid,
                proc_name=ctx.proc_name,
                failure_type=ctx.reason,
                decision=ctx.decision if ctx.decision is not None else ctx.fallback_decision,
                details=f"Resolución extraordinaria: {ctx.reason}"
            )

    def _record_internal_failure(
        self,
        event_id: int,
        target_path: str,
        pid: int,
        proc_name: str,
        failure_type: str,
        decision: int,
        details: str = ""
    ):
        dec_str = "FAN_ALLOW" if decision == FAN_ALLOW else "FAN_DENY"
        record = {
            "timestamp": time.time(),
            "event_id": event_id,
            "target_path": target_path,
            "pid": pid,
            "proc_name": proc_name,
            "failure_type": failure_type,
            "decision": dec_str,
            "details": details
        }
        with self._failure_lock:
            self.internal_failures.append(record)
            if len(self.internal_failures) > 1000:
                self.internal_failures.pop(0)

            if decision == FAN_DENY:
                self.blocked_by_internal_failure.append(record)
                if len(self.blocked_by_internal_failure) > 1000:
                    self.blocked_by_internal_failure.pop(0)

        if decision == FAN_DENY:
            logger.critical(
                "🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: %s | PID: %d (%s) | Archivo: %s | Detalles: %s",
                failure_type, pid, proc_name, target_path, details
            )
            if self.notifier:
                try:
                    self.notifier.alert_threat_blocked(
                        f"FalloInterno.{failure_type}",
                        target_path,
                        pid,
                        proc_name
                    )
                except Exception:
                    pass
        else:
            logger.warning(
                "⚠️ [OPERACIÓN PERMITIDA (FAIL-OPEN)] Tipo: %s | PID: %d (%s) | Archivo: %s | Detalles: %s",
                failure_type, pid, proc_name, target_path, details
            )

        if self.audit_logger and hasattr(self.audit_logger, "record_incident"):
            try:
                self.audit_logger.record_incident(
                    threat_name=f"InternalFailure.{failure_type}",
                    file_path=target_path,
                    action_taken=f"{dec_str}_BY_POLICY",
                    details=f"PID {pid} ({proc_name}) - {details}"
                )
            except Exception:
                pass

    def get_internal_failures(self) -> List[Dict[str, Any]]:
        """Devuelve la lista histórica de fallos internos (timeouts, saturaciones, excepciones, TOCTOU)."""
        with self._failure_lock:
            return list(self.internal_failures)

    def get_blocked_operations(self) -> List[Dict[str, Any]]:
        """Devuelve las operaciones que resultaron bloqueadas (FAN_DENY) por fallos internos."""
        with self._failure_lock:
            return list(self.blocked_by_internal_failure)

    # =========================================================================
    # BUCLE PRINCIPAL DE RECEPCIÓN NO BLOQUEANTE DESACOPLADO
    # =========================================================================
    def process_events(self):
        """
        Bucle de recepción de eventos de fanotify desacoplado del análisis:
        - Recepción no bloqueante de alta velocidad desde el kernel.
        - Encolado limitado (Bounded Work Queue) con detección de saturación inmediata.
        - Temporizador de timeout por evento con respuesta garantizada al kernel.
        - Recuperación automática ante fallos de descriptor de kernel.
        """
        self.running = True
        self._start_workers()
        buffer_size = 32768  # 32 KB para alta tasa de ingestión de eventos

        consecutive_errors = 0
        max_consecutive_errors = 5

        while self.running:
            try:
                if self.fan_fd < 0:
                    break

                poll = select.poll()
                poll.register(self.fan_fd, select.POLLIN | select.POLLERR | select.POLLHUP)
                events = poll.poll(500)
                if not events:
                    continue

                for _, event_flags in events:
                    if event_flags & (select.POLLERR | select.POLLHUP):
                        raise OSError(f"Descriptor fanotify en estado de error (poll flags=0x{event_flags:02x})")

                raw_data = os.read(self.fan_fd, buffer_size)
                if not raw_data:
                    continue

                consecutive_errors = 0
                offset = 0
                while offset + FAN_EVENT_METADATA_LEN <= len(raw_data):
                    meta = FanotifyEventMetadata.from_buffer_copy(raw_data[offset:offset + FAN_EVENT_METADATA_LEN])
                    if meta.vers != 3:
                        break

                    event_fd = meta.fd
                    pid = meta.pid
                    mask = meta.mask

                    # 0. PREVENCIÓN CRÍTICA DE DEADLOCK DEL KERNEL (AUTO-INTERCEPTACIÓN & SISTEMA BASE)
                    if pid == os.getpid() or pid <= 2 or pid in self.ignored_pids:
                        if event_fd >= 0:
                            self.respond(event_fd, FAN_ALLOW)
                            try:
                                os.close(event_fd)
                            except Exception:
                                pass
                        offset += meta.event_len
                        continue

                    # 1. Control de Desbordamiento en Kernel (FAN_Q_OVERFLOW)
                    if mask & FAN_Q_OVERFLOW:
                        self.overflow_count += 1
                        logger.critical("🚨 [FANOTIFY OVERFLOW #%d] Desbordamiento de cola de eventos en kernel detectado.", self.overflow_count)
                        self._record_internal_failure(
                            event_id=-1,
                            target_path="<KERNEL_QUEUE>",
                            pid=pid,
                            proc_name="kernel",
                            failure_type="KERNEL_QUEUE_OVERFLOW",
                            decision=FAN_ALLOW,
                            details=f"Desbordamiento de búfer en kernel fanotify (evento #{self.overflow_count})"
                        )
                        offset += meta.event_len
                        continue

                    # 2. Despacho desacoplado con garantía de respuesta
                    if event_fd >= 0:
                        fallback_decision = self.get_fallback_decision(mask)
                        ctx = AuthorizationContext(
                            fan_fd=self.fan_fd,
                            event_fd=event_fd,
                            pid=pid,
                            mask=mask,
                            fallback_decision=fallback_decision,
                            event_timeout=self.event_timeout,
                            on_respond_callback=self._on_event_responded
                        )
                        ctx.start_timer()

                        # Encolar en la cola de trabajo limitada (sin bloquear el receptor)
                        try:
                            self.work_queue.put_nowait(ctx)
                        except queue.Full:
                            self.queue_overflow_count += 1
                            logger.critical(
                                "🚨 [COLA DE TRABAJO LLENA #%d] Cola de análisis al máximo (%d). "
                                "Aplicando política de fallo inmediata para PID %d.",
                                self.queue_overflow_count, self.max_queue_size, pid
                            )
                            self._record_internal_failure(
                                event_id=event_fd,
                                target_path=f"<fd:{event_fd}>",
                                pid=pid,
                                proc_name=self.get_process_name(pid),
                                failure_type="WORK_QUEUE_OVERFLOW",
                                decision=fallback_decision,
                                details=f"Cola saturada ({self.max_queue_size} eventos). Despacho inmediato."
                            )
                            # Respuesta inmediata para no colgar el proceso del kernel
                            ctx.respond(fallback_decision, reason="QUEUE_OVERFLOW")

                    offset += meta.event_len

            except KeyboardInterrupt:
                break
            except Exception as loop_err:
                consecutive_errors += 1
                logger.error("Error en bucle de polling fanotify (consecutivos: %d): %s", consecutive_errors, loop_err)
                if consecutive_errors >= max_consecutive_errors:
                    logger.warning("Demasiados errores consecutivos en fanotify. Ejecutando recuperación automática...")
                    recovered = self.recover_service()
                    if recovered:
                        consecutive_errors = 0
                    else:
                        logger.critical("Recuperación automática falló. Deteniendo interceptor.")
                        break
                time.sleep(0.1)

        self.stop()

    def recover_service(self) -> bool:
        """
        Recupera automáticamente el servicio de interceptación tras una avería del descriptor:
        1. Limpia y cierra el descriptor de kernel defectuoso.
        2. Drena la cola de trabajo pendiente enviando respuestas de fallback a los eventos huérfanos.
        3. Reinicializa fanotify_init en el kernel.
        4. Re-engancha todas las rutas y puntos de montaje activos.
        5. Reinicia el grupo de trabajadores concurrentes.
        """
        logger.warning("🔄 [RECUPERACIÓN AUTOMÁTICA] Intentando restaurar el servicio Fanotify...")
        old_running = self.running
        self.stop()
        time.sleep(0.3)

        if not self.initialize():
            logger.error("❌ Recuperación automática falló: no se pudo reiniciar fanotify_init.")
            return False

        re_marked = 0
        for mp in list(self.active_mounts):
            if self.mark_directory(mp, mark_mount=True):
                re_marked += 1

        for p in list(self.marked_paths):
            if p not in self.active_mounts:
                if self.mark_directory(p, mark_mount=False, recursive=True):
                    re_marked += 1

        self.running = old_running
        self._start_workers()
        self._start_mount_watcher()
        logger.info("✅ Servicio Fanotify recuperado exitosamente (%d rutas restauradas).", re_marked)
        return True

    def stop(self):
        """Detiene el interceptor, drena la cola respondiendo con fallback y libera descriptores."""
        self.running = False

        # Drenar cola pendiente respondiendo con fallback para no dejar procesos del kernel colgados
        while not self.work_queue.empty():
            try:
                ctx = self.work_queue.get_nowait()
                ctx.respond(ctx.fallback_decision, reason="INTERCEPTOR_SHUTDOWN")
                self.work_queue.task_done()
            except Exception:
                break

        # Esperar al hilo receptor de eventos si fue iniciado en segundo plano por start()
        if self.event_thread and self.event_thread.is_alive() and threading.current_thread() != self.event_thread:
            try:
                self.event_thread.join(timeout=0.5)
            except Exception:
                pass
        self.event_thread = None

        # Detener hilos trabajadores
        with self._workers_lock:
            for w in self.workers:
                if w.is_alive() and threading.current_thread() != w:
                    try:
                        w.join(timeout=0.2)
                    except Exception:
                        pass
            self.workers.clear()

        # Detener centinela de montajes
        if self.mount_watcher_thread and self.mount_watcher_thread.is_alive():
            if threading.current_thread() != self.mount_watcher_thread:
                try:
                    self.mount_watcher_thread.join(timeout=0.2)
                except Exception:
                    pass
        self.mount_watcher_thread = None

        if self.fan_fd >= 0:
            try:
                os.close(self.fan_fd)
            except OSError:
                pass
            self.fan_fd = -1

        self.marked_paths.clear()
        self.active_mounts.clear()
        self.is_initialized = False
        self.is_marked = False
        logger.info("Interceptor fanotify detenido limpiamente.")
