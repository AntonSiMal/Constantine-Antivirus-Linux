"""
Interceptor en Tiempo Real Fanotify con Prevención Anti-Deadlock, Fail-Secure y Receptor de Eventos de Kernel.
Implementa llamadas al sistema nativas fanotify_init(2) y fanotify_mark(2) mediante libc,
gestión de permisos en espacio de usuario y ciclo receptor de eventos de kernel en segundo plano.
"""
import os
import stat
import errno
import select
import ctypes
import logging
import threading
from typing import Dict, Any, Optional, Tuple, Callable, Set, List
from core.engine.scanner import Scanner
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.interceptor")

# Carga de libc para llamadas al sistema fanotify
try:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
except Exception as e:
    logger.error("Error cargando libc.so.6: %s", e)
    libc = None

# =============================================================================
# CONSTANTES DE FANOTIFY DE KERNEL LINUX (linux/fanotify.h & sys/fanotify.h)
# =============================================================================

# Flags para fanotify_init()
FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_NOTIF = 0x00000000
FAN_CLASS_CONTENT = 0x00000004
FAN_CLASS_PRE_CONTENT = 0x00000008
FAN_ALL_CLASS_BITS = 0x0000000C
FAN_UNLIMITED_QUEUE = 0x00000010
FAN_UNLIMITED_MARKS = 0x00000020
FAN_ENABLE_AUDIT = 0x00000040

# Flags para fanotify_mark()
FAN_MARK_ADD = 0x00000001
FAN_MARK_REMOVE = 0x00000002
FAN_MARK_DONT_FOLLOW = 0x00000004
FAN_MARK_ONLYDIR = 0x00000008
FAN_MARK_MOUNT = 0x00000010
FAN_MARK_IGNORED_MASK = 0x00000020
FAN_MARK_IGNORED_SURV_MODIFY = 0x00000040
FAN_MARK_FLUSH = 0x00000080
FAN_MARK_FILESYSTEM = 0x00000100

AT_FDCWD = -100

# Máscaras de eventos informativos y de permiso
FAN_ACCESS = 0x00000001
FAN_MODIFY = 0x00000002
FAN_ATTRIB = 0x00000004
FAN_CLOSE_WRITE = 0x00000008
FAN_CLOSE_NOWRITE = 0x00000010
FAN_OPEN = 0x00000020
FAN_MOVED_FROM = 0x00000040
FAN_MOVED_TO = 0x00000080
FAN_CREATE = 0x00000100
FAN_DELETE = 0x00000200
FAN_DELETE_SELF = 0x00000400
FAN_MOVE_SELF = 0x00000800
FAN_OPEN_EXEC = 0x00001000
FAN_Q_OVERFLOW = 0x00004000
FAN_FS_ERROR = 0x00008000

# Eventos de permiso (Requieren respuesta síncrona en espacio de usuario)
FAN_OPEN_PERM = 0x00010000
FAN_ACCESS_PERM = 0x00020000
FAN_OPEN_EXEC_PERM = 0x00040000

FAN_EVENT_ON_CHILD = 0x08000000
FAN_ONDIR = 0x40000000

# Decisiones de permiso enviadas al kernel
FAN_ALLOW = 0x01
FAN_DENY = 0x02
FAN_AUDIT = 0x10

FAN_NOFD = -1
FANOTIFY_METADATA_VERSION = 3


# =============================================================================
# ESTRUCTURAS C DE FANOTIFY
# =============================================================================

class FanotifyEventMetadata(ctypes.Structure):
    """Estructura de metadata de evento entregada por el kernel (fanotify_event_metadata)."""
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
    """Estructura de respuesta de permiso escrita hacia el descriptor fanotify (fanotify_response)."""
    _fields_ = [
        ("fd", ctypes.c_int32),
        ("response", ctypes.c_uint32),
    ]


# Tipado de llamadas a libc si está disponible
if libc and hasattr(libc, "fanotify_init"):
    libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
    libc.fanotify_init.restype = ctypes.c_int

if libc and hasattr(libc, "fanotify_mark"):
    libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    libc.fanotify_mark.restype = ctypes.c_int


# =============================================================================
# CLASE PRINCIPAL: FanotifyInterceptor
# =============================================================================

class FanotifyInterceptor:
    """
    Interceptor de eventos de kernel on-access (fanotify) con control preventivo
    mediante llamadas nativas fanotify_init() y fanotify_mark(), ciclo receptor
    multihilo y protocolo de respuesta de permiso al kernel.
    """

    def __init__(self, scanner: Optional[Scanner] = None, vault: Optional[CryptographicVault] = None,
                 fail_policy: str = "fail-closed", timeout: float = 0.5, resilience: Optional[Any] = None,
                 excluded_pids: Optional[List[int]] = None, is_test: bool = False):
        self.scanner = scanner or Scanner()
        self.vault = vault or CryptographicVault()
        self.fail_policy = fail_policy
        self.timeout = timeout
        self.resilience = resilience
        self.excluded_pids: Set[int] = set(excluded_pids or [])
        self.delegated_mode: bool = False  # True si ClamOnAcc asume intercepción primaria
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self.state = "INIT"
        self.fanotify_fd: Optional[int] = None
        self.fanotify_operational: bool = False
        self.marked_mounts: List[str] = []
        self.is_test = is_test
        self.events_processed = 0
        self.events_allowed = 0
        self.events_denied = 0

    # -------------------------------------------------------------------------
    # Llamadas de bajo nivel fanotify_init y fanotify_mark
    # -------------------------------------------------------------------------

    def fanotify_init(self, flags: Optional[int] = None, event_f_flags: Optional[int] = None) -> int:
        """
        Invoca la llamada al sistema fanotify_init(2) del kernel Linux.
        Crea el descriptor fanotify con capacidad de interceptar permisos de acceso a archivos.
        """
        if not libc or not hasattr(libc, "fanotify_init"):
            logger.error("libc no tiene disponible el símbolo fanotify_init en este sistema.")
            return -1

        if flags is None:
            # FAN_CLASS_CONTENT permite evaluar y denegar preventivamente antes de I/O
            flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC
        if event_f_flags is None:
            event_f_flags = os.O_RDONLY | os.O_LARGEFILE | os.O_CLOEXEC

        return libc.fanotify_init(flags, event_f_flags)

    def fanotify_mark(self, fanotify_fd: int, flags: int, mask: int, dirfd: int = AT_FDCWD, pathname: str = "/") -> int:
        """
        Invoca la llamada al sistema fanotify_mark(2) del kernel Linux.
        Registra la máscara de eventos y puntos de montaje supervisados.
        """
        if not libc or not hasattr(libc, "fanotify_mark"):
            logger.error("libc no tiene disponible el símbolo fanotify_mark en este sistema.")
            return -1

        path_bytes = os.fsencode(pathname) if isinstance(pathname, str) else pathname
        return libc.fanotify_mark(fanotify_fd, flags, ctypes.c_uint64(mask), dirfd, path_bytes)

    def init_fanotify(self) -> bool:
        """
        Inicializa el descriptor fanotify en el kernel verificando privilegios.
        """
        if self.fanotify_fd is not None and self.fanotify_fd >= 0:
            return True

        fd = self.fanotify_init()
        if fd < 0:
            err = ctypes.get_errno()
            err_name = errno.errorcode.get(err, str(err))
            logger.warning("⚠️ [FANOTIFY EN KERNEL NO DISPONIBLE] fanotify_init falló (errno: %d, %s). "
                           "Requiere privilegios CAP_SYS_ADMIN (root) y soporte fanotify en kernel.", err, err_name)
            self.fanotify_fd = None
            self.fanotify_operational = False
            return False

        self.fanotify_fd = fd
        self.fanotify_operational = True
        logger.info("🛡️ [FANOTIFY KERNEL INICIALIZADO] Descriptor fanotify_fd=%d creado con éxito (FAN_CLASS_CONTENT).", fd)
        return True

    def mark_path(self, path: str, mark_mount: bool = True, flags: Optional[int] = None, mask: Optional[int] = None) -> bool:
        """
        Registra un punto de montaje o sistema de archivos para intercepción mediante fanotify_mark.
        """
        if self.fanotify_fd is None or self.fanotify_fd < 0:
            logger.debug("mark_path llamado sin descriptor fanotify activo.")
            return False

        if not os.path.exists(path):
            logger.warning("Ruta para fanotify_mark no existe: %s", path)
            return False

        if flags is None:
            flags = FAN_MARK_ADD | (FAN_MARK_MOUNT if mark_mount else FAN_MARK_INODE)

        if mask is None:
            mask = FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE

        ret = self.fanotify_mark(self.fanotify_fd, flags, mask, dirfd=AT_FDCWD, pathname=path)
        if ret < 0:
            err = ctypes.get_errno()
            err_name = errno.errorcode.get(err, str(err))
            logger.warning("⚠️ [FANOTIFY MARK FALLÓ] fanotify_mark en '%s' falló con errno %d (%s)", path, err, err_name)
            return False

        if path not in self.marked_mounts:
            self.marked_mounts.append(path)
        logger.info("📍 [FANOTIFY MONTAJE REGISTRADO] Punto '%s' enganchado en kernel (mask=0x%x).", path, mask)
        return True

    def mark_default_mounts(self) -> int:
        """
        Engancha los sistemas de archivos activos del sistema operativo (raíz / y /proc/mounts).
        """
        if self.fanotify_fd is None or self.fanotify_fd < 0:
            return 0

        count = 0
        if self.mark_path("/", mark_mount=True):
            count += 1

        pseudo_fs = {"proc", "sysfs", "devpts", "cgroup", "cgroup2", "pstore", "bpf", "debugfs", "securityfs", "fusectl", "mqueue"}
        if os.path.exists("/proc/mounts"):
            try:
                with open("/proc/mounts", "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            mpoint = parts[1]
                            fstype = parts[2]
                            if fstype not in pseudo_fs and mpoint != "/" and os.path.exists(mpoint):
                                if not self.is_infrastructure_path(mpoint):
                                    if self.mark_path(mpoint, mark_mount=True):
                                        count += 1
            except Exception as e:
                logger.debug("Error leyendo /proc/mounts: %s", e)

        return count

    # -------------------------------------------------------------------------
    # Coordinación y Políticas
    # -------------------------------------------------------------------------

    def register_excluded_pids(self, pids: List[int]):
        """Registra PIDs a excluir para evitar bucles de doble enganche con clamd/clamonacc."""
        self.excluded_pids.update(pids)

    def set_delegated_mode(self, delegated: bool):
        """Activa o desactiva la delegación de intercepción on-access a ClamOnAcc."""
        self.delegated_mode = delegated
        logger.info("⚙️ [INTERCEPTOR] Modo delegado ClamOnAcc: %s", "ACTIVADO" if delegated else "DESACTIVADO")

    def is_infrastructure_path(self, path: str) -> bool:
        """Determina si la ruta corresponde a la infraestructura interna del antivirus para evitar deadlocks."""
        norm = os.path.normpath(path)
        infra_dirs = ("/var/lib/constantine", "/var/log/constantine", "/run/constantine", "/etc/constantine", "/opt/constantine", "/var/lib/clamav", "/run/clamav")
        for idir in infra_dirs:
            if norm == idir or norm.startswith(idir + "/"):
                return True
        return False

    def evaluate_access(self, event_fd: int, file_path: str, pid: int = 0, comm: str = "") -> int:
        """
        Evalúa si se permite o deniega la operación sobre el archivo:
        1. Bypass si el PID pertenece a ClamAV/ClamOnAcc o está en excluded_pids (Modelo Híbrido Coordinado).
        2. Bypass si la intercepción está delegada a ClamOnAcc a nivel de sistema.
        3. Comprobación anti-deadlock e infraestructura interna.
        4. Comprobación anti-TOCTOU (fstat fd vs lstat path).
        5. Escaneo con fail-secure / fail-closed ante excepciones o timeout.
        """
        # 0. Bypass de Modelo Híbrido Coordinado: PID excluido o modo delegado
        if pid in self.excluded_pids or comm in ("clamd", "clamonacc"):
            return FAN_ALLOW
        if self.delegated_mode:
            return FAN_ALLOW

        # 0.1 Bypass de Resiliencia: Modo de Mantenimiento y Disyuntor de Emergencia
        if self.resilience and self.resilience.is_file_access_permitted_fast():
            return FAN_ALLOW

        # 1. Anti-Deadlock Bypass
        if self.is_infrastructure_path(file_path):
            return FAN_ALLOW

        # 2. Comprobación Anti-TOCTOU
        try:
            fd_st = os.fstat(event_fd)
            path_st = os.lstat(file_path)
            if fd_st.st_ino != path_st.st_ino or fd_st.st_dev != path_st.st_dev:
                logger.critical("🚨 [ATAQUE TOCTOU DETECTADO] Sustitución de archivo interceptada: FD %d (%d:%d) != Ruta '%s' (%d:%d). Denegando operación por seguridad.",
                                event_fd, fd_st.st_dev, fd_st.st_ino, file_path, path_st.st_dev, path_st.st_ino)
                logger.critical("🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: TOCTOU_MISMATCH | PID: %d (%s) | Archivo: %s | Detalles: Inodo fd (%d) != inodo ruta (%d)",
                                pid, comm, file_path, fd_st.st_ino, path_st.st_ino)
                return FAN_DENY
        except OSError:
            return FAN_DENY

        # 3. Escaneo y Decisión
        try:
            report = self.scanner.scan_file(file_path)
            if self.resilience:
                self.resilience.record_scan_success()
            if report.is_threat:
                # Cuarentena automática transaccional
                self.vault.quarantine_file(file_path, threat_name=report.threat_name, target_fd=event_fd)
                logger.info("[NOTIFICACIÓN DESKTOP] ⚔️ Constantine: Amenaza Bloqueada | <b>Amenaza:</b> %s - <b>Archivo:</b> %s - <b>Proceso:</b> %s (PID: %d) - <b>Acción:</b> Neutralizado en Baúl",
                            report.threat_name, file_path, comm or "Scanner", pid)
                return FAN_DENY

            # 3.1 Verificación explícita: SOLO permitir si el reporte es VERIFICADO LIMPIO
            if (getattr(report, "is_clean", False) or getattr(report, "status", None) == "CLEAN") and not getattr(report, "is_indeterminate", False):
                return FAN_ALLOW

            # 3.2 Si no es explícitamente limpio ni amenaza confirmada, es ANÁLISIS INDETERMINADO (Fail-Secure)
            if self.resilience:
                self.resilience.record_scan_timeout(file_path)
            det = getattr(report, "details", "Análisis no concluyente")
            if self.fail_policy in ("fail-open", "open") or (self.resilience and self.resilience.is_file_access_permitted_fast()):
                logger.warning("⚠️ [OPERACIÓN PERMITIDA (FAIL-OPEN)] Tipo: INDETERMINATE_SCAN | PID: %d (%s) | Archivo: %s | Detalles: %s (Política open)",
                               pid, comm, file_path, det)
                logger.warning("⚠️ [FAIL-OPEN APLICADO] Permitiendo %s (PID: %d) tras análisis indeterminado: %s", file_path, pid, det)
                return FAN_ALLOW
            else:
                logger.critical("🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: INDETERMINATE_SCAN | PID: %d (%s) | Archivo: %s | Detalles: %s (Política closed)",
                                pid, comm, file_path, det)
                logger.critical("🚨 [FAIL-CLOSED APLICADO] Denegando %s (PID: %d) tras análisis indeterminado: %s", file_path, pid, det)
                return FAN_DENY
        except Exception as e:
            if self.resilience:
                self.resilience.record_scan_timeout(file_path)
            if self.fail_policy == "fail-open" or self.fail_policy == "open" or (self.resilience and self.resilience.is_file_access_permitted_fast()):
                logger.warning("⚠️ [OPERACIÓN PERMITIDA (FAIL-OPEN)] Tipo: SCANNER_EXCEPTION | PID: %d (%s) | Archivo: %s | Detalles: Excepción en análisis: %s (Política open)",
                               pid, comm, file_path, e)
                logger.warning("⚠️ [FAIL-OPEN APLICADO] Permitiendo %s (PID: %d) tras fallo interno: %s", file_path, pid, e)
                return FAN_ALLOW
            else:
                logger.critical("🚨 [OPERACIÓN BLOQUEADA POR FALLO INTERNO] Tipo: SCANNER_EXCEPTION | PID: %d (%s) | Archivo: %s | Detalles: Excepción en análisis: %s (Política closed)",
                                pid, comm, file_path, e)
                logger.critical("🚨 [FAIL-CLOSED APLICADO] Denegando %s (PID: %d) tras fallo interno: %s", file_path, pid, e)
                return FAN_DENY

    # -------------------------------------------------------------------------
    # Ciclo Receptor de Eventos de Kernel y Respuestas de Permiso
    # -------------------------------------------------------------------------

    def _send_permission_response(self, event_fd: int, response_decision: int) -> bool:
        """
        Envía struct fanotify_response escribiendo al descriptor fanotify_fd
        para desbloquear al kernel permitiendo (FAN_ALLOW) o denegando (FAN_DENY) el acceso.
        """
        if self.fanotify_fd is None or self.fanotify_fd < 0:
            return False

        try:
            resp = FanotifyResponse(fd=event_fd, response=response_decision)
            written = os.write(self.fanotify_fd, bytes(resp))
            return written == ctypes.sizeof(FanotifyResponse)
        except OSError as e:
            logger.error("Error escribiendo respuesta fanotify en kernel para fd %d: %s", event_fd, e)
            return False

    def _handle_kernel_event(self, metadata: FanotifyEventMetadata):
        """Procesa un evento individual leído desde el buffer de fanotify."""
        self.events_processed += 1
        event_fd = metadata.fd
        event_mask = metadata.mask
        event_pid = metadata.pid

        if event_mask & FAN_Q_OVERFLOW:
            logger.warning("⚠️ [FANOTIFY COLA DESBORDADA] Se produjo FAN_Q_OVERFLOW en el buffer del kernel.")
            return

        is_perm_event = bool(event_mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM | FAN_OPEN_EXEC_PERM))

        comm = ""
        if event_pid > 0:
            try:
                with open(f"/proc/{event_pid}/comm", "r") as f:
                    comm = f.read().strip()
            except (OSError, IOError):
                comm = ""

        file_path = ""
        if event_fd >= 0:
            try:
                file_path = os.readlink(f"/proc/self/fd/{event_fd}")
            except OSError:
                file_path = f"/proc/self/fd/{event_fd}"

        if is_perm_event and event_fd >= 0:
            response_decision = FAN_ALLOW
            try:
                response_decision = self.evaluate_access(event_fd, file_path, pid=event_pid, comm=comm)
                if response_decision == FAN_DENY:
                    self.events_denied += 1
                else:
                    self.events_allowed += 1
            except Exception as e:
                logger.error("Excepción evaluando permiso fanotify: %s", e)
                response_decision = FAN_DENY if self.fail_policy in ("fail-closed", "closed") else FAN_ALLOW
            finally:
                self._send_permission_response(event_fd, response_decision)
                try:
                    os.close(event_fd)
                except OSError:
                    pass
        elif event_fd >= 0:
            # Para eventos informativos no de permiso (p.ej. FAN_CLOSE_WRITE)
            try:
                os.close(event_fd)
            except OSError:
                pass

    def _event_loop(self):
        """Ciclo receptor en segundo plano que procesa eventos del kernel y responde a eventos de permiso."""
        logger.info("🚀 [FANOTIFY LOOP] Ciclo receptor de eventos de kernel iniciado.")
        meta_len = ctypes.sizeof(FanotifyEventMetadata)

        while self.running and self.fanotify_fd is not None and self.fanotify_fd >= 0:
            try:
                r, _, _ = select.select([self.fanotify_fd], [], [], 0.5)
                if not r or not self.running:
                    continue

                buffer = os.read(self.fanotify_fd, 8192)
                if not buffer:
                    break

                offset = 0
                while len(buffer) - offset >= meta_len:
                    metadata = FanotifyEventMetadata.from_buffer_copy(buffer, offset)
                    event_len = metadata.event_len
                    if event_len < meta_len or offset + event_len > len(buffer):
                        break

                    if metadata.vers != FANOTIFY_METADATA_VERSION:
                        logger.error("Versión no soportada de fanotify metadata: %d", metadata.vers)
                        break

                    self._handle_kernel_event(metadata)
                    offset += event_len

            except BlockingIOError:
                continue
            except (OSError, ValueError) as e:
                if not self.running:
                    break
                logger.error("Error en ciclo receptor fanotify: %s", e)
                break
            except Exception as e:
                logger.error("Excepción inesperada en ciclo receptor fanotify: %s", e)
                if not self.running:
                    break

        logger.info("⏹️ [FANOTIFY LOOP] Ciclo receptor de eventos fanotify finalizado.")

    # -------------------------------------------------------------------------
    # Gestión de Ciclo de Vida
    # -------------------------------------------------------------------------

    def start_listening(self, mock_fd: Optional[int] = None):
        """
        Inicia la escucha de eventos de kernel:
        1. Crea el descriptor mediante fanotify_init() o mock_fd.
        2. Registra puntos de montaje mediante fanotify_mark().
        3. Lanza el ciclo receptor multihilo que evalúa y responde a los eventos.
        """
        self.running = True

        if mock_fd is not None:
            self.fanotify_fd = mock_fd
            self.fanotify_operational = True
            self.state = "ACTIVE"
            self._thread = threading.Thread(target=self._event_loop, daemon=True, name="ConstantineFanotifyWorker")
            self._thread.start()
            logger.info("✅ Hilo receptor de eventos fanotify activo y verificado en segundo plano (mock_fd=%d).", mock_fd)
            return

        initialized = self.init_fanotify()
        if initialized:
            marked_count = self.mark_default_mounts()
            self._thread = threading.Thread(target=self._event_loop, daemon=True, name="ConstantineFanotifyWorker")
            self._thread.start()
            self.state = "ACTIVE"
            logger.info("✅ Hilo receptor de eventos fanotify activo y verificado en segundo plano (fd=%d, montajes=%d).",
                        self.fanotify_fd, marked_count)
        else:
            # En entornos sin privilegios de root (CAP_SYS_ADMIN), el interceptor pasa a modo degradado
            self.state = "ACTIVE"
            self.fanotify_operational = False
            logger.warning("⚠️ [MODO DEGRADADO ACTIVADO] Interceptor fanotify iniciado sin descriptor de kernel (falta CAP_SYS_ADMIN o soporte en kernel).")

    def stop(self):
        """Detiene el ciclo receptor y cierra el descriptor fanotify en kernel."""
        self.running = False
        self.state = "STOPPED"
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            self._thread = None

        if self.fanotify_fd is not None and self.fanotify_fd >= 0:
            try:
                os.close(self.fanotify_fd)
            except OSError:
                pass
            self.fanotify_fd = None

        self.fanotify_operational = False
        self.marked_mounts.clear()
        logger.info("Interceptor fanotify detenido limpiamente.")

    def is_verified_operational(self) -> bool:
        """
        Verifica rigurosamente si el interceptor está en ejecución y con descriptor
        fanotify válido y operativo en el kernel de Linux.
        Bajo ninguna circunstancia retorna True si el descriptor no existe o no es válido.
        """
        return bool(
            self.running
            and self.fanotify_operational
            and self.fanotify_fd is not None
            and self.fanotify_fd >= 0
        )

    def get_status(self) -> Dict[str, Any]:
        """Retorna el diagnóstico completo del estado del interceptor fanotify."""
        return {
            "running": self.running,
            "state": self.state,
            "operational": self.fanotify_operational,
            "fanotify_fd": self.fanotify_fd,
            "marked_mounts": list(self.marked_mounts),
            "delegated_mode": self.delegated_mode,
            "excluded_pids_count": len(self.excluded_pids),
            "events_processed": self.events_processed,
            "events_allowed": self.events_allowed,
            "events_denied": self.events_denied
        }
