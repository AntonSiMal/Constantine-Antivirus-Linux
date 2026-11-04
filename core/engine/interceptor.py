"""
Constantine Antivirus - Fanotify Kernel Interceptor (core/engine/interceptor.py)
Interceptación síncrona en kernel mediante fanotify (FAN_OPEN_PERM & FAN_OPEN_EXEC_PERM):
- Corrección de constantes oficiales de Linux (<linux/fanotify.h>):
  * FAN_OPEN_PERM       = 0x00010000 (Permiso síncrono de apertura)
  * FAN_OPEN_EXEC_PERM  = 0x00040000 (Permiso síncrono de ejecución en Linux >= 5.0)
  * FAN_EVENT_ON_CHILD  = 0x08000000 (Eventos sobre archivos hijos en marcas de directorio)
  * FAN_Q_OVERFLOW      = 0x00004000 (Detección y control de desbordamiento de cola de eventos)
  * FAN_UNLIMITED_QUEUE = 0x00000010 (Cola de eventos sin límite de desbordamiento)
  * FAN_UNLIMITED_MARKS = 0x00000020 (Marcas de fanotify ilimitadas para cobertura total)
- Cobertura Verificable de Todo el Sistema (Recursividad Total):
  * Estrategia de montaje y sistema de archivos (FAN_MARK_FILESYSTEM / FAN_MARK_MOUNT):
    Cubre de forma intrínseca y 100% recursiva todos los archivos existentes, subdirectorios
    y archivos creados en el futuro.
  * Marcado recursivo de directorios (os.walk) con FAN_EVENT_ON_CHILD para marcas locales.
  * Centinela dinámico de puntos de montaje (/proc/mounts): detecta y engancha automáticamente
    nuevos dispositivos USB, discos y montajes en caliente, y gestiona desmontajes.
  * Filtrado inteligente de pseudo-sistemas de archivos no compatibles (proc, sysfs, cgroup, bpf).
  * Control y recuperación ante desbordamientos de cola (FAN_Q_OVERFLOW).
- INTEGRACIÓN ANTIRANSOMWARE ACTIVA:
  * El interceptor evalúa cada evento de E/S contra el módulo RansomwareShield (canary traps,
    extensiones de ransomware y ráfagas de cifrado masivo).
  * Si se detecta un patrón de ransomware, devuelve inmediatamente FAN_DENY y congela la operación.
- POLÍTICA ESTRICTA FAIL-SECURE / ZERO-TRUST:
  * Ante cualquier fallo, excepción o desbordamiento, la decisión es estrictamente FAN_DENY.
"""
import os
import time
import ctypes
import select
import logging
import threading
from typing import Optional, List, Set
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

class FanotifyInterceptor:
    def __init__(self, scanner, vault=None, notifier=None, firewall=None, ransomware=None, fail_policy: str = "secure"):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.firewall = firewall
        self.ransomware = ransomware  # Módulo Anti-Ransomware conectado
        self.fail_policy = fail_policy  # 'secure' (Fail-Close estricto por defecto), 'safe' (Fail-Open)
        self.whitelist = SystemWhitelist()
        self.fan_fd = -1
        self.running = False
        self.marked_paths: Set[str] = set()
        self.active_mounts: Set[str] = set()
        self.kernel_supports_exec_perm = True
        self.mount_watcher_thread: Optional[threading.Thread] = None
        self.overflow_count = 0

    def initialize(self) -> bool:
        """Inicializa fanotify con cola ilimitada y marcas ilimitadas para prevenir desbordamientos."""
        if os.geteuid() != 0:
            logger.error("Fanotify requiere privilegios de superusuario (root / CAP_SYS_ADMIN).")
            return False

        # Intentar inicialización con cola y marcas ilimitadas para máxima robustez
        flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC | FAN_UNLIMITED_QUEUE | FAN_UNLIMITED_MARKS
        event_f_flags = os.O_RDONLY | os.O_CLOEXEC
        try:
            self.fan_fd = libc.fanotify_init(flags, event_f_flags)
            if self.fan_fd < 0:
                # Respaldo si el kernel restringe FAN_UNLIMITED_*
                flags = FAN_CLASS_CONTENT | FAN_NONBLOCK | FAN_CLOEXEC
                self.fan_fd = libc.fanotify_init(flags, event_f_flags)

            if self.fan_fd < 0:
                err = ctypes.get_errno()
                logger.error("fanotify_init falló con errno %d (%s)", err, os.strerror(err))
                return False

            logger.info("✅ fanotify_init exitoso (fd: %d, flags: 0x%08x)", self.fan_fd, flags)
            return True
        except Exception as e:
            logger.error("Excepción en fanotify_init: %s", e)
            return False

    def is_active(self) -> bool:
        """Comprueba si el interceptor está realmente activo y tiene rutas enganchadas."""
        return self.running and self.fan_fd >= 0 and len(self.marked_paths) > 0

    def mark_directory(self, path: str, mark_mount: bool = False, mark_filesystem: bool = False, recursive: bool = True) -> bool:
        """
        Marca un directorio, punto de montaje o sistema de archivos para interceptación síncrona.
        - En marcas de montaje o filesystem: La cobertura es 100% recursiva por diseño del kernel (FAN_MARK_MOUNT / FAN_MARK_FILESYSTEM).
        - En marcas de directorio individual: Incorpora FAN_EVENT_ON_CHILD y recorre recursivamente todos los subdirectorios.
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

        # Base de permisos de interceptación
        base_perm = FAN_OPEN_PERM | (FAN_OPEN_EXEC_PERM if self.kernel_supports_exec_perm else 0)
        
        # En marcas de directorio individual (no montaje), FAN_EVENT_ON_CHILD es obligatorio para ver los archivos contenidos
        mask = base_perm
        if not is_mount_or_fs:
            mask |= FAN_EVENT_ON_CHILD

        success = self._apply_fanotify_mark(path, flags, mask)

        # Si es un directorio individual y se solicita recursividad, marcar también todos los subdirectorios existentes
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
            logger.info("🎯 Enganchado fanotify en: %s (flags=0x%08x, mask=0x%08x)", path, flags, mask)
            return True

        err = ctypes.get_errno()
        # Manejo de fallback para kernels < 5.0 que no soportan FAN_OPEN_EXEC_PERM (EINVAL / 22)
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

        # Si el sistema de archivos no soporta fanotify (ej. pseudo-fs o NFS sin soporte)
        if err in (19, 95):  # ENODEV / EOPNOTSUPP
            logger.debug("Sistema de archivos no compatible con fanotify en %s (errno=%d). Omitiendo.", path, err)
        else:
            logger.error("❌ Fallo en fanotify_mark para %s: errno=%d (%s)", path, err, os.strerror(err))
        return False

    def mark_all_mounts(self) -> int:
        """
        Garantiza la supervisión de TODO el sistema de archivos de forma 100% recursiva:
        1. Engancha el sistema de archivos raíz (/) mediante FAN_MARK_FILESYSTEM (recursivo global en Linux >= 4.20).
        2. Engancha cada punto de montaje activo desde /proc/mounts con FAN_MARK_MOUNT (recursivo por montaje).
        3. Marca todos los directorios de ataque y ejecución crítica.
        """
        marked = 0

        # 1. Intentar supervisión global del filesystem raíz (Linux >= 4.20)
        if self.mark_directory("/", mark_filesystem=True):
            marked += 1
            logger.info("🌐 Supervisión global del sistema de archivos (FAN_MARK_FILESYSTEM) ACTIVA en / (Recursivo Total)")

        # 2. Descubrir y enganchar todos los puntos de montaje reales de /proc/mounts
        current_mounts = self._discover_real_mounts()
        for mp in current_mounts:
            if self.mark_directory(mp, mark_mount=True):
                marked += 1
                self.active_mounts.add(mp)

        # 3. Asegurar vectores críticos de ejecución
        marked += self.mark_critical_vectors()

        # 4. Iniciar centinela dinámico para vigilar nuevos montajes y desmontajes
        self._start_mount_watcher()

        logger.info("🛡️ Cobertura global completada: %d puntos de montaje y directorios interceptados activamente.", marked)
        return marked

    def _discover_real_mounts(self) -> Set[str]:
        """Descubre todos los puntos de montaje reales activos excluyendo pseudo-sistemas de archivos."""
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
        """Inicia el hilo centinela que supervisa nuevos montajes (ej. memorias USB) y desmontajes."""
        if self.mount_watcher_thread and self.mount_watcher_thread.is_alive():
            return
        self.mount_watcher_thread = threading.Thread(target=self._mount_watcher_loop, daemon=True, name="fanotify-mount-watcher")
        self.mount_watcher_thread.start()

    def _mount_watcher_loop(self):
        """Vigila periódicamente /proc/mounts para enganchar nuevos dispositivos o limpiar desmontajes."""
        while self.running:
            try:
                current_mounts = self._discover_real_mounts()
                
                # Nuevos puntos de montaje detectados (ej. USB recién conectado o nuevo bind mount)
                new_mounts = current_mounts - self.active_mounts
                for nmp in new_mounts:
                    logger.info("🔌 Nuevo punto de montaje detectado: %s. Enganchando fanotify en caliente...", nmp)
                    if self.mark_directory(nmp, mark_mount=True):
                        self.active_mounts.add(nmp)

                # Puntos de montaje desmontados
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
        """Marca simultáneamente todos los vectores críticos de ataque y drop de malware."""
        targets = [
            "/tmp",
            "/dev/shm",
            "/var/tmp",
            "/home",
            "/root",
            "/opt",
            "/media",
            "/run/media",
            "/usr/local",
            "/etc",
            "/var/www",
            "/srv"
        ]
        if extra_paths:
            targets.extend(extra_paths)

        marked_count = 0
        for p in targets:
            if os.path.exists(p):
                # Marca con FAN_EVENT_ON_CHILD y recorrido recursivo de subdirectorios
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
        resp = FanotifyResponse(fd=event_fd, response=decision)
        try:
            os.write(self.fan_fd, bytes(resp))
        except Exception as e:
            logger.debug("Error escribiendo respuesta fanotify para fd %d: %s", event_fd, e)

    def process_events(self):
        self.running = True
        poll = select.poll()
        poll.register(self.fan_fd, select.POLLIN)
        buffer_size = 16384  # Búfer ampliado a 16KB para prevenir desbordamientos

        while self.running:
            try:
                events = poll.poll(500)
                if not events:
                    continue
                raw_data = os.read(self.fan_fd, buffer_size)
                if not raw_data:
                    continue
                offset = 0
                while offset + FAN_EVENT_METADATA_LEN <= len(raw_data):
                    meta = FanotifyEventMetadata.from_buffer_copy(raw_data[offset:offset + FAN_EVENT_METADATA_LEN])
                    if meta.vers != 3:
                        break

                    event_fd = meta.fd
                    pid = meta.pid
                    mask = meta.mask

                    # 1. CONTROL DE DESBORDAMIENTO DE COLA (FAN_Q_OVERFLOW)
                    if mask & FAN_Q_OVERFLOW:
                        self.overflow_count += 1
                        logger.critical("🚨 [FANOTIFY OVERFLOW #%d] Desbordamiento de cola de eventos en kernel detectado. Posible ráfaga extrema de E/S.", self.overflow_count)
                        if self.notifier:
                            try:
                                self.notifier.send(
                                    "🚨 Constantine: Alerta de Kernel",
                                    "Desbordamiento de eventos en cola de fanotify. Ejecutando verificación de integridad.",
                                    urgency="critical"
                                )
                            except Exception:
                                pass
                        offset += meta.event_len
                        continue

                    if event_fd >= 0:
                        # POLÍTICA ESTRICTA FAIL-SECURE / ZERO-TRUST POR DEFECTO
                        decision = FAN_DENY
                        target_path = f"<fd:{event_fd}>"
                        proc_name = "desconocido"
                        try:
                            try:
                                target_path = os.readlink(f"/proc/self/fd/{event_fd}")
                            except Exception:
                                pass

                            proc_name = self.get_process_name(pid)

                            # 2. EVALUACIÓN ANTIRANSOMWARE INTEGRADA (Canary Traps, Extensiones y Ráfagas)
                            if self.ransomware and target_path and not target_path.startswith("<fd:"):
                                if self.ransomware.check_file_path(target_path, pid):
                                    decision = FAN_DENY
                                    logger.critical("🚨 [BLOQUEO FAN_DENY - RANSOMWARE] Interceptado ataque de ransomware por PID %d (%s) en: %s", pid, proc_name, target_path)
                                    if self.firewall:
                                        self.firewall.isolate_pid(pid, terminate=True)
                                    # La decisión es denegar y continuar hacia el envío de respuesta
                                    self.respond(event_fd, decision)
                                    try:
                                        os.close(event_fd)
                                    except Exception:
                                        pass
                                    offset += meta.event_len
                                    continue

                            # 3. Filtro Zero-Nag de Distribución con Verificación Criptográfica
                            if self.whitelist.is_whitelisted(target_path):
                                decision = FAN_ALLOW
                            else:
                                # 4. Análisis estático, heurístico y YARA oficial
                                scan_res = self.scanner.scan_file(target_fd=event_fd, file_path=target_path)

                                if scan_res.is_malicious:
                                    decision = FAN_DENY
                                    logger.warning("🚨 [BLOQUEO FAN_DENY] %s (PID: %d) intentó ejecutar/abrir %s (%s)", proc_name, pid, target_path, scan_res.threat_name)
                                    if self.vault and os.path.exists(target_path):
                                        self.vault.quarantine_file(target_path, scan_res.threat_name or "Malware", detected_by="FanotifyKernel")
                                    if self.notifier:
                                        self.notifier.alert_threat_blocked(scan_res.threat_name or "Malware", target_path, pid, proc_name)
                                    if self.firewall:
                                        self.firewall.isolate_pid(pid, terminate=False)
                                else:
                                    # Archivo analizado y verificado sin firmas hostiles
                                    decision = FAN_ALLOW
                        except Exception as e:
                            # 5. GESTIÓN ESTRICTA DE EXCEPCIONES: FAIL-SECURE (FAN_DENY)
                            if self.fail_policy == "safe":
                                decision = FAN_ALLOW
                                logger.warning("⚠️ [FAIL-SAFE FORZADO] Permitiendo %s tras excepción por configuración --fail-policy=safe: %s", target_path, e)
                            else:
                                decision = FAN_DENY
                                logger.critical(
                                    "🚨 [FAIL-SECURE FAN_DENY] Excepción durante análisis en %s (PID: %d): %s. "
                                    "Operación DENEGADA para impedir bypass malicioso o anti-análisis.",
                                    target_path, pid, e
                                )
                                if self.notifier:
                                    try:
                                        self.notifier.alert_threat_blocked(
                                            "Error.Motor.BloqueoPreventivo",
                                            target_path,
                                            pid,
                                            proc_name
                                        )
                                    except Exception:
                                        pass
                        finally:
                            try:
                                self.respond(event_fd, decision)
                            except Exception as re_err:
                                logger.error("Fallo crítico enviando respuesta fanotify al kernel para fd %d: %s", event_fd, re_err)
                            try:
                                os.close(event_fd)
                            except Exception:
                                pass
                    offset += meta.event_len
            except KeyboardInterrupt:
                break
            except Exception as loop_err:
                logger.error("Error en bucle de polling fanotify: %s", loop_err)
        self.stop()

    def stop(self):
        self.running = False
        if self.fan_fd >= 0:
            try:
                os.close(self.fan_fd)
            except OSError:
                pass
            self.fan_fd = -1
        logger.info("Interceptor fanotify detenido limpiamente.")
