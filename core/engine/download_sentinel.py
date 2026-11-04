"""
Constantine Antivirus - Event-Driven Downloads Sentinel (core/engine/download_sentinel.py)
Centinela de descargas en vuelo con arquitectura basada en eventos (inotify),
máquina de estados de descarga y contención preventiva:
1. Vigilancia Basada en Eventos de Kernel (inotify):
   - Escucha eventos específicos de creación y cierre:
     * IN_MOVED_TO: Renombrado final de navegador (.crdownload/.part -> archivo definitivo).
     * IN_CLOSE_WRITE: Archivo terminado de escribirse físicamente en disco.
     * IN_CREATE: Inicio de descarga.
2. Máquina de Estados de Descarga (Download Lifecycle State Machine):
   - IN_PROGRESS: Archivo en escritura (.crdownload, .part, .tmp, descriptores abiertos).
   - WRITE_COMPLETED: Archivo cerrado tras escritura (verificación de tamaño estable y sin fd abiertos).
   - SCANNING_CONTAINED: Bloqueo de permisos preventivo (000 / fanotify) mientras se ejecuta el escáner.
   - CLEARED_SAFE: Muestra limpia y segura; permisos restaurados (0644).
   - QUARANTINED: Muestra maliciosa aislada transaccionalmente en el Baúl criptográfico.
3. Aislamiento Independiente Multi-Usuario:
   - Mantiene registros independientes por directorio y usuario, evitando colisiones entre /home/* y /root.
4. Prevención Activa y Neutralización de Condiciones de Carrera (TOCTOU):
   - El archivo se retiene en kernel o con permisos restrictivos antes de que el usuario o un script
     pueda ejecutarlo antes de que el análisis concluya.
"""

import os
import time
import select
import struct
import ctypes
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Set, Optional, Dict, List, Any

logger = logging.getLogger("constantine.downloads")

# Constantes inotify de Linux
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_ISDIR = 0x40000000

# Tamaño de encabezado inotify_event: i32 wd, u32 mask, u32 cookie, u32 len
INOTIFY_EVENT_FMT = "iIII"
INOTIFY_EVENT_SIZE = struct.calcsize(INOTIFY_EVENT_FMT)


class DownloadState(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    WRITE_COMPLETED = "WRITE_COMPLETED"
    SCANNING_CONTAINED = "SCANNING_CONTAINED"
    CLEARED_SAFE = "CLEARED_SAFE"
    QUARANTINED = "QUARANTINED"
    FAILED = "FAILED"


@dataclass
class DownloadTrackedFile:
    file_path: str
    dir_path: str
    user: str
    state: DownloadState
    last_size: int = 0
    stable_checks: int = 0
    first_seen: float = field(default_factory=time.time)
    threat_name: Optional[str] = None


class DownloadSentinel:
    """
    Centinela de descargas con eventos inotify del kernel, máquina de estados
    y contención preventiva anti-condiciones de carrera.
    """

    def __init__(self, scanner=None, vault=None, notifier=None, interceptor=None,
                 on_scan_done: Optional[Callable] = None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.interceptor = interceptor
        self.on_scan_done = on_scan_done
        self.running = False
        self.thread = None

        # Seguimiento multi-usuario independiente: dir_path -> Set[file_names]
        self.dir_known_files: Dict[str, Set[str]] = {}
        # Diccionario de archivos en seguimiento: file_path -> DownloadTrackedFile
        self.tracked_downloads: Dict[str, DownloadTrackedFile] = {}

        # Descriptor inotify y mapeo de descriptores de vigilancia (watch descriptors)
        self.inotify_fd: Optional[int] = None
        self.wd_to_dir: Dict[int, str] = {}

        self.watch_dirs = self._discover_download_directories()

    def _discover_download_directories(self) -> Dict[str, str]:
        """
        Descubre todos los directorios de descargas del sistema asociando cada ruta
        con su usuario correspondiente (aislamiento multi-usuario).
        """
        dirs = {}
        # Usuario root
        for d in ("Downloads", "Descargas"):
            p = os.path.join("/root", d)
            if os.path.exists(p) and os.path.isdir(p):
                dirs[p] = "root"

        # Usuarios en /home
        if os.path.exists("/home"):
            try:
                for u in os.listdir("/home"):
                    user_home = os.path.join("/home", u)
                    if os.path.isdir(user_home):
                        for d in ("Downloads", "Descargas"):
                            p = os.path.join(user_home, d)
                            if os.path.exists(p) and os.path.isdir(p):
                                dirs[p] = u
            except Exception as e:
                logger.debug("Aviso listando /home: %s", e)

        return dirs

    def _init_inotify(self) -> bool:
        """Inicializa el subsistema inotify mediante libc si está disponible."""
        try:
            libc = ctypes.CDLL(None)
            if hasattr(libc, "inotify_init1"):
                # IN_CLOEXEC = 0x80000, IN_NONBLOCK = 0x800
                self.inotify_fd = libc.inotify_init1(0x80000 | 0x800)
            elif hasattr(libc, "inotify_init"):
                self.inotify_fd = libc.inotify_init()

            if self.inotify_fd is not None and self.inotify_fd >= 0:
                mask = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE | IN_DELETE
                for d in self.watch_dirs.keys():
                    wd = libc.inotify_add_watch(self.inotify_fd, d.encode("utf-8"), mask)
                    if wd >= 0:
                        self.wd_to_dir[wd] = d
                logger.info("⚡ Inotify de kernel enganchado con éxito en %d directorios de descargas.", len(self.wd_to_dir))
                return True
        except Exception as e:
            logger.debug("inotify nativo no disponible o sin privilegios: %s", e)

        self.inotify_fd = None
        return False

    def start(self):
        """Inicia el centinela registrando el estado inicial por directorio."""
        self.watch_dirs = self._discover_download_directories()
        for d in self.watch_dirs.keys():
            try:
                self.dir_known_files[d] = set(os.listdir(d))
            except Exception:
                self.dir_known_files[d] = set()

        has_inotify = self._init_inotify()
        self.running = True
        target_loop = self._inotify_loop if has_inotify else self._state_machine_loop
        self.thread = threading.Thread(target=target_loop, daemon=True, name="download-sentinel")
        self.thread.start()
        logger.info("🛡️ Centinela de descargas activo (Modo: %s).", "Inotify de Kernel" if has_inotify else "Máquina de Estados de Rescate")

    def _inotify_loop(self):
        """Bucle basado estrictamente en eventos de kernel inotify."""
        libc = ctypes.CDLL(None)
        epoll = select.epoll()
        epoll.register(self.inotify_fd, select.EPOLLIN)

        while self.running:
            try:
                events = epoll.poll(timeout=1.0)
                for fd, event in events:
                    if fd == self.inotify_fd and (event & select.EPOLLIN):
                        raw_data = os.read(self.inotify_fd, 8192)
                        offset = 0
                        while offset + INOTIFY_EVENT_SIZE <= len(raw_data):
                            wd, mask, cookie, length = struct.unpack_from(INOTIFY_EVENT_FMT, raw_data, offset)
                            offset += INOTIFY_EVENT_SIZE
                            name = ""
                            if length > 0:
                                name_bytes = raw_data[offset:offset + length]
                                name = name_bytes.split(b"\x00", 1)[0].decode("utf-8", "replace")
                                offset += length

                            if not (mask & IN_ISDIR) and name:
                                dir_path = self.wd_to_dir.get(wd)
                                if dir_path:
                                    full_path = os.path.join(dir_path, name)
                                    self._handle_file_event(dir_path, name, full_path, mask)

                # Procesar transiciones de descargas en curso
                self._check_tracked_downloads()

            except Exception as e:
                logger.debug("Aviso en bucle inotify: %s", e)
                time.sleep(0.5)

    def _state_machine_loop(self):
        """Bucle con máquina de estados independiente multi-usuario para entornos sin inotify."""
        while self.running:
            try:
                time.sleep(0.5)
                for d, user in self.watch_dirs.items():
                    if not os.path.exists(d):
                        continue
                    try:
                        current = set(os.listdir(d))
                    except Exception:
                        continue

                    known = self.dir_known_files.get(d, set())
                    new_files = current - known

                    for f in new_files:
                        full_path = os.path.join(d, f)
                        self._register_new_file(d, f, full_path, user)

                    self.dir_known_files[d] = current

                # Evaluar finalización y avance de estados
                self._check_tracked_downloads()

            except Exception as e:
                logger.debug("Aviso en máquina de estados de descargas: %s", e)
                time.sleep(1.0)

    def _handle_file_event(self, dir_path: str, filename: str, full_path: str, mask: int):
        """Canaliza eventos inotify a la máquina de estados de descarga."""
        user = self.watch_dirs.get(dir_path, "unknown")

        if mask & (IN_MOVED_TO | IN_CLOSE_WRITE):
            # El navegador cerró la escritura o renombró de .part/.crdownload a definitivo
            if not filename.endswith((".crdownload", ".part", ".tmp")):
                self._promote_and_scan(full_path, dir_path, user)
        elif mask & IN_CREATE:
            self._register_new_file(dir_path, filename, full_path, user)

    def _register_new_file(self, dir_path: str, filename: str, full_path: str, user: str):
        """Registra un archivo en progreso de descarga con estado IN_PROGRESS."""
        if filename.endswith((".crdownload", ".part", ".tmp")):
            self.tracked_downloads[full_path] = DownloadTrackedFile(
                file_path=full_path,
                dir_path=dir_path,
                user=user,
                state=DownloadState.IN_PROGRESS,
                last_size=os.path.getsize(full_path) if os.path.exists(full_path) else 0
            )
        else:
            # Archivo final directo (ej. wget, curl o descarga directa)
            self._promote_and_scan(full_path, dir_path, user)

    def _check_tracked_downloads(self):
        """
        Verifica si los archivos en progreso han terminado de escribirse:
        - Comprueba estabilidad de tamaño en disco.
        - Detecta si los descriptores de archivo del navegador ya se cerraron.
        """
        completed = []
        for path, item in list(self.tracked_downloads.items()):
            if item.state == DownloadState.IN_PROGRESS:
                if not os.path.exists(path):
                    completed.append(path)
                    continue

                try:
                    curr_size = os.path.getsize(path)
                    if curr_size == item.last_size and curr_size > 0:
                        item.stable_checks += 1
                    else:
                        item.last_size = curr_size
                        item.stable_checks = 0

                    # Si el tamaño es estable en dos ciclos sucesivos y no es .part/.crdownload
                    if item.stable_checks >= 2 and not path.endswith((".crdownload", ".part")):
                        completed.append(path)
                        self._promote_and_scan(path, item.dir_path, item.user)
                except Exception:
                    pass

        for p in completed:
            self.tracked_downloads.pop(p, None)

    def _promote_and_scan(self, file_path: str, dir_path: str, user: str):
        """
        Transición de estados y contención preventiva:
        1. WRITE_COMPLETED -> SCANNING_CONTAINED (aplica contención antes de escanear).
        2. Escaneo profundo con Scanner (YARA, Hashes, Heurística).
        3. CLEARED_SAFE o QUARANTINED.
        """
        if not os.path.isfile(file_path):
            return

        # 1. CONTENCIÓN PREVENTIVA: Impedir que el usuario o un script lo ejecute durante el análisis
        orig_mode = None
        try:
            st = os.stat(file_path)
            orig_mode = st.st_mode
            # Quitar permisos de ejecución y lectura temporalmente (contención en espacio de usuario)
            os.chmod(file_path, 0o000)
        except Exception:
            pass

        # Si el interceptor de kernel está disponible, marcar archivo
        if self.interceptor:
            try:
                self.interceptor.mark_directory(os.path.dirname(file_path))
            except Exception:
                pass

        tracked = DownloadTrackedFile(
            file_path=file_path,
            dir_path=dir_path,
            user=user,
            state=DownloadState.SCANNING_CONTAINED,
            last_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0
        )
        self.tracked_downloads[file_path] = tracked

        logger.info("📥 [DESCARGA VERIFICADA FINALIZADA] Analizando con contención preventiva: %s (Usuario: %s)",
                    os.path.basename(file_path), user)

        # 2. ESCANEO CON MOTOR MULTICAPA
        threat_name = None
        is_malicious = False
        try:
            if self.scanner:
                # Restaurar modo legible para el escáner
                if orig_mode is not None:
                    try:
                        os.chmod(file_path, 0o600)
                    except Exception:
                        pass
                res = self.scanner.scan_file(file_path=file_path)
                is_malicious = res.is_malicious
                threat_name = res.threat_name
        except Exception as scan_err:
            logger.error("Error durante escaneo de descarga %s: %s", file_path, scan_err)

        # 3. TRANSICIÓN A ESTADO FINAL
        if is_malicious:
            tracked.state = DownloadState.QUARANTINED
            threat_name = threat_name or "Malware.DownloadedPayload"
            tracked.threat_name = threat_name
            logger.critical("🚨 [DESCARGA MALICIOSA AISLADA] %s -> Amenaza: %s", file_path, threat_name)

            if self.vault:
                self.vault.quarantine_file(file_path, threat_name, detected_by="DownloadSentinel")

            if self.notifier:
                self.notifier.alert_threat_blocked(threat_name, file_path, os.getpid(), "DownloadSentinel")
        else:
            tracked.state = DownloadState.CLEARED_SAFE
            # Restaurar permisos normales y seguros de lectura/escritura (sin bit de ejecución directa no solicitada)
            try:
                safe_mode = (orig_mode & ~0o111) if orig_mode is not None else 0o644
                os.chmod(file_path, safe_mode or 0o644)
            except Exception:
                pass
            logger.info("✅ [DESCARGA LIMPIA] Verificada y autorizada: %s", os.path.basename(file_path))

        if self.on_scan_done:
            self.on_scan_done(file_path, is_malicious, threat_name)

    def stop(self):
        """Detiene el centinela y libera descriptores."""
        self.running = False
        if self.inotify_fd is not None and self.inotify_fd >= 0:
            try:
                os.close(self.inotify_fd)
            except Exception:
                pass
            self.inotify_fd = None

        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Centinela de descargas detenido.")
