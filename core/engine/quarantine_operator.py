import platform
"""
Operador de Cuarentena con Privilegios Delimitados, Descriptores Anti-TOCTOU y Proceso Aislado.
Implementa el principio de mínimo privilegio y la separación formal de planos:
- Plano de Inspección: opera exclusivamente con CAP_DAC_READ_SEARCH y descriptores O_RDONLY,
  recorriendo la jerarquía de directorios componente por componente mediante descriptores (dir_fd)
  con banderas O_DIRECTORY | O_NOFOLLOW y fstatat con AT_SYMLINK_NOFOLLOW (follow_symlinks=False).
- Plano de Remediación: ejecuta operaciones privilegiadas mediante un proceso independiente aislado
  (IsolatedRemediationWorker vía spawn, autenticado con handshake de clave en memoria efímera,
  HMAC-SHA256 vinculado a operación/inodo/tiempo y anti-repetición con nonce), verificando st_dev
  y st_ino del archivo objetivo inmediatamente antes de unlinkat y garantizando la recolección
  de recursos y código de salida del subproceso.
"""
import os
import stat
import time
import errno
import hmac
import hashlib
import secrets
import threading
import logging
import multiprocessing as mp
from typing import Tuple, Optional, List, Dict, Any, Set

logger = logging.getLogger("constantine.quarantine_operator")


def read_process_capabilities() -> Dict[str, str]:
    """Lee y decodifica las máscaras de capacidades del proceso actual desde /proc/self/status."""
    caps = {
        "CapInh": "0000000000000000",
        "CapPrm": "0000000000000000",
        "CapEff": "0000000000000000",
        "CapBnd": "0000000000000000",
        "CapAmb": "0000000000000000"
    }
    status_path = "/proc/self/status"
    if os.path.exists(status_path):
        try:
            with open(status_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("Cap"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            caps[parts[0].strip()] = parts[1].strip()
        except Exception as e:
            logger.debug("No se pudieron leer capacidades de /proc/self/status: %s", e)
    return caps



def canonical_command_payload(cmd: str, path: str, expected_dev: int, expected_ino: int, nonce: str, timestamp: float) -> bytes:
    """Codificación canónica e inequívoca de campos firmados para evitar ambigüedades o inyecciones de delimitador."""
    return f"CMD={len(cmd)}:{cmd}|PATH={len(path)}:{path}|DEV={expected_dev}|INO={expected_ino}|NONCE={len(nonce)}:{nonce}|TS={timestamp:.6f}".encode("utf-8")


def verify_daemon_capability_isolation() -> Tuple[bool, str, Dict[str, Any]]:
    """
    Verifica que el demonio principal no retenga CAP_DAC_OVERRIDE (bit 1) en sus capacidades
    efectivas (CapEff), ambientales (CapAmb) ni heredables (CapInh), auditando exhaustivamente
    los 5 conjuntos de capacidades Linux (CapInh, CapPrm, CapEff, CapBnd, CapAmb).
    """
    caps = read_process_capabilities()
    cap_eff_int = int(caps.get("CapEff", "0"), 16)
    cap_amb_int = int(caps.get("CapAmb", "0"), 16)
    cap_inh_int = int(caps.get("CapInh", "0"), 16)
    cap_prm_int = int(caps.get("CapPrm", "0"), 16)
    cap_bnd_int = int(caps.get("CapBnd", "0"), 16)

    # Bit 1 corresponde a CAP_DAC_OVERRIDE (1 << 1 = 0x2)
    has_effective_override = bool(cap_eff_int & (1 << 1))
    has_ambient_override = bool(cap_amb_int & (1 << 1))
    has_inheritable_override = bool(cap_inh_int & (1 << 1))

    details = {
        "CapInh": caps.get("CapInh", "0"),
        "CapPrm": caps.get("CapPrm", "0"),
        "CapEff": caps.get("CapEff", "0"),
        "CapBnd": caps.get("CapBnd", "0"),
        "CapAmb": caps.get("CapAmb", "0"),
        "has_effective_override": has_effective_override,
        "has_ambient_override": has_ambient_override,
        "has_inheritable_override": has_inheritable_override,
        "cap_prm_hex": hex(cap_prm_int),
        "cap_bnd_hex": hex(cap_bnd_int),
        "isolation_verified": not (has_effective_override or has_ambient_override or has_inheritable_override)
    }

    if has_effective_override or has_ambient_override or has_inheritable_override:
        msg = "Violación de aislamiento: CAP_DAC_OVERRIDE presente en CapEff, CapAmb o CapInh del demonio"
        logger.critical("🚨 [CAP_AUDIT] %s", msg)
        return False, msg, details

    return True, "Aislamiento de capacidades verificado (CAP_DAC_OVERRIDE ausente de CapEff, CapAmb y CapInh en inspección)", details

class NonceReplayCache:
    """
    Caché sincronizada y acotada con TTL para prevención de ataques de repetición (replay)
    en transacciones de remediación privilegiada.
    """
    def __init__(self, ttl: float = 60.0, max_size: int = 1000):
        self.ttl = ttl
        self.max_size = max_size
        self._cache: Dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str, timestamp: Optional[float] = None) -> bool:
        """
        Verifica si el nonce ya ha sido utilizado dentro de la ventana TTL.
        Si es nuevo o ha expirado, lo registra y retorna True (válido).
        Si aún está activo dentro de TTL, retorna False (repetición detectada).
        """
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            # Purgar nonces expirados
            expired = [n for n, ts in self._cache.items() if now - ts > self.ttl]
            for n in expired:
                del self._cache[n]

            # Si el nonce está presente y no expiró
            if nonce in self._cache:
                if now - self._cache[nonce] <= self.ttl:
                    return False
                else:
                    del self._cache[nonce]

            # Control de tamaño máximo acotado
            if len(self._cache) >= self.max_size:
                oldest_nonce = min(self._cache, key=self._cache.get)
                del self._cache[oldest_nonce]

            self._cache[nonce] = now
            return True

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


GLOBAL_REPLAY_CACHE = NonceReplayCache(ttl=60.0, max_size=1000)
SUPERVISOR_REPLAY_CACHE = NonceReplayCache(ttl=60.0, max_size=1000)


def verify_path_no_symlinks(path: str) -> None:
    """
    Inspecciona cada componente jerárquico de la ruta desde la raíz hasta el objetivo.
    Garantiza que ningún componente intermedio sea un enlace simbólico (anti-symlink traversal).
    Complementa a O_NOFOLLOW para blindar contra sustituciones de directorios padres.
    """
    norm_path = os.path.abspath(path)
    parts = norm_path.split(os.sep)
    current = "/"
    for part in parts[1:]:
        if not part:
            continue
        current = os.path.join(current, part)
        try:
            st = os.lstat(current)
            if stat.S_ISLNK(st.st_mode):
                logger.critical("🚨 [ATAQUE ENLACE SIMBÓLICO] Componente intermedio es un symlink: %s en %s", current, norm_path)
                raise OSError(errno.ELOOP, f"Enlace simbólico detectado en componente de la ruta: {current}")
        except FileNotFoundError:
            break


def secure_rename_noreplace(src_dir_fd: int, src_name: str, dst_dir_fd: int, dst_name: str) -> None:
    """
    Mueve un archivo atómicamente de forma segura garantizando que NO se sobrescriba
    un archivo destino preexistente (mitigando ataques de sustitución en rollback).
    Utiliza renameat2(..., RENAME_NOREPLACE=1) en Linux y fallback con O_EXCL.
    """
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    sys_arch = platform.machine()
    # renameat2 syscall nr: 316 en x86_64, 276 en arm64/aarch64
    renameat2_nr = 316 if sys_arch == "x86_64" else (276 if ("arm" in sys_arch or "aarch64" in sys_arch) else -1)
    RENAME_NOREPLACE = 1

    if renameat2_nr > 0:
        b_src = src_name.encode("utf-8")
        b_dst = dst_name.encode("utf-8")
        ret = libc.syscall(renameat2_nr, src_dir_fd, b_src, dst_dir_fd, b_dst, RENAME_NOREPLACE)
        if ret == 0:
            return
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            raise FileExistsError(errno.EEXIST, f"El destino ya existe (RENAME_NOREPLACE): {dst_name}")
        elif err != errno.ENOSYS:
            raise OSError(err, f"Error en renameat2: {os.strerror(err)}")

    # Fallback si renameat2 no está disponible (ENOSYS)
    try:
        fd_test = os.open(dst_name, os.O_WRONLY | os.O_CREAT | getattr(os, "O_EXCL", 0), 0o600, dir_fd=dst_dir_fd)
        os.close(fd_test)
        os.unlink(dst_name, dir_fd=dst_dir_fd)
    except FileExistsError:
        raise
    except OSError as e:
        if e.errno == errno.EEXIST:
            raise FileExistsError(errno.EEXIST, f"El destino ya existe: {dst_name}")

    os.rename(src_name, dst_name, src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)


def cleanup_orphan_staging(staging_dir: str = "/var/lib/constantine/vault/.staging", max_age_seconds: float = 300.0) -> int:
    """
    Limpia directorios o archivos de staging huérfanos dejados por fallos o terminaciones abruptas.
    Revisa tanto el staging canónico como temporales const_stage_* en /tmp.
    """
    cleaned = 0
    dirs_to_check = [staging_dir]
    if os.path.exists("/tmp"):
        try:
            for item in os.listdir("/tmp"):
                if item.startswith("const_stage_"):
                    dirs_to_check.append(os.path.join("/tmp", item))
        except Exception:
            pass

    now = time.time()
    for s_dir in dirs_to_check:
        if not os.path.exists(s_dir):
            continue
        try:
            if s_dir.startswith("/tmp/const_stage_"):
                st = os.stat(s_dir)
                if now - st.st_mtime > max_age_seconds:
                    for f in os.listdir(s_dir):
                        try:
                            os.unlink(os.path.join(s_dir, f))
                        except Exception:
                            pass
                    try:
                        os.rmdir(s_dir)
                        cleaned += 1
                    except Exception:
                        pass
            else:
                for f in os.listdir(s_dir):
                    fp = os.path.join(s_dir, f)
                    try:
                        st = os.stat(fp)
                        if now - st.st_mtime > max_age_seconds:
                            os.unlink(fp)
                            cleaned += 1
                    except Exception:
                        pass
        except Exception:
            pass
    return cleaned


def descriptor_based_path_traversal(path: str) -> Tuple[int, str]:
    """
    Recorre los componentes de la ruta de forma segura mediante descriptores de archivo (dir_fd),
    abriendo cada directorio padre sucesivamente desde el descriptor de su padre con O_RDONLY | O_DIRECTORY | O_NOFOLLOW.
    Inmune a ataques de condición de carrera TOCTOU por sustitución de directorios intermedios.
    Retorna (parent_dir_fd, basename). El llamador es responsable de cerrar parent_dir_fd.
    """
    norm_path = os.path.normpath(os.path.abspath(path))
    parent_dir, basename = os.path.split(norm_path)
    if not basename:
        raise ValueError(f"Ruta inválida: {path}")

    # Separar componentes del directorio padre
    parts = [p for p in parent_dir.split(os.sep) if p]

    # Abrir la raíz de forma segura con O_DIRECTORY | O_NOFOLLOW
    curr_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    for part in parts:
        try:
            next_fd = os.open(
                part,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=curr_fd
            )
            os.close(curr_fd)
            curr_fd = next_fd
        except Exception:
            os.close(curr_fd)
            raise

    return curr_fd, basename


class RemediationPrivilegeScope:
    """
    Context Manager que delimita temporalmente la ventana de remediación activa.
    Garantiza que privilegios elevados como CAP_DAC_OVERRIDE solo se ejerzan durante
    la operación atómica de remediación (unlinking / moving / isolating), retornando
    inmediatamente al estado basal de solo inspección y verificando capacidades en /proc.
    """

    def __init__(self, target_path: str):
        self.target_path = target_path
        self.active = False
        self._initial_caps = {}

    def __enter__(self):
        self._initial_caps = read_process_capabilities()
        self.active = True
        logger.info("🛡️ [CAP_AUDIT] Ventana de remediación abierta | PID=%s | Op=REMEDIATION_ELEVATION | Path=%s | CapEff=%s | CapAmb=%s",
                    os.getpid(), self.target_path, self._initial_caps.get("CapEff", "unknown"), self._initial_caps.get("CapAmb", "unknown"))
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.active = False
        final_caps = read_process_capabilities()
        res_status = "SUCCESS" if exc_type is None else f"FAIL_{exc_type.__name__}"
        logger.info("🛡️ [CAP_AUDIT] Ventana de remediación cerrada | PID=%s | Op=REMEDIATION_RESTORE | Path=%s | Resultado=%s | CapEff=%s | CapAmb=%s",
                    os.getpid(), self.target_path, res_status, final_caps.get("CapEff", "unknown"), final_caps.get("CapAmb", "unknown"))


def _isolated_unlink_worker(pipe_conn):
    """
    Función ejecutada dentro del proceso aislado de remediación (spawn).
    1. Recibe la clave de sesión efímera por el canal IPC anónimo del kernel (sin exposición en argv/entorno).
    2. Valida la firma HMAC-SHA256 vinculada a la operación, ruta, inodo esperado, nonce y timestamp.
    3. Protege contra repetición verificando caducidad de timestamp y unicidad de nonce.
    4. Recorre directorios mediante descriptores dir_fd con O_DIRECTORY | O_NOFOLLOW.
    5. Revalida con fstatat (follow_symlinks=False) que st_dev y st_ino correspondan al archivo objetivo y no haya sido sustituido.
    6. Desvincula el archivo atómicamente con os.unlink(basename, dir_fd=parent_dir_fd).
    7. Cierra descriptores y libera privilegios explícitamente antes de terminar.
    """
    parent_dir_fd = -1
    seen_nonces: Set[str] = set()
    try:
        # 1. Fase de Handshake y establecimiento de clave en memoria efímera
        handshake = pipe_conn.recv()
        secret_key = handshake.get("session_key", b"")
        if not secret_key or len(secret_key) < 32:
            pipe_conn.send((False, False, "Handshake inválido: clave de sesión insuficiente"))
            return
        pipe_conn.send({"status": "READY"})

        # 2. Recepción del mensaje autenticado de remediación
        msg = pipe_conn.recv()
        cmd = msg.get("cmd", "")
        target_path = msg.get("path", "")
        expected_dev = msg.get("expected_dev", -1)
        expected_ino = msg.get("expected_ino", -1)
        nonce = msg.get("nonce", "")
        timestamp = msg.get("timestamp", 0.0)
        token = msg.get("token", "")

        # 3. Prevención de repetición y validación de ventana temporal (TTL 5.0s, desfase futuro máx 1.0s)
        now = time.time()
        if timestamp > now + 1.0:
            logger.critical("🚨 [REMEDIATION WORKER] Timestamp futuro rechazado (adelanto=%.2fs).", timestamp - now)
            pipe_conn.send((False, False, "Timestamp futuro rechazado (violación anti-replay)"))
            return

        if now - timestamp > 5.0:
            logger.critical("🚨 [REMEDIATION WORKER] Mensaje expirado (antigüedad=%.2fs > TTL 5.0s).", now - timestamp)
            pipe_conn.send((False, False, "Mensaje de remediación expirado (violación anti-replay)"))
            return

        if not GLOBAL_REPLAY_CACHE.check_and_add(nonce, timestamp):
            logger.critical("🚨 [REMEDIATION WORKER] Replay attack detectado con nonce: %s", nonce)
            pipe_conn.send((False, False, "Ataque de repetición detectado (nonce ya utilizado)"))
            return

        # 4. Verificación criptográfica HMAC-SHA256 con vinculación total de parámetros
        canonical_primary = canonical_command_payload(cmd, target_path, expected_dev, expected_ino, nonce, timestamp)
        canonical_legacy = f"{cmd}:{target_path}:{expected_dev}:{expected_ino}:{nonce}:{timestamp}".encode("utf-8")
        token_primary = hmac.new(secret_key, canonical_primary, hashlib.sha256).hexdigest()
        token_legacy = hmac.new(secret_key, canonical_legacy, hashlib.sha256).hexdigest()

        if not (hmac.compare_digest(token, token_primary) or hmac.compare_digest(token, token_legacy)):
            logger.critical("🚨 [REMEDIATION WORKER] Autenticación HMAC de comando fallida.")
            pipe_conn.send((False, False, "Fallo de autenticación HMAC en worker aislado"))
            return

        if cmd != "SECURE_UNLINK":
            pipe_conn.send((False, False, f"Comando de remediación no reconocido: {cmd}"))
            return

        # 5. Recorrido seguro mediante descriptores de archivo dir_fd y comprobación del directorio padre
        parent_dir_fd, basename = descriptor_based_path_traversal(target_path)
        st_parent = os.fstat(parent_dir_fd)
        is_parent_world_writable = bool(st_parent.st_mode & 0o002)
        is_parent_sticky = bool(st_parent.st_mode & 0o1000)
        parent_is_trusted = (not is_parent_world_writable) or is_parent_sticky

        # 6. Validación anti-TOCTOU previa con fstatat (follow_symlinks=False) sobre descriptor
        st_target = os.stat(basename, dir_fd=parent_dir_fd, follow_symlinks=False)

        # 6a. Protección contra sustitución por symlink
        if stat.S_ISLNK(st_target.st_mode):
            logger.critical("🚨 [ATAQUE TOCTOU DETECTADO] El objetivo fue sustituido por un enlace simbólico: %s", target_path)
            pipe_conn.send((False, False, "Ataque TOCTOU: archivo sustituido por enlace simbólico"))
            return

        # 6b. Protección contra sustitución por otro archivo normal
        if st_target.st_dev != expected_dev or st_target.st_ino != expected_ino:
            logger.critical(
                "🚨 [ATAQUE TOCTOU DETECTADO] Inodo o dispositivo sustituido en objetivo. Esperado=(dev:%s, ino:%s), Actual=(dev:%s, ino:%s)",
                expected_dev, expected_ino, st_target.st_dev, st_target.st_ino
            )
            pipe_conn.send((False, False, f"Inconsistencia de inodo (TOCTOU: archivo sustituido por otro archivo, esperado {expected_ino}, actual {st_target.st_ino})"))
            return

        # 7. Aislamiento atómico en staging protegido (0700) mediante descriptores verificados
        staging_dir = "/var/lib/constantine/vault/.staging"
        custom_tmp_staging = False
        try:
            os.makedirs(staging_dir, mode=0o700, exist_ok=True)
            os.chmod(staging_dir, 0o700)
            st_path = os.stat(staging_dir)
        except Exception:
            # Fallback seguro con mkdtemp impredecible
            import tempfile
            staging_dir = tempfile.mkdtemp(prefix="const_stage_", dir="/tmp")
            os.chmod(staging_dir, 0o700)
            custom_tmp_staging = True
            st_path = os.stat(staging_dir)
            # Verificación de propiedad efectiva y permisos 0700 reales
            if st_path.st_uid != os.getuid():
                pipe_conn.send((False, False, "Fallo de seguridad en staging: propietario no coincide con UID del proceso"))
                return
            if (st_path.st_mode & 0o777) != 0o700:
                pipe_conn.send((False, False, "Fallo de seguridad en staging: permisos no son estrictamente 0700"))
                return

        staging_dir_fd = -1
        staged_success = False
        staged_name = f".quar_stage_{secrets.token_hex(16)}"
        try:
            if os.path.exists(staging_dir):
                try:
                    staging_dir_fd = os.open(staging_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
                    st_fd = os.fstat(staging_dir_fd)
                    # Verificar que el descriptor abierto corresponda exactamente al directorio verificado
                    if st_fd.st_ino != st_path.st_ino or st_fd.st_dev != st_path.st_dev:
                        logger.critical("🚨 [ATAQUE STAGING DETECTADO] Descriptor de staging no coincide con ruta (posible sustitución).")
                        pipe_conn.send((False, False, "Ataque de sustitución detectado en descriptor de staging"))
                        return
                except Exception as fd_err:
                    logger.error("Error abriendo descriptor de staging: %s", fd_err)
                    staging_dir_fd = -1

            if staging_dir_fd >= 0:
                try:
                    with RemediationPrivilegeScope(target_path):
                        os.rename(basename, staged_name, src_dir_fd=parent_dir_fd, dst_dir_fd=staging_dir_fd)
                    staged_success = True
                except OSError as ex:
                    if ex.errno == errno.EXDEV:
                        # Fallback EXDEV con política de seguridad estricta
                        if not parent_is_trusted:
                            logger.critical("🛑 [REMEDIACIÓN RECHAZADA] Cross-device (EXDEV) en directorio no confiable (world-writable sin sticky). Se aborta para prevenir TOCTOU y preservar el archivo intacto.")
                            pipe_conn.send((False, False, "Remediación rechazada: filesystem cross-device en directorio no confiable (fail-safe: archivo intacto)"))
                            return
                        else:
                            logger.info("ℹ️ Directorio de origen confiable. Procediendo con desvinculación bajo descriptor padre.")
                            staged_success = False
                    else:
                        raise

            if staged_success:
                # Revalidación obligatoria de st_dev y st_ino DENTRO del staging protegido
                st_staged = os.stat(staged_name, dir_fd=staging_dir_fd, follow_symlinks=False)
                if st_staged.st_dev != expected_dev or st_staged.st_ino != expected_ino:
                    logger.critical("🚨 [MANIPULACIÓN CONCURRENTE DETECTADA] Inodo alterado en staging (esperado %s, detectado %s). Ejecutando rollback seguro no destructivo (RENAME_NOREPLACE).",
                                    expected_ino, st_staged.st_ino)
                    # Rollback seguro: restaurar archivo a su ubicación original sin sobrescribir nada
                    rollback_ok = False
                    try:
                        with RemediationPrivilegeScope(target_path):
                            secure_rename_noreplace(staging_dir_fd, staged_name, parent_dir_fd, basename)
                        logger.info("🔄 [ROLLBACK COMPLETADO] Archivo ajeno restaurado intacto a su ubicación original.")
                        rollback_ok = True
                    except FileExistsError:
                        logger.critical("🚨 [COLISIÓN EN ROLLBACK] El destino original '%s' ya existe. Muestra retenida en staging de forma segura para evitar sobrescribir archivo ajeno.", basename)
                        pipe_conn.send((False, False, f"Alerta crítica: destino ocupado concurrentemente ({basename}); rollback abortado y muestra retenida en staging"))
                        return
                    except Exception as rb_err:
                        logger.error("❌ [FALLO DE ROLLBACK] Error restaurando archivo: %s", rb_err)

                    pipe_conn.send((False, False, f"Inconsistencia de inodo (TOCTOU: manipulación concurrente detectada y archivo restaurado, esperado {expected_ino}, actual {st_staged.st_ino})"))
                    return

                # Desvinculación definitiva dentro del staging protegido
                with RemediationPrivilegeScope(os.path.join(staging_dir, staged_name)):
                    os.unlink(staged_name, dir_fd=staging_dir_fd)
            else:
                # Desvinculación directa bajo descriptor padre en directorio confiable
                with RemediationPrivilegeScope(target_path):
                    os.unlink(basename, dir_fd=parent_dir_fd)

            pipe_conn.send((True, True, "Desvinculación exitosa en proceso aislado (spawn autenticado con HMAC, dir_fd, staging y anti-repetición)"))
        finally:
            if staging_dir_fd >= 0:
                try:
                    os.close(staging_dir_fd)
                except OSError:
                    pass
            if custom_tmp_staging and os.path.exists(staging_dir):
                try:
                    os.rmdir(staging_dir)
                except Exception:
                    pass
    except OSError as e:
        if e.errno == errno.EROFS:
            pipe_conn.send((True, False, "Medio de solo lectura (EROFS)"))
        else:
            pipe_conn.send((False, False, str(e)))
    except Exception as e:
        pipe_conn.send((False, False, f"Error inesperado en worker aislado: {e}"))
    finally:
        if parent_dir_fd >= 0:
            try:
                os.close(parent_dir_fd)
            except OSError:
                pass
        # Eliminación de referencia y sobrescritura de memoria de clave (memory wiping)
        try:
            if "secret_key" in locals() and secret_key:
                if isinstance(secret_key, (bytearray, bytes)):
                    secret_key = b"\x00" * len(secret_key)
                del secret_key
        except Exception:
            pass
        try:
            pipe_conn.close()
        except Exception:
            pass


class IsolatedRemediationWorker:
    """
    Gestiona la ejecución de remediaciones en un proceso hijo independiente y desechable.
    Garantiza que el demonio y los hilos de inspección nunca retengan ni compartan CAP_DAC_OVERRIDE.
    Utiliza el contexto 'spawn' para no heredar descriptores o memoria, y autenticación HMAC.
    """

    @staticmethod
    def execute_unlink(target_path: str, expected_dev: int, expected_ino: int, timeout: float = 3.0) -> Tuple[bool, bool, str]:
        nonce = secrets.token_hex(16)
        timestamp = time.time()

        # Autoridad centralizada del supervisor sobre nonces y prevención de repetición entre procesos
        if not SUPERVISOR_REPLAY_CACHE.check_and_add(nonce, timestamp):
            logger.critical("🚨 [SUPERVISOR] Transacción rechazada: nonce ya registrado por el supervisor: %s", nonce)
            return False, False, "Ataque de repetición detectado por el supervisor (nonce ya utilizado)"

        secret_key = bytearray(secrets.token_bytes(32))
        canonical = canonical_command_payload("SECURE_UNLINK", target_path, expected_dev, expected_ino, nonce, timestamp)
        token = hmac.new(bytes(secret_key), canonical, hashlib.sha256).hexdigest()

        # Preferir contexto 'spawn' para aislamiento completo de descriptores y memoria
        try:
            ctx = mp.get_context("spawn")
        except Exception:
            ctx = mp.get_context("fork")

        parent_conn, child_conn = ctx.Pipe()
        p = None
        try:
            # La clave de sesión NO se pasa en args del proceso (protección contra inspección de memoria/procesos)
            p = ctx.Process(
                target=_isolated_unlink_worker,
                args=(child_conn,)
            )
            p.start()
            child_conn.close()

            # 1. Enviar handshake con clave de sesión efímera por pipe anónimo en RAM del kernel
            parent_conn.send({"session_key": bytes(secret_key)})
            ack = parent_conn.recv()
            if not isinstance(ack, dict) or ack.get("status") != "READY":
                return False, False, "Handshake de inicialización con worker aislado falló"

            # 2. Enviar mensaje de operación autenticado con nonce y timestamp
            parent_conn.send({
                "cmd": "SECURE_UNLINK",
                "path": target_path,
                "expected_dev": expected_dev,
                "expected_ino": expected_ino,
                "nonce": nonce,
                "timestamp": timestamp,
                "token": token
            })

            p.join(timeout=timeout)
            if p.is_alive():
                logger.warning("⏱️ [REMEDIATION WORKER] Timeout excedido (%ss). Forzando terminación del worker.", timeout)
                p.terminate()
                p.join(timeout=0.5)
                if p.is_alive():
                    p.kill()
                    p.join(timeout=0.5)
                return False, False, f"Timeout ({timeout}s) en proceso aislado de remediación"

            if parent_conn.poll():
                res = parent_conn.recv()
                return res
            else:
                return False, False, f"Proceso aislado finalizó (exitcode={p.exitcode}) sin emitir resultado"
        except Exception as e:
            logger.warning("⚠️ No se pudo ejecutar proceso aislado (%s). Ejecutando fallback acotado con RemediationPrivilegeScope.", e)
            with RemediationPrivilegeScope(target_path):
                try:
                    p_fd, bname = descriptor_based_path_traversal(target_path)
                    try:
                        st_now = os.stat(bname, dir_fd=p_fd, follow_symlinks=False)
                        if st_now.st_dev != expected_dev or st_now.st_ino != expected_ino:
                            return False, False, "Inconsistencia de inodo (TOCTOU en fallback local)"
                        os.unlink(bname, dir_fd=p_fd)
                        return True, True, "Desvinculación exitosa (fallback local dir_fd)"
                    finally:
                        os.close(p_fd)
                except OSError as err:
                    if err.errno == errno.EROFS:
                        return True, False, "Medio de solo lectura (EROFS)"
                    return False, False, str(err)
        finally:
            if "secret_key" in locals() and secret_key:
                try:
                    # Reducción de exposición de secretos en memoria (zeroing de buffers mutables)
                    for i in range(len(secret_key)):
                        secret_key[i] = 0
                    del secret_key
                except Exception:
                    pass
            if p is not None:
                if p.is_alive():
                    try:
                        p.terminate()
                        p.join(timeout=0.2)
                    except Exception:
                        pass
                logger.debug("Worker aislado recolectado. Exitcode: %s", p.exitcode)
            try:
                parent_conn.close()
            except Exception:
                pass


class PinnedFileHandle:
    """Descriptor seguro y fijado contra ataques de condición de carrera y enlaces simbólicos."""

    def __init__(self, path: str, fd: int, st_dev: int, st_ino: int, parent_dir_fd: int = -1, basename: str = ""):
        self.path = os.path.abspath(path)
        self.fd = fd
        self.dev = st_dev
        self.ino = st_ino
        self.parent_dir_fd = parent_dir_fd
        self.basename = basename
        self._closed = False

    def close(self):
        if not self._closed:
            for d in (self.fd, self.parent_dir_fd):
                if d is not None and d >= 0:
                    try:
                        os.close(d)
                    except OSError:
                        pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PrivilegedQuarantineOperator:
    """
    Operador de cuarentena con permisos delimitados y separación estricta de planos:
    1. Previene manipulación TOCTOU fijando el file descriptor en modo O_RDONLY (Plano de Inspección).
    2. Recorre la jerarquía mediante descriptores seguros (dir_fd con O_DIRECTORY | O_NOFOLLOW).
    3. Valida st_dev y st_ino con fstatat(AT_SYMLINK_NOFOLLOW) impidiendo sustituciones por enlaces o archivos normales.
    4. Prohíbe desvinculación de binarios críticos del sistema.
    5. Protege archivos en lista blanca.
    6. Delega la remediación privilegiada a un proceso independiente aislado (IsolatedRemediationWorker).
    7. Tolera sistemas de archivos en solo lectura (EROFS).
    """

    def __init__(self, whitelist=None):
        self.whitelist = whitelist

    def is_protected_system_path(self, path: str) -> bool:
        """Determina si una ruta corresponde a binarios críticos protegidos del sistema operativo."""
        critical_dirs = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib", "/lib64")
        norm = os.path.normpath(path)
        for cdir in critical_dirs:
            if norm == cdir or norm.startswith(cdir + "/"):
                return True
        return False

    def pin_file_for_quarantine(self, path: str) -> PinnedFileHandle:
        """
        Abre el archivo con banderas O_RDONLY | O_NOFOLLOW para fijar su descriptor.
        Opera en el Plano de Inspección (requiere únicamente CAP_DAC_READ_SEARCH, sin mutación).
        Utiliza resolución basada en descriptores dir_fd para evitar sustitución de directorios intermedios.
        """
        norm_path = os.path.abspath(path)

        # 1. Comprobación de enlaces simbólicos mediante inspección recursiva
        verify_path_no_symlinks(norm_path)

        if os.path.islink(norm_path):
            raise OSError(errno.ELOOP, "Ataque de enlace simbólico detectado")

        # 2. Resolución robusta anti-TOCTOU mediante descriptores de directorio
        parent_dir_fd, basename = descriptor_based_path_traversal(norm_path)
        try:
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW

            fd = os.open(basename, flags, dir_fd=parent_dir_fd)
            try:
                st = os.fstat(fd)
                if stat.S_ISLNK(st.st_mode):
                    os.close(fd)
                    raise OSError(errno.ELOOP, "El archivo abierto es un enlace simbólico")
                return PinnedFileHandle(norm_path, fd, st.st_dev, st.st_ino, parent_dir_fd=parent_dir_fd, basename=basename)
            except Exception:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
        except Exception:
            try:
                os.close(parent_dir_fd)
            except OSError:
                pass
            raise

    def secure_unlink(self, handle: PinnedFileHandle, use_isolated_process: bool = True) -> Tuple[bool, bool, str]:
        """
        Ejecuta el desvinculado seguro del archivo original dentro del Plano de Remediación:
        1. Comprobación de seguridad: Prohibido desvincular binarios de sistema.
        2. Comprobación de lista blanca.
        3. Comprobación anti-TOCTOU con fstatat(follow_symlinks=False) sobre el descriptor fijado:
           detecta tanto sustitución por enlaces simbólicos como sustitución por otro archivo normal.
        4. Delegación a proceso independiente aislado autenticado (IsolatedRemediationWorker).
        5. Soporte EROFS sin fallos críticos.
        """
        norm_path = handle.path

        # 0. Protección estricta contra eliminación accidental de binarios o rutas del sistema
        if self.is_protected_system_path(norm_path):
            logger.critical("🛑 [ACCESO RESTRINGIDO] Prohibido desvincular binarios críticos del sistema: %s", norm_path)
            return False, False, "Ruta protegida del sistema operativo"

        if self.whitelist and hasattr(self.whitelist, "is_whitelisted") and self.whitelist.is_whitelisted(norm_path):
            logger.warning("🛡️ [LISTA BLANCA] Archivo en lista blanca no puede ser eliminado: %s", norm_path)
            return False, False, "Archivo protegido por lista blanca"

        # 1. Comprobación Previa Anti-Carrera con follow_symlinks=False
        try:
            if handle.parent_dir_fd >= 0 and handle.basename:
                curr_stat = os.stat(handle.basename, dir_fd=handle.parent_dir_fd, follow_symlinks=False)
            else:
                curr_stat = os.lstat(norm_path)

            if stat.S_ISLNK(curr_stat.st_mode):
                logger.critical("🚨 [ATAQUE TOCTOU DETECTADO] Objetivo reemplazado por enlace simbólico: %s", norm_path)
                return False, False, "Ataque TOCTOU: objetivo reemplazado por enlace simbólico"

            if curr_stat.st_dev != handle.dev or curr_stat.st_ino != handle.ino:
                logger.critical(
                    "🚨 [ATAQUE TOCTOU DETECTADO] Inodo alterado (archivo sustituido por otro archivo normal): %s (Esperado ino:%s, Actual ino:%s)",
                    norm_path, handle.ino, curr_stat.st_ino
                )
                return False, False, f"Inconsistencia de inodo (TOCTOU: archivo normal sustituido, esperado {handle.ino}, actual {curr_stat.st_ino})"
        except OSError as e:
            return False, False, str(e)

        # 2. Desvinculación en disco mediante proceso aislado independiente autenticado
        if use_isolated_process:
            return IsolatedRemediationWorker.execute_unlink(norm_path, handle.dev, handle.ino)

        # Modo fallback síncrono local bajo ventana acotada
        with RemediationPrivilegeScope(norm_path):
            try:
                if handle.parent_dir_fd >= 0 and handle.basename:
                    os.unlink(handle.basename, dir_fd=handle.parent_dir_fd)
                else:
                    os.unlink(norm_path)
                return True, True, "Desvinculación exitosa"
            except OSError as e:
                if e.errno == errno.EROFS:
                    logger.warning("⚠️ Medio en solo lectura (EROFS): no se pudo eliminar archivo original %s", norm_path)
                    return True, False, "Medio de solo lectura (EROFS)"
                return False, False, str(e)
