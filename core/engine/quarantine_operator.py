"""
Constantine Antivirus - Privileged Quarantine Operator (core/engine/quarantine_operator.py)
Componente privilegiado y restringido para aislamiento e inmovilización segura de muestras:

1. Retención e Inmovilización de Descriptores de Archivos (File Descriptors):
   - Inmoviliza el archivo en el kernel (mediante dup() de descriptor fanotify o openat con O_NOFOLLOW),
     garantizando que las operaciones subsecuentes de hash, cifrado y desvinculado se ejecuten
     sobre la entidad física exacta en kernel, erradicando carreras TOCTOU.
2. Validación Estructural y Criptográfica de Identidad:
   - Verifica fstat(fd) contra lstat(path) para corroborar la coincidencia estricta de st_dev y st_ino.
   - Rechaza enlaces simbólicos, nodos de dispositivo (/dev), sockets, tuberías y directorios.
   - Protege sistemas de archivos virtuales y pseudo del kernel (/proc, /sys, /dev).
3. Traslado Atómico y Desvinculado Seguro (Anti-Carrera Pre-Unlink):
   - Re-verifica la identidad del inodo en disco inmediatamente antes de invocar os.unlink().
   - Si el archivo fue reemplazado o suplantado entre el análisis y el borrado, aborta la operación.
4. Resiliencia ante Aislamiento y Medios de Solo Lectura (EROFS):
   - Maneja excepciones de sistemas de archivos de solo lectura garantizando el aislamiento en el baúl
     y documentando en el manifiesto el estado del medio original sin causar caídas en cascada.
"""

import os
import stat
import errno
import logging
import hashlib
from typing import Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger("constantine.quarantine_operator")

FORBIDDEN_ROOT_PREFIXES = (
    "/proc", "/sys", "/dev"
)


@dataclass
class PinnedFileHandle:
    """Descriptor de archivo inmovilizado y verificado por el operador de cuarentena."""
    fd: int
    path: str
    st_dev: int
    st_ino: int
    size_bytes: int
    sha256: str
    is_cloned_fd: bool = False

    def close(self):
        """Cierra el descriptor de archivo de forma segura."""
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except Exception:
                pass
            self.fd = -1


class PrivilegedQuarantineOperator:
    """
    Operador privilegiado y restringido para el traslado y desinfección segura de archivos.
    Valida la identidad del descriptor de archivo para impedir evasiones TOCTOU y coordina
    con las políticas de aislamiento de systemd.
    """

    def __init__(self, whitelist=None):
        self.whitelist = whitelist

    def pin_and_validate(self, file_path: str, target_fd: Optional[int] = None) -> PinnedFileHandle:
        """
        Inmoviliza el descriptor del archivo en el kernel, valida su identidad y calcula su firma SHA-256.
        Lanza excepciones específicas ante suplantaciones TOCTOU o tipos de archivo no permitidos.
        """
        if not file_path:
            raise ValueError("Ruta de archivo no especificada para cuarentena.")

        norm_path = os.path.abspath(file_path)

        # 1. Prohibir operaciones sobre sistemas de archivos virtuales o dispositivos
        for prefix in FORBIDDEN_ROOT_PREFIXES:
            if norm_path == prefix or norm_path.startswith(prefix + "/"):
                raise PermissionError(f"Operación de cuarentena rechazada en ruta de kernel protegida: {norm_path}")

        # 2. Comprobación de enlace simbólico y lstat inicial
        path_stat = os.lstat(norm_path)
        if stat.S_ISLNK(path_stat.st_mode):
            raise PermissionError(f"Ataque de enlace simbólico detectado en {norm_path}. Abortando cuarentena.")

        fd = -1
        is_cloned = False
        try:
            # 3. Adquisición del descriptor inmovilizado (Pinned FD)
            if target_fd is not None and target_fd >= 0:
                fd = os.dup(target_fd)
                is_cloned = True
            else:
                # Abrir con O_NOFOLLOW para rechazar enlaces simbólicos en la hoja
                open_flags = os.O_RDONLY | os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    open_flags |= os.O_NOFOLLOW
                try:
                    fd = os.open(norm_path, open_flags)
                except OSError as e:
                    if e.errno == errno.ELOOP:
                        raise PermissionError(f"Ataque de enlace simbólico detectado en {norm_path} (O_NOFOLLOW rechazó el symlink).")
                    raise
                is_cloned = False

            # 4. Validación de Identidad del Descriptor (fstat)
            fd_stat = os.fstat(fd)

            # Debe ser estrictamente un archivo regular (no directorio, ni dispositivo, ni socket)
            if not stat.S_ISREG(fd_stat.st_mode):
                raise ValueError(f"El objetivo no es un archivo regular (mode=0o{fd_stat.st_mode:o}): {norm_path}")

            # 5. Validación Anti-TOCTOU: Comparar fstat del descriptor con lstat de la ruta

            if path_stat.st_dev != fd_stat.st_dev or path_stat.st_ino != fd_stat.st_ino:
                raise PermissionError(
                    f"Violación de identidad TOCTOU: el descriptor ({fd_stat.st_dev}:{fd_stat.st_ino}) "
                    f"no coincide con la ruta en disco ({path_stat.st_dev}:{path_stat.st_ino})"
                )

            # 5. Cálculo de firma SHA-256 en bloques de 64 KB leyendo directamente del descriptor
            os.lseek(fd, 0, os.SEEK_SET)
            sha = hashlib.sha256()
            total_read = 0
            chunk_size = 64 * 1024
            while True:
                chunk = os.read(fd, chunk_size)
                if not chunk:
                    break
                sha.update(chunk)
                total_read += len(chunk)

            os.lseek(fd, 0, os.SEEK_SET)
            file_hash = sha.hexdigest().lower()

            return PinnedFileHandle(
                fd=fd,
                path=norm_path,
                st_dev=fd_stat.st_dev,
                st_ino=fd_stat.st_ino,
                size_bytes=total_read,
                sha256=file_hash,
                is_cloned_fd=is_cloned
            )

        except Exception:
            if fd >= 0:
                try:
                    os.close(fd)
                except Exception:
                    pass
            raise

    def secure_unlink(self, handle: PinnedFileHandle) -> Tuple[bool, bool, str]:
        """
        Ejecuta el desvinculado seguro del archivo original:
        1. Pre-unlink: Re-valida que el archivo en disco siga siendo el mismo inodo y dispositivo.
        2. Unlink: Ejecuta os.unlink(handle.path).
        3. Manejo de sistemas de archivos de solo lectura (EROFS).
        Retorna (success: bool, is_read_only_fs: bool, message: str).
        """
        if not handle or not handle.path:
            return False, False, "Handle inválido"

        norm_path = handle.path

        # 1. Comprobación Previa Anti-Carrera: el archivo en disco no debe haber sido suplantado
        try:
            curr_stat = os.lstat(norm_path)
            if curr_stat.st_dev != handle.st_dev or curr_stat.st_ino != handle.st_ino:
                logger.critical("🚨 [TOCTOU PRE-UNLINK] El archivo %s fue suplantado antes del borrado. Abortando desvinculado.", norm_path)
                return False, False, "Archivo suplantado entre validación y desvinculado"
        except FileNotFoundError:
            return True, False, "El archivo ya no existe en disco"
        except Exception as e:
            return False, False, f"Fallo en comprobación previa de lstat: {e}"

        # 2. Desvinculado verificado
        try:
            os.unlink(norm_path)
            if os.path.exists(norm_path):
                return False, False, "El archivo sigue existiendo tras os.unlink"
            return True, False, "Desvinculado con éxito"

        except OSError as e:
            if e.errno == errno.EROFS:  # Read-only file system
                logger.warning(
                    "⚠️ [SISTEMA DE ARCHIVOS SOLO LECTURA] No se pudo desvincular %s: "
                    "El medio o espacio de nombres está montado como solo lectura (EROFS). Muestra asegurada en baúl.",
                    norm_path
                )
                return False, True, "Sistema de archivos de solo lectura (EROFS)"
            elif e.errno == errno.ENOENT:
                return True, False, "El archivo ya no existe en disco"
            else:
                logger.error("❌ Fallo al eliminar archivo original %s: %s", norm_path, e)
                return False, False, str(e)
