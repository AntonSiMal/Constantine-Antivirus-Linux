"""
Operador de Cuarentena con Privilegios Delimitados y Fijación de Descriptores.
"""
import os
import stat
import errno
import logging
from typing import Tuple, Optional

logger = logging.getLogger("constantine.quarantine_operator")

class PinnedFileHandle:
    """Descriptor seguro y fijado contra ataques de condición de carrera y enlaces simbólicos."""

    def __init__(self, path: str, fd: int, st_dev: int, st_ino: int):
        self.path = os.path.abspath(path)
        self.fd = fd
        self.dev = st_dev
        self.ino = st_ino
        self._closed = False

    def close(self):
        if not self._closed:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class PrivilegedQuarantineOperator:
    """
    Operador de cuarentena con permisos delimitados:
    1. Previene manipulación TOCTOU fijando el file descriptor.
    2. Prohíbe desvinculación de binarios críticos del sistema.
    3. Protege archivos en lista blanca.
    4. Tolera sistemas de archivos en solo lectura (EROFS).
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
        """Abre el archivo con banderas O_RDONLY | O_NOFOLLOW para fijar su descriptor."""
        norm_path = os.path.abspath(path)
        if os.path.islink(norm_path):
            raise OSError(errno.ELOOP, "Ataque de enlace simbólico detectado")

        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(norm_path, flags)
        try:
            st = os.fstat(fd)
            if stat.S_ISLNK(st.st_mode):
                os.close(fd)
                raise OSError(errno.ELOOP, "El archivo abierto es un enlace simbólico")
            return PinnedFileHandle(norm_path, fd, st.st_dev, st.st_ino)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def secure_unlink(self, handle: PinnedFileHandle) -> Tuple[bool, bool, str]:
        """
        Ejecuta el desvinculado seguro del archivo original:
        1. Comprobación de seguridad: Prohibido desvincular binarios de sistema.
        2. Comprobación de lista blanca.
        3. Comprobación anti-TOCTOU con fstat.
        4. Soporte EROFS sin fallos críticos.
        """
        norm_path = handle.path

        # 0. Protección estricta contra eliminación accidental de binarios o rutas del sistema
        if self.is_protected_system_path(norm_path):
            logger.critical("🛑 [ACCESO RESTRINGIDO] Prohibido desvincular binarios críticos del sistema: %s", norm_path)
            return False, False, "Ruta protegida del sistema operativo"

        if self.whitelist and hasattr(self.whitelist, "is_whitelisted") and self.whitelist.is_whitelisted(norm_path):
            logger.warning("🛡️ [LISTA BLANCA] Archivo en lista blanca no puede ser eliminado: %s", norm_path)
            return False, False, "Archivo protegido por lista blanca"

        # 1. Comprobación Previa Anti-Carrera: el archivo en disco no debe haber sido suplantado
        try:
            curr_stat = os.lstat(norm_path)
            if curr_stat.st_dev != handle.dev or curr_stat.st_ino != handle.ino:
                logger.critical("🚨 [ATAQUE TOCTOU DETECTADO] Inodo alterado antes de desvincular: %s", norm_path)
                return False, False, "Inconsistencia de inodo (TOCTOU)"
        except OSError as e:
            return False, False, str(e)

        # 2. Desvinculación en disco
        try:
            os.unlink(norm_path)
            return True, True, "Desvinculación exitosa"
        except OSError as e:
            if e.errno == errno.EROFS:
                logger.warning("⚠️ Medio en solo lectura (EROFS): no se pudo eliminar archivo original %s", norm_path)
                return True, False, "Medio de solo lectura (EROFS)"
            return False, False, str(e)
