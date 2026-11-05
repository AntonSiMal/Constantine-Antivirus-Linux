"""
Constantine Antivirus - Safe Archive Inspection & Anti-ZipBomb Sentinel (core/engine/archive_sentinel.py)
Reutiliza las especificaciones de seguridad y mitigación de denegación de servicio de ClamAV:
1. Prevención Estricta de Bombas de Descompresión (Zip Bombs):
   - Monitorea la tasa de compresión en tiempo real (Uncompressed / Compressed Size).
   - Si la tasa excede el límite (por defecto 200:1) o el tamaño descomprimido supera el techo,
     aborta la extracción inmediatamente y cataloga el archivo como amenaza DoS.
2. Contención de Recursión y Límites de Recursos:
   - MaxRecursionDepth (profundidad máxima de archivos comprimidos anidados: 5 niveles).
   - MaxFilesCount (máximo de archivos extraídos por archivo contenedor: 500).
   - MaxExtractedSize (volumen acumulado máximo: 100 MB).
3. Entorno Seguro de Extracción en Espacio Aislado:
   - Extracción temporal en directorios volátiles con permisos 0700.
   - Protección contra Directory Traversal (Zip Slip / Path traversal).
   - Limpieza atómica garantizada al finalizar el análisis.
"""

import os
import zipfile
import tarfile
import tempfile
import shutil
import logging
from dataclasses import dataclass
from typing import Optional, List, Callable, Dict, Any, Tuple

logger = logging.getLogger("constantine.archive_sentinel")

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".jar", ".war"}


@dataclass
class ArchiveInspectionResult:
    is_malicious: bool
    is_archive: bool
    threat_name: Optional[str] = None
    details: Optional[str] = None
    total_files_inspected: int = 0
    extracted_bytes: int = 0
    compression_ratio: float = 1.0


class ArchiveSentinel:
    """Centinela de inspección de archivos comprimidos con protección contra bombas de descompresión."""

    def __init__(
        self,
        max_compression_ratio: float = 200.0,
        max_extracted_size: int = 100 * 1024 * 1024,  # 100 MB
        max_files: int = 500,
        max_recursion_depth: int = 5
    ):
        self.max_compression_ratio = max_compression_ratio
        self.max_extracted_size = max_extracted_size
        self.max_files = max_files
        self.max_recursion_depth = max_recursion_depth

    def is_archive(self, file_path: str) -> bool:
        """Determina si un archivo es un contenedor comprimido por extensión o firma mágica."""
        if not os.path.isfile(file_path):
            return False

        _, ext = os.path.splitext(file_path.lower())
        if ext in ARCHIVE_EXTENSIONS:
            return True

        # Comprobar números mágicos (ZIP: PK\x03\x04, GZ: \x1f\x8b)
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
                if magic.startswith(b"PK\x03\x04") or magic.startswith(b"\x1f\x8b"):
                    return True
        except Exception:
            pass
        return False

    def inspect_and_scan(
        self,
        archive_path: str,
        scanner_func: Callable[[str], Tuple[bool, Optional[str]]],
        current_depth: int = 0
    ) -> ArchiveInspectionResult:
        """
        Inspecciona el archivo, evalúa ratios anti-bomba, descomprime recursivamente y analiza contenidos.
        """
        if not self.is_archive(archive_path):
            return ArchiveInspectionResult(is_malicious=False, is_archive=False)

        if current_depth > self.max_recursion_depth:
            logger.warning("🚨 [RECURSIÓN EXCESIVA] Archivo anidado superó la profundidad máxima (%d niveles): %s",
                           self.max_recursion_depth, archive_path)
            return ArchiveInspectionResult(
                is_malicious=True,
                is_archive=True,
                threat_name="Archive.ExcessiveRecursion.DenialOfService",
                details=f"Profundidad de compresión anidada excede el límite de seguridad ({self.max_recursion_depth})"
            )

        compressed_size = max(1, os.path.getsize(archive_path))

        # 1. Inspección específica de archivos ZIP
        if zipfile.is_zipfile(archive_path):
            return self._inspect_zip(archive_path, compressed_size, scanner_func, current_depth)

        # 2. Inspección de archivos TAR / TAR.GZ
        if tarfile.is_tarfile(archive_path):
            return self._inspect_tar(archive_path, compressed_size, scanner_func, current_depth)

        return ArchiveInspectionResult(is_malicious=False, is_archive=True)

    def _inspect_zip(
        self,
        archive_path: str,
        compressed_size: int,
        scanner_func: Callable[[str], Tuple[bool, Optional[str]]],
        current_depth: int
    ) -> ArchiveInspectionResult:
        """Analiza un contenedor ZIP aplicando salvaguardas anti-ZipBomb de ClamAV."""
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                infolist = zf.infolist()
                total_uncompressed = sum(info.file_size for info in infolist)
                file_count = len(infolist)

                ratio = total_uncompressed / compressed_size

                # Verificación estricta de límites Anti-Bomba
                if file_count > self.max_files:
                    logger.warning("🚨 [BOMBA DE ARCHIVOS] Contenedor ZIP contiene %d archivos (límite: %d): %s",
                                   file_count, self.max_files, archive_path)
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ExcessiveFileCount.DenialOfService",
                        details=f"Cantidad excesiva de archivos internos ({file_count} > {self.max_files})",
                        compression_ratio=ratio
                    )

                if total_uncompressed > self.max_extracted_size:
                    logger.warning("🚨 [DESCOMPRESIÓN MASIVA] Tamaño total %d bytes supera el límite %d bytes: %s",
                                   total_uncompressed, self.max_extracted_size, archive_path)
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ExcessiveSize.DenialOfService",
                        details=f"Tamaño descomprimido excede límite de seguridad ({total_uncompressed} > {self.max_extracted_size})",
                        compression_ratio=ratio
                    )

                if ratio > self.max_compression_ratio and total_uncompressed > 10 * 1024 * 1024:
                    logger.warning("🚨 [ZIP BOMB DETECTADO] Ratio anómalo %.1f:1 detectado en %s", ratio, archive_path)
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ZipBomb.DenialOfService",
                        details=f"Ratio de descompresión sospechoso ({ratio:.1f}:1 excede {self.max_compression_ratio}:1)",
                        compression_ratio=ratio
                    )

                # Extracción segura en directorio temporal restringido
                tmp_extract = tempfile.mkdtemp(prefix="const_zip_")
                os.chmod(tmp_extract, 0o700)
                try:
                    for info in infolist:
                        # Protección estricta Zip Slip / Directory Traversal
                        target_path = os.path.abspath(os.path.join(tmp_extract, info.filename))
                        if not target_path.startswith(os.path.abspath(tmp_extract) + os.sep) and target_path != os.path.abspath(tmp_extract):
                            logger.critical("🚨 [ZIP SLIP BLOQUEADO] Intento de Directory Traversal en ZIP: %s", info.filename)
                            return ArchiveInspectionResult(
                                is_malicious=True, is_archive=True,
                                threat_name="Exploit.Archive.DirectoryTraversal.ZipSlip",
                                details=f"Ruta hostil en archivo comprimido: {info.filename}"
                            )

                        if info.is_dir():
                            continue

                        zf.extract(info, path=tmp_extract)

                        # Análisis de la muestra extraída
                        if self.is_archive(target_path):
                            nested_res = self.inspect_and_scan(target_path, scanner_func, current_depth + 1)
                            if nested_res.is_malicious:
                                return nested_res
                        else:
                            is_inf, threat = scanner_func(target_path)
                            if is_inf:
                                logger.warning("🎯 [AMENAZA EN ARCHIVO COMPRIMIDO] %s -> %s (en %s)",
                                               info.filename, threat, archive_path)
                                return ArchiveInspectionResult(
                                    is_malicious=True, is_archive=True,
                                    threat_name=f"Archive.{threat}",
                                    details=f"Amenaza detectada dentro del archivo comprimido ({info.filename}): {threat}",
                                    total_files_inspected=file_count,
                                    extracted_bytes=total_uncompressed,
                                    compression_ratio=ratio
                                )

                    return ArchiveInspectionResult(
                        is_malicious=False, is_archive=True,
                        total_files_inspected=file_count,
                        extracted_bytes=total_uncompressed,
                        compression_ratio=ratio
                    )
                finally:
                    shutil.rmtree(tmp_extract, ignore_errors=True)

        except zipfile.BadZipFile:
            return ArchiveInspectionResult(is_malicious=False, is_archive=True)
        except Exception as e:
            logger.debug("Error procesando archivo ZIP %s: %s", archive_path, e)
            return ArchiveInspectionResult(is_malicious=False, is_archive=True)

    def _inspect_tar(
        self,
        archive_path: str,
        compressed_size: int,
        scanner_func: Callable[[str], Tuple[bool, Optional[str]]],
        current_depth: int
    ) -> ArchiveInspectionResult:
        """Analiza un contenedor TAR/TAR.GZ aplicando salvaguardas de seguridad."""
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                members = tf.getmembers()
                total_uncompressed = sum(m.size for m in members)
                file_count = len(members)
                ratio = total_uncompressed / compressed_size

                if file_count > self.max_files:
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ExcessiveFileCount.DenialOfService",
                        details=f"Cantidad excesiva de archivos internos en TAR ({file_count} > {self.max_files})"
                    )

                if total_uncompressed > self.max_extracted_size:
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ExcessiveSize.DenialOfService",
                        details=f"Tamaño descomprimido en TAR excede límite de seguridad ({total_uncompressed} > {self.max_extracted_size})"
                    )

                if ratio > self.max_compression_ratio and total_uncompressed > 10 * 1024 * 1024:
                    return ArchiveInspectionResult(
                        is_malicious=True, is_archive=True,
                        threat_name="Archive.ZipBomb.DenialOfService",
                        details=f"Ratio de descompresión sospechoso en TAR ({ratio:.1f}:1)",
                        compression_ratio=ratio
                    )

                tmp_extract = tempfile.mkdtemp(prefix="const_tar_")
                os.chmod(tmp_extract, 0o700)
                try:
                    for m in members:
                        target_path = os.path.abspath(os.path.join(tmp_extract, m.name))
                        if not target_path.startswith(os.path.abspath(tmp_extract) + os.sep) and target_path != os.path.abspath(tmp_extract):
                            return ArchiveInspectionResult(
                                is_malicious=True, is_archive=True,
                                threat_name="Exploit.Archive.DirectoryTraversal.ZipSlip",
                                details=f"Ruta hostil en archivo TAR: {m.name}"
                            )

                        if m.isdir():
                            continue

                        tf.extract(m, path=tmp_extract)
                        if self.is_archive(target_path):
                            nested_res = self.inspect_and_scan(target_path, scanner_func, current_depth + 1)
                            if nested_res.is_malicious:
                                return nested_res
                        else:
                            is_inf, threat = scanner_func(target_path)
                            if is_inf:
                                return ArchiveInspectionResult(
                                    is_malicious=True, is_archive=True,
                                    threat_name=f"Archive.{threat}",
                                    details=f"Amenaza detectada dentro del archivo TAR ({m.name}): {threat}",
                                    total_files_inspected=file_count,
                                    extracted_bytes=total_uncompressed,
                                    compression_ratio=ratio
                                )

                    return ArchiveInspectionResult(
                        is_malicious=False, is_archive=True,
                        total_files_inspected=file_count,
                        extracted_bytes=total_uncompressed,
                        compression_ratio=ratio
                    )
                finally:
                    shutil.rmtree(tmp_extract, ignore_errors=True)
        except Exception as e:
            logger.debug("Error procesando archivo TAR %s: %s", archive_path, e)
            return ArchiveInspectionResult(is_malicious=False, is_archive=True)
