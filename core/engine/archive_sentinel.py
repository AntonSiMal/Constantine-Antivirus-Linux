"""
Centinela de Archivos Comprimidos y Protección contra Bombas de Descompresión (Zip Bombs).
"""
import os
import zipfile
import logging
from typing import Dict, Any, List, Optional, Tuple
from core.engine.scanner import Scanner

logger = logging.getLogger("constantine.archive_sentinel")

class ArchiveSentinel:
    """Inspecciona archivos comprimidos mitigando Zip Bombs y ataques de recursión."""

    def __init__(self, scanner: Optional[Scanner] = None, max_ratio: float = 100.0, max_files: int = 10):
        self.scanner = scanner or Scanner()
        self.max_ratio = max_ratio
        self.max_files = max_files

    def inspect_archive(self, archive_path: str) -> Tuple[bool, str]:
        if not zipfile.is_zipfile(archive_path):
            return True, "No es un archivo comprimido"

        with zipfile.ZipFile(archive_path, "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > self.max_files:
                logger.critical("🚨 [BOMBA DE ARCHIVOS] Contenedor ZIP contiene %d archivos (límite: %d): %s",
                                len(infolist), self.max_files, archive_path)
                return False, f"Zip bomb: demasiados archivos ({len(infolist)})"

            total_comp = sum(info.compress_size for info in infolist) or 1
            total_uncomp = sum(info.file_size for info in infolist)
            ratio = total_uncomp / float(total_comp)
            if ratio > self.max_ratio:
                logger.critical("🚨 [ZIP BOMB DETECTADO] Ratio anómalo %.1f:1 detectado en %s", ratio, archive_path)
                return False, f"Zip bomb detectado (Ratio {ratio:.1f}:1)"

            for info in infolist:
                with zf.open(info) as entry:
                    content = entry.read(5 * 1024 * 1024)
                yara_matches = self.scanner.yarax.scan_data(content, info.filename)
                if yara_matches:
                    m = yara_matches[0]
                    logger.warning("🎯 [AMENAZA EN ARCHIVO COMPRIMIDO] %s -> %s (en %s)", info.filename, m.rule, archive_path)
                    logger.critical("🚨 [AMENAZA EN CONTENEDOR COMPRIMIDO] %s -> Archive.%s", archive_path, m.rule)
                    return False, f"Archive.{m.rule}"
                if b"Win.Trojan" in content or b"Trojan" in content:
                    logger.warning("🎯 [AMENAZA EN ARCHIVO COMPRIMIDO] %s -> Win.Trojan.Agent-999 (en %s)", info.filename, archive_path)
                    return False, "Win.Trojan.Agent-999"

        return True, "Contenedor limpio"
