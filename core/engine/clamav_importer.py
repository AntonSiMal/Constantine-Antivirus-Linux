"""
Constantine Antivirus - ClamAV Signature Importer & CVD Parser (core/engine/clamav_importer.py)
Permite la reutilización directa del ecosistema de firmas de ClamAV (Cisco Talos):
1. Ingesta de Bases de Hashes (.hsb / .hdb):
   - Parser de archivos .hsb (SHA-256) y .hdb (MD5) de malware verificado.
   - Validación sintáctica estricta e inserción directa en la base SQLite de Threat Intelligence.
2. Ingesta de Bases Anti-Phishing (.pdb / .wdb):
   - Dominios y URLs fraudulentas curadas por Talos integradas en PhishingShield.
3. Desempaquetado Seguro de Contenedores CVD/CLD:
   - Valida la cabecera canónica de 512 bytes de ClamAV (ClamAV-VDB:...).
   - Descomprime el tar.gz interno protegiendo contra ataques de Directory Traversal (Zip Slip).
4. Auto-descubrimiento en el Sistema:
   - Detecta si ClamAV está instalado en la máquina anfitriona (/var/lib/clamav, etc.)
     y sincroniza automáticamente sus firmas locales hacia Constantine.
"""

import os
import re
import tarfile
import gzip
import logging
from typing import Dict, Any, Optional, List, Tuple

logger = logging.getLogger("constantine.clamav_importer")

SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")

STANDARD_CLAMAV_DB_DIRS = [
    "/var/lib/clamav",
    "/var/db/clamav",
    "/usr/local/share/clamav",
    "/opt/constantine/clamav_db"
]


class ClamAVSignatureImporter:
    """Importador y parser de firmas ClamAV CVD/CLD/HSB/PDB."""

    @staticmethod
    def parse_hsb_line(line: str) -> Optional[Tuple[str, int, str]]:
        """
        Parsea una línea de firma .hsb (SHA-256).
        Formato ClamAV: <Hash_SHA256>:<Tamaño_Bytes>:<Nombre_Amenaza>
        Ejemplo: 8a39a9c68a4e8d356c9a35e729a996024efb5ef604c86ec6e0bf0a68d067c87c:1024:Linux.Ransomware.LockBit
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split(":", 2)
        if len(parts) < 3:
            return None
        hash_val, size_str, threat_name = parts[0].strip().lower(), parts[1].strip(), parts[2].strip()
        if not SHA256_REGEX.match(hash_val):
            return None
        try:
            size_int = int(size_str) if size_str != "*" else 0
        except ValueError:
            size_int = 0
        return hash_val, size_int, threat_name

    @staticmethod
    def parse_hdb_line(line: str) -> Optional[Tuple[str, int, str]]:
        """
        Parsea una línea de firma .hdb (MD5).
        Formato ClamAV: <Hash_MD5>:<Tamaño_Bytes>:<Nombre_Amenaza>
        """
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split(":", 2)
        if len(parts) < 3:
            return None
        hash_val, size_str, threat_name = parts[0].strip().lower(), parts[1].strip(), parts[2].strip()
        if not MD5_REGEX.match(hash_val):
            return None
        try:
            size_int = int(size_str) if size_str != "*" else 0
        except ValueError:
            size_int = 0
        return hash_val, size_int, threat_name

    def import_hsb_file(self, filepath: str, threat_intel, max_records: Optional[int] = None) -> int:
        """
        Lee un archivo .hsb e inserta los hashes válidos en la base SQLite de Threat Intelligence.
        """
        if not os.path.isfile(filepath):
            logger.warning("Archivo de firmas ClamAV no encontrado: %s", filepath)
            return 0

        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parsed = self.parse_hsb_line(line)
                    if parsed:
                        h_val, _, t_name = parsed
                        success = threat_intel.add_hash(
                            sha256=h_val,
                            threat_name=f"ClamAV.{t_name}",
                            source="ClamAV-HSB",
                            confidence=95,
                            tags="clamav,cisco-talos,hsb"
                        )
                        if success:
                            count += 1
                            if max_records and count >= max_records:
                                break
            logger.info("Importadas con éxito %d firmas de malware desde %s", count, filepath)
        except Exception as e:
            logger.error("Error importando archivo .hsb %s: %s", filepath, e)
        return count

    def import_pdb_file(self, filepath: str, phishing_shield) -> int:
        """
        Lee un archivo .pdb/.wdb e inserta dominios y URLs maliciosas en PhishingShield.
        """
        if not os.path.isfile(filepath):
            return 0

        count = 0
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":", 1)
                    target = parts[0].strip()
                    if target and len(target) > 3:
                        if hasattr(phishing_shield, "add_suspicious_domain"):
                            phishing_shield.add_suspicious_domain(target)
                            count += 1
                        elif hasattr(phishing_shield, "custom_blacklist"):
                            phishing_shield.custom_blacklist.add(target.lower())
                            count += 1
        except Exception as e:
            logger.error("Error importando archivo .pdb %s: %s", filepath, e)
        return count

    def unpack_cvd(self, cvd_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Desempaqueta un archivo CVD/CLD de ClamAV:
        - Valida la cabecera de 512 bytes 'ClamAV-VDB:...'.
        - Extrae el archivo tar.gz subsiguiente con protección estricta anti-Directory Traversal.
        """
        if not os.path.isfile(cvd_path):
            return {"success": False, "error": f"Archivo no existe: {cvd_path}"}

        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(cvd_path, "rb") as f:
                header_raw = f.read(512)
                if len(header_raw) < 512 or not header_raw.startswith(b"ClamAV-VDB:"):
                    # Podría ser un CLD (archivo tar.gz directo sin cabecera CVD de 512 bytes)
                    f.seek(0)
                    is_plain_tar = True
                else:
                    is_plain_tar = False

                header_str = header_raw.decode("utf-8", errors="ignore") if not is_plain_tar else ""

                # Extraer archivo tar.gz con protección Path Traversal
                extracted_files = []
                with tarfile.open(fileobj=f, mode="r:gz") as tar:
                    for member in tar.getmembers():
                        # Protección estricta Zip Slip / Directory Traversal
                        target_path = os.path.abspath(os.path.join(output_dir, member.name))
                        if not target_path.startswith(os.path.abspath(output_dir) + os.sep) and target_path != os.path.abspath(output_dir):
                            logger.critical("🚨 [ATAQUE DETECTADO] Intento de Directory Traversal en CVD: %s", member.name)
                            continue
                        tar.extract(member, path=output_dir)
                        extracted_files.append(member.name)

            return {
                "success": True,
                "header": header_str,
                "extracted_files": extracted_files,
                "output_dir": output_dir
            }
        except Exception as e:
            logger.error("Error desempaquetando archivo ClamAV CVD/CLD: %s", e)
            return {"success": False, "error": str(e)}

    def sync_from_local_clamav(self, threat_intel, db_dirs: Optional[List[str]] = None, max_records_per_file: int = 5000) -> Dict[str, Any]:
        """
        Escanea las rutas estándar del sistema en busca de bases de datos de ClamAV instaladas
        y sincroniza automáticamente sus firmas de hashes hacia Constantine.
        """
        search_dirs = db_dirs or STANDARD_CLAMAV_DB_DIRS
        imported_total = 0
        scanned_files = []

        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for entry in os.listdir(d):
                    full_p = os.path.join(d, entry)
                    if entry.endswith(".hsb"):
                        added = self.import_hsb_file(full_p, threat_intel, max_records=max_records_per_file)
                        imported_total += added
                        scanned_files.append(entry)
                    elif entry.endswith((".cvd", ".cld")):
                        # Extraer temporalmente y buscar archivos .hsb
                        import tempfile
                        with tempfile.TemporaryDirectory() as tmp_unpack:
                            res = self.unpack_cvd(full_p, tmp_unpack)
                            if res.get("success"):
                                for root, _, files in os.walk(tmp_unpack):
                                    for ef in files:
                                        if ef.endswith(".hsb"):
                                            added = self.import_hsb_file(os.path.join(root, ef), threat_intel, max_records=max_records_per_file)
                                            imported_total += added
                                scanned_files.append(entry)
            except Exception as e:
                logger.debug("Aviso explorando directorio ClamAV %s: %s", d, e)

        return {
            "imported_hashes": imported_total,
            "processed_sources": scanned_files
        }
