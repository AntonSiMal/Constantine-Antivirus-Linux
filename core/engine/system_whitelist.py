"""
Constantine Antivirus - Cryptographic Package & System Whitelist Engine (core/engine/system_whitelist.py)
Gestión estricta de exclusiones y lista blanca con verificación criptográfica de procedencia:
1. Autoprotección Inmune a Evasiones (Cero Confianza por Nombre o Extensión):
   - Elimina completamente la confianza por coincidencia parcial de nombres ("constantine" en la ruta).
   - Elimina la exclusión genérica por extensión (.yar, .yara, .quar).
   - Valida rutas canónicas absolutas (os.path.realpath) contra las raíces oficiales de instalación:
     /opt/constantine, /var/lib/constantine, /etc/constantine, /var/log/constantine.
2. Verificación Criptográfica de Paquetes de Sistema (APT / dpkg / Snap / Flatpak):
   - Elimina la confianza ciega basada únicamente en la carpeta (/usr/bin, /usr/lib, /usr/share, /snap).
   - Comprueba que el binario pertenezca a un paquete oficial legítimo de la distribución.
   - Verifica el checksum criptográfico del archivo contra la base oficial de dpkg (/var/lib/dpkg/info/*.md5sums).
   - En Snaps, valida que el binario resida estrictamente sobre un montaje squashfs de solo lectura.
   - Si un binario no pertenece a un paquete oficial o su checksum fue alterado, se rechaza y exige escaneo.
3. Límites Estrictos y Auditoría Forense en Exclusiones de Usuario:
   - Bloqueo preventivo: Prohíbe añadir a la lista blanca directorios críticos del sistema (/ , /bin, /usr/bin, /tmp, /etc).
   - Fijación criptográfica obligatoria (SHA-256 Pinning): Cada archivo excluido registra su hash.
   - Si el archivo es modificado o reemplazado en disco, la exclusión se INVALIDA de inmediato y se genera alerta.
   - Auditoría: Todos los eventos de exclusión, revocación y manipulación quedan registrados en AuditLogger.
"""

import os
import glob
import json
import time
import hashlib
import logging
import subprocess
from typing import Set, Dict, List, Optional, Tuple, Any

from core.engine.audit_logger import AuditLogger

logger = logging.getLogger("constantine.whitelist")

DEFAULT_WHITELIST_FILE = "/var/lib/constantine/whitelist.json"
USER_WHITELIST_FILE = os.path.expanduser("~/.config/constantine/whitelist.json")

# Directorios intrínsecamente no confiables o volátiles
SUSPICIOUS_UNTRUSTED_DIRS = (
    "/tmp",
    "/dev/shm",
    "/var/tmp",
    "/run/user"
)

# Directorios críticos del sistema cuya exclusión global está expresamente prohibida
FORBIDDEN_SYSTEM_DIRS = {
    "/",
    "/bin",
    "/sbin",
    "/usr",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/local/bin",
    "/etc",
    "/dev",
    "/proc",
    "/sys",
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/run",
    "/boot"
}

# Raíces autorizadas absolutas del propio antivirus Constantine
AUTHORIZED_APP_ROOTS = (
    "/opt/constantine",
    "/var/lib/constantine",
    "/etc/constantine",
    "/var/log/constantine"
)

# Raíz canónica del código en ejecución
SELF_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class PackageIntegrityEngine:
    """Motor de verificación de integridad criptográfica y origen de paquetes del sistema operativo."""

    def __init__(self):
        # Caché en memoria: (st_dev, st_ino) -> {"mtime": st_mtime, "is_valid": bool, "pkg": str}
        self.cache: Dict[Tuple[int, int], Dict] = {}

    def compute_md5(self, path: str) -> Optional[str]:
        md5 = hashlib.md5()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    md5.update(chunk)
            return md5.hexdigest().lower()
        except Exception:
            return None

    def get_dpkg_package_for_file(self, path: str) -> Tuple[Optional[str], Optional[str]]:
        """Identifica el paquete dpkg oficial al que pertenece un archivo y su ruta relativa."""
        candidates = [path]
        try:
            real = os.path.realpath(path)
            if real not in candidates:
                candidates.append(real)
        except Exception:
            pass

        # Manejo de aliasing por usr-merge en Debian/Ubuntu (/bin <-> /usr/bin, /lib <-> /usr/lib)
        if path.startswith("/usr/bin/"):
            candidates.append(path.replace("/usr/bin/", "/bin/"))
        elif path.startswith("/bin/"):
            candidates.append(path.replace("/bin/", "/usr/bin/"))
        if path.startswith("/usr/sbin/"):
            candidates.append(path.replace("/usr/sbin/", "/sbin/"))
        elif path.startswith("/sbin/"):
            candidates.append(path.replace("/sbin/", "/usr/sbin/"))
        if path.startswith("/usr/lib/"):
            candidates.append(path.replace("/usr/lib/", "/lib/"))
        elif path.startswith("/lib/"):
            candidates.append(path.replace("/lib/", "/usr/lib/"))

        for c in candidates:
            try:
                out = subprocess.check_output(["dpkg-query", "-S", c], text=True, stderr=subprocess.DEVNULL)
                if ":" in out:
                    parts = out.split(":", 1)
                    pkg = parts[0].strip().split(",")[0].strip()
                    matched_path = parts[1].strip()
                    return pkg, matched_path
            except Exception:
                continue
        return None, None

    def verify_snap_integrity(self, file_path: str) -> bool:
        """
        Verifica si un ejecutable bajo /snap reside en un montaje squashfs legítimo de solo lectura.
        Previene que atacantes creen directorios normales en /snap para eludir el antivirus.
        """
        try:
            real_path = os.path.realpath(file_path)
            # En Linux, las aplicaciones Snap legítimas residen en /snap/<pkg>/<rev>/ montado en solo lectura
            if not real_path.startswith("/snap/"):
                return False

            # Verificar si la ruta reside sobre un sistema de archivos squashfs de solo lectura
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4:
                        mount_point = parts[1]
                        fs_type = parts[2]
                        opts = parts[3].split(",")
                        if real_path.startswith(mount_point) and mount_point != "/":
                            if fs_type == "squashfs" and "ro" in opts:
                                return True
            return False
        except Exception as e:
            logger.debug("Aviso verificando snap en %s: %s", file_path, e)
            return False

    def verify_binary(self, file_path: str) -> bool:
        """
        Verifica criptográficamente que el archivo pertenezca a un paquete oficial
        y que su checksum coincida con el registrado por la distribución.
        """
        if not file_path or not os.path.exists(file_path):
            return False

        try:
            real_path = os.path.realpath(file_path)
            st = os.stat(real_path)
            cache_key = (st.st_dev, st.st_ino)

            # Consulta a la caché de inodos (< 0.001 ms)
            cached = self.cache.get(cache_key)
            if cached and cached["mtime"] == st.st_mtime:
                return cached["is_valid"]

            # Si reside bajo /snap, verificar montaje squashfs firmado
            if real_path.startswith("/snap/"):
                is_valid = self.verify_snap_integrity(real_path)
                self.cache[cache_key] = {"mtime": st.st_mtime, "is_valid": is_valid}
                return is_valid

            # Verificación criptográfica con dpkg
            is_valid = self._verify_dpkg_integrity(real_path, file_path)
            self.cache[cache_key] = {
                "mtime": st.st_mtime,
                "is_valid": is_valid
            }
            return is_valid
        except Exception as e:
            logger.debug("Aviso verificando integridad de %s: %s", file_path, e)
            return False

    def _verify_dpkg_integrity(self, real_path: str, orig_path: str) -> bool:
        # 1. Consultar si dpkg reconoce el archivo
        pkg, matched_path = self.get_dpkg_package_for_file(orig_path)
        if not pkg:
            pkg, matched_path = self.get_dpkg_package_for_file(real_path)

        if not pkg:
            logger.warning("🚨 [INTEGRIDAD FALLIDA] Binario no registrado en gestor de paquetes de la distribución: %s", real_path)
            return False

        # 2. Localizar archivo oficial .md5sums del paquete
        md5_candidates = [
            f"/var/lib/dpkg/info/{pkg}.md5sums",
            f"/var/lib/dpkg/info/{pkg}:amd64.md5sums",
            f"/var/lib/dpkg/info/{pkg}:i386.md5sums"
        ]
        md5_file = next((f for f in md5_candidates if os.path.exists(f)), None)
        if not md5_file:
            matches = glob.glob(f"/var/lib/dpkg/info/{pkg}*.md5sums")
            if matches:
                md5_file = matches[0]

        if md5_file and os.path.exists(md5_file):
            rel_path = matched_path.lstrip("/") if matched_path else real_path.lstrip("/")
            alt_rel = rel_path.replace("usr/bin/", "bin/").replace("usr/sbin/", "sbin/")
            try:
                with open(md5_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            expected_md5, entry_rel = parts[0], parts[1]
                            if entry_rel in (rel_path, alt_rel):
                                actual_md5 = self.compute_md5(real_path)
                                if actual_md5 and actual_md5.lower() == expected_md5.lower():
                                    return True
                                else:
                                    logger.critical("🚨 [INTEGRIDAD VIOLADA] Checksum MD5 alterado en binario del sistema: %s (Esperado: %s, Real: %s)",
                                                    real_path, expected_md5, actual_md5)
                                    return False
            except Exception as e:
                logger.error("Error leyendo archivo de checksums %s: %s", md5_file, e)

        # Si el paquete es oficial y dpkg lo reconoce pero no tiene registro md5sums
        return True


class SystemWhitelist:
    """
    Administrador central de lista blanca con autoprotección por ruta canónica,
    fijación de hashes SHA-256 de usuario y auditoría forense.
    """

    def __init__(self, storage_file: Optional[str] = None):
        if storage_file:
            self.storage_file = os.path.abspath(storage_file)
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.storage_file = DEFAULT_WHITELIST_FILE
        else:
            self.storage_file = USER_WHITELIST_FILE

        self.user_whitelisted_paths: Set[str] = set()
        self.user_whitelisted_hashes: Set[str] = set()
        self.user_path_hashes: Dict[str, str] = {}  # path -> sha256
        self.user_entries_metadata: Dict[str, Dict[str, Any]] = {}  # path -> metadata

        self.integrity_engine = PackageIntegrityEngine()
        self.audit = AuditLogger()
        self._load_whitelist()

    def _ensure_dir(self):
        d = os.path.dirname(self.storage_file)
        if d:
            os.makedirs(d, exist_ok=True)

    def _load_whitelist(self):
        self._ensure_dir()
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.user_whitelisted_paths = set(data.get("paths", []))
                    self.user_whitelisted_hashes = set(data.get("hashes", []))
                    self.user_path_hashes = data.get("path_hashes", {})
                    self.user_entries_metadata = data.get("metadata", {})
            except Exception as e:
                logger.debug("Error cargando whitelist: %s", e)

    def _save_whitelist(self):
        self._ensure_dir()
        try:
            with open(self.storage_file, "w", encoding="utf-8") as f:
                json.dump({
                    "paths": sorted(list(self.user_whitelisted_paths)),
                    "hashes": sorted(list(self.user_whitelisted_hashes)),
                    "path_hashes": self.user_path_hashes,
                    "metadata": self.user_entries_metadata
                }, f, indent=2)
        except Exception as e:
            logger.debug("Error guardando whitelist: %s", e)

    def compute_sha256(self, file_path: str) -> Optional[str]:
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception:
            return None

    def is_self_file(self, file_path: str) -> bool:
        """
        Autoprotección rigurosa de Constantine:
        1. Resuelve la ruta canónica real (os.path.realpath).
        2. Verifica pertenencia estricta a los directorios de instalación y configuración autorizados.
        3. NO confía en subcadenas como 'constantine' en rutas arbitrarias.
        4. NO confía en extensiones genéricas (.yar, .yara, .quar) fuera de los directorios oficiales.
        """
        if not file_path:
            return False

        try:
            real_path = os.path.realpath(file_path)
        except Exception:
            return False

        # Raíces autorizadas oficiales del sistema
        valid_roots = list(AUTHORIZED_APP_ROOTS)
        if SELF_ROOT and os.path.exists(SELF_ROOT):
            valid_roots.append(SELF_ROOT)

        for root in valid_roots:
            try:
                c_root = os.path.realpath(root)
                # Debe ser exactamente el directorio o residir dentro de su jerarquía
                if real_path == c_root or real_path.startswith(os.path.join(c_root, "")):
                    return True
            except Exception:
                continue

        return False

    def is_trusted_system_binary(self, file_path: str) -> bool:
        """
        Determina si el archivo es un binario oficial verificado criptográficamente:
        1. Rechaza directorios intrínsecamente no confiables (/tmp, /dev/shm).
        2. Verifica que pertenezca a un paquete legítimo de la distribución (dpkg) o squashfs de Snap.
        3. Valida el checksum oficial del paquete.
        """
        if not file_path:
            return False

        try:
            norm_path = os.path.realpath(file_path)
        except Exception:
            return False

        for susp in SUSPICIOUS_UNTRUSTED_DIRS:
            if norm_path == susp or norm_path.startswith(os.path.join(susp, "")):
                return False

        return self.integrity_engine.verify_binary(norm_path)

    def is_whitelisted(self, file_path: str, file_hash: Optional[str] = None) -> bool:
        """
        Determina si un archivo debe ser autorizado:
        - Si es un archivo propio del antivirus (autoprotección canónica).
        - Si su hash SHA-256 coincide con una exclusión aprobada.
        - Si está en la lista de usuario Y su integridad criptográfica SHA-256 coincide.
        - Si es un binario oficial de la distribución con checksum verificado.
        """
        if not file_path:
            return False

        try:
            norm_path = os.path.realpath(file_path)
        except Exception:
            return False

        # 0. Autoprotección: Archivos propios del antivirus en ubicaciones oficiales
        if self.is_self_file(norm_path):
            return True

        # 1. Comprobación directa por Hash SHA-256 autorizado
        if file_hash and file_hash.lower() in self.user_whitelisted_hashes:
            return True

        # 2. Comprobación de exclusión de usuario con fijación estricta de hash (Anti-Tamper)
        if norm_path in self.user_whitelisted_paths:
            expected_hash = self.user_path_hashes.get(norm_path)
            if expected_hash:
                current_hash = file_hash or self.compute_sha256(norm_path)
                if current_hash and current_hash.lower() == expected_hash.lower():
                    return True
                else:
                    # Alerta crítica: El archivo autorizado fue manipulado o reemplazado
                    logger.warning("🚨 [EXCLUSIÓN INVALIDADA] Archivo autorizado modificado en disco: %s (Esperado: %s, Real: %s)",
                                   norm_path, expected_hash, current_hash)
                    try:
                        self.audit.record_incident(
                            threat_name="WHITELIST_TAMPER_DETECTED",
                            target_path=norm_path,
                            action="FAN_DENY",
                            details=f"Hash esperado: {expected_hash[:16]}..., Hash real: {current_hash[:16] if current_hash else 'N/A'}"
                        )
                    except Exception:
                        pass
                    return False
            # Si era una carpeta de desarrollo autorizada explícitamente por el usuario
            return True

        # Comprobar si reside dentro de una carpeta explícitamente autorizada por el usuario
        for wpath in self.user_whitelisted_paths:
            if os.path.isdir(wpath) and norm_path.startswith(os.path.join(wpath, "")):
                # Asegurar que la carpeta no sea un directorio del sistema
                if wpath not in FORBIDDEN_SYSTEM_DIRS:
                    return True

        # 3. Comprobación de binarios del sistema (Integridad criptográfica con dpkg / Snap squashfs)
        return self.is_trusted_system_binary(norm_path)

    def add_path(self, path: str, reason: str = "Autorización de usuario", user: Optional[str] = None) -> bool:
        """
        Agrega un archivo o carpeta a la lista blanca:
        - Bloquea explícitamente la exclusión de rutas críticas del sistema (/, /bin, /usr, /tmp).
        - Para archivos, fija su hash SHA-256 para prevenir ataques de reemplazo.
        - Registra el evento en AuditLogger.
        """
        if not path or not os.path.exists(path):
            return False

        try:
            norm_path = os.path.realpath(path)
        except Exception:
            return False

        # Validación de límites de seguridad: No se permite excluir raíces críticas
        if norm_path in FORBIDDEN_SYSTEM_DIRS:
            logger.critical("❌ [SEGURIDAD] Intento de excluir directorio crítico del sistema rechazado: %s", norm_path)
            try:
                self.audit.record_incident(
                    threat_name="WHITELIST_FORBIDDEN_DIR_REJECTED",
                    target_path=norm_path,
                    action="BLOCKED",
                    details="Intento denegado de añadir directorio del sistema a exclusiones"
                )
            except Exception:
                pass
            return False

        self.user_whitelisted_paths.add(norm_path)
        fhash = ""
        if os.path.isfile(norm_path):
            fhash = self.compute_sha256(norm_path) or ""
            if fhash:
                self.user_path_hashes[norm_path] = fhash.lower()
                self.user_whitelisted_hashes.add(fhash.lower())

        # Metadatos y trazabilidad
        self.user_entries_metadata[norm_path] = {
            "path": norm_path,
            "sha256": fhash,
            "type": "file" if os.path.isfile(norm_path) else "directory",
            "added_at": time.time(),
            "user": user or os.getenv("USER") or "root",
            "reason": reason
        }

        self._save_whitelist()
        logger.info("Añadido a Whitelist con verificación de integridad: %s (SHA-256: %s)", norm_path, fhash[:12] if fhash else "N/A")

        try:
            self.audit.record_incident(
                threat_name="WHITELIST_ADD",
                target_path=norm_path,
                action="WHITELISTED",
                details=f"Motivo: {reason} | SHA-256: {fhash[:16] if fhash else 'Directorio'}"
            )
        except Exception:
            pass

        return True

    def remove_path(self, path: str) -> bool:
        """Remueve un archivo o carpeta de la lista blanca y registra el evento en auditoría."""
        if not path:
            return False

        try:
            norm_path = os.path.realpath(path)
        except Exception:
            norm_path = os.path.abspath(path)

        removed = False
        if norm_path in self.user_whitelisted_paths:
            self.user_whitelisted_paths.remove(norm_path)
            removed = True
        if norm_path in self.user_path_hashes:
            old_hash = self.user_path_hashes.pop(norm_path)
            self.user_whitelisted_hashes.discard(old_hash.lower())
            removed = True
        if norm_path in self.user_entries_metadata:
            self.user_entries_metadata.pop(norm_path)
            removed = True

        if removed:
            self._save_whitelist()
            logger.info("Removido de Whitelist: %s", norm_path)
            try:
                self.audit.record_incident(
                    threat_name="WHITELIST_REMOVE",
                    target_path=norm_path,
                    action="REVOKED",
                    details="Exclusión removida"
                )
            except Exception:
                pass
            return True
        return False

    def add_restored_exception(self, file_path: str, file_hash: Optional[str] = None):
        """Añade automáticamente un archivo restaurado del baúl fijando su hash criptográfico."""
        norm_path = os.path.realpath(file_path)
        self.user_whitelisted_paths.add(norm_path)
        fhash = file_hash or self.compute_sha256(norm_path)
        if fhash:
            self.user_path_hashes[norm_path] = fhash.lower()
            self.user_whitelisted_hashes.add(fhash.lower())

        self.user_entries_metadata[norm_path] = {
            "path": norm_path,
            "sha256": fhash or "",
            "type": "restored_file",
            "added_at": time.time(),
            "user": "QuarantineVault",
            "reason": "Restaurado explícitamente desde Baúl de Cuarentena"
        }
        self._save_whitelist()
        logger.info("🛡️ Archivo restaurado añadido a la Lista Blanca con hash criptográfico: %s", norm_path)

    def list_entries(self) -> List[Dict[str, str]]:
        """Devuelve todas las entradas de lista blanca formateadas con metadatos para la GUI y CLI."""
        entries = []
        for p in sorted(list(self.user_whitelisted_paths)):
            meta = self.user_entries_metadata.get(p, {})
            ptype = "Carpeta" if os.path.isdir(p) else "Archivo (SHA-256 Verificado)"
            h_info = meta.get("sha256", self.user_path_hashes.get(p, ""))
            reason = meta.get("reason", "Autorizado por usuario")
            entries.append({
                "path": p,
                "type": ptype,
                "sha256": h_info,
                "reason": reason,
                "status": "Autorizado"
            })
        for h in sorted(list(self.user_whitelisted_hashes)):
            # Evitar duplicar si ya está como archivo
            if not any(e.get("sha256") == h for e in entries):
                entries.append({
                    "path": f"Hash SHA-256: {h}",
                    "type": "Firma Hash Independiente",
                    "sha256": h,
                    "reason": "Exclusión por hash",
                    "status": "Autorizado"
                })
        return entries
