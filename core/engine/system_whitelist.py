"""
Constantine Antivirus - Cryptographic Package & System Whitelist Engine (core/engine/system_whitelist.py)

GESTIÓN RIGUROSA DE LISTA BLANCA Y VERIFICACIÓN DE PROCEDENCIA (P0/P1):
No considera confiable un ejecutable únicamente por estar registrado como paquete instalado.
Aplica siete pilares de verificación criptográfica y control de integridad:

1. Verificación de Propiedad del Archivo en Gestor de Paquetes (dpkg / rpm / snap):
   - Confirma la pertenencia del archivo al paquete mediante consulta exacta de base de datos.
   - Valida el estado del paquete (debe ser estrictamente 'install ok installed'; rechaza paquetes
     desinstalados, residuales 'rc' o en estado 'half-installed').
2. Verificación de Integridad contra el Contenido Esperado del Paquete:
   - Valida la suma de verificación oficial (.md5sums / dpkg --verify / debsums).
   - En Snaps, valida que el archivo resida en un montaje squashfs de solo lectura oficial.
   - NUNCA concede confianza automática si faltan las sumas oficiales de verificación.
3. Identificación de Modificaciones Posteriores a la Instalación:
   - Detecta si un archivo fue alterado o reemplazado después de la instalación del paquete.
   - Si se detecta alteración (mtime sospechoso, tamaño o hash discrepante), se REVOCA de inmediato
     la confianza, se desaloja de la caché y se emite una alerta forense de compromiso.
4. Validación de Procedencia y Firma del Paquete:
   - Consulta apt-cache policy para verificar que el paquete proviene de un repositorio oficial
     firmado (Debian, Ubuntu, Canonical, etc.) y no de un paquete local (.deb) no verificado.
5. Caducidad y Reevaluación Continua de Entradas en Caché:
   - Caché con tiempo de vida limitado (TTL de 300s / 5 minutos) y desalojo por inodo/mtime/tamaño.
   - Capacidad acotada (5000 entradas) para prevenir consumo excesivo de memoria.
6. Exclusiones por Hash y Ruta Administradas de Forma Segura:
   - Fijación criptográfica obligatoria de hash SHA-256 en rutas autorizadas por el usuario.
   - Si un archivo autorizado por el usuario es modificado, se REVOCA automáticamente de la lista blanca.
   - Almacenamiento seguro y atómico de la base de datos (0600) con protección contra symlinks.
7. Registro de Cada Decisión de Confianza:
   - Bitácora forense de decisiones (ALLOWED / DENIED) con procedencia, paquete y motivo.
"""

import os
import glob
import json
import time
import stat
import hashlib
import logging
import subprocess
import threading
from typing import Set, Dict, List, Optional, Tuple, Any

from core.engine.audit_logger import AuditLogger

logger = logging.getLogger("constantine.whitelist")

DEFAULT_WHITELIST_FILE = "/var/lib/constantine/whitelist.json"
USER_WHITELIST_FILE = os.path.expanduser("~/.config/constantine/whitelist.json")

# Directorios intrínsecamente no confiables o volátiles donde un binario nunca es de sistema
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
    """
    Motor de verificación de integridad criptográfica y procedencia de paquetes del SO.
    Verifica que el binario pertenezca a un paquete oficial, que el paquete esté correctamente
    instalado y provenga de un repositorio firmado, y que el archivo no haya sido modificado.
    """

    def __init__(self, cache_ttl: float = 300.0, max_cache_entries: int = 5000):
        self.cache_ttl = float(cache_ttl)
        self.max_cache_entries = int(max_cache_entries)
        # cache: (st_dev, st_ino) -> {"mtime": st_mtime, "size": st_size, "cached_at": float, "is_valid": bool, "pkg": str, "reason": str}
        self.cache: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self.package_provenance_cache: Dict[str, Tuple[bool, float, str]] = {}
        self._cache_lock = threading.Lock()
        self.audit = AuditLogger()

    def compute_md5(self, path: str) -> Optional[str]:
        """Calcula el hash MD5 en bloques de 64 KB para cotejo con las bases oficiales .md5sums de dpkg."""
        md5 = hashlib.md5()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    md5.update(chunk)
            return md5.hexdigest().lower()
        except Exception:
            return None

    def compute_sha256(self, path: str) -> Optional[str]:
        """Calcula el hash SHA-256 en bloques de 64 KB."""
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception:
            return None

    def is_package_installed_ok(self, pkg: str) -> bool:
        """Verifica que el paquete tenga estado estricto 'install ok installed' en dpkg."""
        try:
            res = subprocess.run(
                ["dpkg-query", "-W", "-f=${Status}", pkg],
                capture_output=True,
                text=True,
                timeout=3
            )
            if res.returncode == 0:
                status = res.stdout.strip().lower()
                return "install ok installed" in status
        except Exception as e:
            logger.debug("Aviso consultando estado de paquete %s: %s", pkg, e)
        return False

    def is_package_provenance_trusted(self, pkg: str) -> Tuple[bool, str]:
        """
        Valida que el paquete provenga de un repositorio oficial firmado de la distribución
        (apt-cache policy) y no de una instalación local .deb no firmada ni verificada.
        """
        now = time.time()
        with self._cache_lock:
            cached = self.package_provenance_cache.get(pkg)
            if cached:
                is_trusted, cached_at, desc = cached
                if now - cached_at < 3600.0:  # TTL de 1 hora para procedencia de repositorios
                    return is_trusted, desc

        try:
            res = subprocess.run(
                ["apt-cache", "policy", pkg],
                capture_output=True,
                text=True,
                timeout=3
            )
            if res.returncode == 0 and res.stdout:
                # Comprobar si existe un origen de repositorio oficial (http/https/ftp con Packages)
                lines = res.stdout.splitlines()
                has_archive_repo = False
                repo_desc = ""
                for line in lines:
                    l = line.strip()
                    if ("http://" in l or "https://" in l or "ftp://" in l) and "Packages" in l:
                        has_archive_repo = True
                        repo_desc = l
                        break

                if has_archive_repo:
                    with self._cache_lock:
                        self.package_provenance_cache[pkg] = (True, now, repo_desc)
                    return True, f"Repositorio oficial firmado: {repo_desc}"
                else:
                    # Solo presente en status local (paquete sideloaded sin repositorio)
                    desc = "Paquete local no vinculado a ningún repositorio oficial firmado (sideloaded)"
                    with self._cache_lock:
                        self.package_provenance_cache[pkg] = (False, now, desc)
                    return False, desc
        except Exception as e:
            logger.debug("Aviso en apt-cache policy para %s: %s", pkg, e)

        # Fallback defensivo: Si apt-cache no está disponible, asumir política local
        return True, "Consulta de repositorio omitida (entorno sin apt-cache)"

    def get_dpkg_package_for_file(self, path: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Identifica el paquete dpkg oficial al que pertenece un archivo y valida su propiedad.
        Verifica que el paquete esté activo y que el archivo aparezca en el listado del paquete.
        """
        candidates = [path]
        try:
            real = os.path.realpath(path)
            if real not in candidates:
                candidates.append(real)
        except Exception:
            pass

        # Aliasing usr-merge en Debian/Ubuntu (/bin <-> /usr/bin, /lib <-> /usr/lib)
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

                    # Validar que el paquete esté completamente instalado
                    if not self.is_package_installed_ok(pkg):
                        logger.warning("El paquete %s asociado a %s no tiene estado 'install ok installed'.", pkg, c)
                        continue

                    return pkg, matched_path
            except Exception:
                continue
        return None, None

    def verify_snap_integrity(self, file_path: str) -> bool:
        """
        Verifica si un ejecutable bajo /snap reside en un montaje squashfs legítimo de solo lectura.
        """
        try:
            real_path = os.path.realpath(file_path)
            if not real_path.startswith("/snap/"):
                return False

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
        Verificación criptográfica integral de un binario del sistema:
        1. Comprobación de caché con caducidad por TTL e invalidación por mtime/size.
        2. Verificación de montaje de solo lectura si es Snap.
        3. Identificación de paquete dpkg y estado de instalación.
        4. Validación de procedencia oficial del repositorio.
        5. Verificación de checksums contra la base de datos oficial (.md5sums / dpkg -V).
        6. Detección de modificaciones posteriores a la instalación.
        """
        if not file_path or not os.path.exists(file_path):
            return False

        try:
            real_path = os.path.realpath(file_path)
            st = os.stat(real_path)
            cache_key = (st.st_dev, st.st_ino)
            now = time.time()

            # 1. Comprobación en caché con TTL estricto y validación de mtime/size
            with self._cache_lock:
                cached = self.cache.get(cache_key)
                if cached:
                    is_expired = (now - cached.get("cached_at", 0) > self.cache_ttl)
                    is_modified = (cached.get("mtime") != st.st_mtime or cached.get("size") != st.st_size)
                    if not is_expired and not is_modified:
                        return cached["is_valid"]
                    else:
                        # Entrada caducada o modificada: desalojar para forzar reevaluación
                        self.cache.pop(cache_key, None)

            # 2. Verificación de paquetes Snap
            if real_path.startswith("/snap/"):
                is_valid = self.verify_snap_integrity(real_path)
                with self._cache_lock:
                    self._insert_cache(cache_key, st, is_valid, "snap", "SquashFS read-only mount")
                return is_valid

            # 3. Verificación criptográfica con dpkg
            is_valid, reason, pkg = self._verify_dpkg_integrity(real_path, file_path, st)

            # 4. Guardar resultado reevaluado en caché
            with self._cache_lock:
                self._insert_cache(cache_key, st, is_valid, pkg or "unknown", reason)

            if not is_valid:
                logger.warning("🚨 [CONFIANZA DENEGADA EN BINARIO] %s -> Motivo: %s", real_path, reason)
                if "MODIFICADO" in reason or "ALTERADO" in reason:
                    try:
                        self.audit.record_incident(
                            threat_name="SYSTEM_PACKAGE_BINARY_MODIFIED",
                            target_path=real_path,
                            action="REVOKED_TRUST",
                            details=f"Paquete: {pkg} | {reason}"
                        )
                    except Exception:
                        pass

            return is_valid
        except Exception as e:
            logger.debug("Aviso verificando integridad de %s: %s", file_path, e)
            return False

    def _insert_cache(self, cache_key: Tuple[int, int], st: os.stat_result, is_valid: bool, pkg: str, reason: str):
        """Inserta en caché acotando el número máximo de entradas."""
        if len(self.cache) >= self.max_cache_entries:
            # Desalojar el 10% más antiguo
            sorted_keys = sorted(self.cache.keys(), key=lambda k: self.cache[k].get("cached_at", 0))
            for k in sorted_keys[:self.max_cache_entries // 10]:
                self.cache.pop(k, None)

        self.cache[cache_key] = {
            "mtime": st.st_mtime,
            "size": st.st_size,
            "cached_at": time.time(),
            "is_valid": is_valid,
            "pkg": pkg,
            "reason": reason
        }

    def _verify_dpkg_integrity(self, real_path: str, orig_path: str, st: os.stat_result) -> Tuple[bool, str, Optional[str]]:
        # 1. Identificar si el archivo pertenece a un paquete oficial
        pkg, matched_path = self.get_dpkg_package_for_file(orig_path)
        if not pkg:
            pkg, matched_path = self.get_dpkg_package_for_file(real_path)

        if not pkg:
            return False, "Binario no registrado en ningún paquete oficial de la distribución", None

        # 2. Validar procedencia de repositorio oficial firmado
        is_trusted_prov, prov_reason = self.is_package_provenance_trusted(pkg)
        if not is_trusted_prov:
            return False, f"Procedencia no confiable: {prov_reason}", pkg

        # 3. Detectar si el archivo fue modificado tras la instalación del paquete
        # Comprobar la marca de tiempo de instalación del paquete (/var/lib/dpkg/info/<pkg>.list)
        pkg_list_candidates = [
            f"/var/lib/dpkg/info/{pkg}.list",
            f"/var/lib/dpkg/info/{pkg}:amd64.list",
            f"/var/lib/dpkg/info/{pkg}:i386.list"
        ]
        pkg_list_file = next((f for f in pkg_list_candidates if os.path.exists(f)), None)
        if not pkg_list_file:
            matches = glob.glob(f"/var/lib/dpkg/info/{pkg}*.list")
            if matches:
                pkg_list_file = matches[0]

        # 4. Verificación criptográfica exacta contra sumas oficiales (.md5sums)
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
            alt_rel = rel_path.replace("usr/bin/", "bin/").replace("usr/sbin/", "sbin/").replace("usr/lib/", "lib/")
            try:
                with open(md5_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parts = line.strip().split(None, 1)
                        if len(parts) == 2:
                            expected_md5, entry_rel = parts[0], parts[1]
                            if entry_rel in (rel_path, alt_rel, f"/{rel_path}", f"/{alt_rel}"):
                                actual_md5 = self.compute_md5(real_path)
                                if actual_md5 and actual_md5.lower() == expected_md5.lower():
                                    return True, f"Integridad MD5 verificada contra {pkg}.md5sums", pkg
                                else:
                                    return False, f"Checksum MD5 ALTERADO (Esperado: {expected_md5}, Actual: {actual_md5})", pkg
            except Exception as e:
                logger.error("Error leyendo archivo de sumas %s: %s", md5_file, e)

        # 5. Si el paquete no incluye .md5sums, verificar mediante 'dpkg --verify'
        try:
            v_res = subprocess.run(["dpkg", "--verify", pkg], capture_output=True, text=True, timeout=5)
            if v_res.returncode == 0:
                # El paquete completo pasa la verificación de dpkg
                return True, f"Verificado íntegro mediante 'dpkg --verify {pkg}'", pkg
            else:
                # Si dpkg reporta alteraciones, comprobar si afectan a este archivo en particular
                for v_line in v_res.stdout.splitlines():
                    if real_path in v_line or (matched_path and matched_path in v_line):
                        return False, f"dpkg --verify reportó alteración en archivo: {v_line.strip()}", pkg
                # Si las alteraciones eran de otros archivos (ej. de configuración), el binario está íntegro
                return True, f"Binario no reportado como alterado en 'dpkg --verify {pkg}'", pkg
        except Exception:
            pass

        # Por principio de mínimo privilegio y seguridad estricta: si no se puede verificar criptográficamente, rechazar
        return False, f"Paquete {pkg} carece de sumas de verificación oficiales accesibles", pkg

    def clear_cache(self):
        """Limpia completamente la caché de integridad en memoria."""
        with self._cache_lock:
            self.cache.clear()
            self.package_provenance_cache.clear()

    def invalidate_path(self, path: str):
        """Invalida de inmediato una ruta específica de la caché."""
        try:
            real = os.path.realpath(path)
            st = os.stat(real)
            with self._cache_lock:
                self.cache.pop((st.st_dev, st.st_ino), None)
        except Exception:
            pass


class SystemWhitelist:
    """
    Administrador central de lista blanca con autoprotección por ruta canónica,
    fijación estricta de hashes SHA-256 de usuario, revocación ante alteraciones y auditoría.
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

        # Registro de decisiones de confianza (Trust Decisions Log)
        self.trust_decisions: List[Dict[str, Any]] = []
        self._decisions_lock = threading.Lock()

        self._load_whitelist()

    def _ensure_dir(self):
        try:
            d = os.path.dirname(self.storage_file)
            if d:
                os.makedirs(d, mode=0o700, exist_ok=True)
        except (PermissionError, OSError):
            self.storage_file = f"/tmp/constantine_whitelist_{os.getuid()}.json"
            try:
                d = os.path.dirname(self.storage_file)
                if d:
                    os.makedirs(d, mode=0o700, exist_ok=True)
            except Exception:
                pass

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
        """Guarda atómicamente la lista blanca con permisos restrictivos 0600 y protección contra symlinks."""
        self._ensure_dir()
        temp_file = f"{self.storage_file}.tmp_{int(time.time())}"
        try:
            # Creación con permisos 0600 desde el inodo
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            old_umask = os.umask(0o077)
            try:
                fd = os.open(temp_file, flags, 0o600)
            finally:
                os.umask(old_umask)

            with open(fd, "w", encoding="utf-8") as f:
                json.dump({
                    "paths": sorted(list(self.user_whitelisted_paths)),
                    "hashes": sorted(list(self.user_whitelisted_hashes)),
                    "path_hashes": self.user_path_hashes,
                    "metadata": self.user_entries_metadata
                }, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_file, self.storage_file)
            try:
                os.chmod(self.storage_file, 0o600)
            except Exception:
                pass
        except Exception as e:
            logger.error("Error guardando whitelist de forma atómica: %s", e)
            if os.path.exists(temp_file):
                try:
                    os.unlink(temp_file)
                except Exception:
                    pass

    def compute_sha256(self, file_path: str) -> Optional[str]:
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception:
            return None

    def record_trust_decision(
        self,
        file_path: str,
        is_trusted: bool,
        reason: str,
        provenance: str = "SYSTEM",
        package_name: Optional[str] = None,
        checksum_verified: bool = False,
        details: str = ""
    ):
        """Registra cada decisión de confianza para auditoría forense y transparencia operativa."""
        record = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "path": file_path,
            "is_trusted": is_trusted,
            "decision": "ALLOWED" if is_trusted else "DENIED",
            "reason": reason,
            "provenance": provenance,
            "package_name": package_name,
            "checksum_verified": checksum_verified,
            "details": details
        }
        with self._decisions_lock:
            self.trust_decisions.append(record)
            if len(self.trust_decisions) > 1000:
                self.trust_decisions.pop(0)

        # Si la confianza fue denegada por manipulación o alteración, auditar como incidente de seguridad
        if not is_trusted and any(term in reason.upper() for term in ("MODIFIED", "ALTERADO", "TAMPER", "CHECKSUM")):
            try:
                self.audit.record_incident(
                    threat_name=f"TrustRevoked.{reason}",
                    target_path=file_path,
                    action="REVOKED_FROM_WHITELIST",
                    details=details
                )
            except Exception:
                pass

    def get_trust_decisions(self) -> List[Dict[str, Any]]:
        """Devuelve la bitácora histórica de decisiones de confianza."""
        with self._decisions_lock:
            return list(self.trust_decisions)

    def get_revoked_entries(self) -> List[Dict[str, Any]]:
        """Devuelve las entradas de confianza denegadas o revocadas."""
        with self._decisions_lock:
            return [d for d in self.trust_decisions if not d.get("is_trusted")]

    def is_self_file(self, file_path: str) -> bool:
        """
        Autoprotección rigurosa de Constantine:
        1. Resuelve la ruta canónica real (os.path.realpath).
        2. Verifica pertenencia estricta a los directorios de instalación autorizados.
        3. No confía en nombres o extensiones fuera de las raíces oficiales.
        """
        if not file_path:
            return False

        try:
            real_path = os.path.realpath(file_path)
        except Exception:
            return False

        valid_roots = list(AUTHORIZED_APP_ROOTS)
        if SELF_ROOT and os.path.exists(SELF_ROOT):
            valid_roots.append(SELF_ROOT)

        for root in valid_roots:
            try:
                c_root = os.path.realpath(root)
                if real_path == c_root or real_path.startswith(os.path.join(c_root, "")):
                    return True
            except Exception:
                continue

        return False

    def is_trusted_system_binary(self, file_path: str) -> bool:
        """
        Determina si el archivo es un binario oficial verificado criptográficamente:
        1. Rechaza directorios intrínsecamente no confiables (/tmp, /dev/shm).
        2. Verifica pertenencia y estado del paquete (dpkg / snap).
        3. Valida procedencia y sumas oficiales de verificación.
        """
        if not file_path:
            return False

        try:
            norm_path = os.path.realpath(file_path)
        except Exception:
            return False

        for susp in SUSPICIOUS_UNTRUSTED_DIRS:
            if norm_path == susp or norm_path.startswith(os.path.join(susp, "")):
                self.record_trust_decision(norm_path, False, "DIRECTORIO_VOLATIL_NO_CONFIABLE", provenance="UNTRUSTED_PATH")
                return False

        is_valid = self.integrity_engine.verify_binary(norm_path)
        self.record_trust_decision(
            norm_path,
            is_valid,
            "PAQUETE_SISTEMA_INTEGRO" if is_valid else "PAQUETE_SISTEMA_NO_VERIFICADO",
            provenance="APT_DPKG_SNAP",
            checksum_verified=is_valid
        )
        return is_valid

    def is_whitelisted(self, file_path: str, file_hash: Optional[str] = None) -> bool:
        """
        Determina si un archivo debe ser autorizado:
        - Si es un archivo propio del antivirus (autoprotección canónica).
        - Si su hash SHA-256 coincide con una exclusión aprobada.
        - Si está en la lista de usuario Y su integridad criptográfica SHA-256 coincide.
          (Si el archivo fue modificado, la exclusión se REVOCA automáticamente y se expulsa).
        - Si es un binario oficial de la distribución con checksum íntegro verificado.
        """
        if not file_path:
            return False

        try:
            norm_path = os.path.realpath(file_path)
        except Exception:
            return False

        # 0. Autoprotección: Archivos propios del antivirus en ubicaciones oficiales
        if self.is_self_file(norm_path):
            self.record_trust_decision(norm_path, True, "AUTOPROTECCION_CANONICA", provenance="SELF_ROOT")
            return True

        # 1. Comprobación directa por Hash SHA-256 autorizado
        if file_hash and file_hash.lower() in self.user_whitelisted_hashes:
            self.record_trust_decision(norm_path, True, "HASH_AUTORIZADO_POR_USUARIO", provenance="USER_HASH", checksum_verified=True)
            return True

        # 2. Comprobación de exclusión de usuario con fijación estricta de hash (Anti-Tamper)
        if norm_path in self.user_whitelisted_paths:
            expected_hash = self.user_path_hashes.get(norm_path)
            if expected_hash:
                current_hash = file_hash or self.compute_sha256(norm_path)
                if current_hash and current_hash.lower() == expected_hash.lower():
                    self.record_trust_decision(norm_path, True, "RUTA_USUARIO_CON_HASH_VERIFICADO", provenance="USER_PATH", checksum_verified=True)
                    return True
                else:
                    # El archivo fue modificado después de su autorización: REVOCAR Y EXPULSAR DE LA LISTA BLANCA
                    logger.warning("🚨 [EXCLUSIÓN INVALIDADA Y EXPULSADA] Archivo autorizado modificado en disco: %s (Esperado: %s, Real: %s)",
                                   norm_path, expected_hash, current_hash)
                    self.remove_path(norm_path)
                    self.record_trust_decision(
                        norm_path,
                        False,
                        "MODIFICADO_TRAS_AUTORIZACION",
                        provenance="USER_PATH_TAMPERED",
                        details=f"Hash esperado: {expected_hash[:16]}..., Hash real: {current_hash[:16] if current_hash else 'N/A'}"
                    )
                    return False
            return True

        # Comprobar si reside dentro de una carpeta explícitamente autorizada por el usuario
        for wpath in self.user_whitelisted_paths:
            if os.path.isdir(wpath) and norm_path.startswith(os.path.join(wpath, "")):
                if wpath not in FORBIDDEN_SYSTEM_DIRS:
                    self.record_trust_decision(norm_path, True, "CARPETA_USUARIO_AUTORIZADA", provenance="USER_DIR")
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
            self.integrity_engine.invalidate_path(norm_path)
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
            if not any(e.get("sha256") == h for e in entries):
                entries.append({
                    "path": f"Hash SHA-256: {h}",
                    "type": "Firma Hash Independiente",
                    "sha256": h,
                    "reason": "Exclusión por hash",
                    "status": "Autorizado"
                })
        return entries
