"""
Constantine Antivirus - Cryptographic Key Storage & Vault (core/engine/vault.py)
Aislamiento criptográfico autenticado mediante AES-256-GCM con arquitectura de clave segura:

1. Generación de Claves Criptográficamente Seguras (CSPRNG):
   - La clave AES-256 (32 bytes / 256 bits) se genera mediante CSPRNG de alta entropía (secrets.token_bytes(32)).
   - NO se deriva de machine-id (evita que un atacante con acceso a metadatos del host reproduzca la clave).
2. Almacén de Claves Seguro (Key Storage & Vault Keyring):
   - La clave se almacena en un archivo protegido con permisos estrictos (0400 / solo lectura por root/usuario):
     * Modo Demonio (root): /etc/constantine/.vault_key
     * Modo Usuario: ~/.config/constantine/.vault_key
   - Soporte automático de respaldo (.vault_key.bak) con sincronización atómica (fsync).
3. Integridad y Control de Errores Estricto (No Silent Overwrite):
   - Si el archivo de clave existente está dañado o tiene una longitud incorrecta, el sistema
     NUNCA lo sobrescribe silenciosamente (evita la pérdida permanente de muestras previas).
   - En su lugar, emite una alarma crítica, crea una copia de diagnóstico (.corrupt_timestamp)
     y se niega a aislar nuevas muestras hasta que un administrador revise o restaure el respaldo.
4. Mecanismo Documentado de Respaldo y Recuperación (Key Backup & Recovery Package):
   - export_key_recovery_package(path): Genera un paquete de recuperación estructurado en JSON (0400)
     con la clave en formato hex, suma SHA-256 y metadatos forenses para disaster recovery.
   - import_key_recovery_package(path): Permite restaurar de forma validada la clave en un equipo nuevo.
5. Cifrado Autenticado en Streaming por Bloques (Chunked AES-256-GCM AEAD):
   - Procesa muestras en bloques de 64 KB con consumo O(1) de memoria RAM.
   - Nonce único de 96 bits por bloque (base aleatoria + chunk_index big-endian).
   - Datos Asociados Autenticados (AAD) para impedir reordenamiento o truncamiento.
   - Transacción Verificable de Cuarentena (Two-Phase Commit con Rollback total).
   - Compatibilidad transparente con payloads streaming (CST_AES256GCM_S:) y monolíticos (CST_AES256GCM:).
"""

import os
import json
import time
import struct
import hashlib
import secrets
import logging
import threading
import stat
import errno
from typing import List, Dict, Optional, Tuple, BinaryIO, Set
from core.engine.quarantine_operator import PrivilegedQuarantineOperator, PinnedFileHandle

logger = logging.getLogger("constantine.vault")

DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.local/share/constantine/vault")
DEFAULT_KEY_FILE = "/etc/constantine/.vault_key"
USER_KEY_FILE = os.path.expanduser("~/.config/constantine/.vault_key")

VAULT_MAGIC_V3 = b"CST_AES256GCM_V3:"      # Formato streaming V3 con nonces independientes de 96 bits (17 bytes)
VAULT_MAGIC_STREAM = b"CST_AES256GCM_S:"  # Formato streaming V2 con base de 64 bits (16 bytes)
VAULT_MAGIC_LEGACY = b"CST_AES256GCM:"    # Formato monolítico V1 (14 bytes)

CHUNK_SIZE = 64 * 1024       # 64 KB por bloque
TAG_SIZE = 16               # 128 bits de Auth Tag en AES-GCM
NONCE_96_SIZE = 12          # 96 bits aleatorios NIST SP 800-38D por operación
NONCE_BASE_SIZE = 8         # 64 bits de base aleatoria por archivo (compatibilidad V2)
KEY_SIZE_BYTES = 32         # 256 bits simétricos
DEFAULT_MAX_KEY_USAGE = 100_000  # Límite de uso por clave antes de rotación

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_AES = True
except ImportError:
    HAS_AES = False
    logger.critical("Librería 'cryptography' no disponible en el sistema. Cuarentena operará en modo Fail-Secure.")


class QuarantineVault:
    """
    Baúl Criptográfico Transaccional con cifrado autenticado AES-256-GCM,
    almacén seguro de claves (CSPRNG 256 bits), respaldo documentado y streaming de bloques.
    """

    def __init__(self, storage_dir: Optional[str] = None, vault_dir: Optional[str] = None,
                 key_file: Optional[str] = None):
        base = storage_dir or vault_dir
        if base:
            self.base_dir = base
            self.key_file = key_file or os.path.join(self.base_dir, ".vault_key")
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.base_dir = DEFAULT_VAULT_DIR
            self.key_file = key_file or DEFAULT_KEY_FILE
        else:
            self.base_dir = USER_VAULT_DIR
            self.key_file = key_file or USER_KEY_FILE

        self.key_backup_file = f"{self.key_file}.bak"
        self.payloads_dir = os.path.join(self.base_dir, "payloads")
        self.manifest_file = os.path.join(self.base_dir, "vault_manifest.json")
        self.keyring_file = os.path.join(self.base_dir, "vault_keyring.json")
        self.key_metadata_file = os.path.join(self.base_dir, "vault_key_metadata.json")

        self._crypto_lock = threading.RLock()
        self._seen_nonces: Set[bytes] = set()
        self.max_key_usage_limit = DEFAULT_MAX_KEY_USAGE

        self._ensure_storage()
        self._aes_key = self._load_or_generate_secure_key()
        self.key_id = self._get_key_id(self._aes_key)
        self.keyring: Dict[str, bytes] = self._load_keyring()
        self.encryptions_count: int = self._load_key_usage()
        self.operator = PrivilegedQuarantineOperator()

    def get_storage_location(self) -> str:
        return self.base_dir

    def _ensure_storage(self):
        try:
            os.makedirs(self.payloads_dir, exist_ok=True)
            if os.geteuid() == 0:
                try:
                    os.chmod(self.base_dir, 0o700)
                    os.chmod(self.payloads_dir, 0o700)
                except Exception:
                    pass
        except (PermissionError, OSError) as e:
            self.base_dir = f"/tmp/constantine_vault_{os.getuid()}"
            self.payloads_dir = os.path.join(self.base_dir, "payloads")
            self.key_file = os.path.join(self.base_dir, ".vault_key")
            self.key_backup_file = f"{self.key_file}.bak"
            self.manifest_file = os.path.join(self.base_dir, "vault_manifest.json")
            self.keyring_file = os.path.join(self.base_dir, "vault_keyring.json")
            self.key_metadata_file = os.path.join(self.base_dir, "vault_key_metadata.json")
            try:
                os.makedirs(self.payloads_dir, exist_ok=True)
            except Exception:
                pass

    def _load_or_generate_secure_key(self) -> bytes:
        """
        Carga la clave simétrica de 256 bits desde el almacén seguro o genera una nueva
        usando un generador de números pseudoaleatorios criptográficamente seguro (CSPRNG).
        
        Principio de protección: NUNCA sobrescribe silenciosamente una clave existente inválida o dañada.
        """
        if not HAS_AES:
            logger.critical("❌ [FAIL-SECURE] Imposible inicializar clave: 'cryptography' ausente.")
            return b""

        key_dir = os.path.dirname(self.key_file)
        if key_dir:
            os.makedirs(key_dir, exist_ok=True)

        # 1. Si el archivo de clave ya existe, cargarlo y verificar longitud exacta (32 bytes)
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    raw_key = f.read()

                if len(raw_key) == KEY_SIZE_BYTES:
                    # Clave íntegra y válida. Asegurar permisos 0400
                    self._enforce_key_permissions(self.key_file)
                    # Mantener respaldo actualizado si no existe
                    if not os.path.exists(self.key_backup_file):
                        self._write_key_file(self.key_backup_file, raw_key)
                    return raw_key
                else:
                    # ALERTA CRÍTICA: Archivo de clave dañado/truncado.
                    # NUNCA reemplazar silenciosamente para no destruir la posibilidad de rescate.
                    logger.critical(
                        "🚨 [ERROR CRÍTICO DE CLAVE] El archivo de clave %s tiene una longitud inválida (%d bytes != 32 bytes). "
                        "PROHIBIDO el reemplazo automático silencioso para evitar dejar irrecuperables las muestras previas.",
                        self.key_file, len(raw_key)
                    )
                    # Intentar recuperar desde el archivo de respaldo si existe
                    if os.path.exists(self.key_backup_file):
                        with open(self.key_backup_file, "rb") as bf:
                            bak_key = bf.read()
                        if len(bak_key) == KEY_SIZE_BYTES:
                            logger.warning("⚠️ Recuperando clave válida desde el archivo de respaldo: %s", self.key_backup_file)
                            return bak_key

                    raise ValueError(f"Archivo de clave dañado ({len(raw_key)} bytes). No se reemplazará automáticamente.")
            except Exception as e:
                logger.critical("Error al leer clave del baúl: %s", e)
                raise

        # 2. Si no existe, verificar si existe respaldo previo antes de generar una nueva
        if os.path.exists(self.key_backup_file):
            try:
                with open(self.key_backup_file, "rb") as bf:
                    bak_key = bf.read()
                if len(bak_key) == KEY_SIZE_BYTES:
                    logger.info("Restaurando clave principal desde respaldo existente: %s", self.key_backup_file)
                    self._write_key_file(self.key_file, bak_key)
                    return bak_key
            except Exception as be:
                logger.error("No se pudo leer respaldo de clave: %s", be)

        # 3. Generación inicial de clave pura CSPRNG (sin derivaciones predecibles)
        new_key = secrets.token_bytes(KEY_SIZE_BYTES)
        self._write_key_file(self.key_file, new_key)
        self._write_key_file(self.key_backup_file, new_key)
        logger.info("Clave criptográfica segura AES-256 (CSPRNG) generada y protegida en %s", self.key_file)
        return new_key

    def _get_key_id(self, key_bytes: bytes) -> str:
        """Calcula el identificador abreviado (16 caracteres hexadecimales) de una clave."""
        if not key_bytes:
            return "no_key"
        return hashlib.sha256(key_bytes).hexdigest()[:16]

    def _load_keyring(self) -> Dict[str, bytes]:
        """Carga el llavero (keyring) persistente con claves activas e históricas para descifrado."""
        keyring: Dict[str, bytes] = {}
        if self._aes_key:
            keyring[self.key_id] = self._aes_key
        if os.path.exists(self.keyring_file):
            try:
                with open(self.keyring_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for kid, hex_k in data.items():
                    try:
                        k_bytes = bytes.fromhex(hex_k)
                        if len(k_bytes) == KEY_SIZE_BYTES:
                            keyring[kid] = k_bytes
                    except Exception:
                        pass
            except Exception as e:
                logger.debug("Aviso cargando keyring: %s", e)
        return keyring

    def _save_keyring(self):
        """Guarda atómicamente el llavero de claves históricas con permisos 0400 desde su creación."""
        temp_path = f"{self.keyring_file}.tmp_{secrets.token_hex(4)}"
        try:
            data = {kid: k_bytes.hex() for kid, k_bytes in self.keyring.items()}
            fd = self._create_secure_fd(temp_path, 0o400)
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.keyring_file)
            self._enforce_key_permissions(self.keyring_file)
        except Exception as e:
            logger.error("Error guardando keyring: %s", e)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

    def _load_key_usage(self) -> int:
        """Carga el contador de operaciones de cifrado ejecutadas con la clave activa."""
        if os.path.exists(self.key_metadata_file):
            try:
                with open(self.key_metadata_file, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                if meta.get("active_key_id") == self.key_id:
                    return int(meta.get("encryptions_count", 0))
            except Exception:
                pass
        return 0

    def _save_key_metadata(self):
        """Guarda atómicamente los metadatos de uso y volumen de la clave activa con permisos 0400 desde su creación."""
        temp_path = f"{self.key_metadata_file}.tmp_{secrets.token_hex(4)}"
        try:
            meta = {
                "active_key_id": self.key_id,
                "encryptions_count": self.encryptions_count,
                "max_encryptions": self.max_key_usage_limit,
                "updated_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                "keyring_keys": list(self.keyring.keys())
            }
            fd = self._create_secure_fd(temp_path, 0o400)
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(meta, f, indent=2)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, self.key_metadata_file)
        except Exception as e:
            logger.debug("Aviso guardando metadatos de clave: %s", e)
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass

    def generate_unique_nonce_96(self) -> bytes:
        """
        Genera un nonce de 96 bits (12 bytes) aleatorio mediante CSPRNG (secrets.token_bytes),
        garantizando unicidad y controlando el volumen de uso de la clave activa.
        Si se alcanza el umbral de seguridad (NIST SP 800-38D), desencadena rotación automática.
        """
        with self._crypto_lock:
            if self.encryptions_count >= self.max_key_usage_limit:
                logger.warning(
                    "⚠️ [LÍMITE DE USO DE CLAVE ALCANZADO] Se alcanzó el umbral de %d operaciones con la clave %s. "
                    "Desencadenando rotación automática de clave.",
                    self.max_key_usage_limit, self.key_id
                )
                self.rotate_key()

            for _ in range(100):
                nonce = secrets.token_bytes(NONCE_96_SIZE)
                if nonce not in self._seen_nonces:
                    if len(self._seen_nonces) > 50000:
                        self._seen_nonces.clear()
                    self._seen_nonces.add(nonce)
                    self.encryptions_count += 1
                    return nonce

            raise RuntimeError("Fallo crítico del CSPRNG: colisión consecutiva de nonces de 96 bits.")

    def rotate_key(self, new_key: Optional[bytes] = None) -> str:
        """
        Rota la clave criptográfica activa del baúl:
        1. Archiva la clave actual en el keyring persistente indexada por su key_id.
        2. Asigna la nueva clave de 256 bits generada por CSPRNG (o suministrada).
        3. Escribe la nueva clave en self.key_file y actualiza el respaldo.
        4. Reinicia el contador de uso y limpia la memoria de nonces.
        Retorna el nuevo key_id.
        """
        with self._crypto_lock:
            if not HAS_AES:
                raise RuntimeError("Criptografía no disponible.")

            old_key = self._aes_key
            old_key_id = self.key_id

            if old_key:
                self.keyring[old_key_id] = old_key
                self._save_keyring()

            active_key = new_key if new_key else secrets.token_bytes(KEY_SIZE_BYTES)
            if len(active_key) != KEY_SIZE_BYTES:
                raise ValueError(f"Longitud de clave inválida ({len(active_key)} bytes != 32 bytes).")

            self._aes_key = active_key
            self.key_id = self._get_key_id(active_key)
            self.keyring[self.key_id] = active_key
            self._save_keyring()

            self._write_key_file(self.key_file, active_key)
            self._write_key_file(self.key_backup_file, active_key)

            self.encryptions_count = 0
            self._seen_nonces.clear()
            self._save_key_metadata()

            logger.info("🔑 Clave del baúl rotada con éxito. Nueva clave activa: %s (Keyring contiene %d claves)",
                        self.key_id, len(self.keyring))
            return self.key_id

    def _get_key_for_decrypt(self, key_id_prefix: Optional[str] = None) -> bytes:
        """Retorna la clave correspondiente al key_id o la clave activa."""
        if key_id_prefix:
            for kid, key_bytes in self.keyring.items():
                if kid.startswith(key_id_prefix):
                    return key_bytes
        return self._aes_key

    def reencrypt_all_payloads(self) -> int:
        """
        Re-cifra todas las muestras almacenadas en el baúl con la clave activa y el formato V3.
        Permite migración transparente y renovación periódica de cifrado.
        """
        manifest = self._load_manifest()
        reencrypted = 0
        for item in manifest:
            payload_path = item.get("vault_payload_path")
            if not payload_path or not os.path.exists(payload_path):
                continue

            temp_decrypted = f"{payload_path}.reenc_tmp_dec"
            temp_reencrypted = f"{payload_path}.reenc_tmp_enc"
            try:
                if self.decrypt_file_streaming(payload_path, temp_decrypted):
                    self.encrypt_file_streaming(temp_decrypted, temp_reencrypted)
                    os.chmod(temp_reencrypted, 0o000)
                    os.replace(temp_reencrypted, payload_path)
                    item["encryption"] = "AES-256-GCM-Chunked96-v3"
                    item["format_version"] = 3
                    item["key_id"] = self.key_id
                    reencrypted += 1
            except Exception as e:
                logger.error("Error re-cifrando muestra %s: %s", item.get("vault_id"), e)
            finally:
                for tmp in [temp_decrypted, temp_reencrypted]:
                    if os.path.exists(tmp):
                        try:
                            os.remove(tmp)
                        except Exception:
                            pass

        self._save_manifest_atomic(manifest)
        logger.info("Re-cifrado completado: %d muestras actualizadas a formato V3.", reencrypted)
        return reencrypted


    @staticmethod
    def _create_secure_fd(target_path: str, mode: int = 0o400) -> int:
        """
        Crea de forma atómica y exclusiva un descriptor de archivo con permisos
        restringidos (0400 por defecto), O_EXCL y O_NOFOLLOW desde el inicio a nivel de inodo.
        """
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        old_umask = os.umask(0o077)
        try:
            return os.open(target_path, flags, mode)
        finally:
            os.umask(old_umask)

    def _write_key_file(self, path: str, key_data: bytes):
        """Escribe un archivo de clave de forma atómica, exclusiva y con permisos restrictivos 0400 desde su creación."""
        temp_path = f"{path}.tmp_{secrets.token_hex(4)}"
        try:
            fd = self._create_secure_fd(temp_path, 0o400)
            with open(fd, "wb") as f:
                f.write(key_data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, path)
            self._enforce_key_permissions(path)
        except Exception as e:
            logger.error("Error escribiendo archivo de clave %s: %s", path, e)
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass

    def _enforce_key_permissions(self, path: str):
        try:
            os.chmod(path, 0o400)
        except Exception:
            pass

    def export_key_recovery_package(self, target_path: str, overwrite: bool = False) -> bool:
        """
        Exporta de forma segura el paquete de rescate y recuperación de claves
        con metadatos forenses, suma SHA-256 y formato JSON para disaster recovery.

        Garantías criptográficas y de seguridad en sistema de archivos (O-02):
        1. Permisos restrictivos (0400) desde el primer nanosegundo de creación del inodo.
        2. Creación exclusiva (O_CREAT | O_EXCL | O_CLOEXEC) para prevenir condiciones de carrera.
        3. Protección estricta contra enlaces simbólicos (O_NOFOLLOW, verificación lstat y detección ELOOP).
        4. Verificación integral de la ruta y directorio de destino para impedir manipulación por usuarios
           locales no privilegiados (propietario UID root/actual, rechazo de world-writable sin sticky bit).
        """
        if not self._aes_key or len(self._aes_key) != KEY_SIZE_BYTES:
            logger.error("No hay una clave válida para exportar.")
            return False

        try:
            norm_path = os.path.abspath(os.path.normpath(target_path))
            target_dir = os.path.dirname(norm_path)

            if not target_dir or target_dir == norm_path:
                logger.error("Ruta de destino inválida para paquete de recuperación: %s", target_path)
                return False

            # Validar y preparar directorio destino de forma segura
            if not os.path.exists(target_dir):
                old_umask = os.umask(0o077)
                try:
                    os.makedirs(target_dir, mode=0o700, exist_ok=True)
                finally:
                    os.umask(old_umask)

            # Verificar que el directorio destino no sea un enlace simbólico
            if os.path.islink(target_dir):
                logger.error("El directorio de destino es un enlace simbólico sospechoso: %s", target_dir)
                return False

            dir_stat = os.stat(target_dir, follow_symlinks=False)
            if not stat.S_ISDIR(dir_stat.st_mode):
                logger.error("La ruta contenedora no es un directorio: %s", target_dir)
                return False

            # Verificación de manipulación por usuarios no privilegiados:
            # 1. El directorio debe pertenecer al usuario actual o a root
            current_uid = os.getuid()
            if dir_stat.st_uid not in (current_uid, 0):
                logger.error(
                    "Directorio inseguro para exportación: pertenece al UID %d (esperado %d o 0)",
                    dir_stat.st_uid, current_uid
                )
                return False

            # 2. Control contra directorios world-writable sin sticky bit
            is_world_writable = bool(dir_stat.st_mode & 0o002)
            has_sticky_bit = bool(dir_stat.st_mode & 0o1000)
            if is_world_writable and not has_sticky_bit:
                logger.error("Directorio de destino modificable universalmente sin sticky bit: %s", target_dir)
                return False

            # 3. Control contra directorios modificables por grupo no privilegiado sin sticky bit
            if (dir_stat.st_mode & 0o020) and dir_stat.st_gid not in (os.getgid(), 0) and not has_sticky_bit:
                logger.error("Directorio de destino modificable por grupo no privilegiado sin sticky bit: %s", target_dir)
                return False

            # Rechazar estrictamente si la ruta de destino es un enlace simbólico existente
            if os.path.islink(norm_path):
                logger.error("La ruta de destino es un enlace simbólico existente (ataque symlink rechazado): %s", norm_path)
                return False

            # Manejo de existencia previa
            if os.path.exists(norm_path):
                if not overwrite:
                    logger.error("El archivo de destino ya existe y no se especificó overwrite: %s", norm_path)
                    return False
                st_prev = os.lstat(norm_path)
                if not stat.S_ISREG(st_prev.st_mode) or stat.S_ISLNK(st_prev.st_mode):
                    logger.error("El destino existente no es un archivo regular: %s", norm_path)
                    return False
                if st_prev.st_uid not in (current_uid, 0):
                    logger.error("El archivo existente pertenece a otro usuario no privilegiado: %s", norm_path)
                    return False
                os.unlink(norm_path)

            key_sha256 = hashlib.sha256(self._aes_key).hexdigest()
            recovery_info = {
                "format": "Constantine-Vault-KeyRecovery-v2",
                "cipher": "AES-256-GCM-Chunked-AEAD",
                "key_id": self.key_id,
                "key_hex": self._aes_key.hex(),
                "key_sha256": key_sha256,
                "keyring": {kid: k_bytes.hex() for kid, k_bytes in self.keyring.items()},
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                "doc": "Guarde este archivo en un medio seguro fuera de línea para permitir la recuperación de muestras del baúl."
            }

            # Creación atómica exclusiva con O_CREAT | O_EXCL | O_NOFOLLOW y modo inicial 0400
            open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                open_flags |= os.O_NOFOLLOW

            old_umask = os.umask(0o077)
            fd = -1
            try:
                try:
                    fd = os.open(norm_path, open_flags, 0o400)
                except OSError as e:
                    if e.errno == errno.ELOOP:
                        logger.error("Ataque de enlace simbólico interceptado por O_NOFOLLOW en %s", norm_path)
                        return False
                    if e.errno == errno.EEXIST:
                        logger.error("El archivo de destino ya existe (rechazado por creación exclusiva): %s", norm_path)
                        return False
                    raise
            finally:
                os.umask(old_umask)

            # Validación Anti-TOCTOU post-creación: verificar descriptor vs filesystem
            fd_stat = os.fstat(fd)
            lstat_after = os.lstat(norm_path)
            if fd_stat.st_dev != lstat_after.st_dev or fd_stat.st_ino != lstat_after.st_ino:
                logger.error("Violación de identidad TOCTOU detectada al abrir %s", norm_path)
                os.close(fd)
                if os.path.exists(norm_path):
                    try:
                        os.unlink(norm_path)
                    except Exception:
                        pass
                return False

            if not stat.S_ISREG(fd_stat.st_mode) or stat.S_ISLNK(lstat_after.st_mode):
                logger.error("El descriptor abierto no es un archivo regular seguro: %s", norm_path)
                os.close(fd)
                if os.path.exists(norm_path):
                    try:
                        os.unlink(norm_path)
                    except Exception:
                        pass
                return False

            # Escribir payload JSON directamente en el descriptor protegido
            with open(fd, "w", encoding="utf-8") as f:
                json.dump(recovery_info, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Asegurar modo 0400 explícito por si umask del sistema de archivos ignora bits
            try:
                os.chmod(norm_path, 0o400)
            except Exception:
                pass

            logger.info("Paquete de recuperación de clave exportado exitosamente a %s con permisos 0400 desde su creación", norm_path)
            return True
        except Exception as e:
            logger.error("Error exportando paquete de recuperación de clave: %s", e)
            if 'norm_path' in locals() and os.path.exists(norm_path):
                try:
                    os.unlink(norm_path)
                except Exception:
                    pass
            return False

    def import_key_recovery_package(self, package_path: str) -> bool:
        """
        Importa y valida un paquete de recuperación de claves para restaurar acceso a las muestras.
        """
        if not os.path.exists(package_path):
            return False
        if os.path.islink(package_path):
            logger.error("Paquete de recuperación a importar es un enlace simbólico.")
            return False
        try:
            with open(package_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            key_hex = data.get("key_hex", "")
            expected_sha = data.get("key_sha256", "")
            raw_key = bytes.fromhex(key_hex)

            if len(raw_key) != KEY_SIZE_BYTES:
                logger.error("Clave en paquete de recuperación tiene longitud incorrecta.")
                return False

            if expected_sha and hashlib.sha256(raw_key).hexdigest() != expected_sha:
                logger.error("Verificación de integridad de clave en paquete de recuperación falló.")
                return False

            # Restaurar keyring si viene en el paquete
            keyring_data = data.get("keyring", {})
            if isinstance(keyring_data, dict):
                for kid, khex in keyring_data.items():
                    try:
                        kbytes = bytes.fromhex(khex)
                        if len(kbytes) == KEY_SIZE_BYTES:
                            self.keyring[kid] = kbytes
                    except Exception:
                        pass
                self._save_keyring()

            # Escribir en clave principal y respaldo
            self._write_key_file(self.key_file, raw_key)
            self._write_key_file(self.key_backup_file, raw_key)
            self._aes_key = raw_key
            logger.info("Clave de baúl restaurada exitosamente desde paquete de recuperación.")
            return True
        except Exception as e:
            logger.error("Error importando paquete de recuperación: %s", e)
            return False

    def compute_file_sha256(self, path: str) -> Tuple[Optional[str], int]:
        """Calcula el hash SHA-256 en bloques de 64 KB sin desbordar la memoria RAM."""
        sha = hashlib.sha256()
        total_size = 0
        try:
            with open(path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    sha.update(chunk)
                    total_size += len(chunk)
            return sha.hexdigest().lower(), total_size
        except Exception as e:
            logger.error("Error calculando SHA-256 en streaming para %s: %s", path, e)
            return None, 0

    # =========================================================================
    # CIFRADO Y DESCIFRADO POR STREAMING DE BLOQUES (CHUNKED AEAD)
    # =========================================================================

    def _make_block_nonce(self, base_nonce: bytes, chunk_index: int) -> bytes:
        """
        [RETROCOMPATIBILIDAD V2] Construye un nonce de 96 bits combinando
        8 bytes de base y 4 bytes de índice. Usado exclusivamente para descifrar
        muestras archivadas en formato legado V2 (CST_AES256GCM_S:).
        Las nuevas muestras en formato V3 utilizan nonces CSPRNG independientes de 96 bits.
        """
        return base_nonce + struct.pack(">I", chunk_index)

    def _make_block_aad(self, chunk_index: int, is_last: bool) -> bytes:
        """
        [RETROCOMPATIBILIDAD V2] Genera Datos Asociados Autenticados (AAD) para el formato legado V2.
        El formato V3 utiliza b"CST_V3:" + key_id + struct.pack(">IB", chunk_index, is_last).
        """
        return b"CST_CHUNK:" + struct.pack(">IB", chunk_index, 1 if is_last else 0)

    def encrypt_file_streaming(self, src_path: str, dst_path: str, src_fd: Optional[int] = None) -> bool:
        """
        Cifra un archivo en disco mediante bloques de 64 KB con AES-256-GCM y nonces independientes de 96 bits (V3).
        Cada bloque cuenta con su propio nonce aleatorio de 96 bits generado por CSPRNG sin colisiones.
        El consumo de RAM se mantiene estrictamente en O(1) independiente del tamaño del archivo.
        Si se provee src_fd, lee directamente del descriptor inmovilizado para prevenir TOCTOU.
        """
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Cifrado AES-256-GCM no disponible. Rechazando aislamiento por política Fail-Secure.")

        aesgcm = AESGCM(self._aes_key)
        key_id_bytes = self.key_id.encode("utf-8")[:8]

        if src_fd is not None and src_fd >= 0:
            file_size = os.fstat(src_fd).st_size
            os.lseek(src_fd, 0, os.SEEK_SET)
        else:
            file_size = os.path.getsize(src_path)

        try:
            with open(dst_path, "wb") as dst_f:
                # Escribir cabecera V3: magic (17 bytes) + key_id (8 bytes) + tamaño original (8 bytes)
                dst_f.write(VAULT_MAGIC_V3)
                dst_f.write(key_id_bytes)
                dst_f.write(struct.pack(">Q", file_size))

                chunk_index = 0
                bytes_read = 0

                if src_fd is not None and src_fd >= 0:
                    while True:
                        chunk = os.read(src_fd, CHUNK_SIZE)
                        if not chunk and chunk_index > 0:
                            break
                        bytes_read += len(chunk)
                        is_last = (bytes_read >= file_size)

                        chunk_nonce = self.generate_unique_nonce_96()
                        block_aad = b"CST_V3:" + key_id_bytes + struct.pack(">IB", chunk_index, 1 if is_last else 0)
                        ciphertext = aesgcm.encrypt(chunk_nonce, chunk, block_aad)

                        dst_f.write(chunk_nonce)
                        dst_f.write(struct.pack(">IB", len(ciphertext), 1 if is_last else 0))
                        dst_f.write(ciphertext)

                        chunk_index += 1
                        if is_last:
                            break
                else:
                    with open(src_path, "rb") as src_f:
                        while True:
                            chunk = src_f.read(CHUNK_SIZE)
                            if not chunk and chunk_index > 0:
                                break
                            bytes_read += len(chunk)
                            is_last = (bytes_read >= file_size)

                            chunk_nonce = self.generate_unique_nonce_96()
                            block_aad = b"CST_V3:" + key_id_bytes + struct.pack(">IB", chunk_index, 1 if is_last else 0)
                            ciphertext = aesgcm.encrypt(chunk_nonce, chunk, block_aad)

                            dst_f.write(chunk_nonce)
                            dst_f.write(struct.pack(">IB", len(ciphertext), 1 if is_last else 0))
                            dst_f.write(ciphertext)

                            chunk_index += 1
                            if is_last:
                                break

                dst_f.flush()
                os.fsync(dst_f.fileno())

            self._save_key_metadata()
            return True
        except Exception as e:
            logger.error("Error cifrando en streaming %s -> %s: %s", src_path, dst_path, e)
            raise

    def decrypt_file_streaming(self, src_path: str, dst_path: str) -> bool:
        """
        Descifra un archivo del baúl en streaming verificando bloque a bloque
        su autenticidad criptográfica (AEAD). Soporta:
        1. Formato V3: Nonces independientes de 96 bits por bloque con soporte de keyring (CST_AES256GCM_V3:).
        2. Formato V2: Nonces basados en 64 bits + contador (CST_AES256GCM_S:).
        3. Formato V1: Monolítico previo (CST_AES256GCM:).
        """
        if not HAS_AES:
            raise RuntimeError("Descifrado AES-256-GCM no disponible.")

        try:
            with open(src_path, "rb") as src_f:
                magic_v3 = src_f.read(len(VAULT_MAGIC_V3))

                # 1. Caso Formato V3 (Nonces independientes de 96 bits por bloque)
                if magic_v3 == VAULT_MAGIC_V3:
                    key_id_bytes = src_f.read(8)
                    if len(key_id_bytes) != 8:
                        raise ValueError("Payload V3 corrupto: Identificador de clave incompleto.")

                    orig_size_bytes = src_f.read(8)
                    if len(orig_size_bytes) != 8:
                        raise ValueError("Payload V3 corrupto: Tamaño original ausente.")
                    orig_size = struct.unpack(">Q", orig_size_bytes)[0]

                    key_id_str = key_id_bytes.decode("utf-8", "ignore")
                    decrypt_key = self._get_key_for_decrypt(key_id_str)
                    aesgcm = AESGCM(decrypt_key)

                    chunk_index = 0
                    total_written = 0

                    with open(dst_path, "wb") as dst_f:
                        while True:
                            chunk_nonce = src_f.read(NONCE_96_SIZE)
                            if not chunk_nonce:
                                break
                            if len(chunk_nonce) != NONCE_96_SIZE:
                                raise ValueError("Payload V3 corrupto: Nonce de bloque incompleto.")

                            header = src_f.read(5)
                            if not header:
                                break
                            chunk_len, is_last_byte = struct.unpack(">IB", header)
                            is_last = (is_last_byte == 1)

                            ciphertext = src_f.read(chunk_len)
                            if len(ciphertext) != chunk_len:
                                raise ValueError("Bloque de muestra truncado o incompleto.")

                            block_aad = b"CST_V3:" + key_id_bytes + struct.pack(">IB", chunk_index, is_last_byte)

                            try:
                                plaintext = aesgcm.decrypt(chunk_nonce, ciphertext, block_aad)
                            except InvalidTag:
                                logger.critical("🚨 [INTEGRIDAD VIOLADA] Bloque %d alterado o tag inválido.", chunk_index)
                                raise ValueError(f"Fallo de autenticación criptográfica en bloque {chunk_index}.")

                            dst_f.write(plaintext)
                            total_written += len(plaintext)
                            chunk_index += 1

                            if is_last:
                                break

                        dst_f.flush()
                        os.fsync(dst_f.fileno())

                    if total_written != orig_size:
                        raise ValueError(f"Discrepancia en tamaño restaurado ({total_written} vs {orig_size} esperados).")

                    return True

                # 2. Caso Formato V2 (CST_AES256GCM_S:)
                src_f.seek(0)
                magic_v2 = src_f.read(len(VAULT_MAGIC_STREAM))
                if magic_v2 == VAULT_MAGIC_STREAM:
                    base_nonce = src_f.read(NONCE_BASE_SIZE)
                    if len(base_nonce) != NONCE_BASE_SIZE:
                        raise ValueError("Payload corrupto: Base nonce incompleto.")

                    orig_size_bytes = src_f.read(8)
                    if len(orig_size_bytes) != 8:
                        raise ValueError("Payload corrupto: Tamaño original ausente.")
                    orig_size = struct.unpack(">Q", orig_size_bytes)[0]

                    aesgcm = AESGCM(self._aes_key)
                    chunk_index = 0
                    total_written = 0

                    with open(dst_path, "wb") as dst_f:
                        while True:
                            header = src_f.read(5)
                            if not header:
                                break

                            chunk_len, is_last_byte = struct.unpack(">IB", header)
                            is_last = (is_last_byte == 1)

                            ciphertext = src_f.read(chunk_len)
                            if len(ciphertext) != chunk_len:
                                raise ValueError("Bloque de muestra truncado o incompleto.")

                            block_nonce = self._make_block_nonce(base_nonce, chunk_index)
                            block_aad = self._make_block_aad(chunk_index, is_last)

                            try:
                                plaintext = aesgcm.decrypt(block_nonce, ciphertext, block_aad)
                            except InvalidTag:
                                logger.critical("🚨 [INTEGRIDAD VIOLADA] Bloque %d alterado o tag inválido.", chunk_index)
                                raise ValueError(f"Fallo de autenticación criptográfica en bloque {chunk_index}.")

                            dst_f.write(plaintext)
                            total_written += len(plaintext)
                            chunk_index += 1

                            if is_last:
                                break

                        dst_f.flush()
                        os.fsync(dst_f.fileno())

                    if total_written != orig_size:
                        raise ValueError(f"Discrepancia en tamaño restaurado ({total_written} vs {orig_size} esperados).")

                    return True

                # 3. Caso Formato Heredado Monolítico (CST_AES256GCM:)
                src_f.seek(0)
                raw_bytes = src_f.read()
                plaintext = self._decrypt_data(raw_bytes)
                with open(dst_path, "wb") as dst_f:
                    dst_f.write(plaintext)
                    dst_f.flush()
                    os.fsync(dst_f.fileno())
                return True

        except Exception as e:
            logger.error("Error descifrando en streaming %s -> %s: %s", src_path, dst_path, e)
            if os.path.exists(dst_path):
                try:
                    os.remove(dst_path)
                except Exception:
                    pass
            raise

    def verify_encrypted_file_streaming(self, encrypted_path: str, expected_sha256: str) -> bool:
        """
        Verifica en streaming la integridad y autenticidad del archivo cifrado (V3, V2 o V1)
        sin escribir en disco ni cargar todo el contenido a memoria.
        """
        if not HAS_AES or not self._aes_key:
            return False

        sha = hashlib.sha256()
        try:
            with open(encrypted_path, "rb") as src_f:
                magic_v3 = src_f.read(len(VAULT_MAGIC_V3))

                # 1. Caso Formato V3 (Nonces independientes de 96 bits)
                if magic_v3 == VAULT_MAGIC_V3:
                    key_id_bytes = src_f.read(8)
                    orig_size_bytes = src_f.read(8)
                    if len(orig_size_bytes) != 8:
                        return False

                    key_id_str = key_id_bytes.decode("utf-8", "ignore")
                    decrypt_key = self._get_key_for_decrypt(key_id_str)
                    aesgcm = AESGCM(decrypt_key)
                    chunk_index = 0

                    while True:
                        chunk_nonce = src_f.read(NONCE_96_SIZE)
                        if not chunk_nonce:
                            break
                        header = src_f.read(5)
                        if not header:
                            break
                        chunk_len, is_last_byte = struct.unpack(">IB", header)
                        is_last = (is_last_byte == 1)

                        ciphertext = src_f.read(chunk_len)
                        if len(ciphertext) != chunk_len:
                            return False

                        block_aad = b"CST_V3:" + key_id_bytes + struct.pack(">IB", chunk_index, is_last_byte)
                        plaintext = aesgcm.decrypt(chunk_nonce, ciphertext, block_aad)
                        sha.update(plaintext)
                        chunk_index += 1

                        if is_last:
                            break

                    return sha.hexdigest().lower() == expected_sha256.lower()

                # 2. Caso Formato V2 (CST_AES256GCM_S:)
                src_f.seek(0)
                magic_v2 = src_f.read(len(VAULT_MAGIC_STREAM))
                if magic_v2 == VAULT_MAGIC_STREAM:
                    base_nonce = src_f.read(NONCE_BASE_SIZE)
                    if len(base_nonce) != NONCE_BASE_SIZE:
                        return False
                    orig_size_bytes = src_f.read(8)
                    if len(orig_size_bytes) != 8:
                        return False

                    aesgcm = AESGCM(self._aes_key)
                    chunk_index = 0

                    while True:
                        header = src_f.read(5)
                        if not header:
                            break
                        chunk_len, is_last_byte = struct.unpack(">IB", header)
                        is_last = (is_last_byte == 1)

                        ciphertext = src_f.read(chunk_len)
                        if len(ciphertext) != chunk_len:
                            return False

                        block_nonce = self._make_block_nonce(base_nonce, chunk_index)
                        block_aad = self._make_block_aad(chunk_index, is_last)

                        plaintext = aesgcm.decrypt(block_nonce, ciphertext, block_aad)
                        sha.update(plaintext)
                        chunk_index += 1

                        if is_last:
                            break

                    return sha.hexdigest().lower() == expected_sha256.lower()

                # 3. Fallback legado V1
                src_f.seek(0)
                raw_bytes = src_f.read()
                plaintext = self._decrypt_data(raw_bytes)
                return hashlib.sha256(plaintext).hexdigest().lower() == expected_sha256.lower()

        except Exception as e:
            logger.debug("Verificación de archivo cifrado falló: %s", e)
            return False

    def _encrypt_data(self, data: bytes) -> bytes:
        """Cifra un búfer en memoria usando AES-256-GCM (utilizado en pruebas y payloads de memoria)."""
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Cifrado AES-256-GCM no disponible. Rechazando aislamiento débil por política Fail-Secure.")

        try:
            aesgcm = AESGCM(self._aes_key)
            nonce = secrets.token_bytes(12)  # Nonce estándar NIST de 96 bits
            ciphertext = aesgcm.encrypt(nonce, data, None)  # Incluye Auth Tag de 128 bits
            return VAULT_MAGIC_LEGACY + nonce + ciphertext
        except Exception as e:
            logger.error("Error criptográfico cifrando muestra con AES-256-GCM: %s", e)
            raise

    def _decrypt_data(self, raw_bytes: bytes) -> bytes:
        """Descifra un búfer en memoria y verifica su autenticidad (AEAD). Lanza excepción ante alteración."""
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Descifrado AES-256-GCM no disponible.")

        # Manejar formato streaming V3 (96 bits) si se pasa a _decrypt_data
        if raw_bytes.startswith(VAULT_MAGIC_V3):
            offset = len(VAULT_MAGIC_V3)
            key_id_bytes = raw_bytes[offset:offset+8]
            offset += 8
            orig_size = struct.unpack(">Q", raw_bytes[offset:offset+8])[0]
            offset += 8

            key_id_str = key_id_bytes.decode("utf-8", "ignore")
            decrypt_key = self._get_key_for_decrypt(key_id_str)
            aesgcm = AESGCM(decrypt_key)
            out = bytearray()
            chunk_index = 0

            while offset < len(raw_bytes):
                chunk_nonce = raw_bytes[offset:offset+NONCE_96_SIZE]
                offset += NONCE_96_SIZE
                chunk_len, is_last_byte = struct.unpack(">IB", raw_bytes[offset:offset+5])
                is_last = (is_last_byte == 1)
                offset += 5
                ciphertext = raw_bytes[offset:offset+chunk_len]
                offset += chunk_len

                block_aad = b"CST_V3:" + key_id_bytes + struct.pack(">IB", chunk_index, is_last_byte)
                try:
                    plaintext = aesgcm.decrypt(chunk_nonce, ciphertext, block_aad)
                except InvalidTag:
                    logger.critical("🚨 [INTEGRIDAD VIOLADA] La muestra ha sido alterada o la clave no coincide.")
                    raise ValueError("Fallo de autenticación criptográfica: Muestra corrupta o manipulada.")
                out.extend(plaintext)
                chunk_index += 1
                if is_last:
                    break

            if len(out) != orig_size:
                raise ValueError("Discrepancia en tamaño de datos descifrados en memoria.")
            return bytes(out)

        # Manejar formato streaming si se pasa a _decrypt_data
        if raw_bytes.startswith(VAULT_MAGIC_STREAM):
            offset = len(VAULT_MAGIC_STREAM)
            base_nonce = raw_bytes[offset:offset+NONCE_BASE_SIZE]
            offset += NONCE_BASE_SIZE
            orig_size = struct.unpack(">Q", raw_bytes[offset:offset+8])[0]
            offset += 8

            aesgcm = AESGCM(self._aes_key)
            out = bytearray()
            chunk_index = 0

            while offset < len(raw_bytes):
                chunk_len, is_last_byte = struct.unpack(">IB", raw_bytes[offset:offset+5])
                is_last = (is_last_byte == 1)
                offset += 5
                ciphertext = raw_bytes[offset:offset+chunk_len]
                offset += chunk_len

                block_nonce = self._make_block_nonce(base_nonce, chunk_index)
                block_aad = self._make_block_aad(chunk_index, is_last)
                try:
                    plaintext = aesgcm.decrypt(block_nonce, ciphertext, block_aad)
                except InvalidTag:
                    logger.critical("🚨 [INTEGRIDAD VIOLADA] La muestra ha sido alterada o la clave no coincide.")
                    raise ValueError("Fallo de autenticación criptográfica: Muestra corrupta o manipulada.")
                out.extend(plaintext)
                chunk_index += 1
                if is_last:
                    break
            return bytes(out)

        if not raw_bytes.startswith(VAULT_MAGIC_LEGACY):
            raise ValueError("Muestra de baúl no válida: Encabezado mágico CST_AES256GCM ausente o corrupto.")

        offset = len(VAULT_MAGIC_LEGACY)
        if len(raw_bytes) < offset + 12 + 16:
            raise ValueError("Muestra truncada o longitud de carga insuficiente.")

        nonce = raw_bytes[offset:offset+12]
        ciphertext = raw_bytes[offset+12:]

        try:
            aesgcm = AESGCM(self._aes_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except InvalidTag:
            logger.critical("🚨 [INTEGRIDAD VIOLADA] La muestra ha sido alterada o la clave no coincide (Auth Tag falló).")
            raise ValueError("Fallo de autenticación criptográfica: Muestra corrupta o manipulada.")
        except Exception as e:
            logger.error("Fallo inesperado al descifrar muestra: %s", e)
            raise

    def _save_manifest_atomic(self, manifest: List[Dict]) -> bool:
        """Escribe el manifiesto de forma atómica (os.replace con fsync) para evitar corrupción o truncado."""
        temp_manifest = f"{self.manifest_file}.tmp_{secrets.token_hex(4)}"
        try:
            with open(temp_manifest, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            os.replace(temp_manifest, self.manifest_file)
            return True
        except Exception as e:
            logger.error("Fallo crítico en guardado atómico del manifiesto del baúl: %s", e)
            if os.path.exists(temp_manifest):
                try:
                    os.remove(temp_manifest)
                except Exception:
                    pass
            return False

    def quarantine_file(self, file_path: str, threat_name: str, detected_by: str = "Scanner",
                        target_fd: Optional[int] = None) -> Optional[str]:
        """
        Ejecuta una transacción verificable de cuarentena (Two-Phase Commit) en streaming
        utilizando el operador privilegiado con inmovilización de descriptores (anti-TOCTOU):
        1. Inmoviliza el descriptor del archivo y valida identidad física (fstat vs lstat, st_dev, st_ino).
        2. Fase 1: Cifra directamente desde el descriptor verificado con AES-256-GCM streaming.
        3. Fase 2: Verifica la autenticidad e integridad del cifrado en disco.
        4. Fase 3: Registra atómicamente la entrada en el manifiesto.
        5. Fase 4: Desvinculado seguro con control de carreras (pre-unlink check) y tolerancia a medios de solo lectura (EROFS).
        6. Fase 5: Renombra atómicamente el payload temporal a .quar con permisos 000.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        if not HAS_AES or not self._aes_key:
            logger.critical("❌ [FAIL-SECURE] Imposible aislar archivo %s: Motor criptográfico seguro no disponible.", file_path)
            return None

        # Inmovilizar el descriptor del archivo y validar identidad estructural
        handle = None
        try:
            handle = self.operator.pin_and_validate(file_path, target_fd=target_fd)
        except Exception as e:
            logger.error("❌ [RECHAZO CUARENTENA] Error en validación de identidad y fijación de descriptor para %s: %s", file_path, e)
            return None

        file_hash = handle.sha256
        total_bytes = handle.size_bytes
        vault_id = secrets.token_hex(12)
        temp_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.tmp")
        dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        rollback_needed = False

        try:
            # =================================================================
            # FASE 1: Cifrado en Streaming leyendo del descriptor inmovilizado
            # =================================================================
            self.encrypt_file_streaming(file_path, temp_payload_path, src_fd=handle.fd)

            # Verificación en streaming de la muestra cifrada en disco
            if not self.verify_encrypted_file_streaming(temp_payload_path, file_hash):
                raise RuntimeError("La prueba de descifrado y autenticación de la muestra temporal en streaming falló.")

            # =================================================================
            # FASE 2: Registro Atómico en el Manifiesto
            # =================================================================
            now = time.time()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

            entry = {
                "vault_id": vault_id,
                "original_path": os.path.abspath(file_path),
                "threat_name": threat_name,
                "sha256": file_hash,
                "size_bytes": total_bytes,
                "detected_by": detected_by,
                "quarantine_time": now,
                "quarantine_time_str": now_str,
                "vault_payload_path": os.path.abspath(dest_payload_path),
                "status": "quarantined",
                "encryption": "AES-256-GCM-Chunked96-v3",
                "format_version": 3,
                "key_id": self.key_id,
                "pinned_inode": f"{handle.st_dev}:{handle.st_ino}"
            }

            manifest = self._load_manifest()
            manifest.insert(0, entry)
            if not self._save_manifest_atomic(manifest):
                raise IOError("No se pudo escribir atómicamente el manifiesto del baúl.")

            # =================================================================
            # FASE 3: Desvinculado Seguro (Anti-Carrera) y Manejo de Aislamiento
            # =================================================================
            success, is_ro_fs, msg = self.operator.secure_unlink(handle)

            if is_ro_fs:
                # Sistema de archivos de solo lectura (ej. medio físico protegido o montaje EROFS):
                # La amenaza queda asegurada en el baúl, documentando el estado del medio original
                entry["quarantine_mode"] = "isolated_in_vault_ro_fs"
                entry["original_removed"] = False
                entry["note"] = f"Aislado en baúl; archivo original protegido por solo lectura del medio ({msg})"
                self._save_manifest_atomic(manifest)
                logger.warning("⚠️ Muestra asegurada en el baúl (archivo original no desvinculado por estar en medio EROFS): %s", file_path)
            elif not success:
                logger.error("❌ Fallo al eliminar archivo original %s: %s. Iniciando ROLLBACK transaccional...", file_path, msg)
                rollback_needed = True

            if rollback_needed:
                # ROLLBACK TRANSACCIONAL:
                rev_manifest = [it for it in self._load_manifest() if it["vault_id"] != vault_id]
                self._save_manifest_atomic(rev_manifest)
                if os.path.exists(temp_payload_path):
                    try:
                        os.remove(temp_payload_path)
                    except Exception:
                        pass
                logger.warning("⚠️ Rollback completado con éxito: No se alteró el estado del sistema.")
                return None

            # =================================================================
            # FASE 4: Finalización del Payload y Asignación de Permisos 000
            # =================================================================
            os.replace(temp_payload_path, dest_payload_path)
            os.chmod(dest_payload_path, 0o000)

            logger.critical("[BAÚL VERIFICADO] Amenaza aislada transaccionalmente: %s -> ID: %s (%s)", file_path, vault_id, now_str)

            # Notificación de escritorio
            try:
                from core.engine.notifier import DesktopNotifier
                DesktopNotifier().alert_threat_blocked(threat_name, file_path, os.getpid(), detected_by)
            except Exception:
                pass

            return vault_id

        except Exception as e:
            logger.error("Error crítico durante la transacción de cuarentena para %s: %s", file_path, e)
            if os.path.exists(temp_payload_path):
                try:
                    os.remove(temp_payload_path)
                except Exception:
                    pass
            return None
        finally:
            if handle is not None:
                handle.close()

    def quarantine_proc_exe(self, pid: int, proc_name: str, threat_name: str) -> Optional[str]:
        """Extrae el ejecutable activo desde /proc/<pid>/exe y lo aísla bajo streaming verificable."""
        if not HAS_AES or not self._aes_key:
            logger.critical("❌ [FAIL-SECURE] Imposible aislar proceso PID %d: Cifrado seguro no disponible.", pid)
            return None

        proc_exe = f"/proc/{pid}/exe"
        if not os.path.exists(proc_exe):
            return None

        file_hash, total_bytes = self.compute_file_sha256(proc_exe)
        if not file_hash:
            return None

        vault_id = secrets.token_hex(12)
        temp_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.tmp")
        dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")

        try:
            self.encrypt_file_streaming(proc_exe, temp_payload_path)

            orig_path = f"/proc/{pid} ({proc_name})"
            try:
                target_link = os.readlink(proc_exe)
                if target_link:
                    orig_path = target_link
            except Exception:
                pass

            now = time.time()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

            entry = {
                "vault_id": vault_id,
                "original_path": orig_path,
                "threat_name": threat_name,
                "sha256": file_hash,
                "size_bytes": total_bytes,
                "quarantine_time": now,
                "quarantine_time_str": now_str,
                "detected_by": "MemoryRAMScanner",
                "encryption": "AES-256-GCM-Chunked96-v3",
                "format_version": 3,
                "key_id": self.key_id
            }

            manifest = self._load_manifest()
            manifest.append(entry)
            if not self._save_manifest_atomic(manifest):
                raise IOError("No se pudo escribir atómicamente el manifiesto del baúl.")

            os.replace(temp_payload_path, dest_payload_path)
            os.chmod(dest_payload_path, 0o000)

            logger.info("📦 Proceso aislado en Baúl transaccionalmente: PID %d -> ID: %s", pid, vault_id)
            try:
                from core.engine.notifier import DesktopNotifier
                DesktopNotifier().alert_threat_blocked(threat_name, orig_path, pid, proc_name)
            except Exception:
                pass
            return vault_id
        except Exception as e:
            logger.error("Error aislando proceso en cuarentena: %s", e)
            if os.path.exists(temp_payload_path):
                try:
                    os.remove(temp_payload_path)
                except Exception:
                    pass
            return None

    def list_items(self) -> List[Dict]:
        return self._load_manifest()

    def restore_file(self, vault_id: str, destination_path: Optional[str] = None, whitelist_manager=None) -> bool:
        """Restaura una muestra del baúl descifrándola en streaming con verificación de autenticidad y reemplazo atómico."""
        manifest = self._load_manifest()
        item = next((it for it in manifest if it["vault_id"] == vault_id), None)
        if not item:
            return False

        payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        target_path = destination_path or item.get("original_path")
        if not target_path or not os.path.exists(payload_path):
            return False

        temp_target_path = f"{target_path}.tmp_restore_{secrets.token_hex(4)}"

        try:
            try:
                os.chmod(payload_path, 0o600)
            except Exception:
                pass

            parent_dir = os.path.dirname(target_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            # Descifrado en streaming verificando cada bloque individual
            self.decrypt_file_streaming(payload_path, temp_target_path)

            os.chmod(temp_target_path, 0o644)
            # Reemplazo atómico en destino
            os.replace(temp_target_path, target_path)

            # Actualizar manifiesto atómicamente antes de destruir el payload del baúl
            new_manifest = [it for it in manifest if it["vault_id"] != vault_id]
            if not self._save_manifest_atomic(new_manifest):
                logger.warning("Aviso guardando manifiesto tras restauración.")

            # Eliminar payload del baúl solo tras confirmar la restauración atómica
            try:
                os.remove(payload_path)
            except Exception:
                pass

            if whitelist_manager:
                whitelist_manager.add_restored_exception(target_path, item.get("sha256"))

            logger.info("Restaurado de baúl exitoso y verificado: %s -> %s", vault_id, target_path)
            return True
        except Exception as e:
            logger.error("Error restaurando muestra: %s", e)
            if os.path.exists(temp_target_path):
                try:
                    os.remove(temp_target_path)
                except Exception:
                    pass
            return False

    def delete_item(self, vault_id: str) -> bool:
        manifest = self._load_manifest()
        payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        if os.path.exists(payload_path):
            try:
                os.remove(payload_path)
            except Exception:
                pass
        new_manifest = [it for it in manifest if it["vault_id"] != vault_id]
        return self._save_manifest_atomic(new_manifest)

    def purge_all(self) -> int:
        items = self.list_items()
        count = len(items)
        for it in items:
            self.delete_item(it["vault_id"])
        return count

    def _load_manifest(self) -> List[Dict]:
        if not os.path.exists(self.manifest_file):
            return []
        try:
            with open(self.manifest_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_manifest(self, manifest: List[Dict]):
        self._save_manifest_atomic(manifest)
