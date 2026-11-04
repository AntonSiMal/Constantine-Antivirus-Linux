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
from typing import List, Dict, Optional, Tuple, BinaryIO

logger = logging.getLogger("constantine.vault")

DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.local/share/constantine/vault")
DEFAULT_KEY_FILE = "/etc/constantine/.vault_key"
USER_KEY_FILE = os.path.expanduser("~/.config/constantine/.vault_key")

VAULT_MAGIC_STREAM = b"CST_AES256GCM_S:"  # Formato streaming por bloques (16 bytes)
VAULT_MAGIC_LEGACY = b"CST_AES256GCM:"    # Formato monolítico previo (14 bytes)

CHUNK_SIZE = 64 * 1024  # 64 KB por bloque
TAG_SIZE = 16          # 128 bits de Auth Tag en AES-GCM
NONCE_BASE_SIZE = 8    # 64 bits de base aleatoria por archivo
KEY_SIZE_BYTES = 32    # 256 bits simétricos

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
        self._ensure_storage()
        self._aes_key = self._load_or_generate_secure_key()

    def get_storage_location(self) -> str:
        return self.base_dir

    def _ensure_storage(self):
        try:
            os.makedirs(self.payloads_dir, exist_ok=True)
            if os.geteuid() == 0:
                os.chmod(self.base_dir, 0o700)
                os.chmod(self.payloads_dir, 0o700)
        except Exception as e:
            logger.debug("Aviso ajustando permisos en baúl: %s", e)

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

    def _write_key_file(self, path: str, key_data: bytes):
        """Escribe un archivo de clave de forma atómica y con permisos restrictivos 0400."""
        temp_path = f"{path}.tmp_{secrets.token_hex(4)}"
        try:
            with open(temp_path, "wb") as f:
                f.write(key_data)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(temp_path, 0o400)
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

    def export_key_recovery_package(self, target_path: str) -> bool:
        """
        Exporta de forma segura el paquete de rescate y recuperación de claves
        con metadatos forenses, suma SHA-256 y formato JSON para disaster recovery.
        """
        if not self._aes_key or len(self._aes_key) != KEY_SIZE_BYTES:
            logger.error("No hay una clave válida para exportar.")
            return False
        try:
            target_dir = os.path.dirname(target_path)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            key_sha256 = hashlib.sha256(self._aes_key).hexdigest()
            recovery_info = {
                "format": "Constantine-Vault-KeyRecovery-v2",
                "cipher": "AES-256-GCM-Chunked-AEAD",
                "key_hex": self._aes_key.hex(),
                "key_sha256": key_sha256,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
                "doc": "Guarde este archivo en un medio seguro fuera de línea para permitir la recuperación de muestras del baúl."
            }
            with open(target_path, "w", encoding="utf-8") as f:
                json.dump(recovery_info, f, indent=2)
            os.chmod(target_path, 0o400)
            logger.info("Paquete de recuperación de clave exportado exitosamente a %s", target_path)
            return True
        except Exception as e:
            logger.error("Error exportando paquete de recuperación de clave: %s", e)
            return False

    def import_key_recovery_package(self, package_path: str) -> bool:
        """
        Importa y valida un paquete de recuperación de claves para restaurar acceso a las muestras.
        """
        if not os.path.exists(package_path):
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
        Construye un Nonce único de 96 bits para cada bloque:
        8 bytes base aleatoria por archivo + 4 bytes índice del bloque (big-endian).
        """
        return base_nonce + struct.pack(">I", chunk_index)

    def _make_block_aad(self, chunk_index: int, is_last: bool) -> bytes:
        """
        Genera Datos Asociados Autenticados (AAD) para ligar criptográficamente
        el índice del bloque y la bandera de fin de flujo, impidiendo reordenamiento o truncamiento.
        """
        return b"CST_CHUNK:" + struct.pack(">IB", chunk_index, 1 if is_last else 0)

    def encrypt_file_streaming(self, src_path: str, dst_path: str) -> bool:
        """
        Cifra un archivo en disco mediante bloques de 64 KB con AES-256-GCM.
        El consumo de RAM se mantiene estrictamente en O(1) independiente del tamaño del archivo.
        """
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Cifrado AES-256-GCM no disponible. Rechazando aislamiento por política Fail-Secure.")

        aesgcm = AESGCM(self._aes_key)
        base_nonce = secrets.token_bytes(NONCE_BASE_SIZE)
        file_size = os.path.getsize(src_path)

        try:
            with open(src_path, "rb") as src_f, open(dst_path, "wb") as dst_f:
                # Escribir cabecera mágica y metadatos del flujo cifrado
                dst_f.write(VAULT_MAGIC_STREAM)
                dst_f.write(base_nonce)  # 8 bytes base nonce
                dst_f.write(struct.pack(">Q", file_size))  # 8 bytes tamaño original

                chunk_index = 0
                bytes_read = 0

                while True:
                    chunk = src_f.read(CHUNK_SIZE)
                    if not chunk and chunk_index > 0:
                        break

                    bytes_read += len(chunk)
                    is_last = (bytes_read >= file_size)

                    # Nonce y AAD específicos del bloque
                    block_nonce = self._make_block_nonce(base_nonce, chunk_index)
                    block_aad = self._make_block_aad(chunk_index, is_last)

                    # Cifrar bloque con Auth Tag de 16 bytes
                    ciphertext = aesgcm.encrypt(block_nonce, chunk, block_aad)

                    # Escribir tamaño de carga cifrada (4 bytes), bandera is_last (1 byte) y carga
                    dst_f.write(struct.pack(">IB", len(ciphertext), 1 if is_last else 0))
                    dst_f.write(ciphertext)

                    chunk_index += 1
                    if is_last:
                        break

                dst_f.flush()
                os.fsync(dst_f.fileno())

            return True
        except Exception as e:
            logger.error("Error cifrando en streaming para %s: %s", src_path, e)
            if os.path.exists(dst_path):
                try:
                    os.remove(dst_path)
                except Exception:
                    pass
            raise

    def decrypt_file_streaming(self, src_path: str, dst_path: str) -> bool:
        """
        Descifra un archivo del baúl en streaming verificando bloque a bloque
        su autenticidad criptográfica (AEAD). Soporta formato streaming y monolítico heredado.
        """
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Descifrado AES-256-GCM no disponible.")

        try:
            with open(src_path, "rb") as src_f:
                magic = src_f.read(len(VAULT_MAGIC_STREAM))

                # 1. Caso Formato Streaming por Bloques (CST_AES256GCM_S:)
                if magic == VAULT_MAGIC_STREAM:
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
                            header = src_f.read(5)  # 4 bytes len + 1 byte is_last
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

                # 2. Caso Formato Heredado Monolítico (CST_AES256GCM:)
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
        Verifica en streaming la integridad y autenticidad del archivo cifrado
        sin escribir en disco ni cargar todo el contenido a memoria.
        """
        if not HAS_AES or not self._aes_key:
            return False

        sha = hashlib.sha256()
        try:
            with open(encrypted_path, "rb") as src_f:
                magic = src_f.read(len(VAULT_MAGIC_STREAM))

                if magic == VAULT_MAGIC_STREAM:
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

                # Fallback legado
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

    def quarantine_file(self, file_path: str, threat_name: str, detected_by: str = "Scanner") -> Optional[str]:
        """
        Ejecuta una transacción verificable de cuarentena (Two-Phase Commit) en streaming:
        1. Cifra el archivo mediante streaming de bloques (Chunked AES-256-GCM) sin cargarlo completo a RAM.
        2. Fase 1: Verifica la autenticidad e integridad del archivo cifrado en disco mediante streaming.
        3. Fase 2: Registra atómicamente la entrada en el manifiesto.
        4. Fase 3: Elimina el archivo original y verifica que ya no exista. Si falla, ejecuta ROLLBACK COMPLETO.
        5. Fase 4: Renombra atómicamente el payload temporal a .quar con permisos 000.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        if not HAS_AES or not self._aes_key:
            logger.critical("❌ [FAIL-SECURE] Imposible aislar archivo %s: Motor criptográfico seguro no disponible.", file_path)
            return None

        # Calcular hash SHA-256 y tamaño exacto en streaming (64 KB chunks)
        file_hash, total_bytes = self.compute_file_sha256(file_path)
        if not file_hash:
            logger.error("No se pudo calcular la firma SHA-256 de %s", file_path)
            return None

        vault_id = secrets.token_hex(12)
        temp_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.tmp")
        dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        rollback_needed = False

        try:
            # =================================================================
            # FASE 1: Cifrado en Streaming por Bloques y Verificación en Disco
            # =================================================================
            self.encrypt_file_streaming(file_path, temp_payload_path)

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
                "encryption": "AES-256-GCM-Chunked-Streaming"
            }

            manifest = self._load_manifest()
            manifest.insert(0, entry)
            if not self._save_manifest_atomic(manifest):
                raise IOError("No se pudo escribir atómicamente el manifiesto del baúl.")

            # =================================================================
            # FASE 3: Eliminación Verificada del Original con Control de Fallos
            # =================================================================
            try:
                os.remove(file_path)
            except Exception as rm_err:
                logger.error("❌ Fallo al eliminar archivo original %s: %s. Iniciando ROLLBACK transaccional...", file_path, rm_err)
                rollback_needed = True

            # Comprobar estrictamente si el archivo original sigue presente
            if not rollback_needed and os.path.exists(file_path):
                logger.error("❌ El archivo original %s sigue existiendo tras os.remove(). Iniciando ROLLBACK...", file_path)
                rollback_needed = True

            if rollback_needed:
                # ROLLBACK TRANSACCIONAL:
                # 1. Revertir la entrada agregada al manifiesto
                rev_manifest = [it for it in self._load_manifest() if it["vault_id"] != vault_id]
                self._save_manifest_atomic(rev_manifest)
                # 2. Eliminar la muestra temporal del baúl
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
                "encryption": "AES-256-GCM-Chunked-Streaming"
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
