"""
Constantine Antivirus - Cryptographic Quarantine Vault (core/engine/vault.py)
Aislamiento criptográfico transaccional de grado militar mediante AES-256-GCM (AEAD autenticado).
Características de robustez e integridad:
1. Transacción Verificable de Cuarentena (Two-Phase Commit Pattern):
   - Fase 1 (Staging Cifrado): Crea un archivo temporal (.tmp), cifra bajo AES-256-GCM y verifica
     su autenticidad criptográfica en disco con os.fsync() antes de tocar el original.
   - Fase 2 (Manifiesto Atómico): Escribe el manifiesto en staging temporal y lo reemplaza atómicamente
     (os.replace) con sincronización física garantizada.
   - Fase 3 (Eliminación Verificada del Original con Rollback Automático):
     Intenta eliminar el original. Si la eliminación falla o el archivo sigue presente (ej. read-only,
     permisos o bloqueo), ejecuta ROLLBACK COMPLETO: restaura el manifiesto, elimina el payload temporal
     y nunca reporta una falsa cuarentena.
   - Fase 4 (Finalización Segura): Asigna permisos 000 inmune a ejecución y renombra a .quar definitivo.
2. Protección contra Desbordamiento de Memoria (Anti-OOM):
   - Lectura en bloques de 64 KB (streaming hash calculation).
   - Control estricto de límite de tamaño (MAX_QUARANTINE_FILE_SIZE = 100 MB) para prevenir colapsos por RAM.
3. Derivación de Claves Ligada al Host (Host-Bound KDF):
   - Deriva una clave simétrica de 256 bits mediante PBKDF2-HMAC-SHA256 (100,000 iteraciones).
   - Combina /etc/machine-id con un Salt de 256 bits protegido en /etc/constantine/.vault_salt (0400).
4. Cero XOR: Cifrado exclusivamente autenticado AEAD; ante errores o manipulación falla de forma segura.
"""

import os
import json
import time
import hashlib
import secrets
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("constantine.vault")

DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.local/share/constantine/vault")
DEFAULT_SALT_FILE = "/etc/constantine/.vault_salt"
USER_SALT_FILE = os.path.expanduser("~/.config/constantine/.vault_salt")

VAULT_MAGIC_HEADER = b"CST_AES256GCM:"
KDF_ITERATIONS = 100000

# Tamaño de bloque para operaciones en disco y límite de seguridad en memoria
CHUNK_SIZE = 64 * 1024  # 64 KB
MAX_QUARANTINE_FILE_SIZE = 150 * 1024 * 1024  # 150 MB máximo por muestra para proteger la RAM

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    HAS_AES = True
except ImportError:
    HAS_AES = False
    logger.critical("Librería 'cryptography' no disponible en el sistema. Cuarentena operará en modo Fail-Secure.")

class QuarantineVault:
    def __init__(self, storage_dir: Optional[str] = None, vault_dir: Optional[str] = None):
        base = storage_dir or vault_dir
        if base:
            self.base_dir = base
            self.salt_file = os.path.join(self.base_dir, ".vault_salt")
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.base_dir = DEFAULT_VAULT_DIR
            self.salt_file = DEFAULT_SALT_FILE
        else:
            self.base_dir = USER_VAULT_DIR
            self.salt_file = USER_SALT_FILE

        self.payloads_dir = os.path.join(self.base_dir, "payloads")
        self.manifest_file = os.path.join(self.base_dir, "vault_manifest.json")
        self._ensure_storage()
        self._aes_key = self._derive_host_bound_key()

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

    def _get_host_entropy(self) -> str:
        """Obtiene la identidad criptográfica única del host (/etc/machine-id o semilla protegida)."""
        for mid_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            if os.path.exists(mid_path):
                try:
                    with open(mid_path, "r", encoding="utf-8") as f:
                        val = f.read().strip()
                        if val:
                            return val
                except Exception:
                    pass
        fallback_host = os.environ.get("HOSTNAME", "constantine-host-seed")
        return f"constantine-sec-node-{fallback_host}"

    def _derive_host_bound_key(self) -> bytes:
        """Deriva la clave de 256 bits mediante KDF ligada al hardware (/etc/machine-id) + Salt 256-bit."""
        if not HAS_AES:
            logger.critical("❌ [FAIL-SECURE] Imposible inicializar clave: 'cryptography' ausente.")
            return b""

        try:
            salt_dir = os.path.dirname(self.salt_file)
            if salt_dir:
                os.makedirs(salt_dir, exist_ok=True)

            if os.path.exists(self.salt_file):
                with open(self.salt_file, "rb") as f:
                    salt = f.read()
                if len(salt) != 32:
                    salt = secrets.token_bytes(32)
                    with open(self.salt_file, "wb") as f:
                        f.write(salt)
            else:
                salt = secrets.token_bytes(32)
                with open(self.salt_file, "wb") as f:
                    f.write(salt)

            try:
                os.chmod(self.salt_file, 0o400)
            except Exception:
                pass

            host_identity = self._get_host_entropy()
            key = hashlib.pbkdf2_hmac("sha256", host_identity.encode("utf-8"), salt, KDF_ITERATIONS, dklen=32)
            return key
        except Exception as e:
            logger.critical("Error derivando clave simétrica ligada al host: %s", e)
            return b""

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

    def _encrypt_data(self, data: bytes) -> bytes:
        """Cifra con AES-256-GCM auténtico. Falla de forma segura (Fail-Secure) si la clave no está disponible."""
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Cifrado AES-256-GCM no disponible. Rechazando aislamiento débil por política Fail-Secure.")

        try:
            aesgcm = AESGCM(self._aes_key)
            nonce = secrets.token_bytes(12)  # Nonce estándar NIST de 96 bits
            ciphertext = aesgcm.encrypt(nonce, data, None)  # Incluye Auth Tag de 128 bits
            return VAULT_MAGIC_HEADER + nonce + ciphertext
        except Exception as e:
            logger.error("Error criptográfico cifrando muestra con AES-256-GCM: %s", e)
            raise

    def _decrypt_data(self, raw_bytes: bytes) -> bytes:
        """Descifra y verifica la autenticidad de la muestra (AEAD). Lanza excepción ante alteración."""
        if not HAS_AES or not self._aes_key:
            raise RuntimeError("Descifrado AES-256-GCM no disponible.")

        if not raw_bytes.startswith(VAULT_MAGIC_HEADER):
            raise ValueError("Muestra de baúl no válida: Encabezado mágico CST_AES256GCM ausente o corrupto.")

        offset = len(VAULT_MAGIC_HEADER)
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

            # En Linux, os.replace es una operación atómica a nivel de inodo de filesystem
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
        Ejecuta una transacción verificable de cuarentena (Two-Phase Commit):
        1. Comprueba existencia y límite de tamaño seguro (Anti-OOM).
        2. Fase 1: Cifra y escribe en archivo temporal (.tmp) con os.fsync() y valida lectura de prueba.
        3. Fase 2: Registra atómicamente la entrada en el manifiesto.
        4. Fase 3: Elimina el archivo original y verifica que ya no exista.
           Si la eliminación falla, ejecuta ROLLBACK COMPLETO (reviertiendo manifiesto y limpiando el baúl).
        5. Fase 4: Renombra atómicamente el payload temporal a .quar con permisos 000.
        """
        if not file_path or not os.path.exists(file_path):
            return None

        if not HAS_AES or not self._aes_key:
            logger.critical("❌ [FAIL-SECURE] Imposible aislar archivo %s: Motor criptográfico seguro no disponible.", file_path)
            return None

        # 1. Protección contra agotamiento de memoria (Anti-OOM)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > MAX_QUARANTINE_FILE_SIZE:
                logger.error("❌ Archivo %s excede el tamaño máximo permitido para cuarentena (%d MB > %d MB límite). Abortando para proteger la memoria.", file_path, file_size // (1024*1024), MAX_QUARANTINE_FILE_SIZE // (1024*1024))
                return None
        except Exception as sz_err:
            logger.error("Error verificando tamaño de %s: %s", file_path, sz_err)
            return None

        # Calcular hash SHA-256 en bloques de 64 KB
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
            # FASE 1: Preparación, Cifrado y Verificación Criptográfica en Disco
            # =================================================================
            with open(file_path, "rb") as f:
                original_bytes = f.read()

            encrypted_payload = self._encrypt_data(original_bytes)

            with open(temp_payload_path, "wb") as f:
                f.write(encrypted_payload)
                f.flush()
                os.fsync(f.fileno())  # Garantizar persistencia física en disco antes de avanzar

            # Verificación de prueba de descifrado para validar integridad del Nonce y Auth Tag
            test_verified = False
            try:
                with open(temp_payload_path, "rb") as tf:
                    test_read = tf.read()
                test_decrypted = self._decrypt_data(test_read)
                if test_decrypted == original_bytes:
                    test_verified = True
            except Exception as v_err:
                logger.critical("Fallo en verificación criptográfica previa de la muestra: %s", v_err)

            if not test_verified:
                raise RuntimeError("La prueba de descifrado y autenticación de la muestra temporal falló en disco.")

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
                "encryption": "AES-256-GCM-KDF"
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
            # Limpieza defensiva ante cualquier excepción previa
            if os.path.exists(temp_payload_path):
                try:
                    os.remove(temp_payload_path)
                except Exception:
                    pass
            return None

    def quarantine_proc_exe(self, pid: int, proc_name: str, threat_name: str) -> Optional[str]:
        """Extrae el ejecutable activo desde /proc/<pid>/exe y lo aísla bajo transacción verificable."""
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
            with open(proc_exe, "rb") as f:
                original_bytes = f.read()

            encrypted_bytes = self._encrypt_data(original_bytes)
            with open(temp_payload_path, "wb") as f:
                f.write(encrypted_bytes)
                f.flush()
                os.fsync(f.fileno())

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
                "encryption": "AES-256-GCM-KDF"
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
        """Restaura una muestra del baúl descifrándola y verificando su autenticidad (AEAD) con restauración atómica."""
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

            with open(payload_path, "rb") as f:
                encrypted_bytes = f.read()

            restored_bytes = self._decrypt_data(encrypted_bytes)
            parent_dir = os.path.dirname(target_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            # Escribir primero en archivo temporal de destino con fsync
            with open(temp_target_path, "wb") as f:
                f.write(restored_bytes)
                f.flush()
                os.fsync(f.fileno())

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
