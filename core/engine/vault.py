"""
Constantine Antivirus - Quarantine Vault (core/engine/vault.py)
Aislamiento seguro, cifrado XOR y gestión del baúl de amenazas.
Registra fecha, hora y ubicación física exacta de cada muestra,
permite restauración unitaria o masiva añadiendo automáticamente a la Lista Blanca.
"""

import os
import json
import time
import hashlib
import secrets
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("constantine.vault")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AESGCM = True
except ImportError:
    HAS_AESGCM = False

DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.config/constantine/vault")
VAULT_XOR_KEY = b"C0nst4nt1n3_V4ult_S3cur1ty_2026_K3y"
AES_MAGIC_HEADER = b"CST_AES256GCM:"

class QuarantineVault:
    def __init__(self, vault_dir: Optional[str] = None):
        if vault_dir:
            self.vault_dir = vault_dir
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.vault_dir = DEFAULT_VAULT_DIR
        else:
            self.vault_dir = USER_VAULT_DIR

        self.payloads_dir = os.path.join(self.vault_dir, "payloads")
        self.manifest_file = os.path.join(self.vault_dir, "manifest.json")
        self.key_file = os.path.join(self.vault_dir, ".vault_aes.key")
        self._init_vault()

    def _get_or_create_aes_key(self) -> bytes:
        if os.path.exists(self.key_file):
            try:
                with open(self.key_file, "rb") as f:
                    k = f.read()
                    if len(k) == 32:
                        return k
            except Exception:
                pass
        # Generar nueva clave de 256 bits y guardar con permisos 0400
        new_key = os.urandom(32)
        try:
            with open(self.key_file, "wb") as f:
                f.write(new_key)
            os.chmod(self.key_file, 0o400)
        except Exception:
            pass
        return new_key

    def _init_vault(self):
        os.makedirs(self.payloads_dir, mode=0o700, exist_ok=True)
        if not os.path.exists(self.manifest_file):
            self._save_manifest([])

    def get_storage_location(self) -> str:
        """Devuelve la ruta física en disco donde se resguardan las cargas cifradas."""
        return os.path.abspath(self.payloads_dir)

    def _load_manifest(self) -> List[Dict]:
        try:
            if os.path.exists(self.manifest_file):
                with open(self.manifest_file, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug("Error cargando manifiesto: %s", e)
        return []

    def _save_manifest(self, data: List[Dict]):
        try:
            with open(self.manifest_file, "w") as f:
                json.dump(data, f, indent=2)
            os.chmod(self.manifest_file, 0o600)
        except Exception as e:
            logger.debug("Error guardando manifiesto: %s", e)

    def _encrypt_data(self, data: bytes) -> bytes:
        """Cifra datos usando AES-256-GCM autenticado (o fallback si no hay cryptography)."""
        if HAS_AESGCM:
            try:
                key = self._get_or_create_aes_key()
                aesgcm = AESGCM(key)
                nonce = os.urandom(12) # 96-bit nonce estándar
                ciphertext = aesgcm.encrypt(nonce, data, None)
                return AES_MAGIC_HEADER + nonce + ciphertext
            except Exception as e:
                logger.error("Fallo cifrado AES-256-GCM, usando fallback: %s", e)
        # Fallback XOR
        key_len = len(VAULT_XOR_KEY)
        return bytes(b ^ VAULT_XOR_KEY[i % key_len] for i, b in enumerate(data))

    def _decrypt_data(self, raw_bytes: bytes) -> bytes:
        """Descifra datos detectando automáticamente si es AES-256-GCM o XOR legado."""
        if raw_bytes.startswith(AES_MAGIC_HEADER) and HAS_AESGCM:
            try:
                header_len = len(AES_MAGIC_HEADER)
                nonce = raw_bytes[header_len:header_len+12]
                ciphertext = raw_bytes[header_len+12:]
                key = self._get_or_create_aes_key()
                aesgcm = AESGCM(key)
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                logger.error("Error descifrando carga AES-GCM: %s", e)
        # Fallback para cargas XOR previas
        key_len = len(VAULT_XOR_KEY)
        return bytes(b ^ VAULT_XOR_KEY[i % key_len] for i, b in enumerate(raw_bytes))

    def quarantine_proc_exe(self, pid: int, proc_name: str, threat_name: str) -> Optional[str]:
        """Extrae el ejecutable activo o borrado desde /proc/<pid>/exe y lo aísla en el Baúl."""
        proc_exe = f"/proc/{pid}/exe"
        try:
            if not os.path.exists(proc_exe):
                return None
            with open(proc_exe, "rb") as f:
                original_bytes = f.read()

            file_hash = hashlib.sha256(original_bytes).hexdigest()
            vault_id = secrets.token_hex(12)
            dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")

            encrypted_bytes = self._encrypt_data(original_bytes)
            with open(dest_payload_path, "wb") as f:
                f.write(encrypted_bytes)
            os.chmod(dest_payload_path, 0o000)

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
                "quarantine_time": now,
                "quarantine_time_str": now_str,
                "detected_by": "MemoryRAMScanner"
            }

            manifest = self._load_manifest()
            manifest.append(entry)
            self._save_manifest(manifest)
            logger.info("📦 Proceso de RAM aislado en Baúl con AES-256-GCM: PID %d -> %s", pid, vault_id)
            try:
                from core.engine.notifier import DesktopNotifier
                DesktopNotifier().alert_threat_blocked(threat_name, orig_path, pid, proc_name)
            except Exception:
                pass
            return vault_id
        except Exception as e:
            logger.error("Error aislando proceso en cuarentena: %s", e)
            return None

    def _obfuscate(self, data: bytes) -> bytes:
        return self._encrypt_data(data)

    def quarantine_file(self, file_path: str, threat_name: str, detected_by: str = "Scanner") -> Optional[str]:
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "rb") as f:
                original_bytes = f.read()

            file_hash = hashlib.sha256(original_bytes).hexdigest()
            vault_id = secrets.token_hex(12)
            dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")

            # Cifrar bytes y retirar permisos de ejecución
            obfuscated_bytes = self._encrypt_data(original_bytes)
            with open(dest_payload_path, "wb") as f:
                f.write(obfuscated_bytes)
            os.chmod(dest_payload_path, 0o000)

            # Eliminar del archivo de origen en el sistema
            try:
                os.remove(file_path)
            except Exception:
                pass

            now = time.time()
            now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))

            entry = {
                "vault_id": vault_id,
                "original_path": os.path.abspath(file_path),
                "threat_name": threat_name,
                "sha256": file_hash,
                "size_bytes": len(original_bytes),
                "detected_by": detected_by,
                "quarantine_time": now,
                "quarantine_time_str": now_str,
                "vault_payload_path": os.path.abspath(dest_payload_path),
                "status": "quarantined"
            }

            manifest = self._load_manifest()
            manifest.insert(0, entry)
            self._save_manifest(manifest)

            logger.critical("[BAÚL] Amenaza aislada: %s -> ID: %s (%s)", file_path, vault_id, now_str)
            try:
                from core.engine.notifier import DesktopNotifier
                DesktopNotifier().alert_threat_blocked(threat_name, file_path, os.getpid(), detected_by)
            except Exception:
                pass
            return vault_id
        except Exception as e:
            logger.error("Error al aislar en baúl: %s", e)
            return None

    def list_items(self) -> List[Dict]:
        return self._load_manifest()

    def restore_file(self, vault_id: str, destination_path: Optional[str] = None, whitelist_manager=None) -> bool:
        """
        Restaura un archivo del baúl y lo añade automáticamente a la Lista Blanca (Whitelist)
        para que fanotify no vuelva a bloquearlo.
        """
        manifest = self._load_manifest()
        item = next((x for x in manifest if x["vault_id"] == vault_id), None)
        if not item:
            return False

        payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        if not os.path.exists(payload_path):
            return False

        try:
            os.chmod(payload_path, 0o600)
            with open(payload_path, "rb") as f:
                obfuscated = f.read()

            original_bytes = self._decrypt_data(obfuscated)
            target = destination_path or item["original_path"]

            target_dir = os.path.dirname(target)
            if target_dir:
                os.makedirs(target_dir, exist_ok=True)

            with open(target, "wb") as f:
                f.write(original_bytes)
            os.chmod(target, 0o755 if target.endswith((".sh", ".bin", ".elf")) else 0o644)

            try:
                os.remove(payload_path)
            except Exception:
                pass

            manifest = [x for x in manifest if x["vault_id"] != vault_id]
            self._save_manifest(manifest)

            # AÑADIR AUTOMÁTICAMENTE A LA LISTA BLANCA (WHITELIST)
            if whitelist_manager:
                whitelist_manager.add_restored_exception(target, item.get("sha256"))

            logger.info("Archivo restaurado y añadido a la Whitelist: %s", target)
            return True
        except Exception as e:
            logger.error("Error al restaurar archivo: %s", e)
            return False

    def purge_file(self, vault_id: str) -> bool:
        manifest = self._load_manifest()
        item = next((x for x in manifest if x["vault_id"] == vault_id), None)
        if not item:
            return False

        payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        try:
            if os.path.exists(payload_path):
                os.chmod(payload_path, 0o600)
                size = os.path.getsize(payload_path)
                with open(payload_path, "wb") as f:
                    f.write(b"\x00" * size)
                os.remove(payload_path)

            manifest = [x for x in manifest if x["vault_id"] != vault_id]
            self._save_manifest(manifest)
            logger.info("Muestra purgada definitivamente del baúl: %s", vault_id)
            return True
        except Exception as e:
            logger.error("Error al purgar archivo: %s", e)
            return False

    def restore_multiple(self, vault_ids: List[str], whitelist_manager=None) -> int:
        """Restaura múltiples archivos seleccionados y los añade a la lista blanca."""
        success_count = 0
        for vid in vault_ids:
            if self.restore_file(vid, whitelist_manager=whitelist_manager):
                success_count += 1
        return success_count

    def purge_multiple(self, vault_ids: List[str]) -> int:
        """Elimina definitivamente múltiples archivos seleccionados del baúl."""
        success_count = 0
        for vid in vault_ids:
            if self.purge_file(vid):
                success_count += 1
        return success_count
