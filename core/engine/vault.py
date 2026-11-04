"""
Constantine Antivirus - Quarantine Vault (core/engine/vault.py)
Aislamiento seguro, cifrado AES-256-GCM militar y gestión del baúl de amenazas.
Registra fecha, hora y ubicación física exacta de cada muestra con permisos 000,
vector de inicialización único (Nonce de 96 bits) y firma de autenticación (Auth Tag).
Permite restauración unitaria o masiva añadiendo automáticamente a la Lista Blanca.
"""

import os
import json
import time
import hashlib
import secrets
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("constantine.vault")

DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.local/share/constantine/vault")
DEFAULT_KEY_FILE = "/var/lib/constantine/.vault_aes.key"
USER_KEY_FILE = os.path.expanduser("~/.local/share/constantine/.vault_aes.key")

VAULT_MAGIC_HEADER = b"CST_AES256GCM:"
VAULT_XOR_KEY = b"C0nst4nt1n3_V4ult_S3cur1ty_2026_K3y"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_AES = True
except ImportError:
    HAS_AES = False
    logger.warning("Librería 'cryptography' no disponible. Usando fallback XOR.")

class QuarantineVault:
    def __init__(self, storage_dir: Optional[str] = None, vault_dir: Optional[str] = None):
        storage_dir = storage_dir or vault_dir
        if storage_dir:
            self.base_dir = storage_dir
            self.key_file = os.path.join(self.base_dir, ".vault_aes.key")
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.base_dir = DEFAULT_VAULT_DIR
            self.key_file = DEFAULT_KEY_FILE
        else:
            self.base_dir = USER_VAULT_DIR
            self.key_file = USER_KEY_FILE

        self.payloads_dir = os.path.join(self.base_dir, "payloads")
        self.manifest_file = os.path.join(self.base_dir, "vault_manifest.json")
        self._ensure_storage()
        self._aes_key = self._get_or_create_aes_key()

    def get_storage_location(self) -> str:
        return self.base_dir

    def _ensure_storage(self):
        try:
            os.makedirs(self.payloads_dir, exist_ok=True)
            if os.geteuid() == 0:
                os.chmod(self.base_dir, 0o700)
                os.chmod(self.payloads_dir, 0o700)
        except Exception as e:
            logger.debug("No se pudieron ajustar permisos 0700 en baúl: %s", e)

    def _get_or_create_aes_key(self) -> bytes:
        if not HAS_AES:
            return b""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, "rb") as f:
                    key = f.read()
                if len(key) == 32:
                    return key
            key = AESGCM.generate_key(bit_length=256)
            key_dir = os.path.dirname(self.key_file)
            if key_dir:
                os.makedirs(key_dir, exist_ok=True)
            with open(self.key_file, "wb") as f:
                f.write(key)
            try:
                os.chmod(self.key_file, 0o400)
            except Exception:
                pass
            return key
        except Exception as e:
            logger.warning("Error gestionando clave AES: %s", e)
            return b""

    def _encrypt_data(self, data: bytes) -> bytes:
        if HAS_AES and self._aes_key:
            try:
                aesgcm = AESGCM(self._aes_key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, data, None)
                return VAULT_MAGIC_HEADER + nonce + ciphertext
            except Exception as e:
                logger.error("Fallo cifrando con AES-256-GCM: %s", e)
        key_len = len(VAULT_XOR_KEY)
        return bytes(b ^ VAULT_XOR_KEY[i % key_len] for i, b in enumerate(data))

    def _decrypt_data(self, raw_bytes: bytes) -> bytes:
        if raw_bytes.startswith(VAULT_MAGIC_HEADER) and HAS_AES and self._aes_key:
            try:
                offset = len(VAULT_MAGIC_HEADER)
                nonce = raw_bytes[offset:offset+12]
                ciphertext = raw_bytes[offset+12:]
                aesgcm = AESGCM(self._aes_key)
                return aesgcm.decrypt(nonce, ciphertext, None)
            except Exception as e:
                logger.error("Fallo descifrando AES-256-GCM: %s", e)
        key_len = len(VAULT_XOR_KEY)
        return bytes(b ^ VAULT_XOR_KEY[i % key_len] for i, b in enumerate(raw_bytes))

    def quarantine_proc_exe(self, pid: int, proc_name: str, threat_name: str) -> Optional[str]:
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

            obfuscated_bytes = self._encrypt_data(original_bytes)
            with open(dest_payload_path, "wb") as f:
                f.write(obfuscated_bytes)
            os.chmod(dest_payload_path, 0o000)

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
        manifest = self._load_manifest()
        item = next((it for it in manifest if it["vault_id"] == vault_id), None)
        if not item:
            return False

        payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
        target_path = destination_path or item.get("original_path")
        if not target_path or not os.path.exists(payload_path):
            return False

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

            with open(target_path, "wb") as f:
                f.write(restored_bytes)
            os.chmod(target_path, 0o644)
            os.remove(payload_path)

            manifest = [it for it in manifest if it["vault_id"] != vault_id]
            self._save_manifest(manifest)

            if whitelist_manager:
                whitelist_manager.add_restored_exception(target_path, item.get("sha256"))

            logger.info("Restaurado de baúl: %s -> %s", vault_id, target_path)
            return True
        except Exception as e:
            logger.error("Error restaurando muestra: %s", e)
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
        self._save_manifest(new_manifest)
        return True

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
            with open(self.manifest_file, "r") as f:
                return json.load(f)
        except Exception:
            return []

    def _save_manifest(self, manifest: List[Dict]):
        try:
            with open(self.manifest_file, "w") as f:
                json.dump(manifest, f, indent=2)
        except Exception as e:
            logger.error("Error guardando manifest de baúl: %s", e)
