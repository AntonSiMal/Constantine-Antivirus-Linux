"""
Constantine Antivirus - Quarantine Vault (core/engine/vault.py)
"""
import os, json, time, hashlib, secrets, logging
from typing import List, Dict, Optional

logger = logging.getLogger("constantine.vault")
DEFAULT_VAULT_DIR = "/var/lib/constantine/vault"
USER_VAULT_DIR = os.path.expanduser("~/.config/constantine/vault")
VAULT_XOR_KEY = b"C0nst4nt1n3_V4ult_S3cur1ty_2026_K3y"

class QuarantineVault:
    def __init__(self, vault_dir: Optional[str] = None):
        self.vault_dir = vault_dir or (DEFAULT_VAULT_DIR if os.geteuid() == 0 else USER_VAULT_DIR)
        self.payloads_dir = os.path.join(self.vault_dir, "payloads")
        self.manifest_file = os.path.join(self.vault_dir, "manifest.json")
        self._init_vault()

    def _init_vault(self):
        os.makedirs(self.payloads_dir, mode=0o700, exist_ok=True)
        if not os.path.exists(self.manifest_file):
            self._save_manifest([])

    def _load_manifest(self) -> List[Dict]:
        try:
            if os.path.exists(self.manifest_file):
                with open(self.manifest_file, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_manifest(self, data: List[Dict]):
        with open(self.manifest_file, "w") as f:
            json.dump(data, f, indent=2)
        os.chmod(self.manifest_file, 0o600)

    def _obfuscate(self, data: bytes) -> bytes:
        key_len = len(VAULT_XOR_KEY)
        return bytes(b ^ VAULT_XOR_KEY[i % key_len] for i, b in enumerate(data))

    def quarantine_file(self, file_path: str, threat_name: str, detected_by: str = "Scanner") -> Optional[str]:
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "rb") as f:
                original_bytes = f.read()
            file_hash = hashlib.sha256(original_bytes).hexdigest()
            vault_id = secrets.token_hex(12)
            dest_payload_path = os.path.join(self.payloads_dir, f"{vault_id}.quar")
            obfuscated_bytes = self._obfuscate(original_bytes)
            with open(dest_payload_path, "wb") as f:
                f.write(obfuscated_bytes)
            os.chmod(dest_payload_path, 0o000)
            os.remove(file_path)
            entry = {
                "vault_id": vault_id,
                "original_path": os.path.abspath(file_path),
                "threat_name": threat_name,
                "sha256": file_hash,
                "size_bytes": len(original_bytes),
                "detected_by": detected_by,
                "quarantine_time": time.time(),
                "status": "quarantined"
            }
            manifest = self._load_manifest()
            manifest.append(entry)
            self._save_manifest(manifest)
            return vault_id
        except Exception:
            return None

    def list_items(self) -> List[Dict]:
        return self._load_manifest()

    def restore_file(self, vault_id: str, destination_path: Optional[str] = None) -> bool:
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
            original_bytes = self._obfuscate(obfuscated)
            target = destination_path or item["original_path"]
            d = os.path.dirname(target)
            if d:
                os.makedirs(d, exist_ok=True)
            with open(target, "wb") as f:
                f.write(original_bytes)
            os.chmod(target, 0o644)
            os.remove(payload_path)
            manifest = [x for x in manifest if x["vault_id"] != vault_id]
            self._save_manifest(manifest)
            return True
        except Exception:
            return False

    def purge_file(self, vault_id: str) -> bool:
        manifest = self._load_manifest()
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
            return True
        except Exception:
            return False
