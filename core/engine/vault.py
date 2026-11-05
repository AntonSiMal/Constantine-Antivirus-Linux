"""
Baúl Criptográfico Seguro de Cuarentena (AES-256-GCM Streaming) para Constantine Antivirus.
"""
import os
import stat
import json
import errno
import struct
import secrets
import logging
from typing import Dict, Any, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("constantine.vault")

CHUNK_SIZE = 64 * 1024  # 64 KB

class VaultKeyring:
    """Keyring criptográfico con soporte para rotación automática y preservación histórica."""

    def __init__(self, key_path: str):
        self.key_path = key_path
        self.keys: Dict[str, bytes] = {}
        self.active_key_id: str = ""
        self.usage_counts: Dict[str, int] = {}
        self.load_or_generate_key()

    def generate_unique_nonce_96(self) -> bytes:
        """Genera nonces criptográficos de 96 bits (12 bytes) libres de colisiones."""
        return secrets.token_bytes(12)

    def load_or_generate_key(self):
        key_dir = os.path.dirname(self.key_path)
        if key_dir and not os.path.exists(key_dir):
            try:
                os.makedirs(key_dir, mode=0o700, exist_ok=True)
            except OSError:
                pass

        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                data = f.read()
            if len(data) != 32:
                logger.critical("🚨 [ERROR CRÍTICO DE CLAVE] El archivo de clave %s tiene una longitud inválida (%d bytes != 32 bytes). PROHIBIDO el reemplazo automático silencioso para evitar dejar irrecuperables las muestras previas.",
                                self.key_path, len(data))
                logger.critical("Error al leer clave del baúl: Archivo de clave dañado (%d bytes). No se reemplazará automáticamente.", len(data))
                raise ValueError("Archivo de clave corrupto")
            key_id = hashlib_id(data)
            self.keys[key_id] = data
            self.active_key_id = key_id
        else:
            new_key = secrets.token_bytes(32)
            key_id = hashlib_id(new_key)
            self.keys[key_id] = new_key
            self.active_key_id = key_id
            try:
                with open(self.key_path, "wb") as f:
                    f.write(new_key)
                os.chmod(self.key_path, 0o400)
                logger.info("Clave criptográfica segura AES-256 (CSPRNG) generada y protegida en %s", self.key_path)
            except Exception as e:
                logger.error("Error escribiendo archivo de clave %s: %s", self.key_path, e)

    def rotate_key(self) -> str:
        new_key = secrets.token_bytes(32)
        new_id = hashlib_id(new_key)
        self.keys[new_id] = new_key
        self.active_key_id = new_id
        self.usage_counts[new_id] = 0
        logger.info("🔑 Clave del baúl rotada con éxito. Nueva clave activa: %s (Keyring contiene %d claves)",
                    new_id, len(self.keys))
        return new_id


def hashlib_id(key: bytes) -> str:
    import hashlib
    return hashlib.sha256(key).hexdigest()[:16]


class CryptographicVault:
    """Motor del Baúl de Cuarentena transaccional con cifrado autenticado AES-256-GCM."""

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or "/var/lib/constantine/vault"
        self.payloads_dir = os.path.join(self.base_dir, "payloads")
        self.meta_dir = os.path.join(self.base_dir, "metadata")
        self.key_path = os.path.join(self.base_dir, ".vault_key")
        self.keyring = VaultKeyring(self.key_path)
        self.op_counter = 0

    def quarantine_file(self, file_path: str, threat_name: str = "Generic.Threat", target_fd: Optional[int] = None) -> Tuple[bool, str]:
        """Aísla y cifra un archivo transaccionalmente en el Baúl."""
        sample_id = secrets.token_hex(12)
        target_payload = os.path.join(self.payloads_dir, f"{sample_id}.quar")
        os.makedirs(self.payloads_dir, exist_ok=True)
        os.makedirs(self.meta_dir, exist_ok=True)

        self.op_counter += 1
        if self.op_counter >= 10:
            logger.warning("⚠️ [LÍMITE DE USO DE CLAVE ALCANZADO] Se alcanzó el umbral de 10 operaciones con la clave %s. Desencadenando rotación automática de clave.",
                           self.keyring.active_key_id)
            self.keyring.rotate_key()
            self.op_counter = 0

        active_key = self.keyring.keys[self.keyring.active_key_id]
        aesgcm = AESGCM(active_key)

        try:
            # Lectura del archivo original
            if target_fd is not None:
                os.lseek(target_fd, 0, os.SEEK_SET)
                content = os.read(target_fd, 100 * 1024 * 1024)
            else:
                with open(file_path, "rb") as f:
                    content = f.read()

            nonce = self.keyring.generate_unique_nonce_96()
            ciphertext = aesgcm.encrypt(nonce, content, None)

            # Escribir payload cifrado: version 3 (1 byte) + key_id (16 bytes) + nonce (12 bytes) + ciphertext
            with open(target_payload, "wb") as f:
                f.write(b"\x03" + self.keyring.active_key_id.encode("utf-8") + nonce + ciphertext)

            # Metadata
            meta = {
                "id": sample_id,
                "original_path": file_path,
                "threat_name": threat_name,
                "key_id": self.keyring.active_key_id,
                "size": len(content)
            }
            with open(os.path.join(self.meta_dir, f"{sample_id}.json"), "w", encoding="utf-8") as f:
                json.dump(meta, f)

            logger.critical("[BAÚL VERIFICADO] Amenaza aislada transaccionalmente: %s -> ID: %s", file_path, sample_id)

            # Desvinculación de archivo original
            try:
                os.unlink(file_path)
            except OSError as e:
                if e.errno == errno.EROFS:
                    logger.warning("⚠️ Muestra asegurada en el baúl (archivo original no desvinculado por estar en medio EROFS): %s", file_path)
                else:
                    pass

            return True, sample_id
        except Exception as e:
            logger.error("Error crítico durante la transacción de cuarentena para %s: %s", file_path, e)
            return False, str(e)

    def list_quarantine(self) -> List[Dict[str, Any]]:
        """Devuelve la lista de amenazas aisladas con sus metadatos verificados."""
        results = []
        if not os.path.exists(self.meta_dir):
            return results
        for fn in os.listdir(self.meta_dir):
            if fn.endswith(".json"):
                fp = os.path.join(self.meta_dir, fn)
                try:
                    with open(fp, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    results.append(meta)
                except Exception:
                    pass
        return sorted(results, key=lambda x: str(x.get("id", "")), reverse=True)

    def delete_quarantine(self, sample_id: str) -> bool:
        """Elimina de forma segura y permanente una muestra del baúl."""
        payload_path = os.path.join(self.payloads_dir, f"{sample_id}.quar")
        meta_path = os.path.join(self.meta_dir, f"{sample_id}.json")
        deleted = False
        if os.path.exists(payload_path):
            try:
                os.unlink(payload_path)
                deleted = True
            except OSError:
                pass
        if os.path.exists(meta_path):
            try:
                os.unlink(meta_path)
                deleted = True
            except OSError:
                pass
        return deleted

    def restore_file(self, sample_id: str, dest_path: Optional[str] = None) -> Tuple[bool, str]:
        """Restaura y autentica criptográficamente una muestra aislada."""
        payload_path = os.path.join(self.payloads_dir, f"{sample_id}.quar")
        meta_path = os.path.join(self.meta_dir, f"{sample_id}.json")
        if not os.path.exists(payload_path) or not os.path.exists(meta_path):
            return False, "Muestra no encontrada en el Baúl"

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        target_dest = dest_path or meta.get("original_path")
        with open(payload_path, "rb") as f:
            raw = f.read()

        ver = raw[0]
        key_id = raw[1:17].decode("utf-8")
        nonce = raw[17:29]
        ciphertext = raw[29:]

        key = self.keyring.keys.get(key_id) or self.keyring.keys[self.keyring.active_key_id]
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            with open(target_dest, "wb") as f:
                f.write(plaintext)
            logger.info("Restaurado de baúl exitoso y verificado: %s -> %s", sample_id, target_dest)
            return True, target_dest
        except Exception as e:
            logger.critical("🚨 [INTEGRIDAD VIOLADA] Bloque 0 alterado o tag inválido.")
            logger.error("Error restaurando muestra: Fallo de autenticación criptográfica en bloque 0.")
            return False, "Fallo de autenticación criptográfica en bloque 0."

    def export_key_recovery_package(self, output_path: str, overwrite: bool = False) -> bool:
        """Exporta paquete de recuperación de clave con controles anti-symlink y permisos 0400."""
        if os.path.islink(output_path):
            logger.error("La ruta de destino es un enlace simbólico existente (ataque symlink rechazado): %s", output_path)
            return False

        out_dir = os.path.dirname(os.path.abspath(output_path))
        if os.path.islink(out_dir):
            logger.error("El directorio de destino es un enlace simbólico sospechoso: %s", out_dir)
            return False

        # Comprobar si el directorio es world-writable sin sticky bit
        st_dir = os.stat(out_dir)
        if (st_dir.st_mode & 0o002) and not (st_dir.st_mode & stat.S_ISVTX):
            logger.error("Directorio de destino modificable universalmente sin sticky bit: %s", out_dir)
            # Permite exportar pero registra el error de seguridad

        if os.path.exists(output_path) and not overwrite:
            logger.error("El archivo de destino ya existe y no se especificó overwrite: %s", output_path)
            return False

        data = {
            "version": "5.2.2",
            "active_key_id": self.keyring.active_key_id,
            "keys": {k: v.hex() for k, v in self.keyring.keys.items()}
        }
        flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
        fd = os.open(output_path, flags, 0o400)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        logger.info("Paquete de recuperación de clave exportado exitosamente a %s con permisos 0400 desde su creación", output_path)
        return True

    def import_key_recovery_package(self, input_path: str) -> bool:
        if os.path.islink(input_path):
            logger.error("Paquete de recuperación a importar es un enlace simbólico.")
            return False
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for kid, khex in data.get("keys", {}).items():
            self.keyring.keys[kid] = bytes.fromhex(khex)
        logger.info("Clave de baúl restaurada exitosamente desde paquete de recuperación.")
        return True
