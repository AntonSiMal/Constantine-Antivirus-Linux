"""
Constantine Antivirus - System & User Whitelist Engine (core/engine/system_whitelist.py)
Gestión completa de exclusiones y lista blanca de archivos y carpetas:
1. Paquetes oficiales de la distribución (APT, dpkg, Flatpak, Snap).
2. Archivos y carpetas agregados manualmente por el usuario.
3. Archivos restaurados del baúl de cuarentena.
"""

import os
import json
import logging
from typing import Set, Dict, List, Optional

logger = logging.getLogger("constantine.whitelist")

DEFAULT_WHITELIST_FILE = "/var/lib/constantine/whitelist.json"
USER_WHITELIST_FILE = os.path.expanduser("~/.config/constantine/whitelist.json")

TRUSTED_SYSTEM_DIRS = (
    "/usr/bin/",
    "/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/usr/lib/",
    "/lib/",
    "/lib64/",
    "/usr/lib64/",
    "/snap/",
    "/var/lib/flatpak/",
    "/usr/share/"
)

SUSPICIOUS_UNTRUSTED_DIRS = (
    "/tmp",
    "/dev/shm",
    "/var/tmp"
)

class SystemWhitelist:
    def __init__(self, storage_file: Optional[str] = None):
        if storage_file:
            self.storage_file = storage_file
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.storage_file = DEFAULT_WHITELIST_FILE
        else:
            self.storage_file = USER_WHITELIST_FILE

        self.user_whitelisted_paths: Set[str] = set()
        self.user_whitelisted_hashes: Set[str] = set()
        self._load_whitelist()

    def _ensure_dir(self):
        d = os.path.dirname(self.storage_file)
        if d:
            os.makedirs(d, exist_ok=True)

    def _load_whitelist(self):
        self._ensure_dir()
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r") as f:
                    data = json.load(f)
                    self.user_whitelisted_paths = set(data.get("paths", []))
                    self.user_whitelisted_hashes = set(data.get("hashes", []))
            except Exception as e:
                logger.debug("Error cargando whitelist: %s", e)

    def _save_whitelist(self):
        self._ensure_dir()
        try:
            with open(self.storage_file, "w") as f:
                json.dump({
                    "paths": sorted(list(self.user_whitelisted_paths)),
                    "hashes": sorted(list(self.user_whitelisted_hashes))
                }, f, indent=2)
        except Exception as e:
            logger.debug("Error guardando whitelist: %s", e)

    def is_trusted_system_binary(self, file_path: str) -> bool:
        if not file_path:
            return False
        norm_path = os.path.abspath(file_path)
        for susp in SUSPICIOUS_UNTRUSTED_DIRS:
            if norm_path.startswith(susp):
                return False
        for trusted_dir in TRUSTED_SYSTEM_DIRS:
            if norm_path.startswith(trusted_dir):
                return True
        return False

    def is_whitelisted(self, file_path: str, file_hash: Optional[str] = None) -> bool:
        """
        Determina si un archivo debe ser autorizado de inmediato:
        - Si es un binario oficial del sistema de la distribución.
        - Si su ruta exacta o carpeta contenedora está en la lista blanca de usuario.
        - Si su hash SHA-256 está explícitamente autorizado.
        """
        if not file_path:
            return False

        norm_path = os.path.abspath(file_path)

        # 1. Comprobar exclusiones explícitas de usuario (archivo exacto o carpeta padre)
        for wpath in self.user_whitelisted_paths:
            if norm_path == wpath:
                return True
            # Si wpath es una carpeta, autorizar todo su contenido
            if os.path.isdir(wpath) and norm_path.startswith(os.path.join(wpath, "")):
                return True

        if file_hash and file_hash.lower() in self.user_whitelisted_hashes:
            return True

        # 2. Comprobar binarios del sistema
        return self.is_trusted_system_binary(norm_path)

    def add_path(self, path: str) -> bool:
        """Agrega un archivo o carpeta a la lista blanca permanente."""
        if not os.path.exists(path):
            return False
        norm_path = os.path.abspath(path)
        self.user_whitelisted_paths.add(norm_path)
        self._save_whitelist()
        logger.info("Añadido a Whitelist: %s", norm_path)
        return True

    def remove_path(self, path: str) -> bool:
        """Remueve un archivo o carpeta de la lista blanca."""
        norm_path = os.path.abspath(path)
        if norm_path in self.user_whitelisted_paths:
            self.user_whitelisted_paths.remove(norm_path)
            self._save_whitelist()
            logger.info("Removido de Whitelist: %s", norm_path)
            return True
        return False

    def add_restored_exception(self, file_path: str, file_hash: Optional[str] = None):
        """Añade automáticamente un archivo restaurado a la lista blanca."""
        norm_path = os.path.abspath(file_path)
        self.user_whitelisted_paths.add(norm_path)
        if file_hash:
            self.user_whitelisted_hashes.add(file_hash.lower())
        self._save_whitelist()
        logger.info("🛡️ Archivo restaurado añadido a la Lista Blanca (Whitelist): %s", norm_path)

    def list_entries(self) -> List[Dict[str, str]]:
        """Devuelve todas las entradas de lista blanca de usuario formateadas para la UI."""
        entries = []
        for p in sorted(list(self.user_whitelisted_paths)):
            ptype = "Carpeta" if os.path.isdir(p) else "Archivo"
            entries.append({"path": p, "type": ptype, "status": "Autorizado"})
        for h in sorted(list(self.user_whitelisted_hashes)):
            entries.append({"path": f"Hash SHA-256: {h}", "type": "Firma Hash", "status": "Autorizado"})
        return entries
