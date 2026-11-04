"""
Constantine Antivirus - Auto-Updater & Version Checker (core/engine/auto_updater.py)
Rutina de comprobación y actualización automática de la aplicación:
1. Comprueba si existe una versión más reciente en GitHub (AntonSiMal/Constantine-Antivirus-Linux).
2. Notifica al usuario de forma no invasiva con las notas de la versión.
3. Descarga y aplica la actualización de forma segura solicitando privilegios sudo/PAM.
4. Reinicia el demonio de fondo y recarga la interfaz.
"""

import os
import sys
import json
import shutil
import urllib.request
import subprocess
import logging
from typing import Dict, Optional, Tuple

logger = logging.getLogger("constantine.updater")

CURRENT_VERSION = "1.3.0"
GITHUB_REPO = "AntonSiMal/Constantine-Antivirus-Linux"
VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/VERSION"
RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"

class ConstantineUpdater:
    def __init__(self, current_version: str = CURRENT_VERSION):
        self.current_version = current_version
        self.repo = GITHUB_REPO

    def _parse_version(self, ver_str: str) -> Tuple[int, ...]:
        clean = ver_str.strip().lstrip("v").split("-")[0]
        try:
            return tuple(int(x) for x in clean.split("."))
        except Exception:
            return (0, 0, 0)

    def check_for_updates(self) -> Dict:
        """
        Consulta en segundo plano la última versión publicada en GitHub.
        Retorna diccionario con estado de actualización.
        """
        result = {
            "update_available": False,
            "current_version": self.current_version,
            "latest_version": self.current_version,
            "release_notes": "Constantine Antivirus se encuentra al día con los últimos parches y firmas.",
            "download_url": f"https://github.com/{self.repo}/archive/refs/heads/main.tar.gz"
        }

        # 1. Intentar consultar VERSION plano desde raw.githubusercontent.com
        try:
            req = urllib.request.Request(
                VERSION_URL,
                headers={"User-Agent": "Constantine-Antivirus-Client/1.0"}
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                remote_ver = response.read().decode("utf-8").strip()

                if self._parse_version(remote_ver) > self._parse_version(self.current_version):
                    result["update_available"] = True
                    result["latest_version"] = remote_ver
                    result["release_notes"] = f"Nueva versión v{remote_ver} disponible con mejoras de kernel, nuevas reglas YARA y parches de rendimiento."
                    return result
        except Exception as e:
            logger.debug("Comprobación por VERSION url falló o sin red: %s", e)

        # 2. Intentar consultar Releases API
        try:
            req = urllib.request.Request(
                RELEASES_API_URL,
                headers={"User-Agent": "Constantine-Antivirus-Client/1.0"}
            )
            with urllib.request.urlopen(req, timeout=4) as response:
                data = json.loads(response.read().decode("utf-8"))
                tag_name = data.get("tag_name", "").strip()
                if tag_name and self._parse_version(tag_name) > self._parse_version(self.current_version):
                    result["update_available"] = True
                    result["latest_version"] = tag_name
                    result["release_notes"] = data.get("body", result["release_notes"])
                    return result
        except Exception as e:
            logger.debug("Comprobación por Releases API falló: %s", e)

        return result

    def execute_update(self, target_dir: str = "/opt/constantine") -> Tuple[bool, str]:
        """
        Descarga e instala la última versión directamente desde el repositorio oficial.
        """
        if os.geteuid() != 0 and shutil.which("pkexec") is None:
            return False, "Se requieren privilegios de administrador para actualizar los archivos del sistema."

        # Estrategia 1: Si es una instalación clonada con Git, usar git pull
        git_dir = os.path.join(target_dir, ".git")
        if os.path.exists(git_dir) and shutil.which("git"):
            try:
                cmd = ["git", "-C", target_dir, "pull", "origin", "main"]
                if os.geteuid() != 0 and shutil.which("pkexec"):
                    cmd = ["pkexec"] + cmd
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if res.returncode == 0:
                    self._restart_daemon()
                    return True, "Actualización aplicada exitosamente mediante Git."
            except Exception as e:
                logger.error("Fallo al actualizar vía git pull: %s", e)

        # Estrategia 2: Descargar tarball comprimido de GitHub y extraer
        temp_tar = "/tmp/constantine_latest.tar.gz"
        extract_dir = "/tmp/constantine_update_extracted"
        try:
            url = f"https://github.com/{self.repo}/archive/refs/heads/main.tar.gz"
            urllib.request.urlretrieve(url, temp_tar)

            shutil.rmtree(extract_dir, ignore_errors=True)
            os.makedirs(extract_dir, exist_ok=True)

            subprocess.run(["tar", "-xzf", temp_tar, "-C", extract_dir], check=True, timeout=30)
            
            # Buscar carpeta extraída
            extracted_sub = [os.path.join(extract_dir, d) for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
            if extracted_sub:
                source_update = extracted_sub[0]
                # Copiar sobre /opt/constantine
                cmd = ["cp", "-r", f"{source_update}/core", f"{source_update}/gui", f"{source_update}/service", f"{source_update}/daemon.py", target_dir]
                if os.geteuid() != 0 and shutil.which("pkexec"):
                    cmd = ["pkexec"] + cmd
                subprocess.run(cmd, check=True, timeout=30)
                self._restart_daemon()
                return True, "Archivos de Constantine actualizados a la última versión oficial."
        except Exception as e:
            return False, f"Error durante la descarga o reemplazo de archivos: {e}"

        return False, "No se pudo completar el proceso de actualización."

    def _restart_daemon(self):
        try:
            cmd = ["systemctl", "restart", "constantine.service"]
            if os.geteuid() != 0 and shutil.which("pkexec"):
                cmd = ["pkexec"] + cmd
            subprocess.run(cmd, check=False, timeout=10)
        except Exception:
            pass
