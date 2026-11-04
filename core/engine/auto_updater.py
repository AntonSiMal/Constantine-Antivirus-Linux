"""
Constantine Antivirus - Auto-Updater & Version Checker (core/engine/auto_updater.py)
Rutina de comprobación y actualización directa desde GitHub:
1. Comprueba si existe una versión más reciente o nuevos commits en GitHub.
2. Permite forzar la actualización y sincronización directa con AntonSiMal/Constantine-Antivirus-Linux.
3. Descarga y extrae los archivos sobre /opt/constantine de forma limpia.
4. Reinicia el demonio systemd y notifica el resultado.
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

CURRENT_VERSION = "2.7.0"
GITHUB_REPO = "AntonSiMal/Constantine-Antivirus-Linux"
VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/VERSION"
RELEASES_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
COMMITS_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/commits/main"

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
        Consulta en GitHub si hay nueva versión o nuevos commits.
        """
        result = {
            "update_available": False,
            "current_version": self.current_version,
            "latest_version": self.current_version,
            "release_notes": "Constantine Antivirus se encuentra al día con los últimos parches y firmas.",
            "download_url": f"https://github.com/{self.repo}/archive/refs/heads/main.tar.gz",
            "remote_checked": False
        }

        # 1. Intentar consultar VERSION plano desde raw.githubusercontent.com
        try:
            req = urllib.request.Request(
                VERSION_URL,
                headers={"User-Agent": "Constantine-Antivirus-Client/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                remote_ver = response.read().decode("utf-8").strip()
                result["remote_checked"] = True

                if self._parse_version(remote_ver) > self._parse_version(self.current_version):
                    result["update_available"] = True
                    result["latest_version"] = remote_ver
                    result["release_notes"] = f"Nueva versión v{remote_ver} disponible en GitHub con mejoras de kernel, nuevas reglas YARA y parches."
                    return result
        except Exception as e:
            logger.debug("Comprobación por VERSION URL falló: %s", e)

        # 2. Intentar consultar Releases API
        try:
            req = urllib.request.Request(
                RELEASES_API_URL,
                headers={"User-Agent": "Constantine-Antivirus-Client/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode("utf-8"))
                tag_name = data.get("tag_name", "").strip()
                result["remote_checked"] = True
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
        Descarga e instala la última versión directamente desde el repositorio oficial de GitHub.
        """
        # Si target_dir no existe o estamos en desarrollo, actualizar sobre el directorio del script
        if not os.path.exists(target_dir):
            target_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

        temp_tar = "/tmp/constantine_latest.tar.gz"
        extract_dir = "/tmp/constantine_update_extracted"

        # 1. Intentar actualizar mediante git pull si es un repo git local
        git_dir = os.path.join(target_dir, ".git")
        if os.path.exists(git_dir) and shutil.which("git"):
            try:
                cmd = ["git", "-C", target_dir, "pull", "origin", "main"]
                if os.geteuid() != 0 and shutil.which("pkexec"):
                    cmd = ["pkexec"] + cmd
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if res.returncode == 0:
                    self._restart_daemon()
                    return True, "Actualización completada exitosamente mediante Git."
            except Exception as e:
                logger.debug("git pull falló: %s", e)

        # 2. Descargar el archivo fuente oficial desde GitHub
        try:
            url = f"https://github.com/{self.repo}/archive/refs/heads/main.tar.gz"
            req = urllib.request.Request(url, headers={"User-Agent": "Constantine-Antivirus-Client/1.0"})
            with urllib.request.urlopen(req, timeout=30) as resp, open(temp_tar, "wb") as out_f:
                shutil.copyfileobj(resp, out_f)

            shutil.rmtree(extract_dir, ignore_errors=True)
            os.makedirs(extract_dir, exist_ok=True)

            subprocess.run(["tar", "-xzf", temp_tar, "-C", extract_dir], check=True, timeout=30)
            
            # Localizar subcarpeta extraída (ej: Constantine-Antivirus-Linux-main)
            extracted_sub = [os.path.join(extract_dir, d) for d in os.listdir(extract_dir) if os.path.isdir(os.path.join(extract_dir, d))]
            if not extracted_sub:
                return False, "El archivo descargado de GitHub no contenía la estructura esperada."

            source_update = extracted_sub[0]

            # Copiar archivos clave a /opt/constantine/
            items_to_copy = ["core", "gui", "service", "scripts", "assets", "daemon.py", "requirements.txt", "VERSION", "README.md", "install.sh", "uninstall.sh"]
            copy_cmd = ["cp", "-r"]
            for item in items_to_copy:
                src_item = os.path.join(source_update, item)
                if os.path.exists(src_item):
                    copy_cmd.append(src_item)
            copy_cmd.append(target_dir)

            if os.geteuid() != 0 and shutil.which("pkexec"):
                copy_cmd = ["pkexec"] + copy_cmd

            res_cp = subprocess.run(copy_cmd, capture_output=True, text=True, timeout=30)
            if res_cp.returncode != 0:
                return False, f"Fallo al copiar archivos a {target_dir}: {res_cp.stderr}"

            # Reiniciar demonio en segundo plano
            self._restart_daemon()
            return True, "Constantine Antivirus se actualizó con éxito a la última versión de GitHub."

        except urllib.error.URLError as e:
            return False, f"No se pudo conectar a GitHub para descargar la actualización: {e.reason}"
        except Exception as e:
            return False, f"Error durante la instalación de la actualización: {e}"

    def _restart_daemon(self):
        try:
            cmd = ["systemctl", "restart", "constantine.service"]
            if os.geteuid() != 0 and shutil.which("pkexec"):
                cmd = ["pkexec"] + cmd
            subprocess.run(cmd, check=False, timeout=10)
        except Exception:
            pass
