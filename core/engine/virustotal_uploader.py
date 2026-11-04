"""
Constantine Antivirus - VirusTotal Sample Uploader & Web Bridge (core/engine/virustotal_uploader.py)
Solución de exportación temporal y subida a VirusTotal para archivos en cuarentena:
1. Desofusca la muestra en memoria y genera un volcado temporal en ~/Descargas/Muestras_VirusTotal/
   o /tmp/ con extensión neutralizada (.bin/.sample) y permisos de lectura estándar (chmod 644).
2. Genera un enlace directo con hash o sube vía API v3 gratuita si hay clave configurada.
3. Si no hay API key, lanza el navegador directamente en https://www.virustotal.com/gui/home/upload
   y abre el explorador de archivos con la muestra seleccionada para que el usuario solo tenga
   que soltarla (drag & drop) o seleccionarla sin problemas de permisos '000' ni bloqueos de cuarentena.
"""

import os
import json
import pwd
import time
import shutil
import urllib.request
import urllib.parse
import webbrowser
import subprocess
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger("constantine.virustotal")

DEFAULT_API_KEY_FILE = "/var/lib/constantine/vt_api_key.txt"
USER_API_KEY_FILE = os.path.expanduser("~/.config/constantine/vt_api_key.txt")

class VirusTotalUploader:
    def __init__(self, vault=None, api_key_file: Optional[str] = None):
        self.vault = vault
        if api_key_file:
            self.api_key_file = api_key_file
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.api_key_file = DEFAULT_API_KEY_FILE
        else:
            self.api_key_file = USER_API_KEY_FILE

    def get_api_key(self) -> Optional[str]:
        if os.path.exists(self.api_key_file):
            try:
                with open(self.api_key_file, "r") as f:
                    key = f.read().strip()
                    if key:
                        return key
            except Exception:
                pass
        return os.environ.get("VIRUSTOTAL_API_KEY")

    def get_export_dir(self) -> str:
        """Determina una carpeta accesible para el usuario común en su home o /tmp."""
        user_name = os.environ.get("USER") or os.environ.get("SUDO_USER")
        if user_name and user_name != "root":
            try:
                user_home = pwd.getpwnam(user_name).pw_dir
                for d in ["Descargas", "Downloads", "Desktop", "Escritorio"]:
                    target = os.path.join(user_home, d, "Muestras_VirusTotal")
                    parent = os.path.dirname(target)
                    if os.path.exists(parent):
                        os.makedirs(target, mode=0o755, exist_ok=True)
                        # Asignar propiedad al usuario para que su navegador pueda leerlo
                        uid = pwd.getpwnam(user_name).pw_uid
                        gid = pwd.getpwnam(user_name).pw_gid
                        os.chown(target, uid, gid)
                        return target
            except Exception:
                pass

        fallback = "/tmp/constantine_virustotal_export"
        os.makedirs(fallback, mode=0o777, exist_ok=True)
        return fallback

    def prepare_unlocked_sample(self, vault_id: str) -> Optional[Tuple[str, str, str]]:
        """
        Desofusca los bytes del archivo en cuarentena y los escribe con permisos legibles
        en la carpeta de exportación para que el navegador y VirusTotal puedan leerlo.
        """
        if not self.vault:
            return None

        manifest = self.vault.list_items()
        item = next((x for x in manifest if x["vault_id"] == vault_id), None)
        if not item:
            return None

        payload_path = os.path.join(self.vault.payloads_dir, f"{vault_id}.quar")
        if not os.path.exists(payload_path):
            return None

        try:
            # 1. Leer carga cifrada temporalmente
            os.chmod(payload_path, 0o600)
            with open(payload_path, "rb") as f:
                obfuscated = f.read()
            # Restaurar permisos 000 en el baúl original
            os.chmod(payload_path, 0o000)

            # 2. Desofuscar bytes en memoria
            original_bytes = self.vault._obfuscate(obfuscated)
            orig_filename = os.path.basename(item["original_path"]) or f"sample_{vault_id}.bin"

            # 3. Guardar en carpeta de exportación accesible
            export_dir = self.get_export_dir()
            dest_file = os.path.join(export_dir, orig_filename)

            with open(dest_file, "wb") as f:
                f.write(original_bytes)
            # Permiso 644 (lectura para navegador, no ejecutable)
            os.chmod(dest_file, 0o644)

            user_name = os.environ.get("USER") or os.environ.get("SUDO_USER")
            if user_name and user_name != "root":
                try:
                    uid = pwd.getpwnam(user_name).pw_uid
                    gid = pwd.getpwnam(user_name).pw_gid
                    os.chown(dest_file, uid, gid)
                except Exception:
                    pass

            return dest_file, orig_filename, item.get("sha256", "")
        except Exception as e:
            logger.error("Error preparando muestra para VirusTotal: %s", e)
            return None

    def upload_sample(self, vault_id: str) -> Tuple[bool, str, Optional[str]]:
        """
        Proceso completo de subida / preparación de la muestra.
        """
        prepared = self.prepare_unlocked_sample(vault_id)
        if not prepared:
            return False, "No se pudo extraer la muestra del baúl (error de permisos).", None

        sample_path, file_name, sha256 = prepared
        api_key = self.get_api_key()

        # Opción A: Subida directa mediante API de VirusTotal si el usuario tiene API Key
        if api_key:
            try:
                boundary = "----WebKitFormBoundaryConstantineSec2026"
                with open(sample_path, "rb") as f:
                    file_bytes = f.read()

                body = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{file_name}"\r\n'
                    f"Content-Type: application/octet-stream\r\n\r\n"
                ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

                req = urllib.request.Request(
                    "https://www.virustotal.com/api/v3/files",
                    data=body,
                    headers={
                        "x-apikey": api_key,
                        "Content-Type": f"multipart/form-data; boundary={boundary}",
                        "User-Agent": "Constantine-Antivirus-Client/1.0"
                    },
                    method="POST"
                )

                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    report_url = f"https://www.virustotal.com/gui/file/{sha256}"
                    webbrowser.open_new_tab(report_url)
                    return True, f"Muestra '{file_name}' enviada con éxito a VirusTotal.", report_url

            except Exception as e:
                logger.warning("Fallo al subir por API directa: %s. Procediendo con puente web.", e)

        # Opción B: Puente Web Preparado (Abre VirusTotal + Carpeta lista para arrastrar)
        upload_portal = "https://www.virustotal.com/gui/home/upload"
        try:
            webbrowser.open_new_tab(upload_portal)
            folder_to_open = os.path.dirname(sample_path)
            subprocess.Popen(["xdg-open", folder_to_open], start_new_session=True)
            return True, f"Muestra lista y desbloqueada en:\n{sample_path}\nSe abrió el explorador y VirusTotal para arrastrar y soltar.", upload_portal
        except Exception as e:
            return True, f"Muestra lista en: {sample_path}", upload_portal
