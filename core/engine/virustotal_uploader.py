"""
Constantine Antivirus - VirusTotal Sample Uploader & Web Bridge (core/engine/virustotal_uploader.py)
Solución de exportación temporal y subida a VirusTotal para archivos en cuarentena:
1. Descifrado Explícito Autenticado (AES-256-GCM AEAD):
   - Descifra la muestra del baúl utilizando exclusivamente el método criptográfico del baúl (_decrypt_data).
   - Elimina llamadas erróneas a métodos inexistentes o de re-cifrado (_obfuscate).
2. Verificación Estricta de Integridad Criptográfica (SHA-256 Match):
   - Comprueba que el hash SHA-256 de los bytes recién descifrados coincida exactamente
     con el hash original registrado en el manifiesto de la cuarentena antes de escribir a disco.
   - Si el hash no coincide o el descifrado falla, aborta la operación y previene la exportación
     de datos corruptos.
3. Exportación Controlada en Carpeta Temporal con Permisos Seguros:
   - Guarda la muestra con permisos de lectura 0644 sin bit de ejecución (+x) para que el navegador
     y VirusTotal puedan leerla de forma segura.
"""

import os
import json
import pwd
import time
import shutil
import hashlib
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
        Descifra explícitamente la muestra del baúl (AES-256-GCM),
        verifica su hash SHA-256 contra el registro original del manifiesto
        y la guarda temporalmente con permisos 0644 (no ejecutable).
        """
        if not self.vault:
            logger.error("Baúl no conectado al uploader de VirusTotal.")
            return None

        manifest = self.vault.list_items()
        item = next((x for x in manifest if x["vault_id"] == vault_id), None)
        if not item:
            logger.error("Muestra con ID de baúl %s no encontrada en el manifiesto.", vault_id)
            return None

        payload_path = os.path.join(self.vault.payloads_dir, f"{vault_id}.quar")
        if not os.path.exists(payload_path):
            logger.error("Archivo payload cifrado no existe en el baúl: %s", payload_path)
            return None

        expected_sha256 = item.get("sha256", "").lower().strip()

        try:
            # 1. Leer carga cifrada temporalmente
            try:
                os.chmod(payload_path, 0o600)
            except Exception:
                pass

            with open(payload_path, "rb") as f:
                encrypted_bytes = f.read()

            # Restaurar permisos 000 en el baúl original
            try:
                os.chmod(payload_path, 0o000)
            except Exception:
                pass

            # 2. DESCIFRADO EXPLÍCITO AUTÉNTICO (AES-256-GCM)
            # Se utiliza el método explícito _decrypt_data del baúl (nunca re-cifrado u ofuscación)
            try:
                original_bytes = self.vault._decrypt_data(encrypted_bytes)
            except Exception as dec_err:
                logger.critical("Fallo criptográfico descifrando muestra %s para VirusTotal: %s", vault_id, dec_err)
                return None

            # 3. VERIFICACIÓN CRIPTOGRÁFICA DE INTEGRIDAD (SHA-256 Match)
            actual_sha256 = hashlib.sha256(original_bytes).hexdigest().lower()
            if expected_sha256 and actual_sha256 != expected_sha256:
                logger.critical("🚨 [INTEGRIDAD VIOLADA] El hash de la muestra descifrada no coincide con el manifiesto: %s (Esperado: %s, Real: %s)",
                                vault_id, expected_sha256, actual_sha256)
                return None

            # 4. Guardar en carpeta de exportación accesible con permisos seguros
            orig_filename = os.path.basename(item.get("original_path", "")) or f"sample_{vault_id}.bin"
            # Si el archivo original no tiene extensión neutra, agregar sufijo .sample para prevenir ejecución accidental
            export_filename = f"{orig_filename}.sample" if not orig_filename.endswith((".sample", ".bin")) else orig_filename

            export_dir = self.get_export_dir()
            dest_file = os.path.join(export_dir, export_filename)

            with open(dest_file, "wb") as f:
                f.write(original_bytes)

            # Permiso 644 (lectura para navegador y herramientas forenses, SIN bits de ejecución)
            os.chmod(dest_file, 0o644)

            user_name = os.environ.get("USER") or os.environ.get("SUDO_USER")
            if user_name and user_name != "root":
                try:
                    uid = pwd.getpwnam(user_name).pw_uid
                    gid = pwd.getpwnam(user_name).pw_gid
                    os.chown(dest_file, uid, gid)
                except Exception:
                    pass

            logger.info("✅ Muestra descifrada y verificada con éxito: %s (SHA-256: %s)", dest_file, actual_sha256[:16])
            return dest_file, export_filename, actual_sha256

        except Exception as e:
            logger.error("Error crítico preparando muestra para VirusTotal: %s", e)
            return None

    def upload_sample(self, vault_id: str) -> Tuple[bool, str, Optional[str]]:
        """
        Proceso completo de subida / preparación de la muestra.
        """
        prepared = self.prepare_unlocked_sample(vault_id)
        if not prepared:
            return False, "No se pudo extraer y verificar la muestra del baúl (error criptográfico o de permisos).", None

        sample_path, file_name, sha256 = prepared
        api_key = self.get_api_key()

        # Opción A: Subida directa mediante API v3 de VirusTotal si el usuario tiene API Key
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
                    try:
                        webbrowser.open_new_tab(report_url)
                    except Exception:
                        pass
                    return True, f"Muestra '{file_name}' enviada con éxito a VirusTotal.", report_url

            except Exception as e:
                logger.warning("Fallo al subir por API directa: %s. Procediendo con puente web.", e)

        # Opción B: Puente Web Preparado (Abre VirusTotal + Carpeta lista para arrastrar)
        upload_portal = "https://www.virustotal.com/gui/home/upload"
        try:
            try:
                webbrowser.open_new_tab(upload_portal)
            except Exception:
                pass
            folder_to_open = os.path.dirname(sample_path)
            try:
                subprocess.Popen(["xdg-open", folder_to_open], start_new_session=True)
            except Exception:
                pass
            return True, f"Muestra lista y desbloqueada en:\n{sample_path}\nSe abrió el explorador y VirusTotal para arrastrar y soltar.", upload_portal
        except Exception as e:
            return True, f"Muestra lista en: {sample_path}", upload_portal
