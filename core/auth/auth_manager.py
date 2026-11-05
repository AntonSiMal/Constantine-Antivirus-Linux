"""
Constantine Antivirus - Native Linux System Authentication (core/auth/auth_manager.py)
Autenticación nativa contra PAM y privilegios sudo/root de Linux.
Elimina contraseñas maestras propietarias o archivos locales inseguros:
- Valida la contraseña del usuario actual contra el sistema operativo (PAM/sudo)
- Verifica que el usuario pertenezca al grupo administrativo (sudo / wheel)
- Genera tokens de sesión temporales (15 minutos) para el panel de control
"""

import os
import pwd
import grp
import time
import secrets
import subprocess
import logging
from typing import Optional, Dict, Tuple

logger = logging.getLogger("constantine.auth")

class AuthManager:
    def __init__(self, session_timeout_secs: int = 900):
        self.session_timeout = session_timeout_secs
        self.active_sessions: Dict[str, float] = {}

    def get_current_user(self) -> str:
        """Devuelve el nombre del usuario de la sesión actual."""
        try:
            return pwd.getpwuid(os.getuid()).pw_name
        except Exception:
            return os.environ.get("USER", "root")

    def is_user_in_sudoers(self, username: Optional[str] = None) -> bool:
        """Verifica si el usuario tiene privilegios para administrar el sistema (sudo/wheel/root)."""
        username = username or self.get_current_user()
        if username == "root":
            return True

        admin_groups = {"sudo", "wheel", "admin"}
        try:
            # Obtener todos los grupos a los que pertenece el usuario
            user_entry = pwd.getpwnam(username)
            groups = [g.gr_name for g in grp.getgrall() if username in g.gr_mem]
            primary_group = grp.getgrgid(user_entry.pw_gid).gr_name
            groups.append(primary_group)

            return any(g in admin_groups for g in groups)
        except Exception as e:
            logger.debug("Error comprobando grupos para %s: %s", username, e)
            return False

    def is_polkit_available(self) -> bool:
        """Determina si las herramientas de Polkit (pkcheck / pkexec) están presentes en el sistema."""
        import shutil
        return shutil.which("pkcheck") is not None

    def request_polkit_authorization(self, action_id: str = "org.constantine.antivirus.admin.unlock", timeout: int = 35) -> Tuple[bool, Optional[str]]:
        """
        Solicita autorización interactiva a través de Polkit (https://github.com/polkit-org/polkit).
        Invoca el agente de autenticación nativo del escritorio (GNOME/KDE/Polkit) para que el
        usuario ingrese su contraseña en el diálogo seguro del sistema operativo,
        evitando que la GUI de Constantine maneje contraseñas en memoria de proceso.
        """
        if not self.is_polkit_available():
            return False, None

        cmd = [
            "pkcheck",
            f"--action-id={action_id}",
            f"--process={os.getpid()}",
            "--allow-user-interaction"
        ]

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            if res.returncode == 0:
                token = secrets.token_hex(24)
                self.active_sessions[token] = time.time() + self.session_timeout
                logger.info("Autorización Polkit exitosa para acción: %s", action_id)
                return True, token
            else:
                logger.warning("Autorización Polkit denegada o cancelada: %s", res.stderr.decode("utf-8", errors="ignore"))
                return False, None
        except Exception as e:
            logger.debug("Error invocando pkcheck para %s: %s", action_id, e)
            return False, None

    def execute_privileged_helper(self, action: str, *args, timeout: int = 40) -> Tuple[bool, str]:
        """
        Ejecuta una acción administrativa privilegiada a través de pkexec y constantine-helper.
        """
        helper_candidates = [
            "/opt/constantine/service/constantine-helper",
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "service", "constantine-helper")
        ]
        helper_path = next((p for p in helper_candidates if os.path.exists(p)), None)
        if not helper_path:
            return False, "constantine-helper no encontrado"

        cmd = ["pkexec", helper_path, action] + list(args)
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            out = res.stdout.decode("utf-8", errors="ignore").strip()
            err = res.stderr.decode("utf-8", errors="ignore").strip()
            return res.returncode == 0, out or err
        except Exception as e:
            return False, str(e)

    def authenticate_system(self, password: str, username: Optional[str] = None) -> Optional[str]:
        """
        Valida la contraseña directamente contra el subsistema de autenticación de Linux (PAM/sudo).
        No guarda contraseñas en archivos locales ni usa claves por defecto.
        """
        user = username or self.get_current_user()

        if not password:
            return None

        # 1. Comprobar pertenencia a grupos administrativos si no es root
        if user != "root" and not self.is_user_in_sudoers(user):
            logger.warning("El usuario '%s' no tiene privilegios de administrador (sudo/wheel).", user)
            return None

        # 2. Validación de credenciales con sudo nativo del sistema
        try:
            cmd = ["sudo", "-k", "-S", "-v"]
            if user != self.get_current_user() and os.geteuid() == 0:
                cmd = ["su", "-", user, "-c", "sudo -k -S -v"]

            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE
            )
            _, err = p.communicate(input=f"{password}\n".encode("utf-8"), timeout=5)

            if p.returncode == 0:
                # Generar token de sesión en memoria
                token = secrets.token_hex(24)
                self.active_sessions[token] = time.time() + self.session_timeout
                logger.info("Autenticación de sistema exitosa para el usuario: %s", user)
                return token
            else:
                logger.warning("Contraseña de sudo/root incorrecta para el usuario: %s", user)
                return None
        except Exception as e:
            logger.error("Error en proceso de autenticación de sistema: %s", e)
            return None

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Alias compatible para la interfaz gráfica y scripts."""
        return self.authenticate_system(password, username)

    def is_session_valid(self, token: Optional[str]) -> bool:
        """Verifica si la sesión sigue activa y sin expirar."""
        if not token or token not in self.active_sessions:
            return False
        expires = self.active_sessions[token]
        if time.time() > expires:
            del self.active_sessions[token]
            return False
        self.active_sessions[token] = time.time() + self.session_timeout
        return True

    def revoke_session(self, token: str):
        """Cierra la sesión y vuelve a bloquear los controles."""
        if token in self.active_sessions:
            del self.active_sessions[token]
