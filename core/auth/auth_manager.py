"""
Módulo de Gestión de Autorización Nativa y Delegación Polkit para Constantine Antivirus.
"""
import os
import shutil
import logging
import subprocess
from typing import Optional, Tuple

logger = logging.getLogger("constantine.auth")

class AuthManager:
    """Administrador de autenticación y autorización delegada Polkit."""

    def __init__(self, action_id: str = "org.constantine.antivirus.admin.unlock"):
        self.action_id = action_id
        self._pkcheck_bin = shutil.which("pkcheck") or "/usr/bin/pkcheck"

    def is_polkit_available(self) -> bool:
        """Determina si la utilidad pkcheck de Polkit está disponible en el sistema."""
        return os.path.exists(self._pkcheck_bin) and os.access(self._pkcheck_bin, os.X_OK)

    def check_authorization(self, pid: int, uid: int, action: Optional[str] = None) -> Tuple[bool, str]:
        """
        Verifica la autorización del llamador ante Polkit.
        Si el llamador es root (uid == 0), se autoriza de forma inmediata.
        Para usuarios estándar, se consulta a pkcheck.
        """
        if uid == 0:
            return True, "Root autorizado de forma inherente"

        target_action = action or self.action_id
        if not self.is_polkit_available():
            return False, "Polkit (pkcheck) no disponible en el sistema"

        cmd = [
            self._pkcheck_bin,
            "--process", str(pid),
            "--action-id", target_action,
            "--allow-user-interaction"
        ]

        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            if res.returncode == 0:
                logger.info("Autorización Polkit exitosa para acción: %s", target_action)
                return True, "Autorizado por Polkit"
            else:
                err_msg = res.stderr.decode("utf-8", errors="ignore").strip() or "Not authorized"
                logger.warning("Autorización Polkit denegada o cancelada: %s", err_msg)
                return False, f"Polkit denegó la operación: {err_msg}"
        except subprocess.TimeoutExpired:
            logger.error("Timeout durante consulta a Polkit para PID %d", pid)
            return False, "Timeout de autorización"
        except Exception as e:
            logger.error("Error inesperado en consulta a Polkit: %s", e)
            return False, str(e)
