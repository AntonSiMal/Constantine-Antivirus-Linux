"""
Constantine Antivirus - Proton VPN Integration (core/engine/vpn_manager.py)
Separación estricta de responsabilidades (Arquitectura Constantine 5.x):
1. Responsabilidad de Constantine:
   - Instalación y provisión de acceso directo al cliente oficial de Proton VPN.
2. Responsabilidad exclusiva del usuario:
   - Administración completa de Proton VPN: inicio de sesión, conexión, desconexión,
     selección de servidores, perfiles y protocolos.
3. Principio de no intrusión:
   - Constantine NO establece conexiones VPN.
   - Constantine NO selecciona servidores, protocolos ni ubicaciones.
   - Constantine NO supervisa ni administra el túnel VPN.
"""

import os
import shutil
import subprocess
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("constantine.vpn")


class VPNManager:
    """Gestor de Detección y Acceso Directo de Proton VPN."""

    def __init__(self):
        self.proton_candidates = [
            "protonvpn-app",
            "protonvpn",
            "proton-vpn-gnome-desktop",
            "protonvpn-cli"
        ]

    def find_proton_vpn(self) -> Optional[str]:
        for candidate in self.proton_candidates:
            path = shutil.which(candidate)
            if path:
                return path
        return None

    def is_installed(self) -> bool:
        return self.find_proton_vpn() is not None

    def launch(self) -> bool:
        """Lanza el cliente oficial de Proton VPN para administración exclusiva del usuario."""
        binary = self.find_proton_vpn()
        if not binary:
            return False
        try:
            subprocess.Popen([binary], start_new_session=True)
            return True
        except Exception as e:
            logger.error("Error al lanzar Proton VPN: %s", e)
            return False

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna el estado de instalación y la política de separación de responsabilidades."""
        installed = self.is_installed()
        binary = self.find_proton_vpn()
        return {
            "installed": installed,
            "binary": binary,
            "provider": "Proton VPN",
            "managed_by_user": True,
            "details": (
                "Cliente oficial Proton VPN disponible para administración manual del usuario."
                if installed
                else "Proton VPN no está instalado en este equipo."
            )
        }
