"""
Constantine Antivirus - Native Linux Update Guard (core/engine/update_guard.py)
Monitoreo de parches de seguridad, kernels y actualizaciones de paquetes del sistema:
- Detecta el gestor de paquetes de la distribución (APT / dpkg) y parches pendientes.
- Identifica actualizaciones críticas de seguridad y del Kernel de Linux.
- Lanza de forma no intrusiva el Gestor de Actualizaciones oficial de cada distribución:
  * Linux Mint: mintupdate
  * Ubuntu / Debian: update-manager (Gestor de Actualizaciones de Ubuntu / GNOME)
  * Fallback universal: software-properties-gtk / gnome-software / synaptic
"""

import os
import shutil
import subprocess
import logging
from typing import Dict, Optional

logger = logging.getLogger("constantine.updates")

class SystemUpdateGuard:
    def __init__(self):
        # Gestores gráficos nativos por distribución
        self.update_managers = [
            "mintupdate",              # Linux Mint Update Manager
            "update-manager",          # Ubuntu / Debian Update Manager
            "gnome-software",          # GNOME Software Center
            "plasma-discover",         # KDE Discover
            "synaptic"                 # Gestor de paquetes universal
        ]

    def find_native_update_manager(self) -> Optional[str]:
        """Detecta el gestor de actualizaciones nativo instalado en la distribución."""
        for mgr in self.update_managers:
            path = shutil.which(mgr)
            if path:
                return path
        return None

    def check_pending_updates(self) -> Dict:
        """
        Consulta de manera no intrusiva y sin bloquear la pantalla si existen
        actualizaciones de paquetes, seguridad o kernel pendientes.
        """
        info = {
            "has_updates": False,
            "total_updates": 0,
            "security_updates": 0,
            "kernel_upgrade_available": False,
            "current_kernel": os.uname().release,
            "manager_name": os.path.basename(self.find_native_update_manager() or "apt")
        }

        # 1. Comprobación rápida en Ubuntu/Mint vía /usr/lib/update-notifier
        update_notifier_file = "/var/lib/update-notifier/updates-available"
        if os.path.exists(update_notifier_file):
            try:
                with open(update_notifier_file, "r") as f:
                    content = f.read()
                    # Analizar texto típico: "15 updates can be applied immediately. 3 are security updates."
                    for line in content.splitlines():
                        if "can be applied" in line or "pueden aplicarse" in line:
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                info["total_updates"] = int(parts[0])
                        if "security" in line or "seguridad" in line:
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                info["security_updates"] = int(parts[0])
            except Exception:
                pass

        # 2. Comprobación de paquetes con apt-get -s upgrade si no hay caché gráfico
        if info["total_updates"] == 0 and shutil.which("apt-get"):
            try:
                cmd = ["apt-get", "-s", "upgrade"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    lines = res.stdout.splitlines()
                    for line in lines:
                        if "upgraded," in line or "actualizados," in line:
                            parts = line.split()
                            if parts and parts[0].isdigit():
                                info["total_updates"] = int(parts[0])
                        if "linux-image-" in line or "linux-headers-" in line:
                            info["kernel_upgrade_available"] = True
            except Exception:
                pass

        info["has_updates"] = info["total_updates"] > 0
        return info

    def launch_system_update_manager(self) -> bool:
        """
        Invoca la herramienta gráfica oficial del sistema operativo para que el usuario
        revise, elija e instale las actualizaciones con sus propias credenciales.
        """
        mgr = self.find_native_update_manager()
        if not mgr:
            # Fallback en terminal si no hay entorno gráfico
            logger.warning("No se encontró gestor gráfico de actualizaciones.")
            return False

        try:
            subprocess.Popen([mgr], start_new_session=True)
            logger.info("Lanzado el gestor oficial de actualizaciones: %s", mgr)
            return True
        except Exception as e:
            logger.error("Error al invocar %s: %s", mgr, e)
            return False
