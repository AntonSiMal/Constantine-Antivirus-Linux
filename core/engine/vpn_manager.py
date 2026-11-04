"""
Constantine Antivirus - Proton VPN Integration (core/engine/vpn_manager.py)
"""
import os
import shutil
import subprocess
import logging
from typing import Optional

logger = logging.getLogger("constantine.vpn")

class VPNManager:
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
        binary = self.find_proton_vpn()
        if not binary:
            return False
        try:
            subprocess.Popen([binary], start_new_session=True)
            return True
        except Exception:
            return False
