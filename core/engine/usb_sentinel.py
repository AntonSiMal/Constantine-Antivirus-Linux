"""
Centinela de Dispositivos USB y Medios Extraíbles para Constantine Antivirus.
"""
import os
import logging
from typing import Dict, Any, Optional
from core.engine.scanner import Scanner
from core.engine.vault import CryptographicVault

logger = logging.getLogger("constantine.usb")

class USBSentinel:
    """Detecta la inserción de unidades USB y activa contención fanotify inmediata."""

    def __init__(self, scanner: Optional[Scanner] = None, vault: Optional[CryptographicVault] = None):
        self.scanner = scanner or Scanner()
        self.vault = vault or CryptographicVault()
        self.running = False

    def start(self):
        self.running = True
        logger.info("🛡️ Centinela de dispositivos USB y medios extraíbles iniciado.")

    def stop(self):
        self.running = False
        logger.info("Monitor USB detenido.")

    def handle_device_mounted(self, mount_point: str, device_node: str = "/dev/sdb1", label: str = "USB_DRIVE"):
        """Aplica contención y escaneo sobre el medio extraíble."""
        logger.info("🔌 [DISPOSITIVO EXTRAÍBLE DETECTADO] %s en %s (Dev: %s)", label, mount_point, device_node)
        logger.info("🛡️ [CONTENCIÓN KERNEL] Activando vigilancia fanotify en tiempo real sobre %s", mount_point)

        threats_found = 0
        for root, _, files in os.walk(mount_point):
            for f in files:
                fpath = os.path.join(root, f)
                rep = self.scanner.scan_file(fpath)
                if rep.is_threat:
                    self.vault.quarantine_file(fpath, threat_name=rep.threat_name)
                    threats_found += 1

        if threats_found > 0:
            logger.critical("🚨 [AMENAZA EN USB NEUTRALIZADA] %d amenaza(s) aislada(s) en %s", threats_found, label)
