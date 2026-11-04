"""
Constantine Antivirus - USB & Storage Monitor (core/engine/usb_monitor.py)
Monitoreo no invasivo de memorias USB y discos externos:
- Silencioso por defecto: si el medio está limpio, no interrumpe la pantalla del usuario.
- Si contiene malware o autorun malicioso: lo aísla en el baúl y notifica discretamente.
"""

import os
import time
import logging
import threading
from typing import Callable, Set, Optional

logger = logging.getLogger("constantine.usb")

class USBAutoScanner:
    def __init__(self, scanner, vault=None, notifier=None, interceptor=None, callback: Optional[Callable] = None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.interceptor = interceptor
        self.callback = callback
        self.running = False
        self.thread = None
        self.known_mounts: Set[str] = set()
        self.media_dirs = ["/media", "/run/media", "/mnt"]

    def _get_current_external_mounts(self) -> Set[str]:
        mounts = set()
        if not os.path.exists("/proc/mounts"):
            return mounts
        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        device = parts[0]
                        mount_point = parts[1]
                        if device.startswith(("/dev/sd", "/dev/nvme", "/dev/mmcblk", "/dev/fuse")):
                            for base in self.media_dirs:
                                if mount_point.startswith(base) and mount_point != base:
                                    mounts.add(mount_point)
        except Exception:
            pass
        return mounts

    def start(self):
        self.known_mounts = self._get_current_external_mounts()
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Monitor silencioso de almacenamiento USB iniciado.")

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(1.5)
                current = self._get_current_external_mounts()
                new_mounts = current - self.known_mounts
                for mount in new_mounts:
                    self.on_device_connected(mount)
                self.known_mounts = current
            except Exception:
                pass

    def on_device_connected(self, mount_point: str):
        device_name = os.path.basename(mount_point)

        # 1. Enganche fanotify preventivo en silencio
        if self.interceptor:
            self.interceptor.mark_directory(mount_point)

        # 2. Escaneo silencioso en segundo plano
        threats_found = 0
        try:
            for root, dirs, files in os.walk(mount_point):
                for f in files:
                    file_path = os.path.join(root, f)
                    f_lower = f.lower()
                    is_suspicious_name = f_lower in ("autorun.inf", "autorun.vbs", "autorun.bat", "run.sh")

                    scan_res = self.scanner.scan_file(file_path=file_path)
                    if scan_res.is_malicious or is_suspicious_name:
                        threats_found += 1
                        threat_name = scan_res.threat_name or "USB.MaliciousAutorun.Dropper"
                        if self.vault:
                            self.vault.quarantine_file(file_path, threat_name, detected_by="USB-AutoScanner")

            # 3. Filosofía Zero-Nag: SOLO alertar si se detectaron amenazas
            if threats_found > 0:
                if self.notifier:
                    self.notifier.send(
                        title="⚠️ Amenaza Neutralizada en USB",
                        body=f"Se aisló un autorun/malware en <b>{device_name}</b> y fue enviado al Baúl.",
                        urgency="critical",
                        icon="security-high"
                    )
            else:
                # Si está limpio, NO interrumpir al usuario con popups molestos; registrar en log silencioso
                logger.info("Dispositivo USB %s analizado silenciosamente: 0 amenazas.", device_name)

            if self.callback:
                self.callback(mount_point, threats_found)
        except Exception as e:
            logger.debug("Error escaneando USB: %s", e)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
