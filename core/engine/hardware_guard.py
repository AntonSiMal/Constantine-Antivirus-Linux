"""
Constantine Antivirus - Hardware & Peripheral Guard (core/engine/hardware_guard.py)
Monitoreo anti-espía de cámara web y micrófono en Linux:
Vigila descriptores en /dev/video* y /dev/snd/* para alertar accesos no autorizados.
"""

import os
import time
import glob
import subprocess
import logging
import threading
from typing import Callable, Optional, Dict

logger = logging.getLogger("constantine.hardware")

class HardwareGuard:
    def __init__(self, notifier=None, on_alert: Optional[Callable] = None):
        self.notifier = notifier
        self.on_alert = on_alert
        self.running = False
        self.thread = None
        self.known_webcam_pids = set()

    def get_processes_using_camera(self) -> Dict[int, str]:
        pids = {}
        video_devs = glob.glob("/dev/video*")
        if not video_devs:
            return pids

        try:
            cmd = ["fuser"] + video_devs
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            raw = (res.stdout + res.stderr).split()
            for token in raw:
                cleaned = token.strip(":")
                if cleaned.isdigit():
                    pid = int(cleaned)
                    comm = "desconocido"
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            comm = f.read().strip()
                    except Exception:
                        pass
                    pids[pid] = comm
        except Exception:
            pass
        return pids

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Centinela de periféricos (cámara web y micrófono) activo.")

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(2.0)
                current = self.get_processes_using_camera()
                for pid, comm in current.items():
                    if pid not in self.known_webcam_pids:
                        logger.warning("📷 Cámara web activada por proceso: %s (PID: %d)", comm, pid)
                        if self.notifier:
                            self.notifier.send(
                                title="📷 Cámara Web Activada",
                                body=f"La aplicación <b>{comm}</b> (PID {pid}) ha iniciado el uso de tu cámara.",
                                urgency="normal",
                                icon="camera-web"
                            )
                self.known_webcam_pids = set(current.keys())
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
