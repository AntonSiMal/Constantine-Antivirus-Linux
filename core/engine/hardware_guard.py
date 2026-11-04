"""
Constantine Antivirus - Hardware & Peripheral Guard (core/engine/hardware_guard.py)
Monitoreo anti-espía en tiempo real de cámara web (/dev/video*) y micrófono (/dev/snd/*).
Detecta accesos ocultos de troyanos RAT y spyware en Linux.
"""

import os
import glob
import subprocess
import logging
import threading
from typing import Dict, List, Set, Optional, Callable

logger = logging.getLogger("constantine.hardware")

DEFAULT_AUTHORIZED_APPS = {
    "firefox", "chrome", "chromium", "brave", "opera",
    "obs", "discord", "zoom", "teams", "skype", "vlc", "cheese"
}

class HardwareGuard:
    def __init__(self, notifier=None, on_alert: Optional[Callable] = None):
        self.notifier = notifier
        self.on_alert = on_alert
        self.running = False
        self.thread = None
        self.authorized_apps = set(DEFAULT_AUTHORIZED_APPS)
        self.known_camera_pids: Set[int] = set()
        self.known_mic_pids: Set[int] = set()

    def get_camera_processes(self) -> List[Dict[str, str]]:
        processes = []
        video_devs = glob.glob("/dev/video*")
        if not video_devs:
            return processes

        try:
            cmd = ["fuser"] + video_devs
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            raw = (res.stdout + res.stderr).split()
            for token in raw:
                cleaned = token.strip(":")
                if cleaned.isdigit():
                    pid = int(cleaned)
                    comm = self._get_proc_name(pid)
                    processes.append({
                        "pid": str(pid),
                        "comm": comm,
                        "device": "Cámara Web (/dev/video*)",
                        "authorized": comm.lower() in self.authorized_apps
                    })
        except Exception:
            pass
        return processes

    def get_microphone_processes(self) -> List[Dict[str, str]]:
        processes = []
        snd_devs = glob.glob("/dev/snd/pcm*c") # 'c' indica captura de audio
        if not snd_devs:
            snd_devs = glob.glob("/dev/snd/*")

        try:
            cmd = ["fuser"] + snd_devs
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=1)
            raw = (res.stdout + res.stderr).split()
            for token in raw:
                cleaned = token.strip(":")
                if cleaned.isdigit():
                    pid = int(cleaned)
                    comm = self._get_proc_name(pid)
                    processes.append({
                        "pid": str(pid),
                        "comm": comm,
                        "device": "Micrófono (/dev/snd/*)",
                        "authorized": comm.lower() in self.authorized_apps
                    })
        except Exception:
            pass
        return processes

    def _get_proc_name(self, pid: int) -> str:
        try:
            with open(f"/proc/{pid}/comm", "r") as f:
                return f.read().strip()
        except Exception:
            return "desconocido"

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Centinela de periféricos (cámara web y micrófono) activo.")

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(2.0)
                # 1. Supervisar Cámara
                cams = self.get_camera_processes()
                current_cam_pids = {int(p["pid"]) for p in cams}
                new_cams = current_cam_pids - self.known_camera_pids
                for p in cams:
                    if int(p["pid"]) in new_cams and not p["authorized"]:
                        logger.warning("📷 Cámara web activada por app no autorizada: %s (PID: %s)", p["comm"], p["pid"])
                        if self.notifier:
                            self.notifier.send(
                                title="📷 Alerta de Privacidad: Cámara Web",
                                body=f"La aplicación <b>{p['comm']}</b> (PID {p['pid']}) está usando la cámara.",
                                urgency="critical",
                                icon="camera-web"
                            )
                self.known_camera_pids = current_cam_pids

                # 2. Supervisar Micrófono
                mics = self.get_microphone_processes()
                current_mic_pids = {int(p["pid"]) for p in mics}
                new_mics = current_mic_pids - self.known_mic_pids
                for p in mics:
                    if int(p["pid"]) in new_mics and not p["authorized"]:
                        logger.warning("🎙️ Micrófono activado por app no autorizada: %s (PID: %s)", p["comm"], p["pid"])
                self.known_mic_pids = current_mic_pids
            except Exception:
                pass

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
