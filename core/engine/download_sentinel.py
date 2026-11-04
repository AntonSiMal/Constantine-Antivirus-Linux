"""
Constantine Antivirus - In-Flight Downloads Sentinel (core/engine/download_sentinel.py)
Monitoreo de descargas en vuelo en ~/Downloads y ~/Descargas:
Audita archivos en el milisegundo exacto en que el navegador completa la descarga
(renombrado de .crdownload o .part a archivo final).
"""

import os
import pwd
import time
import logging
import threading
from typing import Callable, Set, Optional

logger = logging.getLogger("constantine.downloads")

class DownloadSentinel:
    def __init__(self, scanner=None, vault=None, notifier=None, on_scan_done: Optional[Callable] = None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.on_scan_done = on_scan_done
        self.running = False
        self.thread = None
        self.watch_dirs = self._get_download_directories()
        self.known_files: Set[str] = set()

    def _get_download_directories(self) -> Set[str]:
        dirs = set()
        for user_home in ["/root"] + [f"/home/{u}" for u in os.listdir("/home") if os.path.isdir(f"/home/{u}")]:
            for d in ["Downloads", "Descargas"]:
                p = os.path.join(user_home, d)
                if os.path.exists(p):
                    dirs.add(p)
        return dirs

    def start(self):
        for d in self.watch_dirs:
            try:
                self.known_files.update(os.listdir(d))
            except Exception:
                pass
        self.running = True
        self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        self.thread.start()
        logger.info("Centinela de descargas en vuelo iniciado.")

    def _poll_loop(self):
        while self.running:
            try:
                time.sleep(1.0)
                for d in self.watch_dirs:
                    if not os.path.exists(d):
                        continue
                    current = set(os.listdir(d))
                    new_files = current - self.known_files
                    for f in new_files:
                        if not f.endswith((".crdownload", ".part", ".tmp")):
                            self.on_file_downloaded(os.path.join(d, f))
                    self.known_files = current
            except Exception:
                pass

    def on_file_downloaded(self, file_path: str):
        if not os.path.isfile(file_path):
            return
        logger.info("📥 Nueva descarga detectada: %s", file_path)

        if self.scanner:
            res = self.scanner.scan_file(file_path=file_path)
            if res.is_malicious:
                threat_name = res.threat_name or "Malware.DownloadedFile"
                if self.vault:
                    self.vault.quarantine_file(file_path, threat_name, detected_by="DownloadSentinel")
                if self.notifier:
                    self.notifier.send(
                        title="⚠️ Descarga Maliciosa Bloqueada",
                        body=f"El archivo <b>{os.path.basename(file_path)}</b> contenía malware ({threat_name}). Aislado en el Baúl.",
                        urgency="critical",
                        icon="security-high"
                    )
            else:
                logger.info("Descarga verificada y limpia: %s", os.path.basename(file_path))

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
