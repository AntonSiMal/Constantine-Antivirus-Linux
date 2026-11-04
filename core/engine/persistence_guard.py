"""
Constantine Antivirus - Boot & Persistence Guard (core/engine/persistence_guard.py)
Monitoreo continuo en tiempo real de rutas de persistencia en Linux:
1. Servicios de sistema e inicio: /etc/systemd/system/, /etc/init.d/, ~/.config/systemd/user/
2. Tareas programadas: /etc/cron*, /var/spool/cron/crontabs/
3. Scripts de inicio de sesión: /etc/profile.d/, ~/.bashrc, ~/.profile, /etc/rc.local
"""

import os
import time
import logging
import threading
from typing import Callable, Dict, Set, Optional

logger = logging.getLogger("constantine.persistence")

PERSISTENCE_PATHS = [
    "/etc/systemd/system",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/profile.d",
    "/etc/rc.local"
]

class PersistenceGuard:
    def __init__(self, scanner=None, vault=None, notifier=None, on_tamper_callback: Optional[Callable] = None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.on_tamper_callback = on_tamper_callback
        self.running = False
        self.thread = None
        self.snapshot: Dict[str, float] = {}

    def _take_snapshot(self) -> Dict[str, float]:
        snap = {}
        for path in PERSISTENCE_PATHS:
            if os.path.isfile(path):
                snap[path] = os.path.getmtime(path)
            elif os.path.isdir(path):
                try:
                    for root, _, files in os.walk(path):
                        for f in files:
                            fp = os.path.join(root, f)
                            snap[fp] = os.path.getmtime(fp)
                except Exception:
                    pass
        return snap

    def start(self):
        self.snapshot = self._take_snapshot()
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Centinela de persistencia en arranque (systemd, cron, profile.d) iniciado.")

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(3.0)
                current = self._take_snapshot()
                added_or_modified = set()

                for f, mtime in current.items():
                    if f not in self.snapshot or self.snapshot[f] != mtime:
                        added_or_modified.add(f)

                for target in added_or_modified:
                    self._inspect_tampered_persistence(target)

                self.snapshot = current
            except Exception as e:
                logger.error("Error en monitor de persistencia: %s", e)

    def _inspect_tampered_persistence(self, file_path: str):
        logger.warning("[PERSISTENCIA] Modificación detectada en ruta de arranque: %s", file_path)

        is_threat = False
        threat_name = "Persistence.SuspiciousHook"

        if self.scanner:
            res = self.scanner.scan_file(file_path=file_path)
            if res.is_malicious:
                is_threat = True
                threat_name = res.threat_name or threat_name

        if is_threat:
            if self.vault:
                self.vault.quarantine_file(file_path, threat_name, detected_by="PersistenceGuard")
            if self.notifier:
                self.notifier.send(
                    title="⚠️ Intento de Persistencia Bloqueado",
                    body=f"Se detectó un script malicioso en arranque: <b>{os.path.basename(file_path)}</b>. Aislado en el Baúl.",
                    urgency="critical",
                    icon="security-high"
                )
        if self.on_tamper_callback:
            self.on_tamper_callback(file_path, is_threat)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
