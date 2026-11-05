"""
Registrador de Auditoría Inmutable para Constantine Antivirus.
"""
import os
import json
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.audit")

class AuditLogger:
    """Almacena registros estructurados de eventos de seguridad y decisiones de cuarentena."""

    def __init__(self, log_dir: str = "/var/log/constantine"):
        self.log_dir = log_dir
        self.log_file = os.path.join(self.log_dir, "audit.log")

    def log_event(self, event_type: str, details: Dict[str, Any]):
        entry = {
            "event_type": event_type,
            "details": details
        }
        if os.path.exists(self.log_dir):
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except OSError:
                pass

    def get_events(self, limit: int = 100) -> list:
        """Recupera los eventos más recientes del registro de auditoría."""
        events = []
        if not os.path.exists(self.log_file):
            return events
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                        if len(events) >= limit:
                            break
                    except Exception:
                        pass
        except Exception:
            pass
        return events
