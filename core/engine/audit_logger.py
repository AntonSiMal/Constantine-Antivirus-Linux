"""
Constantine Antivirus - Forensic Audit Logger (core/engine/audit_logger.py)
Registro cronológico de incidentes forenses y exportación en JSON/CSV.
"""

import os
import json
import time
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("constantine.audit")

DEFAULT_LOG_PATH = "/var/lib/constantine/audit_log.json"
FALLBACK_LOG_PATH = "/tmp/constantine_audit_log.json"

class AuditLogger:
    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or (DEFAULT_LOG_PATH if os.geteuid() == 0 else FALLBACK_LOG_PATH)
        self._init_storage()

    def _init_storage(self):
        d = os.path.dirname(self.log_path)
        if d:
            os.makedirs(d, exist_ok=True)
        if not os.path.exists(self.log_path):
            self._save_logs([])

    def _load_logs(self) -> List[Dict]:
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return []

    def _save_logs(self, logs: List[Dict]):
        try:
            with open(self.log_path, "w") as f:
                json.dump(logs, f, indent=2)
        except Exception:
            pass

    def record_incident(self, threat_name: str, target_path: str, action: str, details: str = ""):
        entry = {
            "timestamp": time.time(),
            "time_str": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat": threat_name,
            "target": target_path,
            "action": action,
            "details": details
        }
        logs = self._load_logs()
        logs.insert(0, entry)
        if len(logs) > 500:
            logs = logs[:500]
        self._save_logs(logs)

    def get_incidents(self) -> List[Dict]:
        return self._load_logs()

    def export_report(self, export_path: str) -> bool:
        try:
            logs = self._load_logs()
            with open(export_path, "w") as f:
                json.dump(logs, f, indent=2)
            return True
        except Exception:
            return False
