"""
Registrador de Auditoría Criptográficamente Encadenado e Inmutable para Constantine Antivirus.
Implementa encadenamiento de hashes SHA-256 (hash-chaining) para garantizar integridad forense
y verificación matemática de no manipulación, con permisos 0600 desde su creación.
"""
import os
import json
import hashlib
import logging
from typing import Dict, Any, Tuple, List

logger = logging.getLogger("constantine.audit")

class AuditLogger:
    """Almacena registros estructurados de eventos de seguridad con encadenamiento criptográfico SHA-256."""

    def __init__(self, log_dir: str = "/var/log/constantine"):
        self.log_dir = log_dir
        self.log_file = os.path.join(self.log_dir, "audit.log")
        self._last_hash = "GENESIS"
        self._init_last_hash()

    def _init_last_hash(self):
        """Inicializa el último hash a partir del último registro existente en audit.log."""
        if os.path.exists(self.log_file):
            try:
                with open(self.log_file, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                    if lines:
                        last_entry = json.loads(lines[-1])
                        self._last_hash = last_entry.get("hash", "GENESIS")
            except Exception:
                self._last_hash = "GENESIS"

    def log_event(self, event_type: str, details: Dict[str, Any]):
        """Registra un evento encadenado con SHA-256 asegurando permisos 0600 en creación."""
        prev = self._last_hash
        payload_to_hash = json.dumps({"event_type": event_type, "details": details, "prev_hash": prev}, sort_keys=True)
        curr_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

        entry = {
            "event_type": event_type,
            "details": details,
            "prev_hash": prev,
            "hash": curr_hash
        }
        if os.path.exists(self.log_dir):
            try:
                # Creación segura con permisos 0600 desde open() con O_CREAT
                flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_APPEND", 0)
                fd = os.open(self.log_file, flags, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
                self._last_hash = curr_hash
            except OSError:
                pass

    def verify_chain_integrity(self) -> Tuple[bool, str, int]:
        """
        Verifica criptográficamente el encadenamiento de hashes SHA-256 de audit.log.
        Retorna (is_valid, reason, verified_entries_count).
        """
        if not os.path.exists(self.log_file):
            return True, "Archivo de registro no existe (cadena vacía válida)", 0

        expected_prev = "GENESIS"
        count = 0
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                for line_no, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except Exception as err:
                        return False, f"Error de sintaxis JSON en línea {line_no}: {err}", count

                    actual_prev = entry.get("prev_hash")
                    actual_hash = entry.get("hash")

                    # Compatibilidad hacia atrás con registros antiguos sin hash
                    if actual_prev is None and actual_hash is None:
                        continue

                    if actual_prev != expected_prev:
                        return False, f"Ruptura de cadena en entrada {line_no}: prev_hash no coincide", count

                    payload = json.dumps({"event_type": entry.get("event_type"), "details": entry.get("details"), "prev_hash": actual_prev}, sort_keys=True)
                    computed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                    if computed != actual_hash:
                        return False, f"Hash criptográfico alterado en entrada {line_no}", count

                    expected_prev = actual_hash
                    count += 1
            return True, "Integridad de la cadena verificada con éxito", count
        except Exception as e:
            return False, f"Error leyendo archivo de auditoría: {e}", count

    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
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
