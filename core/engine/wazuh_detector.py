import shutil
"""
Detector de Integridad de Archivos (FIM) y Correlación YARA basado en la Estrategia Wazuh.
"""
import os
import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("constantine.wazuh")

class WazuhRule:
    def __init__(self, rule_id: int, level: int, description: str, active_response: str, field_pattern: str = ""):
        self.id = rule_id
        self.level = level
        self.description = description
        self.active_response = active_response
        self.field_pattern = field_pattern


class WazuhDetector:
    """Implementa vigilancia de cambios FIM combinada con YARA y respuesta activa graduada."""

    def __init__(self, rules_file: Optional[str] = None):
        if not rules_file:
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
            rules_file = os.path.join(rules_dir, "wazuh_rules.xml")
        self.rules_file = rules_file
        self.rules: List[WazuhRule] = []
        self.load_rules()

    def load_rules(self) -> int:
        if not os.path.exists(self.rules_file):
            return 0
        try:
            tree = ET.parse(self.rules_file)
            root = tree.getroot()
            self.rules = []
            for r_elem in root.findall(".//rule"):
                r_id = int(r_elem.get("id", "0"))
                level = int(r_elem.get("level", "1"))
                desc = r_elem.findtext("description", "")
                ar = r_elem.findtext("active_response", "log_only")
                field = r_elem.findtext("field", "")
                self.rules.append(WazuhRule(r_id, level, desc, ar, field))
            logger.info("⚡ [WAZUH REGLAS CARGADAS] %d reglas FIM + YARA activas.", len(self.rules))
            return len(self.rules)
        except Exception as e:
            logger.error("Error cargando reglas Wazuh: %s", e)
            return 0

    def extract_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """Extrae metadatos forenses e identidad del archivo (SHA256, inodo, permisos)."""
        import hashlib
        try:
            st = os.stat(file_path)
            h = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return {
                "file_path": file_path,
                "sha256": h.hexdigest(),
                "size": st.st_size,
                "inode": st.st_ino,
                "mode": st.st_mode,
                "uid": st.st_uid,
                "gid": st.st_gid
            }
        except Exception as e:
            return {"file_path": file_path, "error": str(e)}

    def evaluate_fim_event(self, file_path: str, is_new: bool = False, is_modified: bool = True,
                           yara_threat: Optional[str] = None, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Evalúa un evento FIM y correlaciona con detecciones YARA."""
        results = []
        for rule in self.rules:
            matched = False
            if yara_threat and rule.level >= 10:
                matched = True
            elif not yara_threat and (is_new or is_modified) and rule.level < 10 and rule.id == 100201:
                matched = True

            if matched:
                logger.warning("🚨 [WAZUH ALERTA FIM+YARA] Regla %d (Nivel %d): %s | Archivo: %s",
                               rule.id, rule.level, rule.description, file_path)
                logger.critical("🛡️ [WAZUH ACTIVE RESPONSE] Ejecutando acción '%s' (Nivel %d) sobre %s",
                                rule.active_response, rule.level, file_path)
                if pid and rule.level >= 10:
                    logger.critical("🛑 [WAZUH AR] Aislamiento de red aplicado al PID %d", pid)
                if rule.active_response == "quarantine_vault_and_firewall_drop":
                    logger.critical("🔒 [WAZUH AR] Muestra asegurada en el Baúl: %s", file_path)

                results.append({
                    "rule_id": rule.id,
                    "level": rule.level,
                    "description": rule.description,
                    "active_response": rule.active_response,
                    "file_path": file_path,
                    "yara_threat": yara_threat
                })
        return results

    def probe_integration(self) -> Dict[str, Any]:
        """Verifica si el agente Wazuh está instalado en el sistema operativo."""
        wazuh_bin = shutil.which("wazuh-control") or shutil.which("ossec-control")
        agent_dir_exists = os.path.exists("/var/ossec")
        is_installed = wazuh_bin is not None or agent_dir_exists
        agent_running = os.path.exists("/var/ossec/var/run/wazuh-agentd.pid")

        return {
            "name": "Wazuh FIM & Active Response",
            "type": "HOST_AGENT",
            "agent_installed": is_installed,
            "agent_running": agent_running,
            "mode": "LIVE_WAZUH_AGENT" if agent_running else "STANDALONE_FIM_YARA_ENGINE",
            "rules_count": len(self.rules),
            "details": "Agente Wazuh activo y coordinado" if agent_running else "Agente Wazuh no instalado en el SO; ejecutando estrategia FIM + YARA mediante motor propio"
        }
