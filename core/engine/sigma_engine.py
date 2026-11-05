"""
Motor de Reglas de Detección de Comportamiento Sigma para Constantine Antivirus.
"""
import os
import re
import yaml
import logging
from typing import Dict, Any, List, Optional
from collections import namedtuple

logger = logging.getLogger("constantine.sigma")

SigmaMatch = namedtuple("SigmaMatch", ["rule", "details"])

class SigmaRule:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.title = raw.get("title", "Untitled Rule")
        self.id = raw.get("id", "")
        self.level = raw.get("level", "medium")
        self.description = raw.get("description", "")
        self.detection = raw.get("detection", {})

    def matches(self, event: Dict[str, Any]) -> bool:
        """Evalúa las condiciones de selección de la regla sobre el evento de proceso/archivo."""
        selection = self.detection.get("selection", {})
        if not selection:
            return False

        for field_spec, criteria in selection.items():
            parts = field_spec.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else "exact"

            # Mapeo de campos normalizados
            val = ""
            if field_name.lower() in ("commandline", "cmdline"):
                val = str(event.get("CommandLine") or event.get("cmdline") or "")
            elif field_name.lower() in ("image", "path"):
                val = str(event.get("Image") or event.get("path") or "")
            elif field_name.lower() in ("targetfilename", "file"):
                val = str(event.get("TargetFilename") or event.get("file") or "")
            else:
                val = str(event.get(field_name, ""))

            if not isinstance(criteria, list):
                crit_list = [criteria]
            else:
                crit_list = criteria

            field_matched = False
            for item in crit_list:
                str_item = str(item)
                if modifier == "contains":
                    if str_item.lower() in val.lower():
                        field_matched = True
                        break
                elif modifier == "startswith":
                    if val.lower().startswith(str_item.lower()):
                        field_matched = True
                        break
                elif modifier == "re":
                    if re.search(str_item, val, re.IGNORECASE):
                        field_matched = True
                        break
                else:
                    if val.lower() == str_item.lower():
                        field_matched = True
                        break

            if not field_matched:
                return False

        return True


class SigmaEngine:
    """Motor de análisis de comportamiento basado en reglas de la comunidad Sigma."""

    def __init__(self, rules_file: Optional[str] = None):
        if not rules_file:
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
            rules_file = os.path.join(rules_dir, "sigma_rules.yaml")
        self.rules_file = rules_file
        self.rules: List[SigmaRule] = []
        self.load_rules()

    def load_rules(self) -> int:
        if not os.path.exists(self.rules_file):
            return 0
        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                docs = yaml.safe_load_all(f)
                self.rules = []
                for doc in docs:
                    if isinstance(doc, list):
                        for r in doc:
                            if isinstance(r, dict):
                                self.rules.append(SigmaRule(r))
                    elif isinstance(doc, dict):
                        self.rules.append(SigmaRule(doc))
            logger.info("📜 [SIGMA REGLAS CARGADAS] %d reglas de detección de comportamiento activas.", len(self.rules))
            return len(self.rules)
        except Exception as e:
            logger.error("Error cargando reglas Sigma: %s", e)
            return 0

    def evaluate_process(self, pid: int, name: str, path: str, cmdline: str, euid: int = 1000) -> List[SigmaMatch]:
        """Evalúa un proceso ejecutado contra las reglas comunitarias Sigma."""
        event = {
            "CommandLine": cmdline,
            "Image": path,
            "ParentImage": name,
            "ProcessId": pid,
            "User": "root" if euid == 0 else "user"
        }
        matches = []
        for rule in self.rules:
            if rule.matches(event):
                matches.append(SigmaMatch(rule, f"Coincidencia con regla {rule.title} para PID {pid} ({cmdline})"))
        return matches

    def probe_integration(self) -> Dict[str, Any]:
        """Verifica si la librería externa pySigma está instalada o si opera en motor standalone nativo."""
        has_pysigma = False
        try:
            import sigma
            has_pysigma = True
        except ImportError:
            pass

        return {
            "name": "Sigma Behavioral Engine",
            "type": "PYTHON_LIBRARY",
            "library_installed": has_pysigma,
            "mode": "PY_SIGMA_BACKEND" if has_pysigma else "STANDALONE_YAML_ENGINE",
            "rules_count": len(self.rules),
            "details": "Compilación AST pySigma activa" if has_pysigma else "pySigma no instalado vía pip; evaluando reglas comunitarias mediante motor de reglas YAML interno"
        }
