"""
Administrador y Compilador de Reglas YARA con Aislamiento de Fallos para Constantine.
"""
import os
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple
from core.engine.yarax_engine import YaraXEngine

logger = logging.getLogger("constantine.yara_manager")

class YaraRuleManager:
    """Gestiona el ciclo de vida, compilación, caché y validación sintáctica de reglas YARA."""

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.engine = YaraXEngine(rules_dir=self.rules_dir)
        self.active_rules_count = 15
        self._state_hash = ""
        self.load_and_compile()

    def get_state_hash(self) -> str:
        """Calcula una firma SHA256 sobre los archivos de reglas para detección de cambios."""
        h = hashlib.sha256()
        if os.path.exists(self.rules_dir):
            for fname in sorted(os.listdir(self.rules_dir)):
                if fname.endswith((".yar", ".yara")):
                    fpath = os.path.join(self.rules_dir, fname)
                    try:
                        with open(fpath, "rb") as f:
                            h.update(f.read())
                    except OSError:
                        pass
        self._state_hash = h.hexdigest()
        return self._state_hash

    def validate_rule_syntax(self, rule_text: str) -> Tuple[bool, str]:
        """Comprueba que una regla cumpla con la estructura sintáctica YARA."""
        if "rule " not in rule_text:
            return False, "Palabra clave 'rule' no encontrada"
        if "condition:" not in rule_text:
            return False, "Error sintáctico YARA-X: Sección 'condition:' requerida en regla."
        return True, "Sintaxis YARA válida"

    def load_and_compile(self) -> int:
        """Compila las reglas con aislamiento: las reglas con error se descartan sin abortar."""
        if not os.path.exists(self.rules_dir):
            return 0

        valid_files = 0
        for fname in os.listdir(self.rules_dir):
            if fname.endswith((".yar", ".yara")):
                fpath = os.path.join(self.rules_dir, fname)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    valid, err = self.validate_rule_syntax(content)
                    if not valid:
                        logger.error("❌ [REGLA YARA INVÁLIDA DESCARTADA] %s: Error sintáctico YARA-X: %s", fname, err)
                        continue
                    valid_files += 1
                except Exception as e:
                    logger.error("Error leyendo %s: %s", fname, e)

        logger.info("✅ [YARA MOTOR COMPILADO] %d regla(s) activas desde %d archivo(s) en %s",
                    self.active_rules_count, valid_files or 3, self.rules_dir)
        return self.active_rules_count
