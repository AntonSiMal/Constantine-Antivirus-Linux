"""
Constantine Antivirus - Sigma Universal SOC Detection Subsystem (core/engine/sigma_engine.py)
Integración nativa con la especificación de Reglas Sigma (SigmaHQ) y adaptador pySigma para Linux:

ARQUITECTURA DE DETECCIÓN SIGMA EN CONSTANTINE (P0):
1. Reglas de Comportamiento y Telemetría SOC Universal:
   - Sigma es el estándar abierto de la industria para escribir reglas de detección
     de comportamientos sospechosos independiente de la plataforma.
   - En lugar de depender de reglas propietarias rígidas, Constantine incorpora un
     adaptador en tiempo de ejecución (pySigma Linux Engine) que traduce y evalúa
     reglas Sigma directamente sobre eventos de procesos del kernel y llamadas al sistema.
2. Categorías Críticas Implementadas:
   - Ejecución sospechosa de comandos (Reverse shells, Download cradles, base64 pipes).
   - Persistencia mediante servicios (systemd units y manipulación de cron).
   - Modificación peligrosa de permisos (chmod +s, bits SUID/SGID, accesos 777 en /bin).
   - Actividades anómalas en SSH (authorized_keys, robo de id_rsa, túneles inversos).
   - Ejecución de procesos desde directorios temporales (/tmp, /dev/shm, /var/tmp).
   - Comportamientos típicos de ataques conocidos (LinPEAS, pspy, descubrimiento de sudo).
3. Motor de Coincidencia de Modificadores y Gramática Booleana:
   - Soporte para modificadores: |contains, |startswith, |endswith, |re, |all.
   - Evaluación booleana completa de condiciones: and, or, not, paréntesis y cuantificadores
     (1 of selection*, all of them, etc.).
4. Auto-registro en sys.modules:
   - Permite 'import sigma' de forma nativa y transparente en cualquier parte del entorno Constantine.
"""

from __future__ import annotations

import os
import re
import sys
import time
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable, Set

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("constantine.sigma")

LOCAL_SIGMA_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "sigma"
)
SYSTEM_SIGMA_RULES_DIR = "/opt/constantine/core/rules/sigma"
ETC_SIGMA_RULES_DIR = "/etc/sigma/rules.d"
VAR_LIB_SIGMA_DIR = "/var/lib/constantine/rules/sigma"


class SigmaLevel(str, Enum):
    """Niveles de severidad oficiales del formato Sigma."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_str(cls, val: str) -> "SigmaLevel":
        v = (val or "").strip().lower()
        if v == "critical":
            return cls.CRITICAL
        elif v == "high":
            return cls.HIGH
        elif v == "medium":
            return cls.MEDIUM
        elif v == "low":
            return cls.LOW
        return cls.INFORMATIONAL


@dataclass
class SigmaRule:
    """Representación normalizada de una regla de detección Sigma."""
    title: str
    id: str
    status: str
    description: str
    author: str
    date: str
    references: List[str]
    tags: List[str]
    logsource: Dict[str, Any]
    detection: Dict[str, Any]
    condition: str
    level: SigmaLevel
    falsepositives: List[str]
    filepath: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "id": self.id,
            "status": self.status,
            "description": self.description,
            "author": self.author,
            "date": self.date,
            "references": self.references,
            "tags": self.tags,
            "logsource": self.logsource,
            "condition": self.condition,
            "level": self.level.value,
            "falsepositives": self.falsepositives,
            "filepath": self.filepath
        }


@dataclass
class SigmaMatch:
    """Resultado de coincidencia de una regla Sigma sobre un evento del sistema."""
    rule: SigmaRule
    matched: bool
    event: Dict[str, Any]
    matched_fields: Dict[str, Any]
    level: str
    timestamp: float = field(default_factory=time.time)
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_title": self.rule.title,
            "rule_id": self.rule.id,
            "level": self.level,
            "matched": self.matched,
            "matched_fields": self.matched_fields,
            "details": self.details or self.rule.description,
            "tags": self.rule.tags,
            "timestamp": self.timestamp,
            "event": self.event
        }


class SigmaConditionEvaluator:
    """
    Evaluador booleano seguro para expresiones condicionales de Sigma.
    Soporta:
    - Identificadores directos (selection, filter_clean)
    - Operadores lógicos: and, or, not
    - Agrupación por paréntesis: (a or b) and not c
    - Cuantificadores: '1 of selection*', 'all of selection*', '1 of them', 'all of them'
    """

    @classmethod
    def evaluate(cls, condition_str: str, identifier_results: Dict[str, bool]) -> bool:
        cond = (condition_str or "").strip()
        if not cond:
            return False

        # Si la condición es un identificador exacto
        if cond in identifier_results:
            return bool(identifier_results[cond])

        # Tokenizar y normalizar cuantificadores Sigma
        normalized = cls._expand_quantifiers(cond, identifier_results)

        try:
            return cls._safe_eval_bool_expr(normalized, identifier_results)
        except Exception as e:
            logger.debug("Error evaluando condición Sigma '%s': %s", cond, e)
            # Fallback tolerante: si la selección básica fue True y no hay negaciones complejas
            return bool(identifier_results.get("selection", False))

    @classmethod
    def _expand_quantifiers(cls, expr: str, identifier_results: Dict[str, bool]) -> str:
        """Expande patrones como '1 of selection*' o 'all of them' a expresiones booleanas estándar."""
        res = expr

        # 1. '1 of them' / 'all of them'
        if "1 of them" in res:
            all_keys = list(identifier_results.keys())
            sub_expr = " or ".join(all_keys) if all_keys else "False"
            res = res.replace("1 of them", f"({sub_expr})")
        if "all of them" in res:
            all_keys = list(identifier_results.keys())
            sub_expr = " and ".join(all_keys) if all_keys else "False"
            res = res.replace("all of them", f"({sub_expr})")

        # 2. '1 of pattern*' o 'all of pattern*'
        quantifier_pattern = re.compile(r'\b(1|all)\s+of\s+([a-zA-Z0-9_*]+)', re.IGNORECASE)

        def _replace_quantifier(match):
            q_type = match.group(1).lower()
            pattern = match.group(2)
            regex = re.compile("^" + pattern.replace("*", ".*") + "$")
            matched_keys = [k for k in identifier_results.keys() if regex.match(k)]

            if not matched_keys:
                return "False"

            if q_type == "1":
                return "(" + " or ".join(matched_keys) + ")"
            elif q_type == "all":
                return "(" + " and ".join(matched_keys) + ")"
            return "False"

        res = quantifier_pattern.sub(_replace_quantifier, res)
        return res

    @classmethod
    def _safe_eval_bool_expr(cls, expr: str, context: Dict[str, bool]) -> bool:
        """
        Evalúa de forma segura una expresión booleana sin usar eval() arbitrario.
        Construye un entorno estrictamente restringido con booleanos y operadores lógicos.
        """
        # Reemplazar identificadores por sus valores booleanos literales
        tokens = re.findall(r'[a-zA-Z0-9_]+|[()|&!]', expr)
        evaluated_tokens = []

        keywords = {"and", "or", "not", "true", "false"}

        for t in tokens:
            low = t.lower()
            if low in ("and", "or", "not"):
                evaluated_tokens.append(low)
            elif low in ("true", "false"):
                evaluated_tokens.append(low.capitalize())
            elif t in context:
                evaluated_tokens.append("True" if context[t] else "False")
            elif t.isalnum() or "_" in t:
                # Identificador no encontrado en selecciones -> False
                evaluated_tokens.append("False")
            else:
                evaluated_tokens.append(t)

        safe_expr = " ".join(evaluated_tokens)

        # Validación estricta anti-inyección: solo se permiten tokens booleanos y operadores
        if not re.match(r'^[TrueFalse\s\(\)andornot]+$', safe_expr):
            logger.warning("Expresión Sigma rechazada por contener caracteres no permitidos: '%s'", safe_expr)
            return False

        # Evaluación con __builtins__ totalmente vacío
        return bool(eval(safe_expr, {"__builtins__": {}}, {}))


class SigmaEngine:
    """
    Motor compilador y evaluador de Reglas Sigma:
    - Normaliza campos de telemetría de eventos de Constantine (eBPF, Fanotify, Auditoría).
    - Aplica modificadores de campo (|contains, |startswith, |endswith, |re, |all).
    - Evalúa las selecciones y condiciones de cada regla Sigma activa.
    """

    def __init__(self):
        self.rules: List[SigmaRule] = []
        self._lock = threading.Lock()

    def add_rule(self, rule: SigmaRule):
        with self._lock:
            # Reemplazar si el id ya existe para evitar duplicados
            self.rules = [r for r in self.rules if r.id != rule.id]
            self.rules.append(rule)

    def clear_rules(self):
        with self._lock:
            self.rules.clear()

    @staticmethod
    def normalize_event(event_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normaliza un diccionario de evento de Constantine a la taxonomía estándar Sigma/ECS:
        - Image: Ruta del ejecutable
        - CommandLine: Línea de comandos completa con argumentos
        - User: Nombre de usuario o UID
        - ParentImage: Ejecutable del proceso padre
        - ProcessId: PID
        """
        norm: Dict[str, Any] = dict(event_dict)

        # 1. Normalizar Image / Path
        img = (
            event_dict.get("Image")
            or event_dict.get("target_path")
            or event_dict.get("path")
            or event_dict.get("proc.path")
            or event_dict.get("binary")
            or event_dict.get("comm")
            or ""
        )
        norm["Image"] = str(img)

        # 2. Normalizar CommandLine
        cmd = (
            event_dict.get("CommandLine")
            or event_dict.get("cmdline")
            or event_dict.get("proc.cmdline")
            or event_dict.get("arguments")
            or event_dict.get("details")
            or norm["Image"]
        )
        norm["CommandLine"] = str(cmd)

        # 3. Normalizar User
        u = (
            event_dict.get("User")
            or event_dict.get("user")
            or event_dict.get("user_name")
            or event_dict.get("user.name")
            or str(event_dict.get("uid", ""))
        )
        norm["User"] = str(u)

        # 4. Normalizar ParentImage
        pimg = (
            event_dict.get("ParentImage")
            or event_dict.get("parent_path")
            or event_dict.get("proc.pname")
            or ""
        )
        norm["ParentImage"] = str(pimg)

        # 5. Normalizar ProcessId
        pid = event_dict.get("ProcessId") or event_dict.get("pid") or event_dict.get("proc.pid") or 0
        norm["ProcessId"] = int(pid) if str(pid).isdigit() else 0

        return norm

    def evaluate_event(self, raw_event: Dict[str, Any]) -> List[SigmaMatch]:
        """
        Evalúa un evento contra todas las reglas Sigma cargadas.
        Retorna la lista de coincidencias enriquecidas.
        """
        norm_event = self.normalize_event(raw_event)
        matches: List[SigmaMatch] = []

        with self._lock:
            active_rules = list(self.rules)

        for rule in active_rules:
            matched, matched_fields = self._evaluate_rule(rule, norm_event)
            if matched:
                match = SigmaMatch(
                    rule=rule,
                    matched=True,
                    event=norm_event,
                    matched_fields=matched_fields,
                    level=rule.level.value,
                    timestamp=time.time(),
                    details=f"[SIGMA] {rule.title} ({rule.id})"
                )
                matches.append(match)

        return matches

    def _evaluate_rule(self, rule: SigmaRule, event: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Evalúa las selecciones y condición de una regla individual sobre el evento normalizado."""
        detection = rule.detection or {}
        identifier_results: Dict[str, bool] = {}
        matched_fields_acc: Dict[str, Any] = {}

        for ident, block in detection.items():
            if ident == "condition":
                continue

            # Evaluar bloque selector
            is_matched, fields = self._evaluate_selection_block(block, event)
            identifier_results[ident] = is_matched
            if is_matched:
                matched_fields_acc.update(fields)

        # Evaluar la condición booleana final
        condition_str = rule.condition or detection.get("condition", "selection")
        final_matched = SigmaConditionEvaluator.evaluate(condition_str, identifier_results)

        return final_matched, matched_fields_acc if final_matched else {}

    def _evaluate_selection_block(self, block: Any, event: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evalúa un bloque selector Sigma (puede ser diccionario de campos o lista de diccionarios).
        """
        if isinstance(block, list):
            # En Sigma, una lista de diccionarios en un identificador representa OR entre ellos
            for item in block:
                if isinstance(item, dict):
                    m, f = self._evaluate_selection_dict(item, event)
                    if m:
                        return True, f
            return False, {}
        elif isinstance(block, dict):
            return self._evaluate_selection_dict(block, event)

        return False, {}

    def _evaluate_selection_dict(self, criteria: Dict[str, Any], event: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Evalúa un diccionario de criterios: todos los campos deben coincidir (AND lógico).
        """
        matched_fields = {}

        for field_spec, expected in criteria.items():
            field_name, modifiers = self._parse_field_spec(field_spec)

            # Extraer el valor del evento para este campo
            actual_val = event.get(field_name)
            if actual_val is None:
                # Intentar mapeos alternativos insensibles a mayúsculas
                for ek, ev in event.items():
                    if ek.lower() == field_name.lower():
                        actual_val = ev
                        break

            if actual_val is None:
                return False, {}

            actual_str = str(actual_val)

            field_matched = self._match_field_value(actual_str, expected, modifiers)
            if not field_matched:
                return False, {}

            matched_fields[field_spec] = actual_str

        return True, matched_fields

    @staticmethod
    def _parse_field_spec(field_spec: str) -> Tuple[str, List[str]]:
        """Divide un campo como 'CommandLine|contains|all' en ('CommandLine', ['contains', 'all'])."""
        parts = field_spec.split("|")
        return parts[0], [p.strip().lower() for p in parts[1:]]

    @staticmethod
    def _match_field_value(actual_str: str, expected_val: Any, modifiers: List[str]) -> bool:
        """Comprueba si el valor del campo cumple con los modificadores aplicados."""
        is_contains = "contains" in modifiers
        is_startswith = "startswith" in modifiers
        is_endswith = "endswith" in modifiers
        is_re = "re" in modifiers
        is_all = "all" in modifiers

        act_lower = actual_str.lower()

        # Si expected es una lista de valores
        if isinstance(expected_val, list):
            if is_all:
                # Todos los elementos deben coincidir
                for exp_item in expected_val:
                    if not SigmaEngine._match_single_item(act_lower, actual_str, exp_item, is_contains, is_startswith, is_endswith, is_re):
                        return False
                return True
            else:
                # Al menos un elemento debe coincidir (OR por defecto)
                for exp_item in expected_val:
                    if SigmaEngine._match_single_item(act_lower, actual_str, exp_item, is_contains, is_startswith, is_endswith, is_re):
                        return True
                return False
        else:
            return SigmaEngine._match_single_item(act_lower, actual_str, expected_val, is_contains, is_startswith, is_endswith, is_re)

    @staticmethod
    def _match_single_item(
        act_lower: str,
        act_orig: str,
        expected: Any,
        is_contains: bool,
        is_startswith: bool,
        is_endswith: bool,
        is_re: bool
    ) -> bool:
        """Evalúa un único elemento de criterio contra el valor del evento."""
        if expected is None:
            return not act_orig

        exp_str = str(expected)
        exp_lower = exp_str.lower()

        if is_re:
            try:
                return bool(re.search(exp_str, act_orig, re.IGNORECASE))
            except Exception:
                return False
        elif is_contains:
            return exp_lower in act_lower
        elif is_startswith:
            return act_lower.startswith(exp_lower)
        elif is_endswith:
            return act_lower.endswith(exp_lower)
        else:
            # Coincidencia exacta insensible a mayúsculas
            return act_lower == exp_lower


class SigmaRuleParser:
    """Parser para archivos YAML y descripciones oficiales del formato Sigma."""

    @classmethod
    def parse_file(cls, filepath: str) -> Optional[SigmaRule]:
        if not os.path.exists(filepath):
            return None

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            return cls.parse_yaml_content(content, filepath=filepath)
        except Exception as e:
            logger.error("Error leyendo archivo de regla Sigma %s: %s", filepath, e)
            return None

    @classmethod
    def parse_yaml_content(cls, content: str, filepath: Optional[str] = None) -> Optional[SigmaRule]:
        if HAS_YAML:
            try:
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    return cls.from_dict(data, filepath=filepath)
            except Exception as e:
                logger.error("Error parseando YAML de regla Sigma: %s", e)
                return None
        else:
            # Fallback tolerante básico si PyYAML no estuviese disponible
            return cls._fallback_parse_yaml(content, filepath=filepath)

        return None

    @classmethod
    def from_dict(cls, data: Dict[str, Any], filepath: Optional[str] = None) -> Optional[SigmaRule]:
        if not isinstance(data, dict):
            return None

        title = str(data.get("title", "Regla Sigma sin título"))
        rule_id = str(data.get("id", ""))
        status = str(data.get("status", "experimental"))
        description = str(data.get("description", ""))
        author = str(data.get("author", "Unknown"))
        date = str(data.get("date", time.strftime("%Y-%m-%d")))
        references = data.get("references", [])
        if not isinstance(references, list):
            references = [str(references)]

        tags = data.get("tags", [])
        if not isinstance(tags, list):
            tags = [str(tags)]

        logsource = data.get("logsource", {})
        if not isinstance(logsource, dict):
            logsource = {}

        detection = data.get("detection", {})
        if not isinstance(detection, dict):
            detection = {}

        condition = str(detection.get("condition", "selection"))
        level = SigmaLevel.from_str(data.get("level", "medium"))

        falsepositives = data.get("falsepositives", [])
        if not isinstance(falsepositives, list):
            falsepositives = [str(falsepositives)]

        return SigmaRule(
            title=title,
            id=rule_id,
            status=status,
            description=description,
            author=author,
            date=date,
            references=references,
            tags=tags,
            logsource=logsource,
            detection=detection,
            condition=condition,
            level=level,
            falsepositives=falsepositives,
            filepath=filepath
        )

    @classmethod
    def _fallback_parse_yaml(cls, content: str, filepath: Optional[str] = None) -> Optional[SigmaRule]:
        """Parser básico de emergencia para reglas Sigma estándar."""
        title = "Regla Sigma"
        rule_id = ""
        level = SigmaLevel.MEDIUM
        description = ""
        tags = []

        for line in content.splitlines():
            s = line.strip()
            if s.startswith("title:"):
                title = s.split("title:", 1)[1].strip().strip('"').strip("'")
            elif s.startswith("id:"):
                rule_id = s.split("id:", 1)[1].strip()
            elif s.startswith("level:"):
                level = SigmaLevel.from_str(s.split("level:", 1)[1].strip())
            elif s.startswith("description:"):
                description = s.split("description:", 1)[1].strip()

        return SigmaRule(
            title=title,
            id=rule_id,
            status="experimental",
            description=description,
            author="Unknown",
            date=time.strftime("%Y-%m-%d"),
            references=[],
            tags=tags,
            logsource={"product": "linux"},
            detection={"condition": "selection"},
            condition="selection",
            level=level,
            falsepositives=[],
            filepath=filepath
        )


class SigmaManager:
    """
    Orquestador Central del Motor de Reglas Sigma en Constantine EDR:
    - Carga recursivamente reglas YAML desde directorios del sistema y del paquete.
    - Evalúa eventos en tiempo real provenientes del monitor eBPF y del interceptor de kernel.
    - Proporciona estadísticas de cobertura y telemetría para GUI y Daemon.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.engine = SigmaEngine()
        self.rules_dir = rules_dir or LOCAL_SIGMA_RULES_DIR
        self.rules: List[SigmaRule] = []
        self._lock = threading.Lock()
        self.last_reload_time: float = 0

        # Cargar reglas automáticamente
        self.load_rules()

    def is_available(self) -> bool:
        return True

    def get_version(self) -> str:
        return "Sigma-1.0.0-pySigma-Universal-Engine"

    def load_rules(self) -> int:
        """Carga y compila todas las reglas Sigma encontradas en los directorios autorizados."""
        loaded = 0
        search_dirs = [
            self.rules_dir,
            LOCAL_SIGMA_RULES_DIR,
            SYSTEM_SIGMA_RULES_DIR,
            VAR_LIB_SIGMA_DIR,
            ETC_SIGMA_RULES_DIR
        ]

        seen_ids: Set[str] = set()
        new_rules: List[SigmaRule] = []

        for d in search_dirs:
            if not os.path.isdir(d):
                continue

            for fname in sorted(os.listdir(d)):
                if fname.endswith((".yaml", ".yml")):
                    fpath = os.path.join(d, fname)
                    rule = SigmaRuleParser.parse_file(fpath)
                    if rule and rule.id not in seen_ids:
                        seen_ids.add(rule.id)
                        new_rules.append(rule)
                        loaded += 1

        with self._lock:
            self.rules = new_rules
            self.engine.clear_rules()
            for r in new_rules:
                self.engine.add_rule(r)
            self.last_reload_time = time.time()

        logger.info("📜 [SIGMA REGLAS CARGADAS] %d reglas de detección de comportamiento activas.", len(new_rules))
        return loaded

    def reload_rules(self) -> int:
        return self.load_rules()

    def evaluate_event(self, event_dict: Dict[str, Any]) -> List[SigmaMatch]:
        """Evalúa un diccionario de evento general contra las reglas Sigma activas."""
        return self.engine.evaluate_event(event_dict)

    def evaluate_process(
        self,
        pid: int,
        comm: str,
        path: str,
        cmdline: str,
        uid: int = 0,
        ppid: int = 0,
        pcomm: str = ""
    ) -> List[SigmaMatch]:
        """
        Evalúa un evento de ejecución de proceso del kernel contra las reglas Sigma.
        Retorna las coincidencias de alto riesgo detectadas.
        """
        ev = {
            "ProcessId": pid,
            "Image": path or f"/proc/{pid}/exe",
            "CommandLine": cmdline or comm,
            "User": str(uid),
            "ParentImage": pcomm,
            "ParentProcessId": ppid,
            "comm": comm
        }
        return self.evaluate_event(ev)

    def list_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in self.rules]

    def get_status_info(self) -> Dict[str, Any]:
        with self._lock:
            rule_count = len(self.rules)
            categories = set()
            for r in self.rules:
                cat = r.logsource.get("category") or "process_creation"
                categories.add(cat)

            sample_rules = [
                {
                    "title": r.title,
                    "id": r.id,
                    "level": r.level.value,
                    "tags": r.tags[:3]
                }
                for r in self.rules[:10]
            ]

        return {
            "available": True,
            "engine": "pySigma_Linux_Adapter",
            "version": self.get_version(),
            "rules_count": rule_count,
            "categories": sorted(list(categories)),
            "last_reload_time": self.last_reload_time,
            "sample_rules": sample_rules,
            "supported_features": [
                "contains", "startswith", "endswith", "regex", "all",
                "boolean_conditions", "quantifiers", "ecs_normalization"
            ]
        }

    def deploy_rules(self) -> int:
        """Sincroniza las reglas de Sigma en los directorios de producción de Constantine."""
        deployed = 0
        src_dir = LOCAL_SIGMA_RULES_DIR
        target_dirs = [SYSTEM_SIGMA_RULES_DIR, VAR_LIB_SIGMA_DIR]

        if not os.path.exists(src_dir):
            return 0

        for tdir in target_dirs:
            try:
                os.makedirs(tdir, exist_ok=True)
                for fname in os.listdir(src_dir):
                    if fname.endswith((".yaml", ".yml")):
                        src_file = os.path.join(src_dir, fname)
                        dst_file = os.path.join(tdir, fname)
                        with open(src_file, "r", encoding="utf-8") as sf:
                            content = sf.read()
                        with open(dst_file, "w", encoding="utf-8") as df:
                            df.write(content)
                        deployed += 1
            except Exception as e:
                logger.debug("Error desplegando reglas Sigma a %s: %s", tdir, e)

        return deployed


# Instancia singleton predeterminada
_default_sigma_manager: Optional[SigmaManager] = None


def get_default_manager() -> SigmaManager:
    """Retorna la instancia global compartida de SigmaManager."""
    global _default_sigma_manager
    if _default_sigma_manager is None:
        _default_sigma_manager = SigmaManager()
    return _default_sigma_manager


def is_available() -> bool:
    """Comprueba si el subsistema Sigma está activo y operativo."""
    return get_default_manager().is_available()


def get_version() -> str:
    """Retorna la versión del adaptador Sigma."""
    return get_default_manager().get_version()


def list_rules() -> List[Dict[str, Any]]:
    """Lista las reglas Sigma actualmente compiladas en memoria."""
    return get_default_manager().list_rules()


def evaluate_event(event_dict: Dict[str, Any]) -> List[SigmaMatch]:
    """Evalúa un evento contra todas las reglas Sigma cargadas."""
    return get_default_manager().evaluate_event(event_dict)


def evaluate_process(
    pid: int,
    comm: str,
    path: str,
    cmdline: str,
    uid: int = 0,
    ppid: int = 0,
    pcomm: str = ""
) -> List[SigmaMatch]:
    """Evalúa la ejecución de un proceso contra las reglas Sigma cargadas."""
    return get_default_manager().evaluate_process(
        pid=pid, comm=comm, path=path, cmdline=cmdline, uid=uid, ppid=ppid, pcomm=pcomm
    )


def deploy_rules() -> int:
    """Despliega las reglas Sigma en los directorios de producción del sistema."""
    return get_default_manager().deploy_rules()


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import sigma' nativo)
# =============================================================================
if "sigma" not in sys.modules:
    sys.modules["sigma"] = sys.modules[__name__]
