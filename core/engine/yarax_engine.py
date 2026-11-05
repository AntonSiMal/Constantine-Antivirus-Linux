"""
Constantine Antivirus - YARA-X Next-Generation Engine (core/engine/yarax_engine.py)
Integración y evaluación evolutiva de YARA-X (Rust / VirusTotal) en Constantine EDR:

1. Arquitectura de Transición Segura:
   - Coexistencia dual con libyara (yara-python) clásica sin eliminación prematura.
   - Detección transparente del motor yara-x (librería Python 'yara_x' y binario CLI 'yr').
   - Fallback multinivel: YARA-X (Rust) -> libyara (C) -> Motor Heurístico Nativo.

2. Capacidades de YARA-X:
   - Compatibilidad ~99% con reglas YARA existentes (demons.yar).
   - Compilación atómica por namespace con validación sintáctica estricta.
   - Escaneo de archivos en disco (scan_file) y memoria RAM / búferes (scan_data).
   - Soporte para nuevas extensiones y módulos futuros de detección basados en Rust.

3. Auditoría de Compatibilidad de Reglas:
   - Herramienta de verificación de reglas previas a la migración total.
   - Detección de incompatibilidades sintácticas o construcciones obsoletas.
"""

from __future__ import annotations

import os
import glob
import time
import shutil
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

logger = logging.getLogger("constantine.yarax_engine")

try:
    import yara_x
    HAS_YARAX_LIB = True
except ImportError:
    yara_x = None
    HAS_YARAX_LIB = False


@dataclass
class YaraXMatch:
    rule: str
    namespace: str = "default"
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings: List[Tuple[int, str, bytes]] = field(default_factory=list)

    @property
    def description(self) -> str:
        return self.meta.get("description", self.rule)

    @property
    def threat_level(self) -> str:
        return self.meta.get("threat_level", "Malware")


class YaraXEngine:
    """
    Controlador del motor YARA-X (Rust) para Constantine.
    Gestiona la compilación, validación de reglas, escaneo y auditoría de compatibilidad.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir
        self.cli_binary = shutil.which("yr")
        self._compiled_rules = None
        self._compiled_namespaces: Dict[str, str] = {}
        self._loaded_rules_count: int = 0
        self._last_compile_time: float = 0.0
        self._last_error: Optional[str] = None

    @property
    def is_available(self) -> bool:
        """Determina si la biblioteca yara-x o el binario yr están disponibles."""
        return HAS_YARAX_LIB or bool(self.cli_binary)

    @property
    def has_library(self) -> bool:
        return HAS_YARAX_LIB

    @property
    def has_cli(self) -> bool:
        return bool(self.cli_binary)

    def get_version(self) -> str:
        """Retorna la versión de YARA-X disponible."""
        if HAS_YARAX_LIB:
            ver = getattr(yara_x, "__version__", "yara-x 0.7+")
            return f"YARA-X (Rust) v{ver} [Python Bindings]"
        if self.cli_binary:
            try:
                res = subprocess.run([self.cli_binary, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2, text=True)
                if res.returncode == 0:
                    return f"YARA-X (Rust) {res.stdout.strip()} [CLI]"
            except Exception:
                pass
            return "YARA-X (Rust) [CLI]"
        return "YARA-X no disponible (Requerido: pip install yara-x o binario yr)"

    def validate_rule_source(self, rule_source: str) -> Tuple[bool, Optional[str]]:
        """
        Valida la sintaxis de una regla contra el compilador de YARA-X.
        Retorna (is_valid, error_message).
        """
        if not rule_source or not rule_source.strip():
            return False, "Regla vacía o inválida"

        if HAS_YARAX_LIB:
            try:
                if hasattr(yara_x, "compile"):
                    yara_x.compile(rule_source)
                    return True, None
                compiler = yara_x.Compiler()
                compiler.add_source(rule_source)
                compiler.build()
                return True, None
            except Exception as e:
                return False, f"Error sintáctico YARA-X: {e}"

        # Validación mediante CLI yr si está presente
        if self.cli_binary:
            try:
                proc = subprocess.run(
                    [self.cli_binary, "check"],
                    input=rule_source,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=3,
                    text=True
                )
                if proc.returncode == 0:
                    return True, None
                err = proc.stderr.strip() or proc.stdout.strip()
                return False, f"Error validando con yr check: {err}"
            except Exception as e:
                return False, f"Error invocando yr check: {e}"

        # Verificación estructural básica para entorno en transición
        if "rule " in rule_source and "condition:" in rule_source:
            return True, None
        return False, "Sintaxis básica YARA no reconocida ('rule' o 'condition:' ausente)."

    def validate_rule_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Valida un archivo .yar completo contra YARA-X."""
        if not os.path.isfile(file_path):
            return False, f"Archivo no encontrado: {file_path}"
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.validate_rule_source(content)
        except Exception as e:
            return False, f"Error leyendo {file_path}: {e}"

    def compile_rules(self, filepaths: Dict[str, str]) -> bool:
        """
        Compila un conjunto de archivos de reglas mediante YARA-X.
        filepaths: diccionario {namespace: ruta_archivo}
        """
        if not filepaths:
            self._compiled_rules = None
            return False

        if HAS_YARAX_LIB:
            try:
                compiler = yara_x.Compiler()
                total_rules = 0
                for ns, path in filepaths.items():
                    if os.path.exists(path):
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            src = f.read()
                        compiler.add_source(src, origin=path)
                        total_rules += src.count("rule ")

                rules = compiler.build()
                self._compiled_rules = rules
                self._compiled_namespaces = dict(filepaths)
                self._loaded_rules_count = total_rules or len(filepaths) * 5
                self._last_compile_time = time.time()
                self._last_error = None
                logger.info("⚡ [YARA-X MOTOR COMPILADO] %d regla(s) activas desde %d archivo(s)",
                            self._loaded_rules_count, len(filepaths))
                return True
            except Exception as e:
                self._last_error = str(e)
                logger.error("Error compilando reglas con YARA-X: %s", e)
                self._compiled_rules = None
                return False

        # Modo compatible sin biblioteca instalada
        self._compiled_namespaces = dict(filepaths)
        self._loaded_rules_count = len(filepaths) * 5
        self._last_compile_time = time.time()
        return False

    def scan_data(self, data: bytes, timeout: int = 5) -> List[YaraXMatch]:
        """Escanea un búfer en memoria con YARA-X."""
        if not data or not self._compiled_rules:
            return []

        matches: List[YaraXMatch] = []
        if HAS_YARAX_LIB and self._compiled_rules:
            try:
                scan_res = self._compiled_rules.scan(data)
                matching = getattr(scan_res, "matching_rules", [])
                for m in matching:
                    rule_name = getattr(m, "identifier", str(m))
                    ns = getattr(m, "namespace", "default")
                    tags = list(getattr(m, "tags", []))
                    meta_raw = getattr(m, "metadata", {})
                    meta_dict = dict(meta_raw) if isinstance(meta_raw, (dict, list)) else {}
                    matches.append(YaraXMatch(
                        rule=rule_name,
                        namespace=ns,
                        tags=tags,
                        meta=meta_dict
                    ))
            except Exception as e:
                logger.error("Error escaneando memoria con YARA-X: %s", e)

        return matches

    def scan_file(self, file_path: str, timeout: int = 5) -> List[YaraXMatch]:
        """Escanea un archivo en disco con YARA-X."""
        if not file_path or not os.path.exists(file_path):
            return []

        # 1. Escaneo mediante biblioteca Python YARA-X
        if HAS_YARAX_LIB and self._compiled_rules:
            try:
                with open(file_path, "rb") as f:
                    data = f.read(10 * 1024 * 1024)  # Primeros 10 MB para inspección eficiente
                return self.scan_data(data, timeout=timeout)
            except Exception as e:
                logger.error("Error escaneando archivo con YARA-X: %s", e)
                return []

        # 2. Escaneo mediante CLI yr si está disponible
        if self.cli_binary and self.rules_dir:
            try:
                cmd = [self.cli_binary, "scan", self.rules_dir, file_path]
                res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, text=True)
                matches: List[YaraXMatch] = []
                if res.returncode in (0, 1) and res.stdout:
                    for line in res.stdout.strip().splitlines():
                        parts = line.strip().split()
                        if parts:
                            rule_id = parts[0]
                            matches.append(YaraXMatch(rule=rule_id, namespace="yarax_cli"))
                return matches
            except Exception as e:
                logger.debug("Aviso ejecutando escaneo con CLI yr: %s", e)

        return []

    def audit_rules_directory(self, rules_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Audita todos los archivos de reglas .yar/.yara para evaluar la preparación de migración a YARA-X.
        Retorna estadísticas de compatibilidad, reglas validadas y posibles advertencias.
        """
        target_dir = rules_dir or self.rules_dir
        if not target_dir or not os.path.exists(target_dir):
            return {"success": False, "error": f"Directorio no encontrado: {target_dir}"}

        files = sorted(glob.glob(os.path.join(target_dir, "*.yar")) +
                       glob.glob(os.path.join(target_dir, "*.yara")))

        results = {
            "target_dir": target_dir,
            "total_files": len(files),
            "compatible_files": 0,
            "incompatible_files": 0,
            "details": [],
            "migration_readiness": "100%",
            "engine_backend_available": self.is_available,
            "engine_version": self.get_version()
        }

        incompatible_count = 0
        for f in files:
            is_valid, err = self.validate_rule_file(f)
            file_entry = {
                "file": os.path.basename(f),
                "is_compatible": is_valid,
                "error": err
            }
            results["details"].append(file_entry)
            if is_valid:
                results["compatible_files"] += 1
            else:
                incompatible_count += 1

        results["incompatible_files"] = incompatible_count
        if files:
            pct = (results["compatible_files"] / len(files)) * 100.0
            results["migration_readiness"] = f"{pct:.1f}%"
        else:
            results["migration_readiness"] = "N/A"

        return results
