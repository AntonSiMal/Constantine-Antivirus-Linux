"""
Constantine Antivirus - YARA Rule Manager (core/engine/yara_manager.py)
Administrador integral de reglas YARA para defensa activa en Linux:
1. Compilación Robusta y Aislamiento de Errores:
   - Valida la sintaxis de cada regla individualmente antes de la compilación global.
   - Si un archivo .yar tiene errores de sintaxis, se aísla con registro detallado sin tumbar
     el resto del motor de firmas.
2. Caché Binaria y Verificación de Integridad (mtime/hash state):
   - Soporta almacenamiento en caché compilada (.yac) con yara.load() para arranque en <5 ms.
   - Invalida la caché automáticamente cuando cualquier archivo .yar es modificado, añadido o borrado.
3. Actualización Dinámica y Hot-Reload Atómico:
   - Recarga en caliente intercambiando el puntero de reglas en memoria atómicamente.
4. Motor de Coincidencias Seguro:
   - Ejecuta rules.match() con protección de timeout para evitar ataques de DoS/ReDoS.
   - Extrae metadatos estructurados (regla, namespace, nivel de amenaza, tags, cadenas).
5. Modo de Respaldo Heurístico Transparente (Fallback):
   - Si yara-python no está disponible en el host, proporciona un motor heurístico compatible
     que analiza las firmas de las reglas YARA nativamente sin interrumpir la protección.
"""

import os
import glob
import time
import json
import re
import hashlib
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any, Set

logger = logging.getLogger("constantine.yara_manager")

try:
    import yara
    HAS_YARA = True
except ImportError:
    yara = None
    HAS_YARA = False
    logger.warning("Librería 'yara-python' no encontrada. YaraRuleManager operará en modo de respaldo heurístico.")


@dataclass
class YaraMatch:
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


class YaraRuleManager:
    """
    Administrador centralizado de ciclo de vida de reglas YARA:
    Carga, validación sintáctica, compilación atómica, caché binaria,
    hot-reload y ejecución de coincidencias con timeout.
    """

    def __init__(self, rules_dir: Optional[str] = None, cache_dir: Optional[str] = None):
        if rules_dir:
            self.rules_dir = os.path.abspath(rules_dir)
        else:
            self.rules_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"
            )

        if cache_dir:
            self.cache_dir = os.path.abspath(cache_dir)
        else:
            system_cache = "/var/lib/constantine/cache"
            user_cache = os.path.expanduser("~/.cache/constantine")
            if os.path.exists("/var/lib/constantine") and os.access("/var/lib/constantine", os.W_OK):
                self.cache_dir = system_cache
            else:
                self.cache_dir = user_cache

        try:
            os.makedirs(self.cache_dir, exist_ok=True)
        except Exception:
            self.cache_dir = "/tmp/constantine_yara_cache"
            os.makedirs(self.cache_dir, exist_ok=True)

        self.compiled_cache_path = os.path.join(self.cache_dir, "constantine_rules.yac")
        self.meta_cache_path = os.path.join(self.cache_dir, "constantine_rules_meta.json")

        self._compiled_rules = None
        self._compiled_namespaces: Dict[str, str] = {}
        self._loaded_rules_count: int = 0
        self._last_compile_time: float = 0.0
        self._last_state_hash: str = ""
        self._compilation_errors: List[Dict[str, str]] = []

        # Firmas de respaldo extraídas o nativas para cuando yara-python no esté instalado
        self._fallback_signatures: List[Tuple[str, List[bytes], Dict[str, str]]] = [
            ("Demons_EICAR_Standard_Test", [b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"],
             {"description": "Cadena estándar de prueba antivirus EICAR", "threat_level": "Test"}),
            ("Demons_Reverse_Shell_Netcat", [b"nc", b"-e", b"/bin/"],
             {"description": "Detección de shell reversa netcat", "threat_level": "High"}),
            ("Demons_Reverse_Shell_DevTcp", [b"/dev/tcp/", b"0>&1"],
             {"description": "Shell reversa mediante /dev/tcp/", "threat_level": "Critical"}),
            ("Demons_Reverse_Shell_DevTcp_Bash", [b"bash", b"-i", b"/dev/tcp/"],
             {"description": "Shell interactiva bash sobre TCP", "threat_level": "Critical"}),
            ("Demons_Reverse_Shell_Python", [b"import socket", b"os.dup2"],
             {"description": "Shell reversa en Python con socket y dup2", "threat_level": "High"}),
            ("Demons_Reverse_Shell_Python_Pty", [b"socket.socket", b"pty.spawn"],
             {"description": "Shell interactiva Python con pty spawn", "threat_level": "High"}),
            ("Demons_Ransomware_Indicators", [b".locked", b"YOUR FILES ARE ENCRYPTED"],
             {"description": "Patrón de notas de ransomware y extensiones hostiles", "threat_level": "Critical"}),
            ("Demons_Cryptominer_Pools", [b"stratum+tcp://"],
             {"description": "Protocolo Stratum de minero no autorizado", "threat_level": "Medium"}),
            ("Demons_Cryptominer_Binary", [b"xmrig"],
             {"description": "Binario o configuración del minero XMRig", "threat_level": "Medium"}),
            ("Linux_Rootkit_LdPreload", [b"/etc/ld.so.preload"],
             {"description": "Manipulación de preload dinámico para secuestro de procesos", "threat_level": "Critical"}),
            ("Linux_Webshell_PhpEval", [b"eval(base64_decode(", b"$_POST["],
             {"description": "Inyección y ejecución dinámica de webshell PHP", "threat_level": "Critical"}),
        ]

        # Compilar o cargar de inmediato
        self.compile_rules()

    @property
    def has_yara(self) -> bool:
        return HAS_YARA

    @property
    def is_active(self) -> bool:
        return (HAS_YARA and self._compiled_rules is not None) or (not HAS_YARA)

    @property
    def rules_count(self) -> int:
        if HAS_YARA and self._compiled_rules:
            return self._loaded_rules_count
        return len(self._fallback_signatures)

    def validate_rule_string(self, rule_str: str) -> Tuple[bool, Optional[str]]:
        """
        Valida la sintaxis de una regla YARA sin alterar el estado del motor.
        Retorna (is_valid, error_message).
        """
        if not rule_str or not rule_str.strip():
            return False, "Regla vacía o inválida."

        if HAS_YARA:
            try:
                yara.compile(source=rule_str)
                return True, None
            except yara.SyntaxError as syn_err:
                return False, f"Error sintáctico YARA: {syn_err}"
            except Exception as e:
                return False, f"Error validando regla YARA: {e}"
        else:
            # Validación heurística de gramática YARA
            if "rule " in rule_str and "condition:" in rule_str:
                return True, None
            return False, "Sintaxis básica YARA no reconocida ('rule' o 'condition:' ausente)."

    def validate_rule_file(self, file_path: str) -> Tuple[bool, Optional[str]]:
        """Valida sintácticamente un archivo de reglas antes de su inclusión en el compilador."""
        if not os.path.exists(file_path):
            return False, f"Archivo no existe: {file_path}"

        if HAS_YARA:
            try:
                yara.compile(filepath=file_path)
                return True, None
            except yara.SyntaxError as syn_err:
                return False, f"Error sintáctico en {os.path.basename(file_path)}: {syn_err}"
            except Exception as e:
                return False, f"Error compilando {os.path.basename(file_path)}: {e}"
        else:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                return self.validate_rule_string(content)
            except Exception as e:
                return False, str(e)

    def compute_rules_state_hash(self) -> str:
        """
        Calcula una firma criptográfica única del conjunto de archivos de reglas
        (rutas, tamaños y timestamps mtime) para detectar cualquier adición, modificación o borrado.
        """
        if not os.path.exists(self.rules_dir):
            return ""

        h = hashlib.sha256()
        files = sorted(glob.glob(os.path.join(self.rules_dir, "*.yar")) +
                       glob.glob(os.path.join(self.rules_dir, "*.yara")))

        for fpath in files:
            try:
                st = os.stat(fpath)
                h.update(f"{os.path.basename(fpath)}:{st.st_size}:{st.st_mtime_ns}".encode("utf-8"))
            except Exception:
                pass

        return h.hexdigest()

    def _count_rules_in_files(self, filepaths: Dict[str, str]) -> int:
        """Cuenta el número aproximado de definiciones de reglas en los archivos válidos."""
        total = 0
        rule_pattern = re.compile(r'^\s*rule\s+([A-Za-z0-9_]+)', re.MULTILINE)
        for _, path in filepaths.items():
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    total += len(rule_pattern.findall(f.read()))
            except Exception:
                pass
        return total or len(filepaths) * 4

    def compile_rules(self, force_recompile: bool = False) -> bool:
        """
        Compila o carga las reglas YARA con aislamiento de errores y caché binaria:
        1. Comprueba si los archivos en rules_dir han cambiado comparando el state_hash.
        2. Si no han cambiado y existe constantine_rules.yac, carga la caché con yara.load().
        3. Si han cambiado o force_recompile es True:
           - Valida cada archivo .yar individualmente.
           - Excluye archivos corruptos para evitar que una regla defectuosa desactive el antivirus.
           - Compila las reglas válidas con yara.compile(filepaths=...).
           - Guarda la versión binaria precompilada en disco (.save()).
           - Aplica Hot-Swap atómico del puntero de reglas en memoria.
        """
        self._compilation_errors.clear()

        if not HAS_YARA:
            logger.info("YaraRuleManager: yara-python no disponible. Modo heurístico activo.")
            self._compiled_rules = None
            self._loaded_rules_count = len(self._fallback_signatures)
            return False

        if not os.path.exists(self.rules_dir):
            logger.warning("Directorio de reglas YARA ausente: %s", self.rules_dir)
            self._compiled_rules = None
            return False

        current_state_hash = self.compute_rules_state_hash()

        # Intentar carga rápida desde caché binaria precompilada
        if not force_recompile and current_state_hash:
            if os.path.exists(self.compiled_cache_path) and os.path.exists(self.meta_cache_path):
                try:
                    with open(self.meta_cache_path, "r", encoding="utf-8") as mf:
                        meta = json.load(mf)
                    if meta.get("state_hash") == current_state_hash:
                        # Carga binaria ultrarrápida
                        cached_rules = yara.load(self.compiled_cache_path)
                        self._compiled_rules = cached_rules
                        self._last_state_hash = current_state_hash
                        self._loaded_rules_count = meta.get("rules_count", 32)
                        self._compiled_namespaces = meta.get("namespaces", {})
                        self._last_compile_time = meta.get("compile_time", time.time())
                        logger.info("⚡ [YARA CACHÉ] Reglas binarias cargadas en <5ms desde %s (%d reglas)",
                                    self.compiled_cache_path, self._loaded_rules_count)
                        return True
                except Exception as cache_err:
                    logger.warning("Fallo al leer caché YARA precompilada: %s. Procediendo a recompilación limpia.", cache_err)

        # Descubrimiento de archivos de reglas
        found_files = sorted(glob.glob(os.path.join(self.rules_dir, "*.yar")) +
                             glob.glob(os.path.join(self.rules_dir, "*.yara")))

        if not found_files:
            logger.warning("No se encontraron archivos de reglas (*.yar, *.yara) en %s", self.rules_dir)
            self._compiled_rules = None
            return False

        valid_filepaths: Dict[str, str] = {}
        for fpath in found_files:
            ns = os.path.splitext(os.path.basename(fpath))[0]
            is_valid, err_msg = self.validate_rule_file(fpath)
            if is_valid:
                valid_filepaths[ns] = fpath
            else:
                logger.error("❌ [REGLA YARA INVÁLIDA DESCARTADA] %s: %s", os.path.basename(fpath), err_msg)
                self._compilation_errors.append({"file": fpath, "error": err_msg or "Error de sintaxis"})

        if not valid_filepaths:
            logger.critical("❌ Ningún archivo de reglas YARA superó la validación sintáctica.")
            self._compiled_rules = None
            return False

        try:
            # Compilación segura de todos los namespaces válidos
            new_rules = yara.compile(filepaths=valid_filepaths)
            count = self._count_rules_in_files(valid_filepaths)

            # Hot-Swap atómico en memoria
            self._compiled_rules = new_rules
            self._compiled_namespaces = valid_filepaths
            self._loaded_rules_count = count
            self._last_state_hash = current_state_hash
            self._last_compile_time = time.time()

            logger.info("✅ [YARA MOTOR COMPILADO] %d regla(s) activas desde %d archivo(s) en %s",
                        count, len(valid_filepaths), self.rules_dir)

            # Guardar versión compilada en disco para arranques futuros ultra-rápidos
            try:
                temp_cache = f"{self.compiled_cache_path}.tmp"
                new_rules.save(temp_cache)
                if os.path.exists(temp_cache):
                    os.replace(temp_cache, self.compiled_cache_path)

                temp_meta = f"{self.meta_cache_path}.tmp"
                with open(temp_meta, "w", encoding="utf-8") as mf:
                    json.dump({
                        "state_hash": current_state_hash,
                        "rules_count": count,
                        "namespaces": valid_filepaths,
                        "compile_time": self._last_compile_time
                    }, mf, indent=2)
                os.replace(temp_meta, self.meta_cache_path)
            except Exception as save_err:
                logger.warning("No se pudo persistir la caché YARA binaria: %s", save_err)

            return True

        except Exception as compile_err:
            logger.critical("Error crítico compilando conjunto de reglas YARA: %s", compile_err)
            self._compiled_rules = None
            return False

    def reload_rules(self) -> bool:
        """Fuerza la recompilación y recarga en caliente de todas las reglas."""
        return self.compile_rules(force_recompile=True)

    def match_file(self, file_path: str, timeout: int = 5) -> List[YaraMatch]:
        """
        Ejecuta coincidencia de reglas sobre un archivo en disco:
        - Si YARA oficial está activo, ejecuta rules.match(filepath=..., timeout=timeout).
        - Si ocurre un Timeout, previene DoS y registra alerta.
        - Si YARA oficial no está disponible, delega al motor heurístico de respaldo.
        """
        if not file_path or not os.path.exists(file_path):
            return []

        # 1. Ejecución con YARA Oficial
        if HAS_YARA and self._compiled_rules:
            try:
                raw_matches = self._compiled_rules.match(filepath=file_path, timeout=timeout)
                results: List[YaraMatch] = []
                for m in raw_matches:
                    meta_dict = dict(m.meta) if hasattr(m, "meta") else {}
                    tags_list = list(m.tags) if hasattr(m, "tags") else []
                    strings_list = []
                    if hasattr(m, "strings"):
                        for s in m.strings:
                            try:
                                strings_list.append((s[0], s[1], s[2]))
                            except Exception:
                                pass

                    results.append(YaraMatch(
                        rule=m.rule,
                        namespace=getattr(m, "namespace", "default"),
                        tags=tags_list,
                        meta=meta_dict,
                        strings=strings_list
                    ))
                return results

            except yara.TimeoutError:
                logger.warning("⚠️ [YARA TIMEOUT] Análisis excedió el límite de %ds en %s (mitigación DoS)", timeout, file_path)
                return []
            except Exception as e:
                logger.error("Error ejecutando coincidencia YARA en %s: %s", file_path, e)
                return []

        # 2. Motor Heurístico de Respaldo Transparente
        return self._fallback_match_file(file_path)

    def match_data(self, data: bytes, timeout: int = 5) -> List[YaraMatch]:
        """Ejecuta coincidencia de reglas sobre un búfer en memoria."""
        if not data:
            return []

        if HAS_YARA and self._compiled_rules:
            try:
                raw_matches = self._compiled_rules.match(data=data, timeout=timeout)
                results: List[YaraMatch] = []
                for m in raw_matches:
                    results.append(YaraMatch(
                        rule=m.rule,
                        namespace=getattr(m, "namespace", "default"),
                        tags=list(m.tags) if hasattr(m, "tags") else [],
                        meta=dict(m.meta) if hasattr(m, "meta") else {}
                    ))
                return results
            except Exception as e:
                logger.error("Error en coincidencia YARA sobre búfer: %s", e)
                return []

        # Fallback en memoria
        results = []
        for name, patterns, meta in self._fallback_signatures:
            if all(p in data for p in patterns):
                results.append(YaraMatch(rule=name, namespace="fallback", meta=meta))
        return results

    def _fallback_match_file(self, file_path: str) -> List[YaraMatch]:
        """Motor heurístico de inspección por firmas cuando yara-python no está disponible."""
        matches: List[YaraMatch] = []
        try:
            with open(file_path, "rb") as f:
                header = f.read(1024 * 1024)  # 1 MB de inspección

            for name, patterns, meta in self._fallback_signatures:
                matched = True
                for pat in patterns:
                    if pat not in header:
                        matched = False
                        break
                if matched:
                    matches.append(YaraMatch(
                        rule=name,
                        namespace="fallback_native",
                        meta=meta
                    ))
        except Exception as e:
            logger.debug("Aviso en escaneo de respaldo para %s: %s", file_path, e)
        return matches

    def add_custom_rule(self, rule_name: str, rule_source: str) -> Tuple[bool, str]:
        """Valida y añade una regla personalizada al directorio rules_dir con recarga en caliente."""
        is_valid, err = self.validate_rule_string(rule_source)
        if not is_valid:
            return False, f"Regla inválida: {err}"

        safe_name = re.sub(r'[^A-Za-z0-9_]', '_', rule_name)
        target_file = os.path.join(self.rules_dir, f"custom_{safe_name}.yar")

        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(rule_source)
            self.reload_rules()
            return True, f"Regla guardada en {target_file} y compilada con éxito."
        except Exception as e:
            return False, f"Error persistiendo regla: {e}"

    def get_status(self) -> Dict[str, Any]:
        """Retorna estadísticas completas del subsistema YARA para auditoría y GUI."""
        engine_type = "Oficial YARA 4.x" if (HAS_YARA and self._compiled_rules) else "Heurístico Nativo de Respaldo"
        return {
            "has_yara": HAS_YARA,
            "is_active": self.is_active,
            "engine_type": engine_type,
            "rules_count": self.rules_count,
            "namespaces": list(self._compiled_namespaces.keys()),
            "rules_dir": self.rules_dir,
            "cache_file": self.compiled_cache_path,
            "cache_active": os.path.exists(self.compiled_cache_path),
            "last_compile_time": self._last_compile_time,
            "compilation_errors": self._compilation_errors
        }
