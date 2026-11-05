"""
Constantine Antivirus - Wazuh FIM & YARA Active Response Engine (core/engine/wazuh.py)
Reproducción e integración de la estrategia de File Integrity Monitoring (FIM / syscheck),
detección correlacionada con YARA y Respuesta Activa (Active Response) según severidad:

ARQUITECTURA DE VIGILANCIA DE CAMBIOS Y RESPUESTA ACTIVA WAZUH (P0):
1. Detección de Cambios en Tiempo Real (FIM Event-Driven):
   - En lugar de escanear continuamente todos los archivos del sistema, se capturan eventos
     de creación y modificación de archivos (FILE_CREATED, FILE_MODIFIED, METADATA_CHANGED).
   - Extrae ruta canónica, identidad del proceso y metadatos forenses (SHA-256, UID, GID,
     permisos POSIX, bits SUID/SGID, tamaño y marcas de tiempo).
2. Inspección Específica con YARA en el Punto de Cambio:
   - Al detectarse un cambio o creación, se dispara el análisis dirigido mediante YARA / YARA-X
     únicamente sobre el archivo afectado, optimizando radicalmente el uso de CPU y E/S.
3. Evaluación de Reglas y Decodificadores con Severidad Wazuh (Niveles 1 a 15):
   - Nivel 1 - 3: Informativo / Eventos FIM basales (archivo creado/modificado rutinario).
   - Nivel 4 - 7: Advertencia / Anomalías de bajo riesgo.
   - Nivel 8 - 11: Riesgo Alto / Coincidencia con mineros o binarios SUID (Cuarentena).
   - Nivel 12 - 15: Crítico y Emergencia / Coincidencia YARA con Reverse Shells, C2 o Webshells
     (Respuesta Activa inmediata: Aislamiento de Red + Cuarentena + Terminación de Proceso).
4. Marco de Respuesta Activa (Active Response):
   - firewall_drop: Corte inmediato de tráfico de red para el proceso agresor (NetworkQuarantine).
   - quarantine_vault: Aislamiento transaccional criptográfico en el Baúl AES-256-GCM (QuarantineVault).
   - kill_process: Terminación forzada del proceso con SIGSTOP y SIGKILL.
   - notify_desktop: Notificación visual con criticidad y detalles en tiempo real.
5. Auto-registro en sys.modules:
   - Permite 'import wazuh' de manera nativa en todo el ecosistema Constantine.
"""

from __future__ import annotations

import os
import sys
import stat
import time
import json
import shutil
import hashlib
import logging
import threading
import subprocess
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable, Set

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

logger = logging.getLogger("constantine.wazuh")

WAZUH_RULES_DEFAULT_DIR = "/var/ossec/etc/rules"
CONSTANTINE_WAZUH_RULES_DIR = "/opt/constantine/core/rules/wazuh"
LOCAL_DEV_WAZUH_RULES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "wazuh"
)


class WazuhFIMEventType(str, Enum):
    """Tipos de eventos de File Integrity Monitoring (FIM / syscheck)."""
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    METADATA_CHANGED = "METADATA_CHANGED"


@dataclass
class WazuhFIMEvent:
    """Metadatos e identidad forense extraídos de un archivo creado o modificado."""
    path: str
    event_type: WazuhFIMEventType
    sha256: str = ""
    size: int = 0
    uid: int = 0
    gid: int = 0
    mode: int = 0
    has_suid: bool = False
    has_sgid: bool = False
    mtime: float = field(default_factory=time.time)
    pid: Optional[int] = None
    comm: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    @classmethod
    def from_path(
        cls,
        path: str,
        event_type: WazuhFIMEventType = WazuhFIMEventType.FILE_MODIFIED,
        pid: Optional[int] = None,
        comm: Optional[str] = None
    ) -> Optional["WazuhFIMEvent"]:
        """Extrae de forma segura la identidad y metadatos de un archivo en disco."""
        if not path or not os.path.exists(path):
            return None

        try:
            st = os.stat(path)
            mode = st.st_mode
            size = st.st_size
            uid = st.st_uid
            gid = st.st_gid
            mtime = st.st_mtime
            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)

            # Cálculo seguro de SHA-256 (hasta 10 MB para evitar bloqueo de E/S)
            h = hashlib.sha256()
            if stat.S_ISREG(mode) and size <= 10 * 1024 * 1024:
                with open(path, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                file_hash = h.hexdigest()
            else:
                file_hash = f"size:{size}:mtime:{mtime}"

            return cls(
                path=os.path.abspath(path),
                event_type=event_type,
                sha256=file_hash,
                size=size,
                uid=uid,
                gid=gid,
                mode=mode,
                has_suid=has_suid,
                has_sgid=has_sgid,
                mtime=mtime,
                pid=pid,
                comm=comm,
                timestamp=time.time()
            )
        except Exception as e:
            logger.debug("No se pudieron extraer metadatos FIM de %s: %e", path, e)
            return None


@dataclass
class WazuhAlert:
    """Alerta estructurada de Wazuh correlacionada con YARA y severidad asignada."""
    rule_id: int
    level: int  # 1 a 15
    description: str
    groups: List[str]
    file_path: str
    yara_matches: List[str] = field(default_factory=list)
    active_response_action: Optional[str] = None
    active_response_executed: bool = False
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "level": self.level,
            "description": self.description,
            "groups": self.groups,
            "file_path": self.file_path,
            "yara_matches": self.yara_matches,
            "active_response_action": self.active_response_action,
            "active_response_executed": self.active_response_executed,
            "timestamp": self.timestamp,
            "metadata": self.metadata
        }


class WazuhRule:
    """Regla de seguridad decodificadora compatible con el formato de Wazuh."""

    def __init__(
        self,
        rule_id: int,
        level: int,
        description: str,
        group: List[str],
        criteria: Dict[str, Any],
        active_response: Optional[Dict[str, Any]] = None
    ):
        self.rule_id = rule_id
        self.level = level
        self.description = description
        self.group = group
        self.criteria = criteria or {}
        self.active_response = active_response or {}

    def match(self, event: WazuhFIMEvent, yara_matches: List[str]) -> bool:
        """Determina si un evento FIM y sus resultados YARA cumplen los criterios de la regla."""
        # 1. Criterio de tipo de evento FIM
        req_event = self.criteria.get("event_type")
        if req_event and req_event != event.event_type.value:
            return False

        # 2. Criterio de coincidencia YARA específica
        req_yara = self.criteria.get("yara_rule_matches", [])
        if req_yara:
            if not any(r in yara_matches for r in req_yara):
                return False

        # 3. Criterio de prefijo de ruta de destino
        req_paths = self.criteria.get("target_paths_prefix", [])
        if req_paths:
            if not any(event.path.startswith(p) for p in req_paths):
                return False

        # 4. Criterio de anomalía SUID/SGID
        if self.criteria.get("has_suid_or_sgid"):
            if not (event.has_suid or event.has_sgid):
                return False

        return True


class WazuhActiveResponse:
    """
    Módulo de Respuesta Activa (Active Response) de Wazuh.
    Aplica contención automatizada de severidad graduada utilizando las capacidades de Constantine.
    """

    def __init__(self, vault=None, firewall=None, notifier=None):
        self.vault = vault
        self.firewall = firewall
        self.notifier = notifier
        self.actions_executed = 0

    def execute(self, alert: WazuhAlert, event: WazuhFIMEvent) -> bool:
        """Ejecuta las directivas de respuesta activa según el nivel de severidad."""
        action_name = alert.active_response_action or "default_response"
        executed = False

        logger.critical(
            "🛡️ [WAZUH ACTIVE RESPONSE] Ejecutando acción '%s' (Nivel %d) sobre %s",
            action_name, alert.level, event.path
        )

        # 1. Aislamiento de Red del Proceso Involucrado (Firewall Drop)
        if self.firewall and event.pid and event.pid > 1:
            if alert.level >= 12 or "firewall" in action_name:
                try:
                    self.firewall.contain_process(
                        event.pid,
                        reason=f"Wazuh AR: Regla {alert.rule_id} (Nivel {alert.level})"
                    )
                    logger.critical("🛑 [WAZUH AR] Aislamiento de red aplicado al PID %d", event.pid)
                    executed = True
                except Exception as e:
                    logger.error("Fallo aplicando firewall drop de Wazuh: %s", e)

        # 2. Aislamiento Transaccional en Cuarentena Criptográfica (Baúl Vault)
        if self.vault and os.path.exists(event.path):
            if alert.level >= 8 or "quarantine" in action_name:
                try:
                    self.vault.quarantine_file(
                        file_path=event.path,
                        reason=f"Wazuh AR: Regla {alert.rule_id} (Nivel {alert.level}) - {alert.description}"
                    )
                    logger.critical("🔒 [WAZUH AR] Muestra asegurada en el Baúl: %s", event.path)
                    executed = True
                except Exception as e:
                    logger.error("Fallo aplicando cuarentena de Wazuh: %s", e)

        # 3. Terminación de Proceso Hostil (SIGSTOP + SIGKILL)
        if event.pid and event.pid > 1:
            if alert.level >= 10:
                try:
                    import signal
                    os.kill(event.pid, signal.SIGSTOP)
                    os.kill(event.pid, signal.SIGKILL)
                    logger.critical("⚡ [WAZUH AR] Proceso agresor PID %d neutralizado con SIGKILL.", event.pid)
                    executed = True
                except Exception:
                    pass

        # 4. Notificación de Escritorio al Usuario
        if self.notifier and alert.level >= 4:
            try:
                urgency = "critical" if alert.level >= 10 else "normal"
                self.notifier.send(
                    f"⚔️ Wazuh Active Response (Nivel {alert.level})",
                    f"{alert.description}\nArchivo: {os.path.basename(event.path)}\nAcción: {action_name}",
                    urgency=urgency
                )
                executed = True
            except Exception:
                pass

        if executed:
            self.actions_executed += 1
            alert.active_response_executed = True

        return executed


class WazuhManager:
    """
    Orquestador Central de la Estrategia Wazuh en Constantine EDR:
    Vigila la integridad de archivos (FIM), ejecuta análisis bajo demanda con YARA
    y desencadena la Respuesta Activa adecuada sin sobrecargar el procesador.
    """

    def __init__(
        self,
        scanner=None,
        vault=None,
        firewall=None,
        notifier=None,
        alert_callback: Optional[Callable[[Dict[str, Any]], None]] = None
    ):
        self.scanner = scanner
        self.vault = vault
        self.firewall = firewall
        self.notifier = notifier
        self.alert_callback = alert_callback

        self.rules: List[WazuhRule] = []
        self.active_response = WazuhActiveResponse(
            vault=self.vault,
            firewall=self.firewall,
            notifier=self.notifier
        )

        self.events_inspected = 0
        self.alerts_generated = 0
        self.recent_alerts: List[WazuhAlert] = []
        self._lock = threading.Lock()

        self.reload_rules()

    def is_engine_available(self) -> bool:
        """Determina si la estrategia Wazuh de inspección de cambios está operativa."""
        return len(self.rules) > 0

    def reload_rules(self) -> int:
        """Carga las reglas decodificadoras Wazuh desde los directorios configurados."""
        loaded_rules: List[WazuhRule] = []
        candidate_dirs = [
            CONSTANTINE_WAZUH_RULES_DIR,
            LOCAL_DEV_WAZUH_RULES_DIR,
            WAZUH_RULES_DEFAULT_DIR
        ]

        for cdir in candidate_dirs:
            if os.path.exists(cdir):
                for fname in sorted(os.listdir(cdir)):
                    if fname.endswith((".yaml", ".yml")):
                        fpath = os.path.join(cdir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                docs = yaml.safe_load_all(f) if HAS_YAML else []
                                for doc in docs:
                                    items = doc if isinstance(doc, list) else [doc]
                                    for item in items:
                                        if isinstance(item, dict) and "rule" in item:
                                            r_data = item["rule"]
                                            loaded_rules.append(WazuhRule(
                                                rule_id=int(r_data.get("id", 100000)),
                                                level=int(r_data.get("level", 1)),
                                                description=r_data.get("description", ""),
                                                group=r_data.get("group", []),
                                                criteria=r_data.get("criteria", {}),
                                                active_response=r_data.get("active_response", {})
                                            ))
                        except Exception as e:
                            logger.error("Error parseando reglas Wazuh en %s: %s", fpath, e)

        with self._lock:
            self.rules = loaded_rules
        logger.info("⚡ [WAZUH REGLAS CARGADAS] %d reglas FIM + YARA activas.", len(self.rules))
        return len(self.rules)

    def on_file_changed(
        self,
        path: str,
        event_type: WazuhFIMEventType = WazuhFIMEventType.FILE_MODIFIED,
        pid: Optional[int] = None,
        comm: Optional[str] = None
    ) -> Optional[WazuhAlert]:
        """
        Estrategia Central Wazuh:
        1. Detecta creación o modificación de un archivo (FIM).
        2. Obtiene su ruta, identidad y metadatos forenses.
        3. Ejecuta el análisis correspondiente (YARA-X / Scanner).
        4. Genera una detección estructurada con nivel de severidad.
        5. Aplica Respuesta Activa según la gravedad evaluada.
        """
        if not path or not os.path.exists(path):
            return None

        event = WazuhFIMEvent.from_path(path, event_type=event_type, pid=pid, comm=comm)
        if not event:
            return None

        with self._lock:
            self.events_inspected += 1

        # 3. Ejecutar análisis YARA dirigido únicamente sobre el archivo modificado
        yara_matches: List[str] = []
        if self.scanner and hasattr(self.scanner, "yara_manager"):
            try:
                matches = self.scanner.yara_manager.match_file(path)
                yara_matches = [m.rule for m in matches]
            except Exception as e:
                logger.debug("Error ejecutando YARA dirigido sobre %s: %s", path, e)

        # 4. Correlacionar evento FIM y coincidencias YARA con las reglas de Wazuh
        matched_rule: Optional[WazuhRule] = None
        highest_level = 0

        with self._lock:
            current_rules = list(self.rules)

        for rule in current_rules:
            if rule.match(event, yara_matches):
                if rule.level > highest_level:
                    highest_level = rule.level
                    matched_rule = rule

        if not matched_rule:
            return None

        # 5. Generar Alerta Estructurada
        ar_action = matched_rule.active_response.get("action")
        alert = WazuhAlert(
            rule_id=matched_rule.rule_id,
            level=matched_rule.level,
            description=matched_rule.description,
            groups=matched_rule.group,
            file_path=event.path,
            yara_matches=yara_matches,
            active_response_action=ar_action,
            metadata={
                "sha256": event.sha256,
                "size": event.size,
                "uid": event.uid,
                "mode": oct(event.mode),
                "pid": event.pid,
                "comm": event.comm,
                "event_type": event.event_type.value
            }
        )

        with self._lock:
            self.alerts_generated += 1
            self.recent_alerts.append(alert)
            if len(self.recent_alerts) > 100:
                self.recent_alerts.pop(0)

        logger.warning(
            "🚨 [WAZUH ALERTA FIM+YARA] Regla %d (Nivel %d): %s | Archivo: %s",
            alert.rule_id, alert.level, alert.description, alert.file_path
        )

        # 6. Notificar al callback si existe
        if self.alert_callback:
            try:
                self.alert_callback(alert.to_dict())
            except Exception as e:
                logger.error("Error en callback de alerta Wazuh: %s", e)

        # 7. Aplicar Respuesta Activa según la gravedad
        self.active_response.execute(alert, event)

        return alert

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna telemetría del subsistema Wazuh FIM + YARA y Respuesta Activa."""
        return {
            "available": self.is_engine_available(),
            "strategy": "FIM_CHANGE_DRIVEN_YARA_AND_ACTIVE_RESPONSE",
            "rules_count": len(self.rules),
            "events_inspected": self.events_inspected,
            "alerts_generated": self.alerts_generated,
            "active_responses_executed": self.active_response.actions_executed,
            "rules": [
                {
                    "id": r.rule_id,
                    "level": r.level,
                    "description": r.description,
                    "group": r.group,
                    "action": r.active_response.get("action")
                } for r in self.rules[:15]
            ]
        }


# Instancia singleton predeterminada
_default_wazuh_manager: Optional[WazuhManager] = None


def get_default_manager() -> WazuhManager:
    """Retorna la instancia global compartida de WazuhManager."""
    global _default_wazuh_manager
    if _default_wazuh_manager is None:
        _default_wazuh_manager = WazuhManager()
    return _default_wazuh_manager


def is_available() -> bool:
    """Comprueba si el subsistema Wazuh está activo y disponible."""
    return get_default_manager().is_engine_available()


def get_version() -> Optional[str]:
    """Obtiene la versión de la estrategia Wazuh integrada."""
    return "4.8.0-Constantine-FIM"


def list_rules() -> List[Dict[str, Any]]:
    """Lista las reglas de seguridad FIM y Respuesta Activa."""
    return get_default_manager().get_status_info().get("rules", [])


def analyze_file_change(
    path: str,
    event_type: str = "FILE_MODIFIED",
    pid: Optional[int] = None,
    comm: Optional[str] = None
) -> Optional[WazuhAlert]:
    """Analiza la creación o modificación de un archivo según la estrategia Wazuh."""
    try:
        ev_type = WazuhFIMEventType(event_type)
    except ValueError:
        ev_type = WazuhFIMEventType.FILE_MODIFIED
    return get_default_manager().on_file_changed(path, event_type=ev_type, pid=pid, comm=comm)


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import wazuh' nativo)
# =============================================================================
if "wazuh" not in sys.modules:
    sys.modules["wazuh"] = sys.modules[__name__]
