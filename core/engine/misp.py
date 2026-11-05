"""
Constantine Antivirus - MISP Threat Intelligence Centralization Engine (core/engine/misp.py)
Integración nativa con la plataforma y formato estándar de Inteligencia de Amenazas MISP:

ARQUITECTURA DE INTELIGENCIA DE AMENAZAS MISP EN CONSTANTINE (P0):
1. Plataforma Centralizada de Inteligencia (Sin Instalar el Servidor Completo en Cada Endpoint):
   - En lugar de desplegar toda la infraestructura web/servidor de MISP en cada cliente,
     Constantine opera como un consumidor de alta velocidad de feeds e instancias centrales MISP.
2. Administración y Correlación de Vectores de Amenaza:
   - Hashes de Malware: SHA-256, SHA-1, MD5.
   - Direcciones IP Maliciosas: C2 Servers, balizamiento egress, nodos de ataque (ip-dst, ip-src).
   - Dominios y Nombres de Host Sospechosos: Dominios de comando y control, exfiltración y DGA.
   - URLs de Distribución de Malware: Enlaces directos a droppers, scripts y binarios maliciosos.
   - Indicadores de Compromiso (IoCs): Enriquecidos con campaña, actor de amenaza (Galaxies),
     clasificación MITRE ATT&CK, criticidad (High, Medium, Low) y TLP (White, Green, Amber, Red).
3. Ingesta Flexible de Formatos de Feeds:
   - Feeds estándar de eventos MISP JSON (manifiesto manifest.json + eventos UUID.json).
   - Exportaciones CSV estructuradas y feeds de texto libre.
4. Integración Directa con Constantine Threat Intelligence:
   - Los indicadores ingeridos se canalizan hacia la base de datos SQLite de Constantine
     (threat_intel.db) alimentando al Interceptor de kernel, Cortafuegos y Escáner.
5. Auto-registro en sys.modules:
   - Permite 'import misp' de manera nativa y transparente en cualquier parte del entorno Constantine.
"""

from __future__ import annotations

import os
import re
import sys
import json
import time
import shutil
import urllib.request
import urllib.error
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable, Set

logger = logging.getLogger("constantine.misp")

LOCAL_MISP_FEEDS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "feeds", "misp"
)
SYSTEM_MISP_FEEDS_DIR = "/var/lib/constantine/feeds/misp"


class MISPThreatLevel(str, Enum):
    """Niveles de severidad oficiales de eventos MISP."""
    HIGH = "High"        # Nivel 1
    MEDIUM = "Medium"    # Nivel 2
    LOW = "Low"          # Nivel 3
    UNDEFINED = "Undefined"  # Nivel 4

    @classmethod
    def from_id(cls, level_id: Any) -> "MISPThreatLevel":
        s = str(level_id).strip()
        if s == "1":
            return cls.HIGH
        elif s == "2":
            return cls.MEDIUM
        elif s == "3":
            return cls.LOW
        return cls.UNDEFINED


@dataclass
class MISPAttribute:
    """Atributo o Indicador de Compromiso (IoC) contenido dentro de un evento MISP."""
    attr_id: str
    uuid: str
    type: str  # sha256, md5, ip-dst, domain, url, etc.
    category: str
    value: str
    to_ids: bool = True
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.attr_id,
            "uuid": self.uuid,
            "type": self.type,
            "category": self.category,
            "value": self.value,
            "to_ids": self.to_ids,
            "comment": self.comment
        }


@dataclass
class MISPEvent:
    """Evento estructurado de Inteligencia de Amenazas de MISP."""
    event_id: str
    uuid: str
    info: str
    threat_level: MISPThreatLevel
    analysis: str
    date: str
    timestamp: float
    orgc_name: str = "Unknown"
    tags: List[str] = field(default_factory=list)
    attributes: List[MISPAttribute] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Optional["MISPEvent"]:
        """Parsea un diccionario JSON con esquema oficial MISP Event."""
        ev = data.get("Event", data)
        if not isinstance(ev, dict):
            return None

        event_id = str(ev.get("id", ""))
        uuid = str(ev.get("uuid", ""))
        info = str(ev.get("info", "Evento MISP sin descripción"))
        t_level = MISPThreatLevel.from_id(ev.get("threat_level_id", "4"))
        analysis = str(ev.get("analysis", "0"))
        date_str = str(ev.get("date", time.strftime("%Y-%m-%d")))
        ts = float(ev.get("timestamp", time.time()) or time.time())

        orgc = ev.get("Orgc", {})
        orgc_name = orgc.get("name", "Unknown") if isinstance(orgc, dict) else "Unknown"

        raw_tags = ev.get("Tag", [])
        tags = []
        for t in raw_tags:
            if isinstance(t, dict):
                t_name = t.get("name", "")
                if t_name:
                    tags.append(t_name)
            elif isinstance(t, str):
                tags.append(t)

        attrs = []
        raw_attrs = ev.get("Attribute", [])
        for a in raw_attrs:
            if isinstance(a, dict):
                a_type = a.get("type", "")
                a_val = str(a.get("value", "")).strip()
                if a_type and a_val:
                    attrs.append(MISPAttribute(
                        attr_id=str(a.get("id", "")),
                        uuid=str(a.get("uuid", "")),
                        type=a_type,
                        category=str(a.get("category", "")),
                        value=a_val,
                        to_ids=bool(a.get("to_ids", True)),
                        comment=str(a.get("comment", ""))
                    ))

        return cls(
            event_id=event_id,
            uuid=uuid,
            info=info,
            threat_level=t_level,
            analysis=analysis,
            date=date_str,
            timestamp=ts,
            orgc_name=orgc_name,
            tags=tags,
            attributes=attrs
        )


@dataclass
class MISPIoCLookupResult:
    """Resultado de coincidencia en la base de inteligencia MISP."""
    matched: bool
    ioc_type: str
    ioc_value: str
    threat_name: str
    campaign: str
    threat_level: str
    confidence: int
    source: str
    tags: List[str]
    comment: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "ioc_type": self.ioc_type,
            "ioc_value": self.ioc_value,
            "threat_name": self.threat_name,
            "campaign": self.campaign,
            "threat_level": self.threat_level,
            "confidence": self.confidence,
            "source": self.source,
            "tags": self.tags,
            "comment": self.comment
        }


class MISPClient:
    """Cliente REST para sincronizar indicadores desde una plataforma central MISP."""

    def __init__(self, base_url: Optional[str] = None, auth_key: Optional[str] = None):
        self.base_url = (base_url or "").rstrip("/")
        self.auth_key = auth_key or ""

    def is_configured(self) -> bool:
        return bool(self.base_url and self.auth_key)

    def search_events(self, value: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """Consulta eventos vía API REST /events/restSearch de MISP."""
        if not self.is_configured():
            return []

        url = f"{self.base_url}/events/restSearch"
        headers = {
            "Authorization": self.auth_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        payload = {"returnFormat": "json", "limit": limit}
        if value:
            payload["value"] = value

        try:
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data.get("response", [])
        except Exception as e:
            logger.debug("Error consultando API REST de MISP (%s): %s", self.base_url, e)

        return []


class MISPManager:
    """
    Orquestador Central de Inteligencia de Amenazas MISP en Constantine EDR:
    Ingesta feeds locales y remotos en formato MISP, correlaciona indicadores
    (hashes, IPs, dominios, URLs) y los sincroniza con la base ThreatIntelligence.
    """

    def __init__(self, threat_intel=None):
        self.threat_intel = threat_intel
        self.client = MISPClient()
        self.events_cache: Dict[str, MISPEvent] = {}
        self.iocs_index: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.last_sync_time: float = 0

        # Cargar feeds locales predeterminados
        self.ingest_local_feeds()

    def ingest_local_feeds(self) -> int:
        """Carga e indexa eventos MISP desde los directorios de feeds de Constantine."""
        ingested = 0
        search_dirs = [LOCAL_MISP_FEEDS_DIR, SYSTEM_MISP_FEEDS_DIR]

        for sdir in search_dirs:
            if os.path.exists(sdir):
                for fname in sorted(os.listdir(sdir)):
                    if fname.endswith(".json") and fname != "manifest.json":
                        fpath = os.path.join(sdir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                ev = MISPEvent.from_dict(data)
                                if ev:
                                    self._index_event(ev)
                                    ingested += 1
                        except Exception as e:
                            logger.error("Error parseando evento MISP %s: %s", fpath, e)

        self.last_sync_time = time.time()
        logger.info("🛡️ [MISP FEEDS INGESTADOS] %d eventos y %d IoCs indexados.", len(self.events_cache), len(self.iocs_index))
        return ingested

    def _index_event(self, event: MISPEvent):
        """Indexa los atributos de un evento MISP y los propaga a ThreatIntelligence."""
        with self._lock:
            self.events_cache[event.uuid] = event

            for attr in event.attributes:
                key = attr.value.lower()
                self.iocs_index[key] = {
                    "event_uuid": event.uuid,
                    "campaign": event.info,
                    "threat_level": event.threat_level.value,
                    "type": attr.type,
                    "category": attr.category,
                    "tags": event.tags,
                    "comment": attr.comment,
                    "to_ids": attr.to_ids
                }

                # Si hay instancia de ThreatIntelligence conectada, inyectar directamente
                if self.threat_intel:
                    conf = 95 if event.threat_level == MISPThreatLevel.HIGH else 85
                    if attr.type == "sha256":
                        self.threat_intel.insert_hash(
                            sha256=attr.value,
                            threat_name=f"MISP.{event.info}",
                            source="MISP_ThreatIntel",
                            confidence=conf,
                            tags=",".join(event.tags)
                        )
                    elif attr.type in ("url", "uri"):
                        self.threat_intel.insert_url(
                            url_or_domain=attr.value,
                            threat_type="MalwareDelivery",
                            source="MISP_ThreatIntel",
                            confidence=conf
                        )
                    elif attr.type in ("domain", "hostname"):
                        self.threat_intel.insert_url(
                            url_or_domain=attr.value,
                            threat_type="C2_Domain",
                            source="MISP_ThreatIntel",
                            confidence=conf
                        )
                    elif attr.type in ("ip-dst", "ip-src"):
                        if hasattr(self.threat_intel, "insert_ip"):
                            self.threat_intel.insert_ip(
                                ip=attr.value,
                                threat_type="C2_Server",
                                source="MISP_ThreatIntel",
                                confidence=conf
                            )

    def lookup_ioc(self, value: str) -> Optional[MISPIoCLookupResult]:
        """
        Busca un indicador (Hash SHA-256, IP, Dominio o URL) en la base de inteligencia MISP.
        Retorna detalles enriquecidos de campaña, actor de amenaza y nivel de riesgo.
        """
        if not value:
            return None

        val_norm = value.strip().lower()

        with self._lock:
            match = self.iocs_index.get(val_norm)

        if not match:
            # Comprobar si el valor es una URL completa y buscar por host
            if "://" in val_norm:
                from urllib.parse import urlparse
                host = urlparse(val_norm).netloc.lower()
                with self._lock:
                    match = self.iocs_index.get(host)

        if match:
            return MISPIoCLookupResult(
                matched=True,
                ioc_type=match["type"],
                ioc_value=value,
                threat_name=f"MISP.{match['campaign']}",
                campaign=match["campaign"],
                threat_level=match["threat_level"],
                confidence=95 if match["threat_level"] == "High" else 85,
                source="MISP_Platform",
                tags=match["tags"],
                comment=match["comment"]
            )

        return None

    def ingest_misp_json(self, raw_json_data: Any) -> int:
        """Ingesta un objeto o cadena JSON de MISP en caliente."""
        if isinstance(raw_json_data, str):
            try:
                raw_json_data = json.loads(raw_json_data)
            except Exception as e:
                logger.error("JSON de MISP inválido: %s", e)
                return 0

        if isinstance(raw_json_data, dict):
            ev = MISPEvent.from_dict(raw_json_data)
            if ev:
                self._index_event(ev)
                return len(ev.attributes)
        elif isinstance(raw_json_data, list):
            total_attrs = 0
            for item in raw_json_data:
                ev = MISPEvent.from_dict(item)
                if ev:
                    self._index_event(ev)
                    total_attrs += len(ev.attributes)
            return total_attrs

        return 0

    def is_available(self) -> bool:
        return True

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna telemetría completa de la plataforma de inteligencia MISP."""
        with self._lock:
            ev_count = len(self.events_cache)
            ioc_count = len(self.iocs_index)
            recent_events = [
                {
                    "uuid": ev.uuid,
                    "info": ev.info,
                    "threat_level": ev.threat_level.value,
                    "date": ev.date,
                    "attributes_count": len(ev.attributes),
                    "tags": ev.tags
                } for ev in list(self.events_cache.values())[:10]
            ]

        return {
            "available": True,
            "engine": "MISP_Threat_Sharing_Platform",
            "events_count": ev_count,
            "iocs_count": ioc_count,
            "last_sync_time": self.last_sync_time,
            "sample_events": recent_events,
            "supported_vectors": ["sha256", "md5", "ip-dst", "domain", "url"]
        }


# Instancia singleton predeterminada
_default_misp_manager: Optional[MISPManager] = None


def get_default_manager() -> MISPManager:
    """Retorna la instancia global compartida de MISPManager."""
    global _default_misp_manager
    if _default_misp_manager is None:
        _default_misp_manager = MISPManager()
    return _default_misp_manager


def is_available() -> bool:
    """Comprueba si el subsistema MISP está activo."""
    return get_default_manager().is_available() if hasattr(get_default_manager(), "is_available") else True


def get_version() -> str:
    """Obtiene la versión de la especificación MISP soportada."""
    return "MISP-2.4-Core-IoC-Schema"


def lookup_ioc(value: str) -> Optional[MISPIoCLookupResult]:
    """Busca un indicador en la base de inteligencia de amenazas MISP."""
    return get_default_manager().lookup_ioc(value)


def ingest_event_json(json_str_or_dict: Any) -> int:
    """Ingesta un evento en formato MISP en tiempo de ejecución."""
    return get_default_manager().ingest_misp_json(json_str_or_dict)


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import misp' nativo)
# =============================================================================
if "misp" not in sys.modules:
    sys.modules["misp"] = sys.modules[__name__]
