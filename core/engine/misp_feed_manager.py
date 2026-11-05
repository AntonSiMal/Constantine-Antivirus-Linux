"""
Administrador de Feeds de Inteligencia de Amenazas MISP para Constantine Antivirus.
Soporta MISP como fuente opcional de inteligencia de amenazas (conectores remotos y feeds locales).
"""
import os
import json
import logging
from typing import Dict, Any, List, Optional
from core.engine.threat_intel import ThreatIntelligence

logger = logging.getLogger("constantine.misp")

class MISPFeedManager:
    """Gestiona la ingesta, parseo y correlación de eventos e indicadores MISP."""

    def __init__(self, intel_engine: Optional[ThreatIntelligence] = None, rules_dir: Optional[str] = None):
        self.intel = intel_engine or ThreatIntelligence()
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.events: List[Dict[str, Any]] = []
        self.enabled = True  # Fuente opcional de inteligencia
        self.server_url: Optional[str] = None
        self.api_key: Optional[str] = None
        self.load_rules()

    def set_enabled(self, enabled: bool):
        """Habilita o deshabilita MISP como fuente de inteligencia activa."""
        self.enabled = enabled
        logger.info("⚙️ [MISP] Fuente opcional de inteligencia: %s", "HABILITADA" if enabled else "DESHABILITADA")

    def configure_remote_server(self, url: str, api_key: str) -> Dict[str, Any]:
        """Configura la conexión opcional a una instancia remota de MISP Server."""
        self.server_url = url
        self.api_key = api_key
        logger.info("🌐 [MISP] Servidor remoto configurado: %s", url)
        return {
            "configured": True,
            "url": url,
            "status": "READY"
        }

    def load_rules(self) -> int:
        """Carga eventos MISP locales desde archivo JSON."""
        events_file = os.path.join(self.rules_dir, "misp_events.json")
        if not os.path.exists(events_file):
            return 0

        try:
            with open(events_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_events = data.get("response", []) if isinstance(data, dict) else data
            self.events = raw_events
            iocs_count = self.sync_to_threat_intel()
            logger.info("🛡️ [MISP FEEDS INGESTADOS] %d eventos y %d IoCs indexados.", len(self.events), iocs_count)
            return len(self.events)
        except Exception as e:
            logger.error("Error cargando eventos MISP: %s", e)
            return 0

    def sync_to_threat_intel(self) -> int:
        """Sincroniza los indicadores de eventos MISP en la base de datos de Threat Intelligence."""
        if not self.enabled:
            return 0
        total_synced = 0
        for item in self.events:
            event = item.get("Event", item)
            event_info = event.get("info", "MISP Event")
            tags = ",".join([t.get("name", "") for t in event.get("Tag", [])])
            for attr in event.get("Attribute", []):
                val = attr.get("value", "")
                attr_type = attr.get("type", "")
                comment = attr.get("comment", event_info)
                if val:
                    if self.intel.add_ioc(attr_type, val, source="MISP", confidence=90, description=comment, tags=tags):
                        total_synced += 1
        return total_synced

    def lookup_ioc(self, value: str) -> Optional[Dict[str, Any]]:
        """Busca un IoC en la base de inteligencia."""
        if not self.enabled:
            return None
        return self.intel.lookup_ioc(value)

    def probe_integration(self) -> Dict[str, Any]:
        """Verifica si la librería pymisp está instalada o si opera consumiendo feeds locales."""
        has_pymisp = False
        try:
            import pymisp
            has_pymisp = True
        except ImportError:
            pass

        return {
            "name": "MISP Threat Intelligence Platform (Optional Source)",
            "type": "REST_API_AND_FEED",
            "enabled": self.enabled,
            "library_installed": has_pymisp,
            "api_configured": bool(self.server_url and self.api_key),
            "remote_server": self.server_url,
            "mode": "PYMISP_LIVE_API" if (has_pymisp and self.server_url) else "OFFLINE_FEED_CONSUMER",
            "events_indexed": len(self.events),
            "details": "Conexión activa a MISP Server" if (self.server_url) else "Operando como fuente opcional con feeds e indicadores locales (JSON/CSV) sincronizados en SQLite"
        }
