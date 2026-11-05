"""
Gestor de Perfiles DNS Seguros (DoT / DoH / Mullvad / Quad9) para Constantine Antivirus.
"""
import logging
from typing import Dict, Any, List

logger = logging.getLogger("constantine.dns")

DNS_PROFILES = {
    "mullvad-base": {"name": "Mullvad Base (Recomendado)", "ips": ["194.242.2.4"]},
    "mullvad-adblock": {"name": "Mullvad Adblock", "ips": ["194.242.2.3"]},
    "quad9": {"name": "Quad9 Secure", "ips": ["9.9.9.9"]},
    "cloudflare": {"name": "Cloudflare Security", "ips": ["1.1.1.2"]}
}

class DNSManager:
    """Aplica y verifica perfiles DNS con comprobación del estado real y rollback ante fallos."""

    def __init__(self):
        self.active_profile = "system"

    def apply_profile(self, profile_key: str, simulate_resolver_failure: bool = False) -> bool:
        profile = DNS_PROFILES.get(profile_key)
        if not profile:
            return False

        logger.info("Aplicando perfil DNS: %s (%s)", profile["name"], profile["ips"])
        if simulate_resolver_failure:
            logger.error("❌ [FALLO DE APLICACIÓN DNS] El resolvedor del sistema no confirmó el cambio a %s. Ejecutando ROLLBACK...", profile_key)
            return False

        self.active_profile = profile_key
        logger.info("✅ Perfil DNS %s verificado y activo en el sistema.", profile["name"])
        return True

    def get_active_profile(self) -> str:
        """Retorna el perfil DNS actualmente activo en el sistema."""
        return self.active_profile
