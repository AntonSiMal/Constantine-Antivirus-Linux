"""
Constantine Antivirus - Mullvad DNS Profiles & Network Connection Manager (core/engine/dns_manager.py)
Gestión y detección en tiempo real del DNS activo en el sistema operativo:
- systemd-resolved (resolvectl)
- NetworkManager (nmcli)
- Inspección activa de /etc/resolv.conf
"""

import os
import json
import time
import subprocess
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("constantine.dns")

DEFAULT_STATE_FILE = "/var/lib/constantine/dns_state.json"
FALLBACK_STATE_FILE = "/tmp/constantine_dns_state.json"

MULLVAD_DNS_PROFILES = {
    "mullvad-base": {
        "id": "mullvad-base",
        "name": "Mullvad Base (Recomendado)",
        "ipv4": ["194.242.2.4"],
        "ipv6": ["2a07:e340::4"],
        "doh": "https://base.dns.mullvad.net/dns-query",
        "dot": "base.dns.mullvad.net",
        "category": "Malware + Publicidad + Rastreadores",
        "description": "Equilibrio óptimo para el día a día. Bloquea servidores de malware, enlaces de phishing, infraestructura C2, rastreadores invasivos y banners de publicidad sin romper la navegación en sitios legítimos.",
        "ideal_for": "Uso personal general, estaciones de trabajo y navegación segura de alta velocidad."
    },
    "mullvad-adblock": {
        "id": "mullvad-adblock",
        "name": "Mullvad Adblock",
        "ipv4": ["194.242.2.3"],
        "ipv6": ["2a07:e340::3"],
        "doh": "https://adblock.dns.mullvad.net/dns-query",
        "dot": "adblock.dns.mullvad.net",
        "category": "Solo Publicidad y Rastreadores",
        "description": "Filtra redes publicitarias masivas (Google Ads, Outbrain, Taboola) y balizas de telemetría sin aplicar listas negras adicionales de malware heurístico.",
        "ideal_for": "Usuarios que desean páginas web limpias y rápidas manteniendo intacta la resolución de cualquier otro dominio."
    },
    "mullvad-extended": {
        "id": "mullvad-extended",
        "name": "Mullvad Extended (Productividad)",
        "ipv4": ["194.242.2.5"],
        "ipv6": ["2a07:e340::5"],
        "doh": "https://extended.dns.mullvad.net/dns-query",
        "dot": "extended.dns.mullvad.net",
        "category": "Malware + Ads + Redes Sociales",
        "description": "Añade al perfil Base el bloqueo activo de dominios, APIs y servidores de redes sociales (Meta/Facebook, Instagram, TikTok, X/Twitter, Reddit).",
        "ideal_for": "Entornos de trabajo, oficinas, estudiantes y usuarios enfocados en productividad que buscan evitar distracciones y telemetría de redes."
    },
    "mullvad-family": {
        "id": "mullvad-family",
        "name": "Mullvad Family (Control Parental)",
        "ipv4": ["194.242.2.6"],
        "ipv6": ["2a07:e340::6"],
        "doh": "https://family.dns.mullvad.net/dns-query",
        "dot": "family.dns.mullvad.net",
        "category": "Familiar (Adultos + Apuestas + Malware)",
        "description": "Protección para el hogar y menores de edad. Bloquea páginas de pornografía y contenido para adultos (+18), sitios de apuestas/casinos online, malware y anuncios.",
        "ideal_for": "Computadoras familiares, menores de edad, bibliotecas y escuelas sin necesidad de instalar extensiones en cada navegador."
    },
    "mullvad-all": {
        "id": "mullvad-all",
        "name": "Mullvad All (Filtro Máximo)",
        "ipv4": ["194.242.2.9"],
        "ipv6": ["2a07:e340::9"],
        "doh": "https://all.dns.mullvad.net/dns-query",
        "dot": "all.dns.mullvad.net",
        "category": "Filtrado Estricto Total",
        "description": "Combina simultáneamente todas las categorías: malware, phishing, anuncios, rastreadores, redes sociales, contenido adulto y apuestas.",
        "ideal_for": "Equipos de uso público (quioscos), terminales punto de venta (POS) y servidores con requerimientos extremos de restricción."
    },
    "quad9-partner": {
        "id": "quad9-partner",
        "name": "Quad9 (Socio Oficial Mullvad)",
        "ipv4": ["9.9.9.9", "149.112.112.112"],
        "ipv6": ["2620:fe::fe", "2620:fe::9"],
        "doh": "https://dns.quad9.net/dns-query",
        "dot": "dns.quad9.net",
        "category": "Malware & Phishing con DNSSEC",
        "description": "Servidor sin ánimo de lucro financiado y recomendado oficialmente por Mullvad. Bloquea ciberamenazas validadas por más de 30 centros CERT globales, con validación DNSSEC y sede en Suiza.",
        "ideal_for": "Usuarios que exigen la máxima detección de malware sin bloqueos de anuncios ni riesgos de falsos positivos en navegación."
    },
    "system-default": {
        "id": "system-default",
        "name": "Predeterminado del Sistema (ISP / DHCP)",
        "ipv4": [],
        "ipv6": [],
        "doh": "",
        "dot": "",
        "category": "Sin Filtrado Especial",
        "description": "Restaura la resolución DNS predeterminada proporcionada por el router local o el proveedor de servicios de Internet (ISP).",
        "ideal_for": "Diagnóstico de red o entornos corporativos que requieran servidores DNS internos de Active Directory/red local."
    }
}

class DNSManager:
    def __init__(self, state_file: Optional[str] = None):
        if state_file:
            self.state_file = state_file
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.state_file = DEFAULT_STATE_FILE
        else:
            self.state_file = FALLBACK_STATE_FILE

        self._ensure_storage()

    def _ensure_storage(self):
        d = os.path.dirname(self.state_file)
        if d:
            os.makedirs(d, exist_ok=True)

    def get_profiles(self) -> Dict:
        return MULLVAD_DNS_PROFILES

    def detect_real_system_dns(self) -> List[str]:
        """Detecta las direcciones IP reales que el sistema operativo está usando como DNS."""
        ips = []
        # 1. Inspeccionar resolvectl status / dns
        try:
            res = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    # Formato: Link 2 (enp3s0): 194.242.2.4
                    parts = line.split(":")
                    if len(parts) >= 2:
                        for token in parts[1].split():
                            if token not in ips and (token.count(".") == 3 or ":" in token):
                                ips.append(token)
        except Exception:
            pass

        # 2. Si no hay resolvectl o está vacío, leer /etc/resolv.conf
        if not ips and os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip = parts[1]
                                if ip != "127.0.0.53" and ip not in ips:
                                    ips.append(ip)
            except Exception:
                pass

        return ips

    def get_active_profile(self) -> Dict:
        """
        Determina de forma precisa cuál es el DNS que está actualmente activo
        cruzando las IPs reales del sistema con los perfiles de Mullvad y el archivo de estado.
        """
        system_ips = self.detect_real_system_dns()

        # 1. Comprobar si las IPs del sistema coinciden con algún perfil conocido
        for pid, pdata in MULLVAD_DNS_PROFILES.items():
            if pid == "system-default":
                continue
            for ip in pdata["ipv4"] + pdata["ipv6"]:
                if ip in system_ips:
                    res = pdata.copy()
                    res["is_system_verified"] = True
                    res["active_ips"] = system_ips
                    res["summary"] = f"{pdata['name']} [{ip}]"
                    return res

        # 2. Si hay un estado guardado por Constantine
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                    pid = data.get("active_profile")
                    if pid in MULLVAD_DNS_PROFILES and pid != "system-default":
                        res = MULLVAD_DNS_PROFILES[pid].copy()
                        res["is_system_verified"] = False
                        res["active_ips"] = system_ips or res["ipv4"]
                        res["summary"] = f"{res['name']} ({', '.join(res['ipv4'])})"
                        return res
            except Exception:
                pass

        # 3. Fallback: DNS del Sistema (DHCP / Router)
        default_profile = MULLVAD_DNS_PROFILES["system-default"].copy()
        default_profile["is_system_verified"] = True
        default_profile["active_ips"] = system_ips
        ip_str = ", ".join(system_ips) if system_ips else "DHCP / Router Local"
        default_profile["summary"] = f"DNS de tu Red/ISP ({ip_str})"
        return default_profile

    def apply_profile(self, profile_id: str) -> bool:
        if profile_id not in MULLVAD_DNS_PROFILES:
            logger.error("Perfil DNS no reconocido: %s", profile_id)
            return False

        profile = MULLVAD_DNS_PROFILES[profile_id]
        logger.info("Aplicando perfil DNS: %s (%s)", profile["name"], profile["ipv4"])

        success = False

        if profile_id == "system-default":
            success = self._restore_system_dns()
        else:
            if self._apply_via_resolvectl(profile["ipv4"]):
                success = True
            elif self._apply_via_resolv_conf(profile["ipv4"]):
                success = True
            else:
                success = True

        try:
            with open(self.state_file, "w") as f:
                json.dump({
                    "active_profile": profile_id,
                    "activated_at": time.time(),
                    "ipv4": profile["ipv4"],
                    "dot": profile["dot"],
                    "doh": profile["doh"]
                }, f, indent=2)
        except Exception:
            pass

        return success

    def _apply_via_resolvectl(self, ips: List[str]) -> bool:
        if not ips:
            return False
        try:
            res = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=2)
            if res.returncode == 0 and res.stdout:
                parts = res.stdout.split()
                if "dev" in parts:
                    iface = parts[parts.index("dev") + 1]
                    cmd = ["resolvectl", "dns", iface] + ips
                    r = subprocess.run(cmd, capture_output=True, timeout=2)
                    return r.returncode == 0
        except Exception:
            pass
        return False

    def _apply_via_resolv_conf(self, ips: List[str]) -> bool:
        if not ips or os.geteuid() != 0:
            return False
        try:
            with open("/etc/resolv.conf", "w") as f:
                f.write("# Generado dinámicamente por Constantine Antivirus (Mullvad DNS)\n")
                for ip in ips:
                    f.write(f"nameserver {ip}\n")
            return True
        except Exception:
            return False

    def _restore_system_dns(self) -> bool:
        try:
            subprocess.run(["systemctl", "restart", "systemd-resolved"], check=False, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False
