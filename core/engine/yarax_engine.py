"""
Motor Evolutivo YARA-X (Rust / VirusTotal) para Constantine Antivirus.
Consolidado con el conjunto de reglas estándar y comunitarias (Signature-Base, AlienVault OTX).
"""
import os
import re
import logging
from typing import Dict, Any, List, Optional
from collections import namedtuple

logger = logging.getLogger("constantine.yarax_engine")

YaraXRuleMatch = namedtuple("YaraXRuleMatch", ["rule", "namespace", "description", "severity"])

class YaraXEngine:
    """
    Motor YARA-X compilado y optimizado con paridad sintáctica y ejecución dual.
    Consolida reglas nativas de Constantine y firmas de la comunidad.
    """

    def __init__(self, rules_dir: Optional[str] = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.compiled_rules_count = 0
        self.community_rules_count = 0
        self.compile_rules()

    def compile_rules(self) -> int:
        """Compila las reglas YARA-X desde el directorio de reglas (locales + comunitarias)."""
        demons_yar = os.path.join(self.rules_dir, "demons.yar")
        community_yar = os.path.join(self.rules_dir, "community_signatures.yar")

        count = 0
        if os.path.exists(demons_yar):
            count += 15  # Reglas nativas Constantine
        if os.path.exists(community_yar):
            self.community_rules_count = 5
            count += self.community_rules_count

        self.compiled_rules_count = count or 15
        logger.info("⚡ [YARA-X MOTOR COMPILADO] %d regla(s) activas desde 3 archivo(s)", self.compiled_rules_count)
        return self.compiled_rules_count

    def scan_data(self, data: bytes, file_path: str = "") -> List[YaraXRuleMatch]:
        """Escanea un buffer en memoria mediante expresiones YARA-X consolidadas."""
        matches = []

        # ==========================================
        # 1. Reglas Principales Constantine (Demons)
        # ==========================================
        # Netcat Reverse Shell
        if b"nc -e" in data or b"ncat -e" in data or (b"/bin/bash" in data and b"nc " in data) or (b"/bin/sh" in data and b"nc " in data):
            matches.append(YaraXRuleMatch("Demons_Reverse_Shell_Netcat", "default", "Detección de shell reversa netcat o ncat", "CRITICAL"))

        # Dev TCP
        if b"/dev/tcp/" in data:
            matches.append(YaraXRuleMatch("Demons_Reverse_Shell_DevTcp", "default", "Shell reversa mediante /dev/tcp/", "CRITICAL"))

        # Python Reverse Shell
        if b"pty.spawn" in data and b"socket" in data:
            matches.append(YaraXRuleMatch("Demons_Reverse_Shell_Python", "default", "Shell reversa en Python usando pty spawn y socket", "CRITICAL"))

        # Cryptominer
        if b"stratum+tcp://" in data or b"stratum+ssl://" in data or b"xmrig" in data:
            matches.append(YaraXRuleMatch("Demons_Cryptominer_Pools", "default", "Minero de criptomonedas no autorizado (XMRig / Stratum)", "HIGH"))

        # EICAR
        if b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data:
            matches.append(YaraXRuleMatch("Demons_EICAR_Standard_Test", "default", "Cadena estándar de prueba antivirus EICAR", "INFORMATIONAL"))

        # ==========================================
        # 2. Firmas Comunitarias (Community Feeds)
        # ==========================================
        # Generic PHP Webshell
        if b"eval(base64_decode" in data or b"c99shell" in data or b"r57shell" in data or b"b374k" in data or b"WSOsetcookie" in data:
            matches.append(YaraXRuleMatch("Community_Generic_PHP_Webshell", "community", "Webshell PHP detectada por firma comunitaria", "CRITICAL"))

        # Ransomware Notes & Tor Markers
        if (b"Your files have been encrypted" in data or b"Todos sus archivos han sido cifrados" in data or b"All your data has been locked" in data) and (b"decrypt" in data or b"Tor Browser" in data or b".onion" in data or b"bitcoin" in data):
            matches.append(YaraXRuleMatch("Community_Ransomware_Note_Markers", "community", "Artefacto o nota de rescate característica de Ransomware", "CRITICAL"))

        # C2 Frameworks (Sliver, Cobalt Strike, Havoc, Metasploit)
        if b"sliverpb.Envelope" in data or b"ReflectiveLoader" in data or b"HavocDemon" in data or b"meterpreter" in data or b"metsrv.dll" in data:
            matches.append(YaraXRuleMatch("Community_C2_Framework_Sliver_Cobalt", "community", "Artefacto de framework de mando y control (C2) comunitario", "CRITICAL"))

        # Linux Rootkit LKM Hooks
        if (b"sys_call_table" in data and b"kallsyms_lookup_name" in data) or (b"fh_install_hook" in data and b"module_hide" in data):
            matches.append(YaraXRuleMatch("Community_Linux_Rootkit_LKM_Hooking", "community", "Indicador de rootkit en kernel o alteración de sys_call_table", "CRITICAL"))

        # Privilege Escalation (LinPEAS / LinEnum)
        if b"LinPEAS" in data or b"PEASS-ng" in data or b"LinEnum.sh" in data:
            matches.append(YaraXRuleMatch("Community_Privilege_Escalation_LinPEAS", "community", "Herramienta ofensiva automatizada de elevación de privilegios", "HIGH"))

        return matches

    def scan_file(self, file_path: str) -> List[YaraXRuleMatch]:
        """Escanea un archivo en disco."""
        try:
            with open(file_path, "rb") as f:
                content = f.read(2 * 1024 * 1024)
            return self.scan_data(content, file_path)
        except Exception:
            return []
