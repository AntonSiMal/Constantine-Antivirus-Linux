"""
Constantine Antivirus - Anti-Phishing Shield (core/engine/phishing.py)
"""
import os, re, logging
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import List, Dict, Optional

from core.engine.threat_intel import ThreatIntelligence

@dataclass
class PhishingResult:
    is_phishing: bool
    risk_score: int
    threat_category: Optional[str] = None
    matched_brand: Optional[str] = None
    reasons: List[str] = None

class PhishingShield:
    def __init__(self):
        self.intel = ThreatIntelligence()
        self.target_brands = {
            "google": ["google.com", "accounts.google.com", "gmail.com"],
            "microsoft": ["microsoft.com", "login.live.com", "office.com"],
            "paypal": ["paypal.com"],
            "apple": ["apple.com", "icloud.com"],
            "amazon": ["amazon.com", "amazon.es"],
            "banco": ["bbva.com", "santander.com", "citibanamex.com"]
        }
        self.suspicious_tlds = {"top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "work"}
        self.harvesting_keywords = ["login-verify", "account-update", "signin-secure", "wallet-recovery", "confirm-banking"]
        self.homoglyph_map = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 'vv': 'w', 'rn': 'm'}

    def _normalize(self, text: str) -> str:
        d = text.lower()
        for k, v in self.homoglyph_map.items():
            d = d.replace(k, v)
        return d

    def analyze_url(self, url: str) -> PhishingResult:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            path = parsed.path.lower()
        except Exception:
            return PhishingResult(is_phishing=True, risk_score=90, reasons=["URL malformada"])

        score = 0
        reasons = []
        matched_brand = None

        # Comprobar contra feeds de OpenPhish / URLhaus
        intel_hit = self.intel.lookup_url(host)
        if intel_hit:
            return PhishingResult(
                is_phishing=True,
                risk_score=100,
                threat_category=intel_hit["threat_type"],
                reasons=[f"Dominio fichado en feed comunitario: {intel_hit['source']} ({intel_hit['threat_type']})"]
            )

        if re.match(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$", host):
            score += 45
            reasons.append("Uso de IP directa")

        if "@" in parsed.netloc:
            score += 50
            reasons.append("Técnica de distracción con '@'")

        parts = host.split(".")
        if len(parts) >= 4:
            score += 25
            reasons.append(f"Subdominios excesivos ({len(parts)})")

        tld = parts[-1].lower() if parts else ""
        if tld in self.suspicious_tlds:
            score += 30
            reasons.append(f"TLD sospechoso (.{tld})")

        norm_host = self._normalize(host)
        for brand, legit_domains in self.target_brands.items():
            if brand in norm_host:
                is_legit = any(host == l or host.endswith("." + l) for l in legit_domains)
                if not is_legit:
                    score += 60
                    matched_brand = brand
                    reasons.append(f"Suplantación de marca: {brand.upper()}")

        for kw in self.harvesting_keywords:
            if kw in path or kw in host:
                score += 35
                reasons.append(f"Trampa de credenciales: {kw}")
                break

        is_phish = score >= 50
        return PhishingResult(
            is_phishing=is_phish,
            risk_score=min(score, 100),
            threat_category="Phishing.CredentialHarvester" if is_phish else "Benign",
            matched_brand=matched_brand,
            reasons=reasons
        )

    def audit_hosts_file(self, hosts_path: str = "/etc/hosts") -> List[Dict[str, str]]:
        hijacked = []
        if not os.path.exists(hosts_path):
            return hijacked
        try:
            with open(hosts_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        domains = parts[1:]
                        for dom in domains:
                            for brand, legit_doms in self.target_brands.items():
                                if any(dom == l for l in legit_doms):
                                    if not ip.startswith(("127.0.0.1", "::1")):
                                        hijacked.append({"ip": ip, "domain": dom, "brand": brand})
        except Exception:
            pass
        return hijacked
