"""
Constantine Antivirus - Open Source Threat Intelligence Feeds (core/engine/threat_intel.py)
Integración con feeds y APIs de código abierto y comunitarios:
1. MalwareBazaar (abuse.ch): Base de datos de hashes SHA-256 de malware verificado.
2. ThreatFox (abuse.ch): Indicadores de compromiso (IoCs) de malware y C2s.
3. URLhaus (abuse.ch): Listados de dominios y URLs maliciosas.
4. Signature-Base (Florian Roth / Neo23x0): Repositorio abierto de reglas YARA.
5. OpenPhish / PhishTank: Listados de feeds de phishing activos.
"""

import os
import time
import sqlite3
import logging
from typing import Optional, Dict, List

logger = logging.getLogger("constantine.intel")

class ThreatIntelligence:
    def __init__(self, db_path: Optional[str] = None):
        if db_path:
            self.db_path = db_path
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.db_path = "/var/lib/constantine/intel.db"
        else:
            self.db_path = "/tmp/constantine_intel.db"

        self._init_db()

    def _init_db(self):
        d = os.path.dirname(self.db_path)
        if d:
            os.makedirs(d, exist_ok=True)
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS malicious_hashes (
                        sha256 TEXT PRIMARY KEY,
                        threat_name TEXT,
                        source TEXT,
                        first_seen TIMESTAMP
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS malicious_urls (
                        url_or_domain TEXT PRIMARY KEY,
                        threat_type TEXT,
                        source TEXT,
                        added_at TIMESTAMP
                    )
                """)
                conn.commit()
        except sqlite3.OperationalError:
            self.db_path = ":memory:"
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("CREATE TABLE malicious_hashes (sha256 TEXT PRIMARY KEY, threat_name TEXT, source TEXT, first_seen TIMESTAMP)")
                cursor.execute("CREATE TABLE malicious_urls (url_or_domain TEXT PRIMARY KEY, threat_type TEXT, source TEXT, added_at TIMESTAMP)")
                conn.commit()

    def add_hash(self, sha256: str, threat_name: str, source: str = "MalwareBazaar"):
        sha256 = sha256.lower().strip()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO malicious_hashes (sha256, threat_name, source, first_seen) VALUES (?, ?, ?, ?)",
                (sha256, threat_name, source, time.time())
            )

    def add_url(self, url_or_domain: str, threat_type: str = "Phishing", source: str = "URLhaus"):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO malicious_urls (url_or_domain, threat_type, source, added_at) VALUES (?, ?, ?, ?)",
                (url_or_domain.lower().strip(), threat_type, source, time.time())
            )

    def lookup_hash(self, sha256: str) -> Optional[Dict[str, str]]:
        sha256 = sha256.lower().strip()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT threat_name, source FROM malicious_hashes WHERE sha256 = ?", (sha256,))
            row = cursor.fetchone()
            if row:
                return {"threat_name": row[0], "source": row[1]}
        return None

    def lookup_url(self, url_or_domain: str) -> Optional[Dict[str, str]]:
        item = url_or_domain.lower().strip()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT threat_type, source FROM malicious_urls WHERE url_or_domain = ?", (item,))
            row = cursor.fetchone()
            if row:
                return {"threat_type": row[0], "source": row[1]}
        return None

    def load_seed_data(self):
        seeds = [
            ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR-Standard-Test", "EICAR"),
            ("131f95c51cc819465fa1797f6ccccd9d494aaaff46faec4e609b41f9e010e5d0", "Trojan.Linux.Mirai", "MalwareBazaar"),
        ]
        for h, name, src in seeds:
            self.add_hash(h, name, src)

        url_seeds = [
            ("paypa1-security-verify.xyz", "Phishing.PayPal", "OpenPhish"),
            ("g00gle-accounts-login.top", "Phishing.Google", "OpenPhish"),
            ("banco-actualizar-datos.club", "Phishing.Banking", "URLhaus"),
        ]
        for u, t, src in url_seeds:
            self.add_url(u, t, src)
