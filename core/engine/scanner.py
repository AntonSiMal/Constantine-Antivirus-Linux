"""
Constantine Antivirus - Scanner Engine (core/engine/scanner.py)
"""
import os, hashlib, logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Set

from core.engine.threat_intel import ThreatIntelligence

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

@dataclass
class ScanResult:
    is_malicious: bool
    threat_name: Optional[str] = None
    rule_matched: Optional[str] = None
    sha256: Optional[str] = None
    details: Optional[str] = None

class Scanner:
    def __init__(self, rules_dir: Optional[str] = None, custom_hashes: Optional[Set[str]] = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.intel = ThreatIntelligence()
        self.intel.load_seed_data()
        self.fallback_signatures = [
            ("Demons_EICAR", b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"),
            ("Demons_Reverse_Shell_Netcat", b"nc -e /bin/sh"),
            ("Demons_Reverse_Shell_Netcat", b"nc -e /bin/bash"),
            ("Demons_Reverse_Shell_Netcat", b"mkfifo /tmp/"),
            ("Demons_Reverse_Shell_DevTcp", b"/dev/tcp/"),
            ("Demons_Reverse_Shell_Python", b"socket.socket(socket.AF_INET"),
            ("Demons_Cryptominer", b"stratum+tcp://"),
            ("Demons_Cryptominer", b"xmrig"),
        ]

    def compute_sha256(self, file_path_or_fd) -> Optional[str]:
        sha = hashlib.sha256()
        try:
            if isinstance(file_path_or_fd, int):
                path = f"/proc/self/fd/{file_path_or_fd}"
            else:
                path = file_path_or_fd
            with open(path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception:
            return None

    def scan_file(self, target_fd: Optional[int] = None, file_path: Optional[str] = None) -> ScanResult:
        path = f"/proc/self/fd/{target_fd}" if (target_fd is not None and target_fd >= 0) else file_path
        if not path or not os.path.exists(path):
            return ScanResult(is_malicious=False, details="No accesible")

        file_hash = self.compute_sha256(path)
        if file_hash:
            match = self.intel.lookup_hash(file_hash)
            if match:
                return ScanResult(
                    is_malicious=True,
                    threat_name=f"{match['threat_name']} ({match['source']})",
                    rule_matched="COMMUNITY_HASH_MATCH",
                    sha256=file_hash,
                    details=f"Coincidencia en base de datos abierta: {match['source']}"
                )

        try:
            with open(path, "rb") as f:
                header = f.read(512 * 1024)
                for rule_name, pat in self.fallback_signatures:
                    if pat in header:
                        return ScanResult(
                            is_malicious=True,
                            threat_name=f"Heuristic.{rule_name}",
                            rule_matched=rule_name,
                            sha256=file_hash,
                            details=f"Firma heurística: {rule_name}"
                        )
        except Exception:
            pass
        return ScanResult(is_malicious=False, sha256=file_hash)
