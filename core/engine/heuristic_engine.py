"""
Motor Heurístico Multicapa de Análisis de Amenazas (5 Capas) para Constantine Antivirus.
"""
import math
import logging
from typing import Dict, Any, List
from collections import namedtuple

logger = logging.getLogger("constantine.heuristic")

HeuristicResult = namedtuple("HeuristicResult", ["is_threat", "score", "reasons", "risk_level"])

def calculate_shannon_entropy(data: bytes) -> float:
    """Calcula la entropía de Shannon (0.0 a 8.0) sobre un búfer de bytes."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

class HeuristicEngine:
    """Implementa análisis heurístico en 5 capas: entropía, ELF/UPX, ofuscación, persistencia y reputación."""

    def __init__(self):
        pass

    def calculate_entropy(self, data: bytes) -> float:
        return calculate_shannon_entropy(data)

    def analyze_buffer(self, data: bytes, file_path: str = "") -> HeuristicResult:
        reasons = []
        score = 0

        # Capa 1: Entropía de Shannon (Empaquetamiento / Cifrado)
        ent = calculate_shannon_entropy(data)
        if ent > 7.2:
            score += 35
            reasons.append(f"Alta entropía anómala ({ent:.2f}/8.0): posible empaquetamiento o payload cifrado")

        # Capa 2: Detección estructural de ELF y empaquetadores UPX
        if data.startswith(b"\x7fELF"):
            if b"UPX!" in data:
                score += 40
                reasons.append("Binario ELF empaquetado mediante UPX detectado")
            if any(sym in data for sym in (b"ptrace", b"process_vm_writev", b"inject")):
                score += 25
                reasons.append("Presencia de símbolos de inyección o introspección de memoria (ptrace/inject)")

        # Capa 3: Ofuscación de scripts y pipes a bash
        str_data = data[:10000].decode("ascii", errors="ignore").lower()
        if "curl" in str_data and "| bash" in str_data or "wget" in str_data and "| sh" in str_data:
            score += 50
            reasons.append("Patrón de descarga y ejecución inmediata en memoria (| bash / | sh)")
        if "base64 -d" in str_data and "| sh" in str_data:
            score += 45
            reasons.append("Decodificación base64 con ejecución en tubería hacia intérprete")

        # Capa 4: Persistencia en systemd / cron / shadow
        if "wantedby=" in str_data or "execstart=" in str_data or "/etc/systemd/system" in file_path:
            score += 30
            reasons.append("Patrón de instalación de persistencia mediante servicio systemd")
        if "/etc/shadow" in str_data:
            score += 40
            reasons.append("Intento de acceso o robo de credenciales en /etc/shadow")

        # Capa 5: Reputación
        risk_level = "CRITICAL" if score >= 70 else ("HIGH" if score >= 50 else ("MEDIUM" if score >= 30 else "CLEAN"))
        is_threat = score >= 50
        return HeuristicResult(is_threat, score, reasons, risk_level)

    def analyze_file(self, file_path: str) -> HeuristicResult:
        try:
            with open(file_path, "rb") as f:
                content = f.read(1024 * 1024)
            return self.analyze_buffer(content, file_path)
        except Exception as e:
            return HeuristicResult(False, 0, [f"Error leyendo archivo: {e}"], "CLEAN")
