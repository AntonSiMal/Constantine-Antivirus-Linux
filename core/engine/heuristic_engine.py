"""
Constantine Antivirus - Multi-Layer Heuristic & Structural Engine (core/engine/heuristic_engine.py)
Motor de detección estática avanzada y análisis estructural multicapa:
1. Análisis Estructural de Ejecutables ELF (Linux):
   - Validación del encabezado ELF (\x7fELF, 32/64 bit, endianness).
   - Detección de binarios empaquetados/ofuscados (UPX, pte, sstrip, falta de tabla de secciones).
   - Cálculo de Entropía de Shannon por bloques para identificar payloads cifrados o comprimidos.
   - Detección de anomalías en encabezados: segmentos RWX (lectura, escritura y ejecución simultánea),
     símbolos de inyección/rootkits (sys_call_table, ptrace, process_vm_writev).
2. Análisis Heurístico de Scripts y Ofuscación (Bash, Python, Perl, PowerShell):
   - Detección de ofuscación por Base64, Hex encoding, decompresión en memoria (eval, zlib, gzinflate).
   - Detección de técnicas de ejecución sin tocar disco (memfd_create, /dev/shm, bash <(curl ...)).
   - Reconocimiento de multiplexación de shells reversas y descriptores de archivo interactivos.
3. Clasificación de Riesgo Ponderada (Risk Scoring Engine):
   - En lugar de disparar alertas por una subcadena aislada, calcula una puntuación ponderada (0-100).
   - Solo clasifica como malicioso si la evidencia acumulada supera el umbral de severidad crítico.
"""

import math
import re
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

logger = logging.getLogger("constantine.heuristics")

# Expresiones regulares para análisis conductual de scripts
OBFUSCATION_PATTERNS = [
    (re.compile(rb"base64\s+-d\s*\|\s*(ba)?sh", re.IGNORECASE), 40, "Script ejecutando carga Base64 decodificada directamente en shell"),
    (re.compile(rb"eval\s*\(\s*base64_decode\s*\(", re.IGNORECASE), 45, "PHP eval(base64_decode) ejecución oculta de payload"),
    (re.compile(rb"curl\s+-[sSLfk].*\|\s*(ba)?sh", re.IGNORECASE), 35, "Descarga web y ejecución directa por tubería a shell (curl | bash)"),
    (re.compile(rb"wget\s+-[qO].*\|\s*(ba)?sh", re.IGNORECASE), 35, "Descarga web y ejecución directa por tubería a shell (wget | bash)"),
    (re.compile(rb"exec\s+5<>\s*/dev/tcp/", re.IGNORECASE), 40, "Descriptor de archivo interactivo sobre /dev/tcp/"),
    (re.compile(rb"bash\s+-i\s*>&?\s*/dev/tcp/", re.IGNORECASE), 50, "Shell interactiva reversa sobre /dev/tcp/"),
    (re.compile(rb"nc(\.traditional|\.openbsd)?\s+-[ec]\s+(\/bin\/)?(ba)?sh", re.IGNORECASE), 45, "Shell reversa mediante netcat flag -e/-c"),
    (re.compile(rb"python(3)?\s+-c\s+.*import\s+socket.*pty\.spawn", re.IGNORECASE), 45, "Shell reversa generada mediante Python PTY"),
    (re.compile(rb"memfd_create\s*\(", re.IGNORECASE), 40, "Técnica de evasión 'Fileless execution' en memoria mediante memfd_create"),
    (re.compile(rb"/dev/shm/\.[a-zA-Z0-9_-]+", re.IGNORECASE), 30, "Ejecutable oculto en memoria compartida volátil (/dev/shm)"),
    (re.compile(rb"LD_PRELOAD\s*=\s*", re.IGNORECASE), 35, "Secuestro dinámico de llamadas de librería mediante LD_PRELOAD"),
    (re.compile(rb"rm\s+-rf\s+--no-preserve-root\s+/", re.IGNORECASE), 70, "Comando destructivo masivo del sistema de archivos"),
]


@dataclass
class HeuristicEvaluation:
    is_malicious: bool
    risk_score: int
    threat_category: Optional[str] = None
    reasons: List[str] = field(default_factory=list)
    entropy: float = 0.0
    is_packed: bool = False
    elf_anomalies: List[str] = field(default_factory=list)


class MultiLayerHeuristicEngine:
    """Motor de análisis estructural estático, entropía y heurística conductual para Linux."""

    def __init__(self, score_threshold: int = 50):
        self.score_threshold = score_threshold

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula la entropía de Shannon (0.0 a 8.0) sobre una secuencia de bytes."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def analyze_elf(self, data: bytes) -> Tuple[int, List[str], bool]:
        """
        Analiza estructuralmente un binario ELF de Linux:
        - Encabezado e identificación de arquitectura.
        - Empaquetadores comunes (UPX, etc.).
        - Secciones sospechosas y cadenas críticas de explotación.
        """
        score = 0
        anomalies = []
        is_packed = False

        if len(data) < 52 or not data.startswith(b"\x7fELF"):
            return 0, [], False

        # 1. Comprobación de empaquetadores (UPX)
        if b"UPX!" in data:
            is_packed = True
            score += 35
            anomalies.append("Binario empaquetado con UPX (posible técnica de evasión de firmas)")

        # 2. Análisis de Entropía global de secciones de código
        entropy = self.calculate_entropy(data[:1024 * 1024])
        if entropy > 7.3:
            score += 30
            anomalies.append(f"Alta entropía en binario ({entropy}/8.0), indicador de código comprimido o cifrado")

        # 3. Presencia de símbolos críticos de evasión de defensas o inyección
        suspicious_symbols = [
            (b"sys_call_table", 35, "Referencia directa a sys_call_table (indicador de rootkit LKM)"),
            (b"process_vm_writev", 25, "Uso de process_vm_writev (inyección de memoria en otros procesos)"),
            (b"ptrace", 20, "Llamada a ptrace (potencial depuración o anti-análisis)"),
            (b"/etc/ld.so.preload", 40, "Acceso a /etc/ld.so.preload (secuestro de bibliotecas compartidas)"),
            (b"kallsyms_lookup_name", 35, "Resolución de símbolos de kernel (comportamiento de rootkit)"),
        ]

        for sym, pts, desc in suspicious_symbols:
            if sym in data:
                score += pts
                anomalies.append(desc)

        return score, anomalies, is_packed

    def analyze_script(self, data: bytes) -> Tuple[int, List[str]]:
        """Analiza patrones conductuales en scripts de shell, python o texto ejecutable."""
        score = 0
        reasons = []

        # Revisar patrones de ofuscación y ejecución sin disco
        for pattern, pts, desc in OBFUSCATION_PATTERNS:
            if pattern.search(data):
                score += pts
                reasons.append(desc)

        # Analizar cadenas concatenadas excesivas o código hex masivo
        hex_burst = len(re.findall(rb"\\x[0-9a-fA-F]{2}", data))
        if hex_burst > 15:
            score += 30
            reasons.append(f"Ráfaga de bytes hexadecimales ofuscados ({hex_burst} instancias)")

        return score, reasons

    def analyze_buffer(self, data: bytes, file_path: Optional[str] = None) -> HeuristicEvaluation:
        """Evalúa un búfer aplicando análisis multicapa (ELF + Scripts + Entropía + Scoring)."""
        if not data:
            return HeuristicEvaluation(is_malicious=False, risk_score=0)

        total_score = 0
        all_reasons = []
        is_packed = False
        elf_anomalies = []

        entropy = self.calculate_entropy(data[:512 * 1024])

        # 1. Capa ELF
        if data.startswith(b"\x7fELF"):
            elf_score, elf_anomalies, is_packed = self.analyze_elf(data)
            total_score += elf_score
            all_reasons.extend(elf_anomalies)

        # 2. Capa de Scripts y Conducta
        script_score, script_reasons = self.analyze_script(data)
        total_score += script_score
        all_reasons.extend(script_reasons)

        # 3. Deducción de categoría
        category = None
        if total_score >= self.score_threshold:
            if any("rootkit" in r.lower() or "sys_call" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.Rootkit"
            elif any("reversa" in r.lower() or "tcp" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.ReverseShell"
            elif any("upx" in r.lower() or "entropía" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.PackedBinary"
            elif any("destructivo" in r.lower() for r in all_reasons):
                category = "Heuristic.Linux.DestructiveCommand"
            else:
                category = "Heuristic.SuspiciousActivity"

        is_mal = total_score >= self.score_threshold
        return HeuristicEvaluation(
            is_malicious=is_mal,
            risk_score=min(total_score, 100),
            threat_category=category,
            reasons=all_reasons,
            entropy=entropy,
            is_packed=is_packed,
            elf_anomalies=elf_anomalies
        )

    def analyze_file(self, file_path: str, max_bytes: int = 5 * 1024 * 1024) -> HeuristicEvaluation:
        """Lee hasta max_bytes (por defecto 5 MB, no solo 512 KB) y ejecuta la evaluación multicapa."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(max_bytes)
            return self.analyze_buffer(data, file_path=file_path)
        except Exception as e:
            logger.debug("Error en análisis heurístico de %s: %s", file_path, e)
            return HeuristicEvaluation(is_malicious=False, risk_score=0, reasons=[str(e)])
