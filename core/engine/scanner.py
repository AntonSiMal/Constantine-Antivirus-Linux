"""
Constantine Antivirus - Scanner Engine (core/engine/scanner.py)
Motor híbrido de escaneo y clasificación de amenazas en tiempo real:
1. Threat Intelligence Hash Lookup:
   - Coincidencias exactas SHA-256 contra bases locales y feeds MalwareBazaar / ThreatFox.
2. Motor YARA de Alto Rendimiento (core/engine/yara_manager.py):
   - Compilación atómica, validación sintáctica previa, caché binaria (.yac) y ejecución
     aislada con yara.compile() y rules.match() con protección de timeout anti-DoS.
3. Motor Heurístico Multicapa y Análisis Estructural (core/engine/heuristic_engine.py):
   - Análisis estructural ELF (entropía de Shannon, detección UPX, símbolos rootkit/inyección).
   - Detección conductual y ofuscación de scripts (eval, base64, descargas directas a shell, memfd_create).
   - Puntuación de riesgo ponderada (Risk Scoring) sin depender de subcadenas simples aisladas.
"""

import os
import hashlib
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Set

from core.engine.threat_intel import ThreatIntelligence
from core.engine.yara_manager import YaraRuleManager, YaraMatch
from core.engine.heuristic_engine import MultiLayerHeuristicEngine, HeuristicEvaluation

logger = logging.getLogger("constantine.scanner")


@dataclass
class ScanResult:
    is_malicious: bool
    threat_name: Optional[str] = None
    rule_matched: Optional[str] = None
    sha256: Optional[str] = None
    details: Optional[str] = None
    namespace: Optional[str] = None
    risk_score: int = 0


class Scanner:
    """
    Motor principal de escaneo de Constantine Antivirus.
    Coordina la búsqueda de hashes de reputación, delega el análisis de patrones YARA
    y ejecuta análisis estructural y conductual heurístico multicapa.
    """

    def __init__(self, rules_dir: Optional[str] = None, custom_hashes: Optional[Set[str]] = None):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.intel = ThreatIntelligence()
        self.intel.load_seed_data()

        # Administrador especializado de reglas YARA
        self.yara_manager = YaraRuleManager(rules_dir=self.rules_dir)

        # Motor heurístico estructural y conductual multicapa
        self.heuristics = MultiLayerHeuristicEngine(score_threshold=45)

    @property
    def yara_rules(self):
        """Propiedad de compatibilidad con código heredado."""
        return self.yara_manager._compiled_rules

    @property
    def yara_rules_count(self) -> int:
        return self.yara_manager.rules_count

    def compile_yara_rules(self) -> bool:
        """Delega la compilación y validación a YaraRuleManager."""
        return self.yara_manager.compile_rules(force_recompile=True)

    def is_yara_active(self) -> bool:
        """Indica si el subsistema YARA está operativo."""
        return self.yara_manager.is_active

    def is_self_or_excluded(self, path: str) -> bool:
        """
        Determina si un archivo pertenece a la infraestructura oficial de Constantine.
        Delega la validación estricta a la lista blanca oficial sin confiar en nombres
        o extensiones arbitrarias fuera de los directorios autorizados.
        """
        if not path:
            return False
        from core.engine.system_whitelist import SystemWhitelist
        return SystemWhitelist().is_self_file(path)

    def compute_sha256(self, file_path_or_fd) -> Optional[str]:
        """Calcula el hash SHA-256 en bloques de 64 KB para evitar consumo excesivo de memoria RAM."""
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

    def get_signatures_info(self) -> dict:
        """Retorna estadísticas consolidadas de Threat Intelligence y YARA."""
        info = self.intel.get_db_info()
        yara_status = self.yara_manager.get_status()
        info["has_yara"] = yara_status["has_yara"]
        info["yara_engine_status"] = yara_status["engine_type"]
        info["yara_rules_count"] = yara_status["rules_count"]
        info["yara_namespaces"] = yara_status["namespaces"]
        info["yara_cache_active"] = yara_status["cache_active"]
        info["heuristic_layers"] = ["ELF_Structure", "Shannon_Entropy", "Script_Behavior", "Packing_Detection"]
        return info

    def update_signatures(self):
        """Recarga en caliente las firmas YARA y actualiza marcas de Threat Intelligence."""
        self.yara_manager.reload_rules()
        self.intel.touch_updates()

    def scan_file(self, target_fd: Optional[int] = None, file_path: Optional[str] = None) -> ScanResult:
        """
        Analiza un descriptor de archivo o ruta en disco mediante enfoque multicapa:
        1. Comprobación de Threat Intelligence (Hashes SHA-256 de malware conocido).
        2. Análisis YARA (reglas compiladas y evaluadas con timeout anti-DoS).
        3. Análisis Estructural y Conductual Multicapa (ELF, entropía, ofuscación y scoring de riesgo).
        """
        path = f"/proc/self/fd/{target_fd}" if (target_fd is not None and target_fd >= 0) else file_path
        if not path or not os.path.exists(path):
            return ScanResult(is_malicious=False, details="No accesible")

        # 1. Inteligencia de Amenazas (Hashes SHA-256)
        file_hash = self.compute_sha256(path)
        if file_hash:
            match = self.intel.lookup_hash(file_hash)
            if match:
                return ScanResult(
                    is_malicious=True,
                    threat_name=f"{match['threat_name']} ({match['source']})",
                    rule_matched="COMMUNITY_HASH_MATCH",
                    sha256=file_hash,
                    details=f"Coincidencia en base de firmas de malware: {match['source']}",
                    risk_score=100
                )

        # 2. Análisis con Motor YARA (evaluado con rules.match() oficial o fallback)
        yara_matches = self.yara_manager.match_file(path, timeout=5)
        if yara_matches:
            primary_match = yara_matches[0]
            logger.warning("🎯 [YARA DETECCIÓN] Archivo %s coincide con regla: %s (%s) [Namespace: %s]",
                           path, primary_match.rule, primary_match.description, primary_match.namespace)
            return ScanResult(
                is_malicious=True,
                threat_name=f"YARA.{primary_match.rule}",
                rule_matched=primary_match.rule,
                sha256=file_hash,
                details=f"Regla YARA: {primary_match.description} [Nivel: {primary_match.threat_level}]",
                namespace=primary_match.namespace,
                risk_score=90
            )

        # 3. Análisis Heurístico y Estructural Multicapa (hasta 5 MB, no solo 512 KB)
        try:
            heur_res = self.heuristics.analyze_file(path, max_bytes=5 * 1024 * 1024)
            if heur_res.is_malicious:
                reasons_str = "; ".join(heur_res.reasons[:3])
                logger.warning("🧬 [HEURÍSTICA MULTICAPA] Amenaza conductual en %s (Score: %d/100, Entropía: %.2f) -> %s",
                               path, heur_res.risk_score, heur_res.entropy, reasons_str)
                return ScanResult(
                    is_malicious=True,
                    threat_name=heur_res.threat_category or "Heuristic.SuspiciousActivity",
                    rule_matched="BEHAVIORAL_SCORING",
                    sha256=file_hash,
                    details=f"Análisis multicapa (Score {heur_res.risk_score}/100, Entropía {heur_res.entropy}): {reasons_str}",
                    risk_score=heur_res.risk_score
                )
        except Exception as e:
            logger.debug("Error en capa heurística: %s", e)

        return ScanResult(is_malicious=False, sha256=file_hash)
