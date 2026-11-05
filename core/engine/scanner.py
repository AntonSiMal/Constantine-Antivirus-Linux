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
from typing import Optional, List, Dict, Set, Any, Tuple

from core.engine.threat_intel import ThreatIntelligence
from core.engine.yara_manager import YaraRuleManager, YaraMatch
from core.engine.heuristic_engine import MultiLayerHeuristicEngine, HeuristicEvaluation
from core.engine.clamav_bridge import ClamAVDaemonClient
from core.engine.archive_sentinel import ArchiveSentinel
from core.engine.clamav_importer import ClamAVSignatureImporter
from core.engine.clamav_manager import ClamAVManager
import yara_x
from core.engine.yarax_engine import YaraXEngine
import tetragon
from core.engine.tetragon import TetragonManager
import falco
from core.engine.falco import FalcoManager
import wazuh
from core.engine.wazuh import WazuhManager, WazuhAlert
import osquery
from core.engine.osquery import OSQueryManager
import misp
from core.engine.misp import MISPManager
import sigma
from core.engine.sigma_engine import SigmaManager

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
    risk_level: Optional[str] = None
    risk_action: Optional[str] = None


class SandboxedScanWorker:
    """
    Gestor de separación de privilegios para el motor de escaneo (Least Privilege Architecture).
    Garantiza que el análisis de archivos no confiables (YARA y heurística multicapa)
    se ejecute sin privilegios administrativos:
    - Si el proceso invocador es root, ejecuta el análisis desescalando privilegios
      al usuario de servicio 'constantine-scanner' (o 'nobody' como fallback)
      y aplicando PR_SET_NO_NEW_PRIVS.
    - Si el proceso invocador es un usuario normal (ej. pruebas unitarias o GUI), se ejecuta
      directamente en el contexto no privilegiado existente.
    """
    def __init__(self, service_user: str = "constantine-scanner"):
        self.service_user = service_user
        self.unprivileged_uid, self.unprivileged_gid = self._get_unprivileged_ids()

    def _get_unprivileged_ids(self) -> Tuple[int, int]:
        try:
            import pwd
            try:
                pw = pwd.getpwnam(self.service_user)
                return pw.pw_uid, pw.pw_gid
            except KeyError:
                pw = pwd.getpwnam("nobody")
                return pw.pw_uid, pw.pw_gid
        except Exception:
            return 65534, 65534

    def drop_privileges(self):
        """Desescala privilegios de forma irreversible si el proceso actual es root."""
        if os.geteuid() == 0:
            try:
                os.setgroups([])
                os.setgid(self.unprivileged_gid)
                os.setuid(self.unprivileged_uid)
                import ctypes
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                # PR_SET_NO_NEW_PRIVS = 38
                libc.prctl(38, 1, 0, 0, 0)
            except Exception as e:
                logger.debug("Aviso desescalando privilegios en worker de análisis: %s", e)

    def execute_sandboxed_analysis(
        self,
        path: str,
        yara_manager: YaraRuleManager,
        heuristics: MultiLayerHeuristicEngine
    ) -> Tuple[Optional[List[YaraMatch]], Optional[HeuristicEvaluation]]:
        """
        Ejecuta el análisis YARA y heurístico en un contexto con privilegios restringidos.
        Si se ejecuta como root, aísla el análisis en un proceso hijo que renuncia a root
        y a todas las capacidades administrativas antes de procesar el archivo.
        """
        if os.geteuid() != 0:
            # Ya opera en espacio de usuario sin privilegios administrativos
            yara_matches = yara_manager.match_file(path, timeout=5)
            try:
                heur_res = heuristics.analyze_file(path, max_bytes=5 * 1024 * 1024)
            except Exception:
                heur_res = None
            return yara_matches, heur_res

        # Si corre como root (en el demonio de producción), aislar en proceso hijo con privilegios revocados
        try:
            import pickle
            r_fd, w_fd = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.close(r_fd)
                try:
                    self.drop_privileges()
                    matches = yara_manager.match_file(path, timeout=5)
                    try:
                        h_res = heuristics.analyze_file(path, max_bytes=5 * 1024 * 1024)
                    except Exception:
                        h_res = None
                    payload = pickle.dumps((matches, h_res))
                    os.write(w_fd, payload)
                except Exception as child_err:
                    logger.debug("Error en worker sandboxed: %s", child_err)
                finally:
                    os.close(w_fd)
                    os._exit(0)
            else:
                os.close(w_fd)
                raw_bytes = b""
                while chunk := os.read(r_fd, 4096):
                    raw_bytes += chunk
                os.close(r_fd)
                _, status = os.waitpid(pid, 0)
                if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0 and raw_bytes:
                    return pickle.loads(raw_bytes)
                else:
                    logger.warning("Worker sandboxed terminó con estado anómalo (status=%d).", status)
        except Exception as fork_err:
            logger.debug("Aviso ejecutando worker sandboxed por fork: %s. Ejecutando con respaldo.", fork_err)

        # Respaldo seguro
        yara_matches = yara_manager.match_file(path, timeout=5)
        try:
            heur_res = heuristics.analyze_file(path, max_bytes=5 * 1024 * 1024)
        except Exception:
            heur_res = None
        return yara_matches, heur_res

class Scanner:
    """
    Motor principal de escaneo de Constantine Antivirus.
    Coordina la búsqueda de hashes de reputación, delega el análisis de patrones YARA
    y ejecuta análisis estructural y conductual heurístico multicapa.
    """

    def __init__(self, rules_dir: Optional[str] = None, custom_hashes: Optional[Set[str]] = None, service_user: str = "constantine-scanner"):
        self.rules_dir = rules_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
        self.intel = ThreatIntelligence()
        self.intel.load_seed_data()

        # Administrador especializado de reglas YARA (sin privilegios administrativos)
        self.yara_manager = YaraRuleManager(rules_dir=self.rules_dir)
        self.yarax_engine = self.yara_manager.yarax_engine

        # Motor heurístico estructural y conductual multicapa (sin privilegios administrativos)
        self.heuristics = MultiLayerHeuristicEngine(score_threshold=45)

        # Trabajador aislado con separación de privilegios para YARA y Heurística
        self.sandbox_worker = SandboxedScanWorker(service_user=service_user)

        # Gestor integral del motor antivirus ClamAV (clamd, freshclam, clamonacc, archivos comprimidos)
        self.clamav_manager = ClamAVManager(threat_intel=self.intel)
        self.clamav_bridge = self.clamav_manager.bridge
        self.archive_sentinel = self.clamav_manager.archive_sentinel
        self.clamav_importer = self.clamav_manager.importer

        # Gestor de observabilidad y enforcement Tetragon
        self.tetragon_manager = TetragonManager()

        # Gestor de detección conductual y alertas Falco (CNCF)
        self.falco_manager = FalcoManager(vault=getattr(self, "vault", None))

        # Gestor de vigilancia de cambios FIM + YARA y Respuesta Activa (Wazuh)
        self.wazuh_manager = WazuhManager(scanner=self, vault=getattr(self, "vault", None))

        # Gestor de diagnóstico e inventario del sistema basado en SQL (osquery)
        self.osquery_manager = OSQueryManager()

        # Gestor centralizado de inteligencia de amenazas MISP
        self.misp_manager = MISPManager(threat_intel=self.intel)

        # Gestor universal de reglas de detección de comportamiento Sigma (SOC)
        self.sigma_manager = SigmaManager()
        # Gestor central de eventos y motor de decisiones (Data Flow)
        from core.engine.event_manager import ConstantineEventManager
        self.event_manager = ConstantineEventManager(scanner=self)

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
        info["heuristic_layers"] = ["ELF_Structure", "Shannon_Entropy", "Script_Behavior", "Packing_Detection", "Archive_Sentinel"]
        info["clamd_available"] = self.clamav_bridge.is_available()
        info["clamd_version"] = self.clamav_bridge.get_version() if info["clamd_available"] else None
        info["clamav_engine"] = self.clamav_manager.get_status_info()
        info["tetragon"] = self.tetragon_manager.get_status_info() if hasattr(self, "tetragon_manager") else {}
        info["falco"] = self.falco_manager.get_status_info() if hasattr(self, "falco_manager") else {}
        info["wazuh"] = self.wazuh_manager.get_status_info() if hasattr(self, "wazuh_manager") else {}
        info["osquery"] = self.osquery_manager.get_status_info() if hasattr(self, "osquery_manager") else {}
        info["misp"] = self.misp_manager.get_status_info() if hasattr(self, "misp_manager") else {}
        info["sigma"] = self.sigma_manager.get_status_info() if hasattr(self, "sigma_manager") else {}
        info["event_manager"] = self.event_manager.get_status_info() if hasattr(self, "event_manager") else {}
        return info

    def update_signatures(self, sync_remote: bool = True, timeout: int = 15) -> Dict[str, Any]:
        """
        Recarga en caliente las firmas YARA y ejecuta la sincronización real de feeds
        de Threat Intelligence. Actualiza la marca temporal únicamente si la operación tiene éxito.
        """
        yara_reloaded = self.yara_manager.reload_rules()
        sync_result = None
        clamav_sync = None
        if sync_remote:
            sync_result = self.intel.sync_feeds(timeout=timeout)
            clamav_sync = self.clamav_manager.update_signatures(timeout=timeout)
        else:
            self.intel.touch_updates()

        return {
            "yara_reloaded": yara_reloaded,
            "feed_sync": sync_result,
            "clamav_sync": clamav_sync
        }

    def _scan_file_shallow(self, path: str) -> Tuple[bool, Optional[str]]:
        """
        Análisis rápido para archivos extraídos de contenedores comprimidos.
        Retorna (is_malicious, threat_name).
        """
        h = self.compute_sha256(path)
        if h:
            match = self.intel.lookup_hash(h)
            if match:
                return True, f"{match['threat_name']} ({match['source']})"

        # Escaneo con motor ClamAV si el demonio clamd está disponible
        if hasattr(self, "clamav_bridge") and self.clamav_bridge.is_available():
            is_clam, clam_threat = self.clamav_bridge.scan_file(path)
            if is_clam and clam_threat:
                return True, f"ClamAV.{clam_threat}"

        yara_matches, heur_res = self.sandbox_worker.execute_sandboxed_analysis(path, self.yara_manager, self.heuristics)
        if yara_matches:
            return True, f"YARA.{yara_matches[0].rule}"
        if heur_res and heur_res.is_malicious:
            return True, heur_res.threat_category or "Heuristic.SuspiciousActivity"

        return False, None

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

        # 1. Inteligencia de Amenazas (Hashes SHA-256 e Indicadores MISP)
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
                    risk_score=100,
                    risk_level="CRITICAL",
                    risk_action="BLOCK_AND_ISOLATE"
                )
            if hasattr(self, "misp_manager"):
                misp_match = self.misp_manager.lookup_ioc(file_hash)
                if misp_match and misp_match.matched:
                    return ScanResult(
                        is_malicious=True,
                        threat_name=misp_match.threat_name,
                        rule_matched="MISP_IOC_MATCH",
                        sha256=file_hash,
                        details=f"Indicador MISP [{misp_match.threat_level}]: {misp_match.comment or misp_match.campaign}",
                        risk_score=misp_match.confidence,
                        risk_level="CRITICAL" if misp_match.threat_level == "High" else "HIGH",
                        risk_action="BLOCK_AND_ISOLATE"
                    )

        # 2. Centinela de Archivos Comprimidos (Anti-ZipBomb y Descompresión Recursiva Segura)
        if self.archive_sentinel.is_archive(path):
            archive_res = self.archive_sentinel.inspect_and_scan(path, scanner_func=self._scan_file_shallow)
            if archive_res.is_malicious:
                logger.warning("🚨 [AMENAZA EN CONTENEDOR COMPRIMIDO] %s -> %s", path, archive_res.threat_name)
                return ScanResult(
                    is_malicious=True,
                    threat_name=archive_res.threat_name,
                    rule_matched="ARCHIVE_INSPECTION_THREAT",
                    sha256=file_hash,
                    details=archive_res.details or "Amenaza o bomba de descompresión detectada en archivo",
                    risk_score=95,
                    risk_level="CRITICAL",
                    risk_action="BLOCK_AND_ISOLATE"
                )

        # 3. Escáner Secundario ClamAV Daemon (si clamd está activo)
        if self.clamav_bridge.is_available():
            is_clam, clam_threat = self.clamav_bridge.scan_file(path)
            if is_clam and clam_threat:
                logger.warning("🎯 [CLAMAV DETECCIÓN] %s -> %s", path, clam_threat)
                return ScanResult(
                    is_malicious=True,
                    threat_name=f"ClamAV.{clam_threat}",
                    rule_matched="CLAMAV_DAEMON_MATCH",
                    sha256=file_hash,
                    details=f"Detectado por motor secundario ClamAV: {clam_threat}",
                    risk_score=95,
                    risk_level="CRITICAL",
                    risk_action="BLOCK_AND_ISOLATE"
                )

        # 4 y 5. Análisis con Motor YARA y Heurístico con Separación de Privilegios
        # El análisis de archivos no confiables se aísla mediante el SandboxedScanWorker
        # garantizando que si se ejecuta como root, el parser no conserve capacidades administrativas.
        yara_matches, heur_res = self.sandbox_worker.execute_sandboxed_analysis(path, self.yara_manager, self.heuristics)

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
                risk_score=90,
                risk_level="CRITICAL",
                risk_action="BLOCK_AND_ISOLATE"
            )

        if heur_res and heur_res.is_malicious:
            reasons_str = "; ".join(heur_res.reasons[:3])
            lvl = getattr(heur_res, "risk_level", "HIGH")
            act = getattr(heur_res, "action", "DEEP_ANALYZE")
            lvl_str = lvl.value if hasattr(lvl, "value") else str(lvl)
            act_str = act.value if hasattr(act, "value") else str(act)
            logger.warning("🧬 [HEURÍSTICA 5 CAPAS] Amenaza en %s (Nivel: %s, Acción: %s, Score: %d/100) -> %s",
                           path, lvl_str, act_str, heur_res.risk_score, reasons_str)
            return ScanResult(
                is_malicious=True,
                threat_name=heur_res.threat_category or "Heuristic.SuspiciousActivity",
                rule_matched="BEHAVIORAL_SCORING",
                sha256=file_hash,
                details=f"Análisis 5 capas (Nivel {lvl_str}, Acción {act_str}, Score {heur_res.risk_score}/100): {reasons_str}",
                risk_score=heur_res.risk_score,
                risk_level=lvl_str,
                risk_action=act_str
            )

        clean_lvl = getattr(heur_res, "risk_level", "LOW") if heur_res else "LOW"
        clean_act = getattr(heur_res, "action", "PERMIT_AND_LOG") if heur_res else "PERMIT_AND_LOG"
        clean_score = getattr(heur_res, "risk_score", 0) if heur_res else 0
        return ScanResult(
            is_malicious=False,
            sha256=file_hash,
            risk_score=clean_score,
            risk_level=clean_lvl.value if hasattr(clean_lvl, "value") else str(clean_lvl),
            risk_action=clean_act.value if hasattr(clean_act, "value") else str(clean_act)
        )
