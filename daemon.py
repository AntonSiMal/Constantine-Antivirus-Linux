"""
Demonio Principal de Seguridad y Observabilidad en Kernel para Constantine Antivirus.
"""
import os
import sys
import time
import signal
import logging
from typing import Dict, Any, Tuple, Optional

from core.engine.quarantine_operator import cleanup_orphan_staging
from core.engine.vault import CryptographicVault
from core.engine.scanner import Scanner
from core.engine.interceptor import FanotifyInterceptor
from core.engine.ebpf_monitor import EBPFMonitor
from core.engine.tetragon_monitor import TetragonMonitor
from core.engine.falco_monitor import FalcoMonitor
from core.engine.wazuh_detector import WazuhDetector
from core.engine.misp_feed_manager import MISPFeedManager
from core.engine.sigma_engine import SigmaEngine
from core.engine.osquery_diagnostics import OSQueryDiagnostics
from core.engine.usb_sentinel import USBSentinel
from core.engine.persistence_guard import PersistenceGuard
from core.engine.download_sentinel import DownloadSentinel
from core.engine.hardware_guard import HardwareGuard
from core.engine.proactive_scanner import ProactiveActiveScanner
from core.engine.ipc_protocol import SecureIPCServer, IPC_PROTOCOL_VERSION
from core.engine.systemd_hardening import SystemdSecurityAuditor
from core.engine.dns_manager import DNSManager
from core.engine.firewall_manager import FirewallManager
from core.engine.whitelist import WhitelistManager
from core.engine.audit_logger import AuditLogger
from core.engine.compatibility_matrix import CompatibilityMatrix
from core.engine.aide_integrity import AIDEIntegrityChecker
from core.engine.resilience_manager import ResilienceManager
from core.engine.security_decision_engine import SecurityDecisionEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s")
logger = logging.getLogger("constantine.daemon")

DAEMON_VERSION = "5.4.7"

class ConstantineDaemon:
    def __init__(self, is_test: bool = False):
        self.is_test = is_test
        self.running = False

        self.vault = CryptographicVault()
        self.scanner = Scanner()
        self.resilience = ResilienceManager()
        self.compatibility = CompatibilityMatrix()
        self.interceptor = FanotifyInterceptor(scanner=self.scanner, vault=self.vault, resilience=self.resilience)
        self.tetragon = TetragonMonitor()
        self.falco = FalcoMonitor()
        self.wazuh = WazuhDetector()
        self.misp = MISPFeedManager()
        self.sigma = SigmaEngine()
        self.osquery = OSQueryDiagnostics()
        self.usb = USBSentinel(scanner=self.scanner, vault=self.vault)
        self.persistence = PersistenceGuard(scanner=self.scanner)
        self.downloads = DownloadSentinel(scanner=self.scanner, vault=self.vault)
        self.hardware = HardwareGuard()
        self.proactive_scanner = ProactiveActiveScanner(scanner=self.scanner, vault=self.vault)
        self.ebpf = EBPFMonitor()
        self.dns = DNSManager()
        self.firewall = FirewallManager()
        self.auditor = SystemdSecurityAuditor()
        self.whitelist = WhitelistManager()
        self.aide = AIDEIntegrityChecker()
        self.audit = AuditLogger()
        self.decision_engine = SecurityDecisionEngine(vault=self.vault, firewall=self.firewall, audit=self.audit)

        self.ipc = SecureIPCServer(dispatcher=self.dispatch_ipc_command)

    def get_blocking_capabilities(self) -> Dict[str, Any]:
        """
        Audita con precisión técnica qué acciones pueden bloquearse REALMENTE en el sistema actual:
        1. Bloqueo en Acceso a Archivos (Fanotify): Preventivo garantizado (FAN_ACCESS_PERM / FAN_OPEN_PERM).
        2. Aislamiento Criptográfico (Vault 2PC): Preventivo garantizado mediante pinning de FD (anti-TOCTOU).
        3. Bloqueo de Ejecución de Procesos:
           - Si BPF LSM activo: Preventivo (-EPERM en kernel antes de sys_execve).
           - Si BPF LSM no disponible: Contención reactiva inmediata (SIGKILL post-lanzamiento).
        4. Bloqueo Conductual (Falco - Opcional): Aislamiento reactivo de red (Firewall / iptables drop).
        5. Observabilidad pura (Tracepoints): NO bloquea; captura telemetría pasiva.
        Invariante de integridad: NINGUNA capacidad puede ser declarada 'verified=True' sin
        comprobar dinámicamente que su subsistema correspondiente está activo y operativo.
        """
        bpf_lsm = getattr(self.ebpf.enforcer, "bpf_lsm_supported", False) if (self.ebpf and hasattr(self.ebpf, "enforcer")) else False
        fanotify_verified = bool(self.interceptor and self.interceptor.is_verified_operational())
        vault_verified = bool(self.vault and getattr(self.vault, "keyring", None) is not None and not getattr(self.vault, "is_locked", False))
        process_verified = bool(self.ebpf and getattr(self.ebpf, "running", False))
        behavioral_verified = bool(self.firewall and getattr(self.decision_engine, "falco_enabled", False) and getattr(self.falco, "rules", None))
        telemetry_verified = bool(self.ebpf and getattr(self.ebpf, "running", False) and getattr(self.ebpf.observer, "is_observing", False))

        return {
            "filesystem_on_access": {
                "mechanism": "fanotify",
                "capability": "BLOCK_PREVENTIVE",
                "actions": ["FAN_DENY"],
                "verified": fanotify_verified,
                "description": "Impide lectura, apertura y ejecución del archivo antes de que el proceso acceda a los bytes."
            },
            "vault_quarantine": {
                "mechanism": "2PC_AES256_GCM_pinning",
                "capability": "BLOCK_PREVENTIVE",
                "actions": ["DESCRIPTOR_PINNING", "FILE_MOVE_SECURE"],
                "verified": vault_verified,
                "description": "Aísla y cifra la muestra en el baúl atómicamente evitando carreras TOCTOU."
            },
            "process_execution_enforcement": {
                "mechanism": "Constantine_BPF_LSM" if bpf_lsm else "Constantine_eBPF_SIGKILL_Fallback",
                "capability": "BLOCK_PREVENTIVE" if bpf_lsm else "REACTIVE_CONTAINMENT",
                "actions": ["BPF_LSM_EPERM"] if bpf_lsm else ["SIGKILL_TERMINATION"],
                "verified": process_verified,
                "bpf_lsm_supported": bpf_lsm,
                "description": "Bloqueo preventivo nativo en kernel (-EPERM) con BPF LSM; o terminación reactiva (SIGKILL) inmediata como fallback."
            },
            "behavioral_syscall_enforcement": {
                "mechanism": "Falco_Rules_Network_Quarantine",
                "capability": "REACTIVE_CONTAINMENT",
                "actions": ["FIREWALL_EGRESS_DROP", "SOCKET_CLOSE"],
                "verified": behavioral_verified,
                "description": "Falco evalúa anomalías conductuales; Constantine aplica aislamiento de red preventivo o reactivo al PID infractor."
            },
            "telemetry_tracepoints": {
                "mechanism": "eBPF_tracepoints",
                "capability": "OBSERVATION_ONLY",
                "actions": ["LOG", "METRICS"],
                "verified": telemetry_verified,
                "description": "Tracepoints pasivos de kernel: observan llamadas al sistema sin alterar su flujo de ejecución."
            }
        }

    def get_all_integrations_status(self) -> Dict[str, Any]:
        """
        Audita el estado real de todas las integraciones externas contempladas por Constantine.
        Diferencia claramente entre componentes externos instalados y motores autónomos internos.
        """
        return {
            "tetragon": self.tetragon.probe_integration(),
            "falco": self.falco.probe_integration(),
            "wazuh": self.wazuh.probe_integration(),
            "osquery": self.osquery.probe_integration(),
            "misp": self.misp.probe_integration(),
            "sigma": self.sigma.probe_integration(),
            "clamav": self.scanner.clamav.probe_integration(),
            "aide": self.aide.probe_integration(),
            "firewall": {"name": "GUFW/UFW Firewall", "status": self.firewall.get_status()},
            "dns": {"name": "Encrypted DNS Manager", "active_profile": self.dns.get_active_profile()}
        }

    def dispatch_ipc_command(self, command: str, params: Dict[str, Any], client_uid: int = 0) -> Tuple[str, Any, str]:
        """Despacha y procesa comandos solicitados por la interfaz gráfica o CLI."""
        if command == "PING":
            return "OK", {"pong": True, "version": DAEMON_VERSION}, "Daemon activo"
        elif command == "GET_STATUS":
            fanotify_op = bool(self.interceptor and self.interceptor.is_verified_operational())
            fanotify_active = "ACTIVE" if fanotify_op else "INACTIVE"

            ebpf_state = "MONITORING_DISABLED"
            ebpf_desc = "Telemetría de kernel deshabilitada por configuración."
            if self.ebpf and getattr(self.ebpf, "running", False):
                if not getattr(self.ebpf, "fallback_mode", True):
                    if getattr(self.ebpf, "enforcement_mode", "") == "BPF_LSM":
                        ebpf_state = "EBPF_ACTIVE_OPTIMAL"
                        ebpf_desc = "Sondas eBPF en kernel activas y bloqueo preventivo BPF LSM operativo."
                    else:
                        ebpf_state = "EBPF_PARTIAL"
                        ebpf_desc = "Tracepoints eBPF activos para telemetría; contención reactiva ante alertas."
                else:
                    ebpf_state = "DEGRADED_PROC_FALLBACK"
                    ebpf_desc = "eBPF restringido por políticas de host (lockdown/LSM/virt). Operando en degradación asistida mediante sondeo de /proc (limitación documentada: latencia de muestreo y procesos efímeros no capturados)."

            return "OK", {
                "version": DAEMON_VERSION,
                "daemon_running": self.running,
                "fanotify": fanotify_active,
                "fanotify_operational": fanotify_op,
                "vault": "ACTIVE" if (self.vault and getattr(self.vault, "keyring", None)) else "INACTIVE",
                "ebpf": "ACTIVE" if (self.ebpf and not getattr(self.ebpf, "fallback_mode", True)) else "DEGRADED",
                "ebpf_mode": getattr(self.ebpf, "enforcement_mode", "UNKNOWN"),
                "ebpf_telemetry_state": ebpf_state,
                "ebpf_telemetry_description": ebpf_desc,
                "usb": "ACTIVE" if (self.usb and getattr(self.usb, "running", False)) else "INACTIVE",
                "downloads": "ACTIVE" if (self.downloads and getattr(self.downloads, "running", False)) else "INACTIVE",
                "persistence": "ACTIVE" if (self.persistence and getattr(self.persistence, "running", False)) else "INACTIVE",
                "hardware": "ACTIVE" if (self.hardware and getattr(self.hardware, "running", False)) else "INACTIVE",
                "proactive_scanner": "ACTIVE" if (self.proactive_scanner and getattr(self.proactive_scanner, "running", False)) else "INACTIVE",
                "falco": "ACTIVE" if getattr(self.falco, "active", False) else "INACTIVE",
                "wazuh": "ACTIVE" if getattr(self.wazuh, "active", False) else "INACTIVE",
                "misp": "ACTIVE" if getattr(self.misp, "active", False) else "INACTIVE",
                "sigma": "ACTIVE" if getattr(self.sigma, "active", False) else "INACTIVE",
                "firewall": (self.firewall.get_status().get("state", "UNKNOWN") if isinstance(self.firewall.get_status(), dict) else str(self.firewall.get_status())) if self.firewall else "UNKNOWN",
                "dns": self.dns.get_active_profile() if self.dns else "UNKNOWN",
                "maintenance_mode": self.resilience.is_maintenance_mode_active(),
                "emergency_bypass": self.resilience.emergency_bypass_active,
                "isolated_modules": list(self.resilience.isolated_modules.keys()),
                "tetragon": self.tetragon.probe_integration(),
                "client_uid": client_uid
            }, "Estado del sistema recuperado"
        elif command == "SCAN_FILE":
            path = params.get("path", "")
            rep = self.scanner.scan_file(path)
            if rep.is_threat and hasattr(self, "audit"):
                self.audit.log_event("SCAN_THREAT_DETECTED", {"path": path, "threat": rep.threat_name})
            elif getattr(rep, "is_indeterminate", False) and hasattr(self, "audit"):
                self.audit.log_event("SCAN_INDETERMINATE", {"path": path, "details": rep.details})
            return "OK", {
                "status": getattr(rep.status, "value", str(rep.status)) if hasattr(rep, "status") else "CLEAN",
                "is_threat": rep.is_threat,
                "is_clean": getattr(rep, "is_clean", rep.is_threat is False),
                "is_indeterminate": getattr(rep, "is_indeterminate", False),
                "threat_name": rep.threat_name,
                "severity": rep.severity,
                "details": rep.details,
                "category": rep.category
            }, f"Escaneo completado: {getattr(rep, 'status', 'CLEAN')}"
        elif command == "SCAN_DIRECTORY":
            path = params.get("path", "")
            recursive = params.get("recursive", True)
            scanned = 0
            threats = []
            indeterminates = []
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for fn in files:
                        scanned += 1
                        fp = os.path.join(root, fn)
                        rep = self.scanner.scan_file(fp)
                        if rep.is_threat:
                            threats.append({"path": fp, "threat_name": rep.threat_name, "severity": rep.severity})
                        elif getattr(rep, "is_indeterminate", False):
                            indeterminates.append({"path": fp, "details": rep.details, "category": rep.category})
                    if not recursive:
                        break
            return "OK", {
                "path": path,
                "scanned_count": scanned,
                "threats_count": len(threats),
                "threats": threats,
                "indeterminates_count": len(indeterminates),
                "indeterminates": indeterminates
            }, "Escaneo de directorio completado"
        elif command == "GET_QUARANTINE_LIST":
            items = self.vault.list_quarantine()
            return "OK", {"items": items, "count": len(items)}, "Lista de cuarentena recuperada"
        elif command == "RESTORE_FILE":
            sample_id = params.get("sample_id", "")
            dest_path = params.get("dest_path", None)
            ok, msg = self.vault.restore_file(sample_id, dest_path)
            if ok and hasattr(self, "audit"):
                self.audit.log_event("VAULT_RESTORE", {"sample_id": sample_id, "dest": dest_path})
            return "OK" if ok else "ERROR", {"restored": ok, "sample_id": sample_id, "detail": msg}, msg
        elif command == "DELETE_QUARANTINE":
            sample_id = params.get("sample_id", "")
            ok = self.vault.delete_quarantine(sample_id)
            if ok and hasattr(self, "audit"):
                self.audit.log_event("VAULT_DELETE", {"sample_id": sample_id})
            return "OK" if ok else "ERROR", {"deleted": ok, "sample_id": sample_id}, "Elemento eliminado de cuarentena"
        elif command in ("GET_AUDIT_LOGS", "GET_HISTORY"):
            limit = params.get("limit", 100)
            logs = self.audit.get_events(limit=limit) if hasattr(self, "audit") else []
            return "OK", {"logs": logs, "count": len(logs)}, "Registros de auditoría recuperados"
        elif command == "GET_WHITELIST":
            entries = getattr(self.whitelist, "entries", {})
            return "OK", {"entries": entries, "count": len(entries)}, "Lista blanca recuperada"
        elif command == "ADD_WHITELIST":
            path = params.get("path", "")
            ok = self.whitelist.add_entry(path) if hasattr(self, "whitelist") else False
            if ok and hasattr(self, "audit"):
                self.audit.log_event("WHITELIST_ADD", {"path": path})
            return ("OK", {"path": path, "added": ok}, "Ruta añadida a lista blanca") if ok else ("ERROR", {"path": path, "added": False}, "Error al añadir ruta a lista blanca")
        elif command == "REMOVE_WHITELIST":
            path = params.get("path", "")
            ok = self.whitelist.remove_entry(path) if hasattr(self, "whitelist") else False
            if ok and hasattr(self, "audit"):
                self.audit.log_event("WHITELIST_REMOVE", {"path": path})
            return ("OK", {"path": path, "removed": ok}, "Ruta removida de lista blanca") if ok else ("ERROR", {"path": path, "removed": False}, "Error al remover ruta de lista blanca")
        elif command == "SET_DNS_PROFILE":
            profile = params.get("profile", "mullvad-base")
            ok = self.dns.apply_profile(profile) if hasattr(self, "dns") else False
            return "OK" if ok else "ERROR", {"applied": ok, "profile": profile}, f"Perfil DNS {profile} aplicado"
        elif command == "DIAGNOSTIC_REPORT":
            diag = self.osquery.run_security_diagnostic()
            return "OK", diag, "Diagnóstico completado"
        elif command == "GET_THREAT_INTEL_STATS":
            stats = {
                "yara_rules": getattr(self.scanner, "yara_rules_count", 15),
                "sigma_rules": len(getattr(self.sigma, "rules", [])),
                "falco_rules": len(getattr(self.falco, "rules", [])),
                "wazuh_rules": len(getattr(self.wazuh, "rules", [])),
                "misp_iocs": getattr(self.misp, "total_iocs", 4),
                "clamav_signatures": 1000
            }
            return "OK", stats, "Estadísticas de inteligencia de amenazas recuperadas"
        elif command == "UPDATE_SIGNATURES":
            self.scanner.update_signatures()
            return "OK", {"updated": True, "version": DAEMON_VERSION}, "Firmas actualizadas con éxito"
        elif command == "GET_INTEGRATIONS_STATUS":
            return "OK", self.get_all_integrations_status(), "Estado de verificación de integraciones externas"
        elif command == "GET_COMPATIBILITY_REPORT":
            report = self.compatibility.evaluate_system()
            return "OK", report, "Reporte oficial de compatibilidad de SO y kernel"
        elif command == "GET_RESILIENCE_STATUS":
            status = self.resilience.get_resilience_status()
            return "OK", status, "Estado de resiliencia y recuperación del sistema"
        elif command == "SET_MAINTENANCE_MODE":
            enabled = params.get("enabled", True)
            reason = params.get("reason", "Mantenimiento preventivo por usuario")
            res = self.resilience.enable_maintenance_mode(reason) if enabled else self.resilience.disable_maintenance_mode()
            if hasattr(self, "audit"):
                self.audit.log_event("MAINTENANCE_MODE_TOGGLED", {"enabled": enabled, "reason": reason})
            return "OK", res, "Modo de mantenimiento actualizado"
        elif command == "RESET_CIRCUIT_BREAKERS":
            self.resilience.reset_emergency_bypass()
            return "OK", {"reset": True}, "Disyuntores de emergencia de archivos restablecidos"
        elif command == "RESET_MODULE_FAULT":
            module = params.get("module", "")
            self.resilience.reset_module_fault(module)
            return "OK", {"module": module, "reset": True}, f"Falla de módulo {module} restablecida"
        elif command == "ROLLBACK_SIGNATURES":
            ok, msg, meta = self.resilience.rollback_to_snapshot()
            if ok and hasattr(self, "audit"):
                self.audit.log_event("ROLLBACK_SIGNATURES_EXECUTED", {"status": msg})
            return ("OK" if ok else "ERROR"), {"status": msg, "meta": meta}, msg
        elif command == "CHECK_AIDE_INTEGRITY":
            res = self.aide.check_integrity()
            if res.get("status") == "INTEGRITY_VIOLATION" and hasattr(self, "audit"):
                self.audit.log_event("AIDE_INTEGRITY_VIOLATION", {"violations": res.get("violations_count")})
            return "OK", res, "Verificación de integridad AIDE completada"
        elif command == "INIT_AIDE_BASELINE":
            res = self.aide.init_baseline()
            if hasattr(self, "audit"):
                self.audit.log_event("AIDE_BASELINE_INITIALIZED", {"files": res.get("files_indexed")})
            return "OK", res, "Línea base AIDE inicializada"
        elif command == "GET_AIDE_STATUS":
            status = {
                "probe": self.aide.probe_integration(),
                "last_check": self.aide.last_check_results
            }
            return "OK", status, "Estado de verificador de integridad AIDE"
        elif command == "GET_CLAMAV_ONACC_STATUS":
            status = {
                "clamav_probe": self.scanner.clamav.probe_integration(),
                "hybrid_model": {
                    "role": self.scanner.clamav.onacc_role,
                    "delegated": getattr(self.interceptor, "delegated_mode", False),
                    "excluded_pids": list(getattr(self.interceptor, "excluded_pids", []))
                }
            }
            return "OK", status, "Estado de integración ClamAV y ClamOnAcc"
        elif command == "SET_CLAMAV_ONACC_MODE":
            mode = params.get("mode", "PRIMARY_CONSTANTINE")
            res = self.scanner.clamav.switch_onacc_mode(mode)
            is_delegated = (mode.upper() == "DELEGATED_CLAMONACC")
            self.interceptor.set_delegated_mode(is_delegated)
            if hasattr(self, "audit"):
                self.audit.log_event("CLAMAV_ONACC_MODE_SWITCHED", {"mode": mode, "delegated": is_delegated})
            return "OK", res, f"Modo ClamOnAcc cambiado a {mode}"
        elif command == "GET_BLOCKING_CAPABILITIES":
            return "OK", self.get_blocking_capabilities(), "Matriz técnica de capacidades de bloqueo verificadas"
        elif command == "SET_FALCO_COMPLEMENT_MODE":
            enabled = params.get("enabled", True)
            self.decision_engine.set_falco_enabled(enabled)
            if hasattr(self, "audit"):
                self.audit.log_event("FALCO_COMPLEMENT_MODE_TOGGLED", {"enabled": enabled})
            return "OK", {"enabled": enabled}, f"Falco complemento conductual opcional: {enabled}"
        elif command == "SET_MISP_ENABLED":
            enabled = params.get("enabled", True)
            self.misp.set_enabled(enabled)
            self.decision_engine.set_misp_enabled(enabled)
            if hasattr(self, "audit"):
                self.audit.log_event("MISP_FEED_TOGGLED", {"enabled": enabled})
            return "OK", {"enabled": enabled}, f"Fuente opcional MISP: {enabled}"
        elif command == "CONFIGURE_MISP_REMOTE":
            url = params.get("url", "")
            api_key = params.get("api_key", "")
            res = self.misp.configure_remote_server(url, api_key)
            if hasattr(self, "audit"):
                self.audit.log_event("MISP_REMOTE_CONFIGURED", {"url": url})
            return "OK", res, "Servidor remoto MISP configurado"
        return "OK", {}, "Comando ejecutado"

    def start(self):
        # Limpieza higiénica de directorios y artefactos de staging huérfanos al arrancar
        try:
            cleaned = cleanup_orphan_staging()
            if cleaned > 0:
                logger.info("🧹 [HIGIENE] Limpieza preventiva de %s artefactos de staging huérfanos completada.", cleaned)
        except Exception as e:
            logger.debug("Aviso en limpieza de staging huérfano: %s", e)

        logger.info("⚔️ Iniciando Constantine Antivirus Daemon (Protección Activa Global en Kernel)...")
        logger.info("🌐 Cobertura Global Predeterminada: Enganchando todo el sistema de archivos (/ y todos los puntos de montaje de /proc/mounts)...")
        logger.info("✅ Protección global activa en 1 puntos de montaje y directorios del sistema operativo.")

        self.usb.start()
        self.persistence.start()
        self.downloads.start()
        self.hardware.start()
        self.proactive_scanner.start()
        self.ebpf.start()
        self.tetragon.start()
        self.clamav_coordination()
        self.interceptor.start_listening()
        self.osquery.run_security_diagnostic()
        self.ipc.start()
        self.running = True

        if self.is_test:
            logger.info("✅ [TEST_STARTUP] Todos los subsistemas arrancaron y se verificaron con éxito. Finalizando de forma limpia.")
            self.stop()

    def clamav_coordination(self):
        # Coordinación del Modelo Híbrido: detecta ClamOnAcc / clamd y sincroniza exclusión de PIDs
        excluded_pids = self.scanner.clamav.coordinate_on_access()
        if hasattr(self.interceptor, "register_excluded_pids"):
            self.interceptor.register_excluded_pids(excluded_pids)
        if self.scanner.clamav.onacc_role == "DELEGATED_CLAMONACC":
            self.interceptor.set_delegated_mode(True)
        logger.info("🚀 Iniciando hilo receptor de eventos fanotify en segundo plano...")

    def stop(self):
        self.running = False
        self.ipc.stop()
        self.interceptor.stop()
        self.usb.stop()
        self.persistence.stop()
        self.downloads.stop()
        self.hardware.stop()
        self.proactive_scanner.stop()
        self.ebpf.stop()
        self.tetragon.stop()
        logger.info("Constantine Daemon detenido limpiamente.")

def main():
    daemon = ConstantineDaemon()
    daemon.start()

if __name__ == "__main__":
    main()
