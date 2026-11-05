"""
Motor Central de Decisiones de Seguridad (Security Decision Engine) para Constantine Antivirus.
Unifica y correlaciona eventos provenientes de:
1. Eventos del Sistema de Archivos (Fanotify on-access).
2. Eventos del Kernel / Procesos (Tetragon eBPF).
3. Eventos Conductuales (Falco Syscalls - Complemento Opcional).
4. Detección Estática y Firmas (YARA-X, ClamAV/ClamOnAcc, MISP Threat Intel, Heurística).
5. Auditoría de Integridad del Sistema Operativo (AIDE FIM Baseline).
6. Telemetría y Postura de Seguridad (osquery SQL Diagnostics).
7. Reglas de Comportamiento de Procesos (Sigma Rules Engine).

Aplica la matriz de acciones bloqueables verificables:
- Bloqueo Preventivo en Kernel (BPF LSM -EPERM).
- Bloqueo en Acceso a Archivo (Fanotify FAN_DENY).
- Aislamiento Criptográfico Inmediato (Cryptographic Vault 2PC).
- Contención Reactiva Post-Detección (SIGKILL de proceso agresor).
- Aislamiento de Red del Proceso (Network Quarantine / Firewall drop).
"""
import os
import logging
from typing import Dict, Any, List, Optional, Tuple, NamedTuple

logger = logging.getLogger("constantine.decision_engine")

class SecurityDecision(NamedTuple):
    is_blocked: bool
    enforcement_action: str      # "BPF_LSM_EPERM", "FANOTIFY_DENY", "SIGKILL_CONTAINMENT", "NETWORK_ISOLATE", "ALLOW"
    threat_level: str            # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    primary_engine: str          # "TETRAGON", "FANOTIFY_SCANNER", "FALCO", "SIGMA", "AIDE", "OSQUERY", "HEURISTIC"
    reason: str
    quarantined: bool = False
    process_killed: bool = False
    network_isolated: bool = False
    details: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_blocked": self.is_blocked,
            "enforcement_action": self.enforcement_action,
            "threat_level": self.threat_level,
            "primary_engine": self.primary_engine,
            "reason": self.reason,
            "quarantined": self.quarantined,
            "process_killed": self.process_killed,
            "network_isolated": self.network_isolated,
            "details": self.details
        }


class SecurityDecisionEngine:
    """
    Orquestador Central de Decisiones y Respuestas de Seguridad.
    Conecta los eventos de kernel (Tetragon), comportamiento (Falco, Sigma), integridad (AIDE, osquery)
    y archivos (Fanotify on-access).
    """

    def __init__(self, vault=None, firewall=None, audit=None):
        self.vault = vault
        self.firewall = firewall
        self.audit = audit
        self.falco_enabled = True  # Falco como complemento conductual opcional
        self.misp_enabled = True   # MISP como fuente opcional de inteligencia

    def set_falco_enabled(self, enabled: bool):
        """Habilita o deshabilita Falco como complemento conductual opcional."""
        self.falco_enabled = enabled
        logger.info("⚙️ [DECISION ENGINE] Módulo complementario Falco: %s", "HABILITADO" if enabled else "DESHABILITADO")

    def set_misp_enabled(self, enabled: bool):
        """Habilita o deshabilita MISP como fuente de inteligencia activa."""
        self.misp_enabled = enabled
        logger.info("⚙️ [DECISION ENGINE] Fuente de inteligencia MISP: %s", "HABILITADA" if enabled else "DESHABILITADA")

    def evaluate_process_execution(self, pid: int, binary_path: str, argv: List[str],
                                   tetragon_monitor=None, ebpf_monitor=None,
                                   sigma_engine=None) -> SecurityDecision:
        """
        Evalúa y aplica enforcement sobre la ejecución de un proceso:
        1. Políticas Tetragon eBPF.
        2. Reglas conductuales de la comunidad Sigma.
        3. Monitor eBPF interno (observación + detección).

        Acción bloqueable verificable:
        - Si BPF LSM está disponible: -EPERM en sys_execve (pre-ejecución).
        - Si no: SIGKILL inmediato al proceso detectado (post-ejecución).
        """
        # 1. Consulta a Tetragon
        tetragon_allowed = True
        tetragon_reason = "Operación permitida"
        if tetragon_monitor:
            tetragon_allowed, action, tetragon_reason = tetragon_monitor.evaluate_process_execution(pid, binary_path, argv)

        # 2. Consulta a Reglas Sigma de Comportamiento
        sigma_threat = False
        sigma_reason = ""
        if sigma_engine:
            cmdline = f"{binary_path} {' '.join(argv)}".strip()
            sigma_matches = sigma_engine.evaluate_process(pid, os.path.basename(binary_path), binary_path, cmdline)
            if sigma_matches:
                top_rule = sigma_matches[0].rule
                if top_rule.level in ("critical", "high"):
                    sigma_threat = True
                    sigma_reason = f"Regla Sigma [{top_rule.title}]: {top_rule.description}"

        # 3. Consulta al monitor eBPF interno (observación + detección)
        ebpf_threat = False
        if ebpf_monitor and hasattr(ebpf_monitor, "detector"):
            event = ebpf_monitor.observer.capture_event(pid, binary_path, argv, "execve")
            det_rep = ebpf_monitor.detector.analyze_event(event)
            ebpf_threat = det_rep.is_threat

        if not tetragon_allowed or sigma_threat or ebpf_threat:
            bpf_lsm_avail = False
            if ebpf_monitor and hasattr(ebpf_monitor, "enforcer"):
                bpf_lsm_avail = ebpf_monitor.enforcer.bpf_lsm_supported

            killed = False
            if not bpf_lsm_avail:
                try:
                    import signal
                    os.kill(pid, signal.SIGKILL)
                    killed = True
                    logger.info("🛑 [DECISION ENGINE] Proceso hostil PID %d terminado con SIGKILL.", pid)
                except (ProcessLookupError, PermissionError):
                    pass

            primary = "SIGMA" if sigma_threat else "TETRAGON"
            action_name = "BPF_LSM_EPERM" if bpf_lsm_avail else "SIGKILL_CONTAINMENT"
            reason_text = sigma_reason if sigma_threat else f"Tetragon/eBPF Runtime Enforcement: {tetragon_reason}"

            if self.audit:
                self.audit.log_event("PROCESS_ENFORCEMENT_BLOCKED", {
                    "pid": pid,
                    "binary": binary_path,
                    "action": action_name,
                    "reason": reason_text,
                    "primary_engine": primary
                })

            return SecurityDecision(
                is_blocked=True,
                enforcement_action=action_name,
                threat_level="CRITICAL",
                primary_engine=primary,
                reason=reason_text,
                quarantined=False,
                process_killed=killed or bpf_lsm_avail,
                network_isolated=False,
                details={"pid": pid, "binary": binary_path, "argv": argv}
            )

        return SecurityDecision(
            is_blocked=False,
            enforcement_action="ALLOW",
            threat_level="CLEAN",
            primary_engine="TETRAGON",
            reason="Proceso autorizado conforme a TracingPolicies y reglas Sigma",
            quarantined=False,
            process_killed=False,
            network_isolated=False,
            details={"pid": pid, "binary": binary_path}
        )

    def evaluate_behavioral_syscall(self, event: Dict[str, Any], falco_monitor=None) -> SecurityDecision:
        """
        Evalúa un evento de llamada al sistema mediante las reglas de Falco (Complemento Opcional).
        Acción bloqueable verificable:
        - Si genera alerta CRITICAL o EMERGENCY: Aislamiento de red del proceso agresor (Firewall drop).
        """
        if not self.falco_enabled or not falco_monitor:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="ALLOW",
                threat_level="CLEAN",
                primary_engine="FALCO",
                reason="Módulo complementario Falco no activo",
                quarantined=False,
                process_killed=False,
                network_isolated=False
            )

        alerts = falco_monitor.evaluate_syscall_event(event)
        if not alerts:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="ALLOW",
                threat_level="CLEAN",
                primary_engine="FALCO",
                reason="Llamada al sistema conforme a reglas Falco",
                quarantined=False,
                process_killed=False,
                network_isolated=False
            )

        top_alert = alerts[0]
        pid = event.get("pid", 0)
        proc = event.get("proc", "")
        isolated = False

        if top_alert.priority in ("CRITICAL", "EMERGENCY"):
            if self.firewall and pid:
                self.firewall.isolate_process_network(pid)
                isolated = True

            action_name = "NETWORK_ISOLATE"
            if self.audit:
                self.audit.log_event("BEHAVIORAL_ANOMALY_BLOCKED", {
                    "rule": top_alert.rule,
                    "priority": top_alert.priority,
                    "pid": pid,
                    "action": action_name
                })

            return SecurityDecision(
                is_blocked=True,
                enforcement_action=action_name,
                threat_level=top_alert.priority,
                primary_engine="FALCO",
                reason=f"Falco Syscall Alert [{top_alert.rule}]: {top_alert.output}",
                quarantined=False,
                process_killed=False,
                network_isolated=isolated,
                details={"event": event, "rule": top_alert.rule}
            )

        return SecurityDecision(
            is_blocked=False,
            enforcement_action="ALLOW",
            threat_level="MEDIUM",
            primary_engine="FALCO",
            reason=f"Alerta informativa/auditoría Falco [{top_alert.rule}]: {top_alert.output}",
            quarantined=False,
            process_killed=False,
            network_isolated=False,
            details={"event": event, "rule": top_alert.rule}
        )

    def evaluate_system_integrity(self, aide_checker=None) -> SecurityDecision:
        """
        Evalúa la integridad de archivos y configuraciones críticas del sistema (AIDE).
        Detecta modificaciones de binarios en /usr/bin, /usr/sbin, /etc y /boot.
        """
        if not aide_checker:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="ALLOW",
                threat_level="CLEAN",
                primary_engine="AIDE",
                reason="Verificador AIDE no disponible"
            )

        res = aide_checker.check_integrity()
        if res.get("status") == "INTEGRITY_VIOLATION":
            violations = res.get("violations_count", 1)
            reason = f"Violación de integridad AIDE detectada en {violations} archivo(s) crítico(s)"
            if self.audit:
                self.audit.log_event("AIDE_INTEGRITY_VIOLATION_DETECTED", {
                    "violations": violations,
                    "modified": res.get("modified", [])
                })

            return SecurityDecision(
                is_blocked=False,  # AIDE es un sensor de auditoría/alerta forense
                enforcement_action="AUDIT_ALERT",
                threat_level="CRITICAL",
                primary_engine="AIDE",
                reason=reason,
                quarantined=False,
                process_killed=False,
                network_isolated=False,
                details=res
            )

        return SecurityDecision(
            is_blocked=False,
            enforcement_action="ALLOW",
            threat_level="CLEAN",
            primary_engine="AIDE",
            reason="Línea base AIDE íntegra. No se detectaron alteraciones en archivos críticos.",
            quarantined=False,
            process_killed=False,
            network_isolated=False
        )

    def evaluate_system_posture(self, osquery_diagnostics=None) -> SecurityDecision:
        """
        Evalúa la postura de seguridad global e inventario del equipo mediante consultas SQL (osquery).
        """
        if not osquery_diagnostics:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="ALLOW",
                threat_level="CLEAN",
                primary_engine="OSQUERY",
                reason="osquery no disponible"
            )

        diag = osquery_diagnostics.run_security_diagnostic()
        score = diag.get("score", 100)
        rating = diag.get("rating", "OPTIMAL")

        if rating == "NEEDS_ATTENTION" or score < 70:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="AUDIT_ALERT",
                threat_level="HIGH",
                primary_engine="OSQUERY",
                reason=f"osquery diagnóstico advierte anomalías de higiene o procesos sospechosos (Score: {score})",
                quarantined=False,
                process_killed=False,
                network_isolated=False,
                details=diag
            )

        return SecurityDecision(
            is_blocked=False,
            enforcement_action="ALLOW",
            threat_level="CLEAN",
            primary_engine="OSQUERY",
            reason=f"osquery diagnóstico óptimo (Score: {score}/100)",
            quarantined=False,
            process_killed=False,
            network_isolated=False,
            details=diag
        )

    def evaluate_file_access(self, file_path: str, event_fd: int, pid: int = 0,
                             comm: str = "", scanner=None) -> SecurityDecision:
        """
        Evalúa y aplica enforcement sobre el acceso a un archivo (Fanotify on-access).
        Acción bloqueable verificable:
        - Fanotify FAN_DENY (bloqueo preventivo antes de que el proceso lea o ejecute el archivo).
        - Cuarentena inmediata con cifrado AES-256 en el baúl (anti-TOCTOU).
        """
        if not scanner:
            return SecurityDecision(
                is_blocked=False,
                enforcement_action="ALLOW",
                threat_level="CLEAN",
                primary_engine="FANOTIFY_SCANNER",
                reason="Escáner no disponible"
            )

        report = scanner.scan_file(file_path)
        if report.is_threat:
            quarantined = False
            if self.vault:
                ok, _ = self.vault.quarantine_file(file_path, threat_name=report.threat_name, target_fd=event_fd)
                quarantined = ok

            if self.audit:
                self.audit.log_event("FILE_ACCESS_DENIED", {
                    "path": file_path,
                    "threat": report.threat_name,
                    "engine": report.engine,
                    "pid": pid
                })

            return SecurityDecision(
                is_blocked=True,
                enforcement_action="FANOTIFY_DENY",
                threat_level=report.severity,
                primary_engine="FANOTIFY_SCANNER",
                reason=f"Amenaza detectada por {report.engine} ({report.threat_name}): {report.details}",
                quarantined=quarantined,
                process_killed=False,
                network_isolated=False,
                details=report.to_dict() if hasattr(report, "to_dict") else {}
            )

        return SecurityDecision(
            is_blocked=False,
            enforcement_action="ALLOW",
            threat_level="CLEAN",
            primary_engine="FANOTIFY_SCANNER",
            reason="Archivo verificado limpio por escáner multicapa",
            quarantined=False,
            process_killed=False,
            network_isolated=False
        )
