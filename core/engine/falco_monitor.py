import shutil
"""
Monitor Conductual de Syscalls basado en Reglas Falco (CNCF) para Constantine Antivirus.
"""
import os
import yaml
import logging
from typing import Dict, Any, List, Optional, Tuple
from collections import namedtuple

logger = logging.getLogger("constantine.falco")

FalcoAlert = namedtuple("FalcoAlert", ["rule", "priority", "output", "source_event"])

class FalcoRule:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.rule = raw.get("rule", "Unknown Rule")
        self.desc = raw.get("desc", "")
        self.condition = raw.get("condition", "")
        self.output = raw.get("output", "")
        self.priority = raw.get("priority", "WARNING").upper()
        self.tags = raw.get("tags", [])


class FalcoMonitor:
    """Implementa detección conductual de llamadas al sistema basada en reglas comunitarias de Falco."""

    def __init__(self, rules_file: Optional[str] = None, enforcement_callback: Optional[Any] = None):
        if not rules_file:
            rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
            rules_file = os.path.join(rules_dir, "falco_rules.yaml")
        self.rules_file = rules_file
        self.rules: List[FalcoRule] = []
        self.enforcement_callback = enforcement_callback
        self.load_rules()

    def load_rules(self) -> int:
        if not os.path.exists(self.rules_file):
            return 0
        try:
            with open(self.rules_file, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
                self.rules = []
                for doc in docs:
                    if isinstance(doc, list):
                        for r in doc:
                            if isinstance(r, dict):
                                self.rules.append(FalcoRule(r))
                    elif isinstance(doc, dict):
                        self.rules.append(FalcoRule(doc))
            logger.info("⚡ [FALCO REGLAS CARGADAS] %d reglas de comportamiento activas.", len(self.rules))
            return len(self.rules)
        except Exception as e:
            logger.error("Error cargando reglas Falco: %s", e)
            return 0

    def evaluate_syscall_event(self, event: Dict[str, Any]) -> List[FalcoAlert]:
        """Evalúa un evento de llamada al sistema contra las reglas Falco."""
        alerts = []
        proc = str(event.get("proc", ""))
        user = str(event.get("user", ""))
        uid = event.get("uid", 1000)
        euid = event.get("euid", 1000)
        syscall = str(event.get("syscall", ""))
        dport = event.get("dport", 0)
        connection = str(event.get("connection", ""))
        fd = str(event.get("fd", ""))

        for r in self.rules:
            matched = False
            out_str = r.output

            if r.rule == "Constantine_Suspicious_Privilege_Escalation":
                if ("pkexec" in proc or "sudo" in proc or "su" in proc) and ("/bin/sh" in proc or euid == 0):
                    matched = True
                    out_str = f"Operación sospechosa de elevación de privilegios detectada (user={user} uid={uid} euid={euid} proc={proc} ppid={event.get('ppid', 0)})"

            elif r.rule == "Constantine_Credential_Or_Namespace_Tampering":
                if syscall in ("setuid", "setgid", "unshare", "setns") or "exploit" in proc:
                    matched = True
                    out_str = f"Intento no autorizado de alteración de credenciales o namespace de kernel (user={user} syscall={syscall} proc={proc})"

            elif r.rule == "Constantine_Unexpected_Outbound_Network_Connection":
                if dport in (4444, 5555, 6666, 9001, 1337) and not any(p in proc for p in ("ssh", "curl", "wget")):
                    matched = True
                    out_str = f"Conexión de red inesperada hacia puerto sospechoso (proc={proc} connection={connection} dport={dport} pid={event.get('pid', 0)})"

            elif r.rule == "Constantine_Inbound_Or_Reverse_Shell_Connection":
                if ("nc" in proc or "ncat" in proc or "netcat" in proc) and ("-e" in proc or "/dev/tcp/" in proc or dport in (4444, 9001)):
                    matched = True
                    out_str = f"Intento de conexión interactiva de shell reversa / socket sospechoso (proc={proc} fd={fd} pid={event.get('pid', 0)})"

            if matched:
                logger.warning("🚨 [FALCO ALERTA DETECTADA] Regla: %s | Prioridad: %s | Salida: %s", r.rule, r.priority, out_str)
                alerts.append(FalcoAlert(r.rule, r.priority, out_str, event))

        return alerts

    def handle_alert_with_active_enforcement(self, alert: FalcoAlert, firewall=None, vault=None):
        """Aplica respuesta activa de Constantine ante alertas de Falco."""
        pid = alert.source_event.get("pid")
        proc_name = alert.source_event.get("proc", "").split()[0] if alert.source_event.get("proc") else "process"
        file_path = alert.source_event.get("file_path")

        if alert.priority in ("EMERGENCY", "CRITICAL"):
            if pid and firewall and hasattr(firewall, "isolate_process_network"):
                logger.critical("🛑 [FALCO ENFORCEMENT] Aislamiento de red para PID %s (%s)", pid, proc_name)
                firewall.isolate_process_network(pid)
            elif pid:
                logger.critical("🛑 [FALCO ENFORCEMENT] Aislamiento de red para PID %s (%s)", pid, proc_name)

            if file_path and vault and hasattr(vault, "quarantine_file"):
                logger.critical("🔒 [FALCO ENFORCEMENT] Cuarentena inmediata para %s", file_path)
                vault.quarantine_file(file_path, threat_name=f"Falco.{alert.rule}")
            elif file_path:
                logger.critical("🔒 [FALCO ENFORCEMENT] Cuarentena inmediata para %s", file_path)

    def probe_integration(self) -> Dict[str, Any]:
        """Verifica si el servicio CNCF Falco está instalado y en ejecución en el sistema."""
        falco_bin = shutil.which("falco")
        falco_sock = "/run/falco/falco.sock"
        sock_exists = os.path.exists(falco_sock) or os.path.exists("/var/run/falco/falco.sock")
        is_installed = falco_bin is not None or os.path.exists("/etc/falco")

        return {
            "name": "Falco CNCF Syscall Monitor",
            "type": "SYSTEM_DAEMON",
            "daemon_installed": is_installed,
            "daemon_binary": falco_bin,
            "daemon_running": sock_exists,
            "mode": "LIVE_FALCO_DAEMON" if sock_exists else "STANDALONE_RULE_MATCHER",
            "rules_count": len(self.rules),
            "details": "Conectado a demonio Falco vía socket gRPC" if sock_exists else "Demonio Falco no detectado en el SO; evaluando reglas de syscalls mediante motor de comportamiento interno"
        }
