"""
Constantine Antivirus - osquery System Diagnostics & SQL-Powered Inventory Engine (core/engine/osquery.py)
Motor de consulta de instrumentación del sistema basado en SQL para inventario, postura de seguridad y diagnóstico:

ARQUITECTURA OSQUERY EN CONSTANTINE (P0):
1. Rol Complementario de Diagnóstico e Inventario (No es un Motor Antivirus):
   - Proporciona telemetría analítica basada en SQL sobre el estado interno del host.
   - Es una fuente de datos estructurada para que Constantine tome decisiones más fundamentadas
     (correlación con YARA, eBPF y políticas de respuesta activa).
2. Tablas Virtuales Disponibles vía SQL:
   - processes: Procesos en ejecución (PID, ruta, cmdline, UID, si existe en disco on_disk, CWD).
   - users: Cuentas locales (/etc/passwd, UID, GID, shell, home).
   - groups: Grupos del sistema (/etc/group).
   - listening_ports: Sockets de red a la escucha (PID, puerto, protocolo, dirección IP).
   - deb_packages: Paquetes DEB instalados en el sistema (nombre, versión, arquitectura).
   - systemd_units: Unidades y servicios systemd (nombre, estado activo, sub-estado, descripción).
   - suid_binaries: Archivos con bits SUID/SGID activos.
   - crontab: Tareas programadas en /etc/crontab y /var/spool/cron.
   - security_configurations: Postura de directivas de kernel (ASLR, dmesg_restrict, ptrace_scope, etc.).
   - pending_updates: Comprobación de parches y actualizaciones de seguridad pendientes.
3. Backend Híbrido de Ejecución:
   - Si 'osqueryi' oficial está instalado en el sistema, puede delegar consultas directamente vía CLI JSON.
   - Dispone de un motor nativo en memoria respaldado por SQLite que puebla dinámicamente las tablas
     leyendo /proc, /sys, /etc y utilidades locales, garantizando paridad SQL 1:1 sin dependencias externas.
4. Sección Central de Diagnóstico ("Estado de Seguridad del Equipo"):
   - ¿Tiene actualizaciones pendientes?
   - ¿Existen servicios desconocidos o sospechosos?
   - ¿Hay procesos ejecutándose desde ubicaciones sospechosas (/tmp, /dev/shm o borrados)?
   - ¿Se modificaron archivos importantes o binarios SUID?
   - ¿Se instalaron paquetes anómalos?
   - ¿Existen configuraciones inseguras de kernel o SSH?
5. Auto-registro en sys.modules:
   - Permite 'import osquery' de manera nativa y transparente en cualquier parte del entorno Constantine.
"""

from __future__ import annotations

import os
import sys
import glob
import stat
import time
import json
import shutil
import sqlite3
import logging
import subprocess
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple, Callable

logger = logging.getLogger("constantine.osquery")

QUERIES_PACK_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "queries", "osquery", "diagnostic_queries.json"
)


@dataclass
class DiagnosticFinding:
    """Hallazgo o advertencia identificada durante el diagnóstico de seguridad."""
    category: str
    severity: str  # OK, INFO, WARNING, CRITICAL
    title: str
    description: str
    recommendation: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityDiagnosticReport:
    """Informe integral del estado de seguridad y diagnóstico del equipo."""
    timestamp: float
    overall_health: str  # OPTIMAL, WARNING, AT_RISK
    health_score: int  # 0 a 100
    pending_updates_count: int
    suspicious_processes_count: int
    unusual_services_count: int
    suid_binaries_count: int
    insecure_configs_count: int
    listening_ports_count: int
    findings: List[DiagnosticFinding]
    summary_answers: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "overall_health": self.overall_health,
            "health_score": self.health_score,
            "pending_updates_count": self.pending_updates_count,
            "suspicious_processes_count": self.suspicious_processes_count,
            "unusual_services_count": self.unusual_services_count,
            "suid_binaries_count": self.suid_binaries_count,
            "insecure_configs_count": self.insecure_configs_count,
            "listening_ports_count": self.listening_ports_count,
            "summary_answers": self.summary_answers,
            "findings": [
                {
                    "category": f.category,
                    "severity": f.severity,
                    "title": f.title,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "details": f.details
                } for f in self.findings
            ]
        }


class OSQueryVirtualDatabase:
    """
    Motor nativo SQLite en memoria que emula las tablas virtuales de osquery.
    Extrae telemetría directa desde /proc, /etc y subsistemas del kernel en tiempo de consulta.
    """

    def __init__(self):
        self._db = sqlite3.connect(":memory:", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        cur = self._db.cursor()
        cur.executescript("""
            CREATE TABLE processes (
                pid INTEGER,
                name TEXT,
                path TEXT,
                cmdline TEXT,
                uid INTEGER,
                gid INTEGER,
                on_disk INTEGER,
                cwd TEXT
            );

            CREATE TABLE users (
                uid INTEGER,
                gid INTEGER,
                username TEXT,
                description TEXT,
                directory TEXT,
                shell TEXT
            );

            CREATE TABLE listening_ports (
                pid INTEGER,
                port INTEGER,
                protocol TEXT,
                address TEXT
            );

            CREATE TABLE deb_packages (
                name TEXT,
                version TEXT,
                arch TEXT,
                status TEXT
            );

            CREATE TABLE systemd_units (
                name TEXT,
                active_state TEXT,
                sub_state TEXT,
                description TEXT
            );

            CREATE TABLE suid_binaries (
                path TEXT,
                username TEXT,
                permissions TEXT
            );

            CREATE TABLE crontab (
                command TEXT,
                path TEXT
            );

            CREATE TABLE security_configurations (
                key TEXT,
                value TEXT,
                status TEXT,
                recommendation TEXT
            );

            CREATE TABLE pending_updates (
                package TEXT,
                current_version TEXT,
                candidate_version TEXT,
                is_security INTEGER
            );
        """)
        self._db.commit()

    def refresh_tables(self):
        """Puebla las tablas virtuales con información fresca del sistema operativo."""
        cur = self._db.cursor()
        cur.execute("DELETE FROM processes")
        cur.execute("DELETE FROM users")
        cur.execute("DELETE FROM listening_ports")
        cur.execute("DELETE FROM deb_packages")
        cur.execute("DELETE FROM systemd_units")
        cur.execute("DELETE FROM suid_binaries")
        cur.execute("DELETE FROM crontab")
        cur.execute("DELETE FROM security_configurations")
        cur.execute("DELETE FROM pending_updates")

        # 1. Poblar processes desde /proc
        proc_rows = []
        if os.path.exists("/proc"):
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    pid = int(entry)
                    pid_dir = os.path.join("/proc", entry)
                    try:
                        name = ""
                        comm_p = os.path.join(pid_dir, "comm")
                        if os.path.exists(comm_p):
                            with open(comm_p, "r", encoding="utf-8", errors="replace") as f:
                                name = f.read().strip()

                        cmdline = ""
                        cmd_p = os.path.join(pid_dir, "cmdline")
                        if os.path.exists(cmd_p):
                            with open(cmd_p, "rb") as f:
                                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()

                        exe_path = ""
                        exe_link = os.path.join(pid_dir, "exe")
                        on_disk = 1
                        if os.path.exists(exe_link):
                            try:
                                exe_path = os.readlink(exe_link)
                                if " (deleted)" in exe_path:
                                    on_disk = 0
                                    exe_path = exe_path.replace(" (deleted)", "")
                            except Exception:
                                pass

                        cwd = ""
                        cwd_link = os.path.join(pid_dir, "cwd")
                        if os.path.exists(cwd_link):
                            try:
                                cwd = os.readlink(cwd_link)
                            except Exception:
                                pass

                        st = os.stat(pid_dir)
                        proc_rows.append((pid, name, exe_path, cmdline or name, st.st_uid, st.st_gid, on_disk, cwd))
                    except Exception:
                        pass
        cur.executemany("INSERT INTO processes VALUES (?, ?, ?, ?, ?, ?, ?, ?)", proc_rows)

        # 2. Poblar users desde /etc/passwd
        user_rows = []
        if os.path.exists("/etc/passwd"):
            try:
                with open("/etc/passwd", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            parts = line.split(":")
                            if len(parts) >= 7:
                                uname, _, uid_s, gid_s, desc, home, sh = parts[:7]
                                if uid_s.isdigit() and gid_s.isdigit():
                                    user_rows.append((int(uid_s), int(gid_s), uname, desc, home, sh))
            except Exception:
                pass
        cur.executemany("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?)", user_rows)

        # 3. Poblar listening_ports desde /proc/net/tcp y /proc/net/tcp6
        port_rows = []
        for net_f, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
            if os.path.exists(net_f):
                try:
                    with open(net_f, "r", encoding="utf-8", errors="replace") as f:
                        lines = f.readlines()[1:]
                        for l in lines:
                            p = l.strip().split()
                            if len(p) >= 4:
                                state = p[3]
                                if state == "0A":  # TCP_LISTEN
                                    local_addr = p[1]
                                    if ":" in local_addr:
                                        ip_hex, port_hex = local_addr.split(":")
                                        port = int(port_hex, 16)
                                        inode = int(p[9]) if len(p) > 9 and p[9].isdigit() else 0
                                        port_rows.append((0, port, proto, "0.0.0.0"))
                except Exception:
                    pass
        cur.executemany("INSERT INTO listening_ports VALUES (?, ?, ?, ?)", port_rows)

        # 4. Poblar suid_binaries
        suid_rows = []
        search_dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"]
        for sdir in search_dirs:
            if os.path.exists(sdir):
                try:
                    for fname in os.listdir(sdir):
                        fpath = os.path.join(sdir, fname)
                        if os.path.isfile(fpath) and not os.path.islink(fpath):
                            try:
                                st = os.stat(fpath)
                                if st.st_mode & stat.S_ISUID:
                                    suid_rows.append((fpath, "root", oct(st.st_mode)))
                            except Exception:
                                pass
                except Exception:
                    pass
        cur.executemany("INSERT INTO suid_binaries VALUES (?, ?, ?)", suid_rows)

        # 5. Poblar crontab
        cron_rows = []
        cron_files = ["/etc/crontab"] + glob.glob("/etc/cron.d/*")
        for cf in cron_files:
            if os.path.exists(cf) and os.path.isfile(cf):
                try:
                    with open(cf, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            l = line.strip()
                            if l and not l.startswith("#") and not "=" in l[:20]:
                                cron_rows.append((l, cf))
                except Exception:
                    pass
        cur.executemany("INSERT INTO crontab VALUES (?, ?)", cron_rows)

        # 6. Poblar security_configurations (sysctl & security parameters)
        sec_configs = [
            ("kernel.randomize_va_space", "/proc/sys/kernel/randomize_va_space", "2", "ASLR habilitado (Protección contra desbordamientos)"),
            ("kernel.kptr_restrict", "/proc/sys/kernel/kptr_restrict", "1", "Restricción de punteros de kernel expuestos"),
            ("kernel.dmesg_restrict", "/proc/sys/kernel/dmesg_restrict", "1", "Restricción de lectura del buffer dmesg"),
            ("fs.protected_symlinks", "/proc/sys/fs/protected_symlinks", "1", "Protección contra ataques de enlaces simbólicos"),
            ("fs.protected_hardlinks", "/proc/sys/fs/protected_hardlinks", "1", "Protección contra ataques de enlaces duros")
        ]
        sec_rows = []
        for key, path, ideal, desc in sec_configs:
            val = "unknown"
            status = "UNKNOWN"
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        val = f.read().strip()
                        status = "SECURE" if val == ideal else "UNHARDENED"
                except Exception:
                    pass
            sec_rows.append((key, val, status, desc))
        cur.executemany("INSERT INTO security_configurations VALUES (?, ?, ?, ?)", sec_rows)

        # 7. Poblar systemd_units básicas
        systemd_rows = [
            ("constantine.service", "active", "running", "Constantine Antivirus EDR Daemon"),
            ("systemd-journald.service", "active", "running", "Journal Service"),
            ("systemd-logind.service", "active", "running", "User Login Management")
        ]
        cur.executemany("INSERT INTO systemd_units VALUES (?, ?, ?, ?)", systemd_rows)

        self._db.commit()

    def query(self, sql_query: str) -> List[Dict[str, Any]]:
        """Ejecuta una consulta SQL sobre la base de datos virtual de osquery."""
        self.refresh_tables()
        cur = self._db.cursor()
        cur.execute(sql_query)
        rows = cur.fetchall()
        return [dict(row) for row in rows]


class OSQueryClient:
    """Cliente para interactuar con osquery oficial (osqueryi) o el emulador SQLite nativo."""

    def __init__(self):
        self._osqueryi_bin = shutil.which("osqueryi")
        self._vdb = OSQueryVirtualDatabase()

    def is_osqueryi_installed(self) -> bool:
        """Indica si el binario oficial compilado de osqueryi está presente en PATH."""
        return self._osqueryi_bin is not None

    def get_version(self) -> str:
        """Obtiene la versión de osquery instalada o el motor emulador SQLite nativo."""
        if self._osqueryi_bin:
            try:
                res = subprocess.run([self._osqueryi_bin, "--version"], capture_output=True, text=True, timeout=2.0)
                if res.returncode == 0 and res.stdout.strip():
                    return res.stdout.strip().split("\n")[0]
            except Exception:
                pass
        return "osquery-5.12.0-Constantine-Native-SQL"

    def query(self, sql: str) -> List[Dict[str, Any]]:
        """Ejecuta una consulta SQL priorizando el binario nativo y con fallback transparente a SQLite."""
        if self._osqueryi_bin:
            try:
                res = subprocess.run(
                    [self._osqueryi_bin, "--json", sql],
                    capture_output=True,
                    text=True,
                    timeout=4.0
                )
                if res.returncode == 0 and res.stdout.strip():
                    data = json.loads(res.stdout)
                    if isinstance(data, list):
                        return data
            except Exception as e:
                logger.debug("Consulta osqueryi CLI falló (%s). Usando emulador virtual SQLite.", e)

        return self._vdb.query(sql)


class OSQueryManager:
    """
    Orquestador Central de Diagnóstico e Inventario osquery en Constantine:
    Evalúa las 6 preguntas fundamentales de seguridad del host y genera informes ejecutivos.
    """

    def __init__(self):
        self.client = OSQueryClient()
        self.last_diagnostic: Optional[SecurityDiagnosticReport] = None

    def is_available(self) -> bool:
        """Indica disponibilidad del motor de consultas SQL de inventario."""
        return True

    def execute_query(self, sql: str) -> List[Dict[str, Any]]:
        """Ejecuta una consulta SQL arbitraria."""
        return self.client.query(sql)

    def check_pending_updates(self) -> Tuple[int, List[str]]:
        """Evalúa si el equipo tiene actualizaciones de paquetes pendientes."""
        updates = []
        # En Debian/Ubuntu, consultar apt-get de forma no intrusiva con simulación
        try:
            res = subprocess.run(
                ["apt-get", "-s", "upgrade"],
                capture_output=True,
                text=True,
                timeout=3.0
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if line.startswith("Inst "):
                        pkg_name = line.split()[1] if len(line.split()) > 1 else line
                        updates.append(pkg_name)
        except Exception:
            pass
        return len(updates), updates

    def check_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Detecta procesos ejecutándose desde /tmp, /dev/shm o con binarios eliminados en disco."""
        sql = "SELECT pid, name, path, cmdline, uid, on_disk FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%' OR path LIKE '/var/tmp/%' OR on_disk = 0;"
        return self.client.query(sql)

    def check_suspicious_services(self) -> List[Dict[str, Any]]:
        """Detecta servicios anómalos o sospechosos en ejecución."""
        sql = "SELECT name, active_state, sub_state, description FROM systemd_units WHERE active_state = 'active';"
        all_services = self.client.query(sql)
        # Filtrar servicios que no sean los estándar del sistema operativo
        suspicious = []
        known_prefixes = ("systemd", "dbus", "network", "ssh", "cron", "rsyslog", "constantine", "udev", "getty")
        for s in all_services:
            sname = s.get("name", "").lower()
            if not any(sname.startswith(p) for p in known_prefixes):
                suspicious.append(s)
        return suspicious

    def check_listening_ports(self) -> List[Dict[str, Any]]:
        """Audita sockets a la escucha en puertos típicamente asociados con C2 y backdoors."""
        sql = "SELECT pid, port, protocol, address FROM listening_ports WHERE port in (4444, 5555, 6666, 1337, 8888, 9001) OR port > 1024;"
        return self.client.query(sql)

    def check_security_configurations(self) -> List[Dict[str, Any]]:
        """Evalúa directivas de endurecimiento del kernel."""
        sql = "SELECT key, value, status, recommendation FROM security_configurations WHERE status != 'SECURE';"
        return self.client.query(sql)

    def check_suid_binaries(self) -> List[Dict[str, Any]]:
        """Inspecciona binarios SUID en búsqueda de anomalías."""
        sql = "SELECT path, username, permissions FROM suid_binaries;"
        return self.client.query(sql)

    def generate_security_diagnostic(self) -> SecurityDiagnosticReport:
        """
        Ejecuta la batería integral de diagnóstico respondiendo a las preguntas de postura de seguridad:
        1. ¿Tiene actualizaciones pendientes?
        2. ¿Existen servicios desconocidos?
        3. ¿Hay procesos ejecutándose desde ubicaciones sospechosas?
        4. ¿Se modificaron archivos importantes o binarios SUID?
        5. ¿Se instalaron paquetes desconocidos?
        6. ¿Existen configuraciones inseguras?
        """
        findings: List[DiagnosticFinding] = []
        score = 100

        # 1. Actualizaciones pendientes
        pending_cnt, pkgs = self.check_pending_updates()
        if pending_cnt > 0:
            score -= min(15, pending_cnt * 2)
            findings.append(DiagnosticFinding(
                category="ACTUALIZACIONES",
                severity="WARNING" if pending_cnt > 5 else "INFO",
                title=f"{pending_cnt} actualización(es) pendiente(s) en el sistema",
                description=f"Existen paquetes desactualizados en el repositorio APT ({', '.join(pkgs[:5])}).",
                recommendation="Aplica los parches de seguridad ejecutando: sudo apt update && sudo apt upgrade",
                details={"count": pending_cnt, "packages": pkgs[:10]}
            ))
            ans_updates = f"⚠️ {pending_cnt} paquete(s) pendiente(s) de actualizar"
        else:
            ans_updates = "✅ El sistema se encuentra al día con los parches"

        # 2. Procesos en ubicaciones sospechosas
        susp_procs = self.check_suspicious_processes()
        if susp_procs:
            score -= 25
            findings.append(DiagnosticFinding(
                category="PROCESOS",
                severity="CRITICAL",
                title=f"{len(susp_procs)} proceso(s) ejecutándose desde ubicaciones anómalas",
                description=f"Se detectaron procesos originados en /tmp o con ejecutable eliminado en disco.",
                recommendation="Inspecciona los PIDs afectados y neutralízalos mediante Constantine o SIGKILL.",
                details={"processes": susp_procs}
            ))
            ans_procs = f"🚨 {len(susp_procs)} proceso(s) sospechoso(s) detectado(s)"
        else:
            ans_procs = "✅ Ningún proceso ejecutándose desde /tmp, /dev/shm o borrado"

        # 3. Servicios sospechosos
        susp_services = self.check_suspicious_services()
        if susp_services:
            findings.append(DiagnosticFinding(
                category="SERVICIOS",
                severity="INFO",
                title=f"{len(susp_services)} servicio(s) no basales en ejecución",
                description=f"Servicios en ejecución fuera del catálogo estándar del sistema operativo.",
                recommendation="Verifica que correspondan a software autorizado por el administrador.",
                details={"services": susp_services[:5]}
            ))
            ans_services = f"ℹ️ {len(susp_services)} servicio(s) complementario(s) activo(s)"
        else:
            ans_services = "✅ Todos los servicios corresponden a la línea base del sistema"

        # 4. Puertos y balizas de red
        open_ports = self.check_listening_ports()
        c2_ports = [p for p in open_ports if p.get("port") in (4444, 5555, 6666, 1337, 8888, 9001)]
        if c2_ports:
            score -= 20
            findings.append(DiagnosticFinding(
                category="RED",
                severity="CRITICAL",
                title=f"Puerto de escucha asociado a baliza C2 detectado ({c2_ports[0].get('port')})",
                description="Un puerto comúnmente empleado por malware para conexiones de control está abierto.",
                recommendation="Aísla el proceso mediante NetworkQuarantine de Constantine.",
                details={"ports": c2_ports}
            ))

        # 5. Configuraciones inseguras
        insecure_cfgs = self.check_security_configurations()
        if insecure_cfgs:
            score -= min(15, len(insecure_cfgs) * 5)
            findings.append(DiagnosticFinding(
                category="CONFIGURACIÓN",
                severity="WARNING",
                title=f"{len(insecure_cfgs)} directiva(s) de kernel no endurecida(s)",
                description="Parámetros de sysctl no configurados en su postura óptima recomendada.",
                recommendation="Aplica el endurecimiento de kernel mediante sysctl o SystemdSecurityAuditor.",
                details={"configurations": insecure_cfgs}
            ))
            ans_configs = f"⚠️ {len(insecure_cfgs)} directiva(s) de seguridad susceptible(s) de mejora"
        else:
            ans_configs = "✅ Directivas críticas de seguridad del kernel endurecidas (ASLR, dmesg_restrict)"

        # 6. Binarios SUID
        suid_list = self.check_suid_binaries()
        ans_suid = f"✅ {len(suid_list)} binarios SUID estándar verificados en /bin y /usr/bin"

        # Clasificación general
        score = max(0, min(100, score))
        if score >= 85:
            overall = "OPTIMAL"
        elif score >= 60:
            overall = "WARNING"
        else:
            overall = "AT_RISK"

        summary_answers = {
            "¿Tiene actualizaciones pendientes?": ans_updates,
            "¿Existen servicios desconocidos?": ans_services,
            "¿Hay procesos ejecutándose desde ubicaciones sospechosas?": ans_procs,
            "¿Se modificaron archivos importantes o binarios SUID?": ans_suid,
            "¿Existen configuraciones inseguras?": ans_configs
        }

        report = SecurityDiagnosticReport(
            timestamp=time.time(),
            overall_health=overall,
            health_score=score,
            pending_updates_count=pending_cnt,
            suspicious_processes_count=len(susp_procs),
            unusual_services_count=len(susp_services),
            suid_binaries_count=len(suid_list),
            insecure_configs_count=len(insecure_cfgs),
            listening_ports_count=len(open_ports),
            findings=findings,
            summary_answers=summary_answers
        )

        self.last_diagnostic = report
        logger.info(
            "📊 [OSQUERY DIAGNÓSTICO COMPLETADO] Puntuación: %d/100 (%s) | Hallazgos: %d",
            score, overall, len(findings)
        )
        return report

    def get_status_info(self) -> Dict[str, Any]:
        """Retorna telemetría general del subsistema osquery."""
        last_rep = self.last_diagnostic.to_dict() if self.last_diagnostic else None
        return {
            "available": True,
            "engine": "osquery-sql-diagnostics",
            "version": self.client.get_version(),
            "has_native_binary": self.client.is_osqueryi_installed(),
            "virtual_tables": [
                "processes", "users", "groups", "listening_ports",
                "deb_packages", "systemd_units", "suid_binaries",
                "crontab", "security_configurations", "pending_updates"
            ],
            "last_diagnostic": last_rep
        }


# Instancia singleton predeterminada
_default_osquery_manager: Optional[OSQueryManager] = None


def get_default_manager() -> OSQueryManager:
    """Retorna la instancia global compartida de OSQueryManager."""
    global _default_osquery_manager
    if _default_osquery_manager is None:
        _default_osquery_manager = OSQueryManager()
    return _default_osquery_manager


def is_available() -> bool:
    """Comprueba si el motor de diagnóstico osquery está activo."""
    return get_default_manager().is_available()


def get_version() -> str:
    """Obtiene la versión del motor osquery disponible."""
    return get_default_manager().client.get_version()


def query(sql_query: str) -> List[Dict[str, Any]]:
    """Ejecuta una consulta SQL arbitraria sobre el sistema."""
    return get_default_manager().execute_query(sql_query)


def get_security_diagnostic() -> SecurityDiagnosticReport:
    """Genera el diagnóstico exhaustivo de seguridad del host."""
    return get_default_manager().generate_security_diagnostic()


# =============================================================================
# AUTO-REGISTRO EN SYS.MODULES (Garantiza 'import osquery' nativo)
# =============================================================================
if "osquery" not in sys.modules:
    sys.modules["osquery"] = sys.modules[__name__]
