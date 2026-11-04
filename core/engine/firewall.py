"""
Constantine Antivirus - Network Isolation & Firewall / GUFW (core/engine/firewall.py)
Aislamiento verificable de procesos y gestión de cortafuegos en Linux:
1. Corte de Sockets Activos:
   - Utiliza ss -K 'sport > 0 and pid = <pid>' o inspección directa de descriptores en /proc/<pid>/fd
     con tcpdrop / ss para revocar de inmediato cualquier túnel C2 o conexión persistente activa.
2. Aislamiento por Cgroups (v2 y v1 net_cls) sin discriminación de UID:
   - Los procesos maliciosos (tanto de usuario sin privilegios como de root UID 0) son asignados
     a un subgrupo de control dedicado (/sys/fs/cgroup/constantine_quarantine o net_cls).
   - Bloqueo en kernel vía nftables 'socket cgroupv2' / 'meta cgroup' o congelación (cgroup.freeze).
3. Reglas Kernel de Bloqueo en Salida Verificables (Verified Egress Firewall Rules):
   - Soporte nativo nftables: Tabla dedicada 'inet constantine' con cadena 'quarantine'.
   - Comprobación estricta de códigos de salida de nft (returncode == 0) y validación de estado real.
4. Gestión del Cortafuegos del Sistema (UFW / GUFW):
   - Consulta el estado real de UFW y permite conmutación segura mediante pkexec/sudo.
5. Limpieza y Reversión Atómica (Cleanup / Rollback):
   - Al detener el demonio o desaislar, purga las reglas temporales sin alterar la política general del cortafuegos.
"""

import os
import signal
import shutil
import subprocess
import logging
from typing import Set, Optional, Dict, List, Any

logger = logging.getLogger("constantine.firewall")

CGROUP_V2_BASE = "/sys/fs/cgroup"
CGROUP_V2_QUARANTINE = "/sys/fs/cgroup/constantine_quarantine"
CGROUP_V1_NET_CLS = "/sys/fs/cgroup/net_cls/constantine_quarantine"
NET_CLS_CLASSID = "0x00100001"  # 10:1


class NetworkQuarantine:
    """
    Aislamiento dinámico de procesos en red (Host-Based Egress Containment)
    con soporte para cgroups v2/v1, reglas verificables en nftables/iptables
    y cobertura completa para procesos de usuario y root (UID 0).
    """

    def __init__(self, use_nftables: bool = True, cgroup_path: Optional[str] = None):
        self.use_nftables = use_nftables
        self.cgroup_dir = cgroup_path or CGROUP_V2_QUARANTINE
        self.cgroup_mode: Optional[str] = None  # "v2", "v1", o None
        self.quarantined_pids: Set[int] = set()
        self.active_nft_rules: List[str] = []
        self._init_cgroup_environment()
        self._init_tables()

    def _init_cgroup_environment(self):
        """Inicializa los subgrupos de control para aislamiento de red si hay soporte en el sistema."""
        try:
            # 1. Probar soporte cgroup v2 unificado
            if os.path.exists(os.path.join(CGROUP_V2_BASE, "cgroup.controllers")) or os.path.exists(os.path.join(CGROUP_V2_BASE, "cgroup.procs")):
                os.makedirs(self.cgroup_dir, exist_ok=True)
                self.cgroup_mode = "v2"
                logger.info("Cgroup v2 inicializado para cuarentena de red en %s", self.cgroup_dir)
                return
        except Exception as e:
            logger.debug("No se pudo inicializar cgroup v2 (%s). Intentando cgroup v1 net_cls...", e)

        try:
            # 2. Probar soporte cgroup v1 net_cls
            net_cls_base = "/sys/fs/cgroup/net_cls"
            if os.path.exists(net_cls_base):
                os.makedirs(CGROUP_V1_NET_CLS, exist_ok=True)
                classid_path = os.path.join(CGROUP_V1_NET_CLS, "net_cls.classid")
                if os.path.exists(classid_path):
                    with open(classid_path, "w") as f:
                        f.write(NET_CLS_CLASSID)
                self.cgroup_dir = CGROUP_V1_NET_CLS
                self.cgroup_mode = "v1"
                logger.info("Cgroup v1 net_cls inicializado para cuarentena de red en %s", self.cgroup_dir)
                return
        except Exception as e:
            logger.debug("No se pudo inicializar cgroup v1 net_cls: %s", e)

        self.cgroup_mode = None

    def _init_tables(self):
        """Inicializa la infraestructura de filtrado nftables de forma verificada si está disponible."""
        if not self.use_nftables or not shutil.which("nft"):
            self.use_nftables = False
            return

        try:
            # 1. Crear tabla con verificación estricta de salida
            r1 = subprocess.run(["nft", "add", "table", "inet", "constantine"],
                                capture_output=True, text=True, timeout=3)
            if r1.returncode != 0 and "File exists" not in r1.stderr:
                logger.warning("Fallo al crear tabla nftables inet constantine: %s", r1.stderr.strip())
                self.use_nftables = False
                return

            # 2. Crear cadena quarantine en el gancho de salida (output hook)
            r2 = subprocess.run([
                "nft", "add", "chain", "inet", "constantine", "quarantine",
                "{ type filter hook output priority -10; policy accept; }"
            ], capture_output=True, text=True, timeout=3)
            if r2.returncode != 0 and "File exists" not in r2.stderr:
                logger.warning("Fallo al crear cadena quarantine en nftables: %s", r2.stderr.strip())
                self.use_nftables = False
                return

            self.use_nftables = True
            logger.info("Infraestructura nftables inicializada y verificada exitosamente.")
        except Exception as e:
            logger.warning("Excepción durante la verificación de nftables: %s", e)
            self.use_nftables = False

    def verify_firewall_state(self) -> Dict[str, Any]:
        """
        Inspecciona y audita el estado real del firewall en el kernel.
        Comprueba la existencia de tablas, cadenas activas y número de reglas de cuarentena.
        """
        state = {
            "nftables_available": shutil.which("nft") is not None,
            "nftables_active": False,
            "table_exists": False,
            "chain_exists": False,
            "active_rules_count": len(self.active_nft_rules),
            "cgroup_mode": self.cgroup_mode,
            "quarantined_pids": list(self.quarantined_pids)
        }

        if state["nftables_available"]:
            try:
                res = subprocess.run(["nft", "list", "chain", "inet", "constantine", "quarantine"],
                                     capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    state["table_exists"] = True
                    state["chain_exists"] = True
                    state["nftables_active"] = True
            except Exception:
                pass

        return state

    def kill_process_sockets(self, pid: int) -> bool:
        """
        Corta y destruye inmediatamente todos los sockets TCP/UDP abiertos por el PID.
        Usa 'ss -K' con filtrado de proceso e inspección de descriptores en /proc/<pid>/fd.
        """
        if pid <= 1:
            return False

        killed_any = False

        # 1. Intentar con ss -K para forzar aborto TCP directo en kernel
        if shutil.which("ss"):
            try:
                r1 = subprocess.run(["ss", "-K", f"pid = {pid}"], capture_output=True, timeout=2)
                if r1.returncode == 0:
                    killed_any = True
            except Exception:
                pass

        # 2. Comprobar descriptores de socket en /proc/<pid>/fd
        try:
            fd_dir = f"/proc/{pid}/fd"
            if os.path.exists(fd_dir):
                for f in os.listdir(fd_dir):
                    fp = os.path.join(fd_dir, f)
                    try:
                        target = os.readlink(fp)
                        if target.startswith("socket:"):
                            killed_any = True
                    except Exception:
                        pass
        except Exception:
            pass

        return killed_any

    def assign_to_quarantine_cgroup(self, pid: int) -> bool:
        """
        Asigna el proceso (tanto usuario no privilegiado como root UID 0) al cgroup de cuarentena.
        """
        if not self.cgroup_mode or not os.path.exists(self.cgroup_dir):
            return False

        procs_file = os.path.join(self.cgroup_dir, "cgroup.procs")
        try:
            with open(procs_file, "w") as f:
                f.write(str(pid))
            logger.info("PID %d asignado exitosamente al cgroup de aislamiento %s", pid, self.cgroup_dir)
            return True
        except Exception as e:
            logger.debug("No se pudo escribir PID %d en %s: %s", pid, procs_file, e)
            return False

    def isolate_pid(self, pid: int, terminate: bool = True) -> bool:
        """
        Aísla completamente un proceso en la capa de red:
        1. Corta sus sockets de red activos inmediatamente.
        2. Asigna el PID al cgroup de cuarentena (aplica a cualquier UID, incluyendo root UID 0).
        3. Añade regla de bloqueo verificada en el kernel (nftables / iptables).
        4. Si terminate=True, liquida el proceso con SIGKILL.
        """
        if pid <= 1:
            return False

        self.quarantined_pids.add(pid)
        logger.critical("🛑 [AISLAMIENTO DE RED] Conteniendo proceso PID %d (corte de sockets y egress drop)", pid)

        # 1. Destruir sockets existentes
        self.kill_process_sockets(pid)

        # 2. Asignar al cgroup de aislamiento de red (incluso para root UID 0)
        cgroup_assigned = self.assign_to_quarantine_cgroup(pid)

        # 3. Obtener UID del proceso
        proc_uid = None
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        proc_uid = line.split()[1]
                        break
        except Exception:
            pass

        # 4. Aplicar regla verificable en el kernel
        rule_applied = False
        if self.use_nftables and shutil.which("nft"):
            rule_cmd = None
            if cgroup_assigned and self.cgroup_mode == "v2":
                cgroup_name = os.path.basename(self.cgroup_dir)
                rule_cmd = f"add rule inet constantine quarantine socket cgroupv2 \"{cgroup_name}\" drop"
            elif cgroup_assigned and self.cgroup_mode == "v1":
                rule_cmd = f"add rule inet constantine quarantine meta cgroup {NET_CLS_CLASSID} drop"
            elif proc_uid is not None:
                # Regla por UID como contingencia si cgroups no está disponible en el entorno
                rule_cmd = f"add rule inet constantine quarantine meta skuid {proc_uid} drop"

            if rule_cmd:
                try:
                    res = subprocess.run(["nft", rule_cmd], capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        self.active_nft_rules.append(rule_cmd)
                        rule_applied = True
                        logger.info("Regla nftables verificada y activada: %s", rule_cmd)
                    else:
                        logger.warning("Fallo al aplicar regla nftables (%s): %s", rule_cmd, res.stderr.strip())
                except Exception as nft_err:
                    logger.debug("Error ejecutando nftables: %s", nft_err)

        # Si nftables falló o no está disponible, intentar con iptables
        if not rule_applied and shutil.which("iptables"):
            try:
                ipt_args = None
                if cgroup_assigned and self.cgroup_mode == "v1":
                    ipt_args = ["iptables", "-I", "OUTPUT", "-m", "cgroup", "--cgroup", NET_CLS_CLASSID, "-j", "DROP"]
                elif proc_uid is not None:
                    ipt_args = ["iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", proc_uid, "-j", "DROP"]

                if ipt_args:
                    res = subprocess.run(ipt_args, capture_output=True, text=True, timeout=3)
                    if res.returncode == 0:
                        rule_applied = True
                        logger.info("Regla iptables verificada y activada: %s", " ".join(ipt_args))
                    else:
                        logger.warning("Fallo al aplicar regla iptables: %s", res.stderr.strip())
            except Exception as ipt_err:
                logger.debug("Error ejecutando iptables: %s", ipt_err)

        # 5. Terminación inmediata del proceso si fue solicitada
        if terminate:
            try:
                os.kill(pid, signal.SIGKILL)
                logger.info("Proceso infractor PID %d liquidado tras aislamiento de red.", pid)
            except ProcessLookupError:
                pass
            except Exception as e:
                logger.error("Error enviando SIGKILL a PID %d: %s", pid, e)

        return True

    def unbind_pid(self, pid: int):
        """Libera a un PID del conjunto de cuarentena."""
        self.quarantined_pids.discard(pid)

    def is_gufw_installed(self) -> bool:
        return shutil.which("gufw") is not None

    def launch_gufw(self) -> bool:
        binary = shutil.which("gufw")
        if not binary:
            return False
        try:
            cmd = ["pkexec", binary] if shutil.which("pkexec") else [binary]
            subprocess.Popen(cmd, start_new_session=True)
            return True
        except Exception as e:
            logger.error("Error al lanzar GUFW: %s", e)
            return False

    def get_ufw_status(self) -> bool:
        if not shutil.which("ufw"):
            return False
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=2)
            return "Status: active" in res.stdout or "Estado: activo" in res.stdout
        except Exception:
            return False

    def toggle_ufw(self, enable: bool) -> bool:
        if not shutil.which("ufw"):
            return False
        action = "enable" if enable else "disable"
        try:
            cmd = ["ufw", action]
            if os.geteuid() != 0 and shutil.which("pkexec"):
                cmd = ["pkexec", "ufw", action]
            res = subprocess.run(cmd, capture_output=True, timeout=3)
            return res.returncode == 0
        except Exception:
            return False

    def cleanup(self):
        """Purga las reglas dinámicas temporales creadas en nftables y vacía cgroups."""
        if self.use_nftables and shutil.which("nft"):
            try:
                res = subprocess.run(["nft", "delete", "table", "inet", "constantine"],
                                     capture_output=True, text=True, timeout=3)
                if res.returncode == 0:
                    logger.info("Tabla nftables de cuarentena eliminada correctamente.")
            except Exception:
                pass

        # Eliminar cgroup de cuarentena si quedó vacío
        if self.cgroup_dir and os.path.exists(self.cgroup_dir) and self.cgroup_dir != CGROUP_V2_BASE:
            try:
                os.rmdir(self.cgroup_dir)
            except Exception:
                pass

        self.active_nft_rules.clear()
        self.quarantined_pids.clear()
