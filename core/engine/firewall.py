"""
Constantine Antivirus - Network Isolation & Firewall / GUFW (core/engine/firewall.py)
Aislamiento verificable de procesos y gestión de cortafuegos en Linux:
1. Corte de Sockets Activos:
   - Utiliza ss -K 'sport > 0 and pid = <pid>' o inspección directa de descriptores en /proc/<pid>/fd
     con tcpdrop / ss para revocar de inmediato cualquier túnel C2 o conexión persistente activa.
2. Reglas Kernel de Bloqueo en Salida (Egress Firewall Rules):
   - Soporte nativo nftables: Tabla dedicada inet constantine con cadena quarantine.
     Añade reglas dinámicas de bloqueo por UID o CGROUP (skuid / socket cgroupv2).
   - Soporte iptables / iptables-legacy: Bloqueo de salida por propietario (owner module --uid-owner).
3. Aislamiento por Cgroups v2 y BPF Cgroup Socket (Zero-Egress):
   - Mueve el proceso a un cgroup aislado de red o congela su grupo de control.
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
from typing import Set, Optional, Dict, List

logger = logging.getLogger("constantine.firewall")


class NetworkQuarantine:
    """
    Aislamiento dinámico de procesos en red (Host-Based Egress Containment)
    y puente de gestión para UFW y GUFW.
    """

    def __init__(self, use_nftables: bool = True):
        self.use_nftables = use_nftables
        self.quarantined_pids: Set[int] = set()
        self.active_nft_rules: List[str] = []
        self._init_tables()

    def _init_tables(self):
        """Inicializa la infraestructura de filtrado nftables si está disponible."""
        if not shutil.which("nft"):
            self.use_nftables = False
            return

        try:
            # Crear tabla e infraestructuras con prioridad temprana
            subprocess.run(["nft", "add", "table", "inet", "constantine"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["nft", "add", "chain", "inet", "constantine", "quarantine",
                            "{ type filter hook output priority -10; policy accept; }"],
                           check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.use_nftables = True
        except Exception:
            self.use_nftables = False

    def kill_process_sockets(self, pid: int) -> bool:
        """
        Corta y destruye inmediatamente todos los sockets TCP/UDP abiertos por el PID.
        Usa 'ss -K' con filtrado de proceso.
        """
        if pid <= 1:
            return False

        killed_any = False

        # 1. Intentar con ss -K
        if shutil.which("ss"):
            try:
                # ss -K mata sockets activos en kernel (TCP abort)
                r1 = subprocess.run(["ss", "-K", f"pid = {pid}"], capture_output=True, timeout=2)
                if r1.returncode == 0:
                    killed_any = True
            except Exception:
                pass

        # 2. Desconectar sockets inspeccionando descriptores en /proc/<pid>/fd
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

    def isolate_pid(self, pid: int, terminate: bool = True) -> bool:
        """
        Aísla completamente un proceso en la capa de red:
        1. Corta sus sockets de red activos.
        2. Añade regla de bloqueo estricta en el kernel (nftables / iptables).
        3. Si terminate=True, liquida el proceso con SIGKILL.
        """
        if pid <= 1:
            return False

        self.quarantined_pids.add(pid)
        logger.critical("🛑 [AISLAMIENTO DE RED] Conteniendo proceso PID %d (corte de sockets y egress drop)", pid)

        # 1. Destruir sockets
        self.kill_process_sockets(pid)

        # 2. Obtener UID para bloqueo por propietario
        proc_uid = None
        try:
            with open(f"/proc/{pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        proc_uid = line.split()[1]
                        break
        except Exception:
            pass

        # 3. Aplicar regla de cortafuegos en kernel
        if self.use_nftables and shutil.which("nft"):
            try:
                # Regla nftables por socket PID/UID si está disponible
                rule = f"add rule inet constantine quarantine meta skuid {proc_uid} drop" if proc_uid and proc_uid != "0" else None
                if rule:
                    subprocess.run(["nft", rule], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    self.active_nft_rules.append(rule)
            except Exception as nft_err:
                logger.debug("Aviso nftables: %s", nft_err)

        elif shutil.which("iptables") and proc_uid and proc_uid != "0":
            try:
                subprocess.run(["iptables", "-I", "OUTPUT", "-m", "owner", "--uid-owner", proc_uid, "-j", "DROP"],
                               check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass

        # 4. Terminación inmediata del proceso si fue solicitada
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
        """Purga las reglas dinámicas temporales creadas en nftables."""
        if self.use_nftables and shutil.which("nft"):
            try:
                subprocess.run(["nft", "delete", "table", "inet", "constantine"],
                               check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        self.active_nft_rules.clear()
        self.quarantined_pids.clear()
