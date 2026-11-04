"""
Constantine Antivirus - Network Isolation & Firewall / GUFW (core/engine/firewall.py)
"""
import os
import signal
import shutil
import subprocess
import logging

logger = logging.getLogger("constantine.firewall")

class NetworkQuarantine:
    def __init__(self, use_nftables: bool = True):
        self.use_nftables = use_nftables
        self.quarantined_pids = set()
        self._init_tables()

    def _init_tables(self):
        if self.use_nftables:
            try:
                subprocess.run(["nft", "add", "table", "inet", "constantine"], stderr=subprocess.DEVNULL)
                subprocess.run(["nft", "add", "chain", "inet", "constantine", "quarantine", "{ type filter hook output priority -10; policy accept; }"], stderr=subprocess.DEVNULL)
            except Exception:
                self.use_nftables = False

    def kill_process_sockets(self, pid: int) -> bool:
        try:
            res = subprocess.run(["ss", "-K", f"pid = {pid}"], capture_output=True, timeout=2)
            return res.returncode == 0
        except Exception:
            return False

    def isolate_pid(self, pid: int, terminate: bool = True):
        if pid in self.quarantined_pids:
            return
        self.quarantined_pids.add(pid)
        self.kill_process_sockets(pid)
        if not self.use_nftables:
            try:
                subprocess.run(["iptables", "-I", "OUTPUT", "-m", "owner", "--pid-owner", str(pid), "-j", "DROP"], stderr=subprocess.DEVNULL)
            except Exception:
                pass
        if terminate:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

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
        try:
            res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=2)
            return "Status: active" in res.stdout or "Estado: activo" in res.stdout
        except Exception:
            return False

    def toggle_ufw(self, enable: bool) -> bool:
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
        if self.use_nftables:
            try:
                subprocess.run(["nft", "delete", "table", "inet", "constantine"], stderr=subprocess.DEVNULL)
            except Exception:
                pass
