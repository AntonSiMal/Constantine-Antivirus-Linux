"""
Constantine Antivirus - Desktop Notification Dispatcher (core/engine/notifier.py)
"""
import os, pwd, glob, subprocess, logging
from typing import List, Dict

logger = logging.getLogger("constantine.notifier")

class DesktopNotifier:
    def __init__(self, app_name: str = "Constantine Antivirus"):
        self.app_name = app_name

    def find_active_sessions(self) -> List[Dict[str, str]]:
        sessions = []
        for bus_path in glob.glob("/run/user/*/bus"):
            try:
                uid = int(bus_path.split("/")[3])
                if uid < 1000:
                    continue
                username = pwd.getpwuid(uid).pw_name
                runtime_dir = f"/run/user/{uid}"
                sessions.append({
                    "uid": uid,
                    "username": username,
                    "bus_path": bus_path,
                    "runtime_dir": runtime_dir,
                    "display": ":0",
                    "wayland_display": "wayland-0" if os.path.exists(f"{runtime_dir}/wayland-0") else ""
                })
            except Exception:
                pass
        return sessions

    def alert_threat_blocked(self, threat_name: str, target_path: str, pid: int, proc_name: str = "desconocido"):
        title = "⚔️ Constantine: Amenaza Bloqueada"
        body = f"<b>Amenaza:</b> {threat_name}\n<b>Archivo:</b> {target_path}\n<b>Proceso:</b> {proc_name} (PID: {pid})\n<b>Acción:</b> Neutralizado en Baúl"
        self.send(title, body, urgency="critical", icon="security-high")

    def send(self, title: str, body: str, urgency: str = "critical", icon: str = "security-high"):
        sessions = self.find_active_sessions()
        if not sessions:
            logger.info("[ALERTA] %s | %s", title, body.replace("\n", " - "))
            return
        for sess in sessions:
            uid = sess["uid"]
            env = os.environ.copy()
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={sess['bus_path']}"
            env["XDG_RUNTIME_DIR"] = sess["runtime_dir"]
            env["DISPLAY"] = sess["display"]
            if sess["wayland_display"]:
                env["WAYLAND_DISPLAY"] = sess["wayland_display"]
            cmd = ["notify-send", f"--app-name={self.app_name}", f"--urgency={urgency}", f"--icon={icon}", title, body]
            try:
                def demote():
                    os.setgid(pwd.getpwuid(uid).pw_gid)
                    os.setuid(uid)
                subprocess.run(cmd, env=env, preexec_fn=demote if os.geteuid() == 0 else None, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
