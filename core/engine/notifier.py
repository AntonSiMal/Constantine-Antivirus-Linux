"""
Constantine Antivirus - Desktop Notification Dispatcher (core/engine/notifier.py)
Envío de notificaciones de escritorio nativas (notify-send) para alertar amenazas en tiempo real:
- Compatible con ejecuciones multi-usuario y multi-sesión (X11 / Wayland).
- Si se ejecuta desde el demonio root (UID 0), detecta los sockets de bus de sesión (/run/user/<uid>/bus)
  y despacha la notificación a los escritorios gráficos activos degradando privilegios.
- Si se ejecuta desde la GUI (usuario no-root), despacha notify-send de forma directa e inmediata.
- Registra todas las alertas en /var/log/constantine/defense.log y en /tmp/constantine_latest_alert.txt.
"""
import os
import pwd
import glob
import json
import time
import subprocess
import logging
from typing import List, Dict

logger = logging.getLogger("constantine.notifier")

ALERT_CACHE_FILE = "/tmp/constantine_latest_alert.txt"
ALERTS_JSON_FILE = "/tmp/constantine_alerts.json"
DEFENSE_LOG_FILE = "/var/log/constantine/defense.log"

class DesktopNotifier:
    def __init__(self, app_name: str = "Constantine Antivirus"):
        self.app_name = app_name

    def find_active_sessions(self) -> List[Dict[str, str]]:
        """Identifica sesiones gráficas activas de usuarios en el sistema (UID >= 1000)."""
        sessions = []
        # 1. Búsqueda por socket de bus de sesión D-Bus de systemd
        for bus_path in glob.glob("/run/user/*/bus"):
            try:
                parts = bus_path.split("/")
                if len(parts) < 4:
                    continue
                uid = int(parts[3])
                if uid < 1000:
                    continue
                try:
                    pw = pwd.getpwuid(uid)
                    username = pw.pw_name
                except KeyError:
                    continue
                runtime_dir = f"/run/user/{uid}"
                sessions.append({
                    "uid": uid,
                    "username": username,
                    "bus_path": bus_path,
                    "runtime_dir": runtime_dir,
                    "display": os.environ.get("DISPLAY", ":0"),
                    "wayland_display": "wayland-0" if os.path.exists(f"{runtime_dir}/wayland-0") else ""
                })
            except Exception:
                pass

        # 2. Respaldo por loginctl si no se encontraron buses directos
        if not sessions and os.path.exists("/usr/bin/loginctl"):
            try:
                out = subprocess.check_output(["loginctl", "list-users", "--no-legend"], text=True, timeout=2)
                for line in out.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].isdigit():
                        uid = int(parts[0])
                        if uid >= 1000:
                            username = parts[1]
                            runtime_dir = f"/run/user/{uid}"
                            sessions.append({
                                "uid": uid,
                                "username": username,
                                "bus_path": f"/run/user/{uid}/bus",
                                "runtime_dir": runtime_dir,
                                "display": ":0",
                                "wayland_display": "wayland-0" if os.path.exists(f"{runtime_dir}/wayland-0") else ""
                            })
            except Exception:
                pass

        return sessions

    def record_alert(self, title: str, body: str, urgency: str = "critical"):
        """Registra la alerta en el log persistente y en el búfer temporal para la GUI."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "title": title,
            "body": body,
            "urgency": urgency
        }
        # Guardar última alerta en texto
        try:
            with open(ALERT_CACHE_FILE, "w", encoding="utf-8") as f:
                f.write(f"[{timestamp}] {title}\n{body}\n")
        except Exception:
            pass

        # Guardar en cola JSON de alertas recientes
        try:
            alerts = []
            if os.path.exists(ALERTS_JSON_FILE):
                try:
                    with open(ALERTS_JSON_FILE, "r", encoding="utf-8") as f:
                        alerts = json.load(f)
                except Exception:
                    alerts = []
            alerts.insert(0, entry)
            alerts = alerts[:50] # Conservar las 50 más recientes
            with open(ALERTS_JSON_FILE, "w", encoding="utf-8") as f:
                json.dump(alerts, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

        # Registrar en defense.log
        try:
            log_dir = os.path.dirname(DEFENSE_LOG_FILE)
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            with open(DEFENSE_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{timestamp}] [ALERTA-AMENAZA] {title} | {body.replace(chr(10), ' ')}\n")
        except Exception:
            pass

    def alert_threat_blocked(self, threat_name: str, target_path: str, pid: int, proc_name: str = "desconocido"):
        """Despacha una notificación crítica de amenaza neutralizada y aislada en el baúl."""
        title = "⚔️ Constantine: Amenaza Bloqueada"
        body = f"<b>Amenaza:</b> {threat_name}\n<b>Archivo:</b> {target_path}\n<b>Proceso:</b> {proc_name} (PID: {pid})\n<b>Acción:</b> Neutralizado en Baúl"
        self.send(title, body, urgency="critical", icon="security-high")

    def alert_ransomware_detected(self, threat_type: str, proc_name: str, pid: int, detail: str = ""):
        """Despacha alerta crítica ante detección de ráfaga de ransomware o alteración de señuelo."""
        title = "🚨 Constantine: Ataque de Ransomware Neutralizado"
        body = f"<b>Tipo:</b> {threat_type}\n<b>Proceso Bloqueado:</b> {proc_name} (PID: {pid})\n<b>Detalle:</b> {detail}\n<b>Acción:</b> Proceso terminado (SIGKILL) y disco protegido"
        self.send(title, body, urgency="critical", icon="security-high")

    def send(self, title: str, body: str, urgency: str = "critical", icon: str = "security-high"):
        """Envía la notificación mediante notify-send asegurando entrega tanto en root como en espacio de usuario."""
        self.record_alert(title, body, urgency)
        logger.info("[NOTIFICACIÓN DESKTOP] %s | %s", title, body.replace("\n", " - "))

        # 1. Si no somos root (ejecutado directamente desde la GUI del usuario)
        if os.geteuid() != 0:
            cmd = ["notify-send", f"--app-name={self.app_name}", f"--urgency={urgency}", f"--icon={icon}", title, body]
            try:
                subprocess.run(cmd, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except Exception as e:
                logger.debug("Error enviando notificación no-root: %s", e)

        # 2. Si somos root (ejecutado desde el demonio o servicio en background)
        sessions = self.find_active_sessions()
        if not sessions:
            # Fallback a notify-send directo si hay entorno gráfico heredado
            if "DISPLAY" in os.environ or "WAYLAND_DISPLAY" in os.environ:
                cmd = ["notify-send", f"--app-name={self.app_name}", f"--urgency={urgency}", f"--icon={icon}", title, body]
                try:
                    subprocess.run(cmd, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            return

        for sess in sessions:
            uid = sess["uid"]
            username = sess["username"]
            env = os.environ.copy()
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={sess['bus_path']}"
            env["XDG_RUNTIME_DIR"] = sess["runtime_dir"]
            env["DISPLAY"] = sess["display"]
            if sess["wayland_display"]:
                env["WAYLAND_DISPLAY"] = sess["wayland_display"]
            
            cmd = ["notify-send", f"--app-name={self.app_name}", f"--urgency={urgency}", f"--icon={icon}", title, body]
            
            try:
                def demote():
                    try:
                        os.setgid(pwd.getpwuid(uid).pw_gid)
                        os.setuid(uid)
                    except Exception:
                        pass
                subprocess.run(
                    cmd,
                    env=env,
                    preexec_fn=demote if os.geteuid() == 0 else None,
                    timeout=3,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception:
                # Intentar vía su como alternativa
                try:
                    safe_su_cmd = [
                        "su", "-", username, "-s", "/bin/sh", "-c",
                        'exec notify-send "$@"', "--",
                        f"--app-name={self.app_name}",
                        f"--urgency={urgency}",
                        f"--icon={icon}",
                        title,
                        body
                    ]
                    subprocess.run(safe_su_cmd, env=env, timeout=3, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
                except Exception:
                    pass
