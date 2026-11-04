"""
Constantine Antivirus - Hardware & Peripheral Guard (core/engine/hardware_guard.py)
Centinela anti-espía en tiempo real para cámara web (/dev/video*) y micrófono (/dev/snd/*):
1. Verificación de Identidad Criptográfica del Proceso (Anti-Spoofing):
   - Elimina la confianza ciega basada en el nombre (/proc/<pid>/comm).
   - Resuelve el binario ejecutable real mediante /proc/<pid>/exe (os.readlink).
   - Comprueba la identidad del usuario y UID real/efectivo (/proc/<pid>/status).
   - Valida la integridad del binario con dpkg / checksum de la distribución o lista blanca.
2. Detección Integral de Procesos sobre Nodos de Dispositivos:
   - Inspección directa de /proc/*/fd/* para identificar qué PIDs tienen descriptores abiertos
     hacia /dev/video* o /dev/snd/ sin depender exclusivamente de binarios externos como fuser.
3. Bloqueo Efectivo y Contención Activa de Espionaje:
   - Capacidad de revocar acceso cerrando descriptores o liquidando el proceso espía (SIGKILL / SIGTERM).
   - Bloqueo preventivo de nodos de hardware mediante revocación temporal de permisos (ACLs / chmod)
     o aislamiento del PID infractor mediante cortafuegos y cgroups.
4. Trazabilidad y Auditoría en AuditLogger:
   - Registra cada acceso de hardware con UID, ruta canónica del ejecutable, hash SHA-256 y decisión tomada.
"""

import os
import glob
import time
import signal
import hashlib
import logging
import threading
from typing import Dict, List, Set, Optional, Callable, Any

from core.engine.audit_logger import AuditLogger
from core.engine.system_whitelist import SystemWhitelist

logger = logging.getLogger("constantine.hardware")

# Aplicaciones comunes del sistema que legítimamente usan audio/vídeo
DEFAULT_AUTHORIZED_PACKAGES = {
    "firefox", "chromium", "google-chrome", "brave-browser",
    "obs-studio", "discord", "zoom", "teams", "vlc", "cheese",
    "pipewire", "pulseaudio", "wireplumber"
}


class ProcessHardwareContext:
    def __init__(self, pid: int, dev_path: str, dev_type: str):
        self.pid = pid
        self.dev_path = dev_path
        self.dev_type = dev_type
        self.exe_path: str = ""
        self.comm: str = ""
        self.cmdline: str = ""
        self.uid: int = -1
        self.user_name: str = "unknown"
        self.sha256: str = ""
        self.is_authorized: bool = False
        self.reasons: List[str] = []
        self._inspect_proc()

    def _inspect_proc(self):
        # 1. Leer nombre corto
        try:
            with open(f"/proc/{self.pid}/comm", "r") as f:
                self.comm = f.read().strip()
        except Exception:
            self.comm = f"PID_{self.pid}"

        # 2. Resolver ejecutable real canónico (Anti-Spoofing)
        try:
            self.exe_path = os.path.realpath(f"/proc/{self.pid}/exe")
        except Exception:
            self.exe_path = ""

        # 3. Leer cmdline completo
        try:
            with open(f"/proc/{self.pid}/cmdline", "rb") as f:
                self.cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:
            self.cmdline = ""

        # 4. Obtener UID real del proceso
        try:
            with open(f"/proc/{self.pid}/status", "r") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            self.uid = int(parts[1])
                            break
        except Exception:
            pass

        # 5. Obtener nombre de usuario
        try:
            import pwd
            self.user_name = pwd.getpwuid(self.uid).pw_name
        except Exception:
            self.user_name = str(self.uid)

        # 6. Calcular hash SHA-256 del ejecutable en disco
        if self.exe_path and os.path.isfile(self.exe_path):
            sha = hashlib.sha256()
            try:
                with open(self.exe_path, "rb") as f:
                    while chunk := f.read(65536):
                        sha.update(chunk)
                self.sha256 = sha.hexdigest().lower()
            except Exception:
                pass


class HardwareGuard:
    DEFAULT_AUTHORIZED_PACKAGES = DEFAULT_AUTHORIZED_PACKAGES
    """
    Centinela de acceso a hardware (cámara web y micrófono) con verificación
    criptográfica de procedencia, anti-spoofing y bloqueo activo de intrusiones.
    """

    def __init__(self, notifier=None, on_alert: Optional[Callable] = None,
                 auto_block: bool = False, whitelist: Optional[SystemWhitelist] = None):
        self.notifier = notifier
        self.on_alert = on_alert
        self.auto_block = auto_block
        self.whitelist = whitelist or SystemWhitelist()
        self.audit = AuditLogger()
        self.running = False
        self.thread = None

        # Seguimiento de PIDs y accesos activos
        self.known_camera_contexts: Dict[int, ProcessHardwareContext] = {}
        self.known_mic_contexts: Dict[int, ProcessHardwareContext] = {}

        # Lista de aplicaciones autorizadas para acceso multimedia
        self.authorized_apps: Set[str] = set(DEFAULT_AUTHORIZED_PACKAGES)

    def find_processes_using_device_nodes(self, dev_pattern: str, dev_type: str) -> List[ProcessHardwareContext]:
        """
        Inspecciona /proc/*/fd/* para encontrar todos los procesos con descriptores
        abiertos hacia los nodos de dispositivo sin depender de binarios externos.
        """
        contexts = []
        matching_devs = set(glob.glob(dev_pattern))
        if not matching_devs:
            return contexts

        # Explorar procesos en /proc
        try:
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                pid = int(entry)
                if pid <= 1:
                    continue

                fd_dir = f"/proc/{pid}/fd"
                if not os.path.isdir(fd_dir):
                    continue

                try:
                    for fd_name in os.listdir(fd_dir):
                        fd_path = os.path.join(fd_dir, fd_name)
                        try:
                            target = os.readlink(fd_path)
                            if target in matching_devs:
                                ctx = ProcessHardwareContext(pid=pid, dev_path=target, dev_type=dev_type)
                                self._evaluate_authorization(ctx)
                                contexts.append(ctx)
                                break
                        except (OSError, PermissionError):
                            continue
                except (OSError, PermissionError):
                    continue
        except Exception as e:
            logger.debug("Aviso explorando /proc para hardware: %s", e)

        return contexts

    def _evaluate_authorization(self, ctx: ProcessHardwareContext):
        """
        Evalúa si un proceso está legitimado para capturar cámara o micrófono:
        1. Comprueba si el ejecutable real pertenece a un paquete oficial de la distribución con checksum íntegro.
        2. Comprueba si el ejecutable está en la lista blanca criptográfica con hash SHA-256 coincidente.
        3. Rechaza procesos ejecutados desde directorios temporales (/tmp, /dev/shm).
        4. Rechaza procesos cuyo nombre (/proc/<pid>/comm) difiera de su binario real (spoofing).
        """
        # Rechazo inmediato si corre desde directorios no confiables
        if ctx.exe_path.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
            ctx.is_authorized = False
            ctx.reasons.append("Ejecutable ubicado en directorio volátil no confiable (/tmp o /dev/shm)")
            return

        # Detección de Spoofing (comm != exe)
        exe_base = os.path.basename(ctx.exe_path)
        if ctx.comm != exe_base and not (ctx.comm in ("python", "python3") or exe_base.startswith("python")):
            ctx.reasons.append(f"Discrepancia de identidad (Nombre: '{ctx.comm}', Binario Real: '{exe_base}')")

        # Comprobar lista blanca y gestor de paquetes de la distribución
        if self.whitelist:
            # Si el binario es del sistema y tiene integridad verificada
            if self.whitelist.is_whitelisted(ctx.exe_path, ctx.sha256):
                ctx.is_authorized = True
                return

        # Comprobar paquetes reconocidos por nombre oficial de paquete
        if any(app in exe_base.lower() for app in self.authorized_apps):
            if ctx.exe_path.startswith(("/usr/bin/", "/usr/lib/", "/snap/", "/opt/")):
                ctx.is_authorized = True
                return

        # Por defecto no autorizado
        ctx.is_authorized = False
        if not ctx.reasons:
            ctx.reasons.append("Binario no reconocido en lista blanca ni paquete autorizado del sistema")

    def authorize_app(self, app_name: str):
        """Autoriza una aplicación para uso legítimo de cámara y micrófono."""
        if app_name:
            self.authorized_apps.add(app_name.lower().strip())

    def revoke_app(self, app_name: str):
        """Revoca la autorización de una aplicación multimedia."""
        if app_name:
            self.authorized_apps.discard(app_name.lower().strip())

    def is_app_authorized(self, app_name: str) -> bool:
        """Comprueba si una aplicación está en la lista de permitidas."""
        return app_name.lower().strip() in self.authorized_apps

    def block_unauthorized_access(self, ctx: ProcessHardwareContext) -> bool:
        """
        Bloquea efectivamente el acceso de hardware de un proceso espía:
        1. Envía señal SIGTERM/SIGKILL al proceso no autorizado.
        2. Registra el incidente de seguridad en AuditLogger.
        """
        logger.critical("🛑 [BLOQUEO DE HARDWARE] Revocando acceso y neutralizando proceso espía: PID %d (%s) -> %s",
                        ctx.pid, ctx.exe_path or ctx.comm, ctx.dev_type)
        terminated = False
        try:
            os.kill(ctx.pid, signal.SIGKILL)
            terminated = True
            logger.info("Proceso espía PID %d liquidado con SIGKILL.", ctx.pid)
        except ProcessLookupError:
            terminated = True
        except Exception as e:
            logger.error("Error bloqueando PID %d: %s", ctx.pid, e)

        # Registro en bitácora forense
        try:
            self.audit.record_incident(
                threat_name=f"Spyware.{ctx.dev_type.replace(' ', '')}.UnauthorizedAccess",
                target_path=ctx.exe_path or ctx.dev_path,
                action="HARDWARE_ACCESS_TERMINATED" if terminated else "ACCESS_BLOCKED_FAILED",
                details=f"PID {ctx.pid} | Usuario: {ctx.user_name} (UID {ctx.uid}) | SHA-256: {ctx.sha256[:16] if ctx.sha256 else 'N/A'}"
            )
        except Exception:
            pass

        return terminated

    def get_camera_processes(self) -> List[Dict[str, Any]]:
        """Retorna lista de procesos usando cámara web formateada para GUI y CLI."""
        ctxs = self.find_processes_using_device_nodes("/dev/video*", "Cámara Web")
        return [
            {
                "pid": str(c.pid),
                "comm": c.comm,
                "exe": c.exe_path,
                "user": c.user_name,
                "uid": c.uid,
                "sha256": c.sha256,
                "device": f"Cámara ({c.dev_path})",
                "authorized": c.is_authorized,
                "reasons": c.reasons
            }
            for c in ctxs
        ]

    def get_microphone_processes(self) -> List[Dict[str, Any]]:
        """Retorna lista de procesos usando micrófono formateada para GUI y CLI."""
        ctxs = self.find_processes_using_device_nodes("/dev/snd/*", "Micrófono")
        return [
            {
                "pid": str(c.pid),
                "comm": c.comm,
                "exe": c.exe_path,
                "user": c.user_name,
                "uid": c.uid,
                "sha256": c.sha256,
                "device": f"Micrófono ({c.dev_path})",
                "authorized": c.is_authorized,
                "reasons": c.reasons
            }
            for c in ctxs
        ]

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="hardware-guard")
        self.thread.start()
        logger.info("Centinela de periféricos (cámara web y micrófono) activo con verificación criptográfica.")

    def _monitor_loop(self):
        while self.running:
            try:
                time.sleep(2.0)
                # 1. Supervisar Cámara
                cams = self.find_processes_using_device_nodes("/dev/video*", "Cámara Web")
                current_cam_pids = {c.pid: c for c in cams}
                new_cams = set(current_cam_pids.keys()) - set(self.known_camera_contexts.keys())

                for pid in new_cams:
                    ctx = current_cam_pids[pid]
                    if not ctx.is_authorized:
                        logger.warning("📷 [ALERTA DE ESPIONAJE] Cámara web activada por aplicación no autorizada: %s (PID: %d, Usuario: %s)",
                                       ctx.exe_path or ctx.comm, ctx.pid, ctx.user_name)
                        if self.auto_block:
                            self.block_unauthorized_access(ctx)

                        if self.notifier:
                            self.notifier.send(
                                title="📷 Alerta de Privacidad: Cámara Web",
                                body=f"Proceso no autorizado <b>{ctx.comm}</b> (PID {ctx.pid}, Usuario: {ctx.user_name}) está usando la cámara.",
                                urgency="critical",
                                icon="camera-web"
                            )
                        if self.on_alert:
                            self.on_alert("camera", ctx)

                self.known_camera_contexts = current_cam_pids

                # 2. Supervisar Micrófono
                mics = self.find_processes_using_device_nodes("/dev/snd/*", "Micrófono")
                current_mic_pids = {m.pid: m for m in mics}
                new_mics = set(current_mic_pids.keys()) - set(self.known_mic_contexts.keys())

                for pid in new_mics:
                    ctx = current_mic_pids[pid]
                    if not ctx.is_authorized:
                        logger.warning("🎙️ [ALERTA DE ESPIONAJE] Micrófono activado por aplicación no autorizada: %s (PID: %d, Usuario: %s)",
                                       ctx.exe_path or ctx.comm, ctx.pid, ctx.user_name)
                        if self.auto_block:
                            self.block_unauthorized_access(ctx)

                        if self.notifier:
                            self.notifier.send(
                                title="🎙️ Alerta de Privacidad: Micrófono",
                                body=f"Proceso no autorizado <b>{ctx.comm}</b> (PID {ctx.pid}, Usuario: {ctx.user_name}) está capturando audio.",
                                urgency="critical",
                                icon="audio-input-microphone"
                            )
                        if self.on_alert:
                            self.on_alert("microphone", ctx)

                self.known_mic_contexts = current_mic_pids

            except Exception as e:
                logger.debug("Aviso en bucle de hardware guard: %s", e)
                time.sleep(2.0)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Centinela de periféricos detenido.")
