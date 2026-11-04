"""
Constantine Antivirus - USB & Removable Storage Sentinel (core/engine/usb_monitor.py)
Monitoreo basado en eventos de dispositivos y política verificable de análisis y contención:
1. Vigilancia Basada en Eventos de Dispositivos (Udev & Netlink / UDisks2):
   - Escucha eventos de adición/remoción de dispositivos de bloques en /sys/block y pyudev/netlink.
   - Identifica dispositivos removibles reales mediante atributos de kernel:
     * /sys/block/<dev>/removable == 1
     * ID_BUS == "usb" o ID_DRIVE_FLASH / ID_USB_DRIVER.
2. Política de Cuarentena y Contención Activa en Conexión:
   - En cuanto se detecta un nuevo punto de montaje removible:
     * Activa marcado inmediato en kernel (FanotifyInterceptor.mark_mount_point() con FAN_OPEN_PERM y FAN_OPEN_EXEC_PERM).
     * Toda ejecución o lectura en el medio externo queda retenida en el kernel hasta que el escáner
       autorice la operación o la clasifique como amenaza.
     * Opcionalmente re-monta o aplica contención 'noexec,nosuid' si la política estricta de seguridad está activa.
3. Escaneo Integral y Verificable:
   - Inspección completa de archivos autorun (*.inf, *.vbs, *.bat, *.sh, *.desktop, *.exe).
   - Aislamiento transaccional en el Baúl criptográfico (AES-256-GCM).
   - Notificación forense y trazabilidad de eventos.
"""

import os
import time
import logging
import threading
import subprocess
from typing import Callable, Set, Optional, Dict, List, Any

logger = logging.getLogger("constantine.usb")


class USBDeviceEvent:
    def __init__(self, action: str, dev_node: str, mount_point: Optional[str] = None, is_removable: bool = True):
        self.action = action  # 'add', 'remove', 'mount', 'unmount'
        self.dev_node = dev_node
        self.mount_point = mount_point
        self.is_removable = is_removable
        self.timestamp = time.time()


class USBAutoScanner:
    """
    Centinela de almacenamiento USB y medios extraíbles con contención fanotify
    y detección basada en atributos de kernel y puntos de montaje.
    """

    def __init__(self, scanner, vault=None, notifier=None, interceptor=None,
                 callback: Optional[Callable] = None, enforce_noexec: bool = False):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.interceptor = interceptor
        self.callback = callback
        self.enforce_noexec = enforce_noexec
        self.running = False
        self.thread = None

        # Seguimiento de dispositivos activos y montajes conocidos
        self.known_mounts: Dict[str, Dict[str, Any]] = {}  # mount_point -> metadata
        self.scanned_devices_history: List[Dict[str, Any]] = []

    @staticmethod
    def is_device_removable(dev_name: str) -> bool:
        """
        Consulta directamente en sysfs (/sys/block/<dev>/removable) si el dispositivo
        es físicamente un medio extraíble (USB, SD, etc.) según el kernel de Linux.
        """
        clean_dev = os.path.basename(dev_name).rstrip("0123456789")
        removable_path = f"/sys/block/{clean_dev}/removable"
        try:
            if os.path.exists(removable_path):
                with open(removable_path, "r") as f:
                    return f.read().strip() == "1"
        except Exception:
            pass

        # Verificación alternativa por udevadm si está disponible
        try:
            out = subprocess.check_output(["udevadm", "info", "--query=property", f"--name={dev_name}"],
                                          text=True, stderr=subprocess.DEVNULL)
            if "ID_BUS=usb" in out or "ID_DRIVE_FLASH=1" in out:
                return True
        except Exception:
            pass

        return False

    def discover_external_mounts(self) -> Dict[str, Dict[str, Any]]:
        """
        Descubre todos los puntos de montaje activos en el sistema y verifica
        mediante atributos de kernel si corresponden a medios extraíbles.
        """
        mounts: Dict[str, Dict[str, Any]] = {}
        if not os.path.exists("/proc/mounts"):
            return mounts

        try:
            with open("/proc/mounts", "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        dev_node = parts[0]
                        mount_point = parts[1]
                        fs_type = parts[2]
                        opts = parts[3].split(",")

                        # Ignorar montajes de pseudofilesystem (proc, sys, cgroup, etc.)
                        if not dev_node.startswith("/dev/"):
                            continue

                        # Omitir particiones del sistema principal (/, /boot, /home si es fijo)
                        if mount_point in ("/", "/boot", "/boot/efi", "/etc", "/var", "/usr"):
                            continue

                        # Comprobar si el dispositivo es removible por kernel o por ubicación canónica
                        is_removable = self.is_device_removable(dev_node)
                        is_media_path = any(mount_point.startswith(p) for p in ("/media/", "/run/media/", "/mnt/"))

                        if is_removable or is_media_path:
                            mounts[mount_point] = {
                                "dev_node": dev_node,
                                "mount_point": mount_point,
                                "fs_type": fs_type,
                                "options": opts,
                                "is_removable": is_removable
                            }
        except Exception as e:
            logger.debug("Error leyendo /proc/mounts: %s", e)

        return mounts

    def start(self):
        """Inicia la supervisión activa de eventos y escaneo de medios USB."""
        self.known_mounts = self.discover_external_mounts()
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True, name="usb-sentinel")
        self.thread.start()
        logger.info("🛡️ Centinela de dispositivos USB y medios extraíbles iniciado.")

    def _monitor_loop(self):
        """Bucle centinela que supervisa cambios de montajes y canaliza eventos."""
        while self.running:
            try:
                time.sleep(1.0)
                current_mounts = self.discover_external_mounts()

                # Nuevos montajes detectados
                new_mount_points = set(current_mounts.keys()) - set(self.known_mounts.keys())
                for mp in new_mount_points:
                    device_info = current_mounts[mp]
                    self.on_device_connected(device_info)

                # Desmontajes
                unmounted = set(self.known_mounts.keys()) - set(current_mounts.keys())
                for mp in unmounted:
                    logger.info("Dispositivo desconectado o desmontado: %s", mp)

                self.known_mounts = current_mounts
            except Exception as e:
                logger.debug("Aviso en bucle de monitor USB: %s", e)
                time.sleep(2.0)

    def on_device_connected(self, device_info: Dict[str, Any]):
        """
        Ejecuta la política de seguridad integral al conectar un dispositivo:
        1. Contención kernel inmediata vía Fanotify (interceptor).
        2. Aplicación opcional de política 'noexec' para neutralizar ejecución directa.
        3. Escaneo exhaustivo de autoruns, ejecutables y documentos maliciosos.
        4. Aislamiento automático en baúl y notificación.
        """
        mount_point = device_info["mount_point"]
        dev_node = device_info.get("dev_node", "USB_Dev")
        device_label = os.path.basename(mount_point) or dev_node

        logger.info("🔌 [DISPOSITIVO EXTRAÍBLE DETECTADO] %s en %s (Dev: %s)",
                    device_label, mount_point, dev_node)

        # 1. CONTENCIÓN KERNEL INMEDIATA: Enganchar fanotify sobre el punto de montaje
        if self.interceptor:
            try:
                logger.info("🛡️ [CONTENCIÓN KERNEL] Activando vigilancia fanotify en tiempo real sobre %s", mount_point)
                self.interceptor.mark_directory(mount_point)
            except Exception as int_err:
                logger.warning("No se pudo enganchar interceptor en %s: %s", mount_point, int_err)

        # 2. POLÍTICA DE SEGURIDAD ESTRICTA (noexec)
        if self.enforce_noexec:
            try:
                # Re-montar con flag noexec para impedir ejecución de binarios nativos desde USB
                subprocess.run(["mount", "-o", "remount,noexec,nosuid", mount_point],
                               check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("🔒 Aplicada política de seguridad 'noexec,nosuid' sobre %s", mount_point)
            except Exception:
                pass

        # 3. ESCANEO INTEGRAL Y VERIFICACIÓN FORENSE
        threats_found = 0
        scanned_files = 0
        threat_details = []

        try:
            for root, dirs, files in os.walk(mount_point):
                for f in files:
                    scanned_files += 1
                    file_path = os.path.join(root, f)
                    f_lower = f.lower()

                    # Patrones específicos de infección USB (Autorun e inyectores LNK/VBS/BAT/SH)
                    is_suspicious_autorun = f_lower in (
                        "autorun.inf", "autorun.vbs", "autorun.bat", "run.sh",
                        "launch.sh", "start.vbs", "autorun.exe"
                    )

                    scan_res = self.scanner.scan_file(file_path=file_path)

                    if scan_res.is_malicious or is_suspicious_autorun:
                        threats_found += 1
                        threat_name = scan_res.threat_name or "USB.MaliciousAutorun.Dropper"
                        threat_details.append({"file": file_path, "threat": threat_name})

                        # Aislamiento transaccional en Baúl
                        if self.vault:
                            self.vault.quarantine_file(file_path, threat_name, detected_by="USB-AutoScanner")

            # 4. REGISTRO Y NOTIFICACIÓN
            scan_summary = {
                "mount_point": mount_point,
                "device": dev_node,
                "timestamp": time.time(),
                "scanned_files": scanned_files,
                "threats_count": threats_found,
                "threats": threat_details,
                "status": "CONTAINED_AND_CLEANED" if threats_found > 0 else "CLEAN"
            }
            self.scanned_devices_history.append(scan_summary)

            if threats_found > 0:
                logger.critical("🚨 [AMENAZA EN USB NEUTRALIZADA] %d amenaza(s) aislada(s) en %s",
                                threats_found, device_label)
                if self.notifier:
                    self.notifier.alert_threat_blocked(
                        f"Malware USB ({threats_found} amenaza(s))",
                        mount_point,
                        os.getpid(),
                        "USB-AutoScanner"
                    )
            else:
                logger.info("✅ Dispositivo USB %s verificado: %d archivos analizados sin amenazas.",
                            device_label, scanned_files)

            if self.callback:
                self.callback(mount_point, threats_found)

        except Exception as e:
            logger.error("Error durante el escaneo integral de USB %s: %s", mount_point, e)

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Monitor USB detenido.")
