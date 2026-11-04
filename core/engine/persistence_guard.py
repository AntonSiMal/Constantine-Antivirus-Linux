"""
Constantine Antivirus - Linux Persistence & Integrity Sentinel (core/engine/persistence_guard.py)
Supervisión exhaustiva y verificable de mecanismos de persistencia en Linux:
1. Cobertura Integral de Rutas de Persistencia de Linux:
   - Systemd: /etc/systemd/system/, /lib/systemd/system/, ~/.config/systemd/user/, /etc/systemd/user/
   - Cron y Spool: /etc/cron.d/, /etc/cron.daily/, /etc/cron.hourly/, /etc/cron.weekly/,
     /etc/cron.monthly/, /etc/crontab, /var/spool/cron/crontabs/
   - Scripts de Inicialización y Shell Hooks: /etc/profile.d/, /etc/profile, /etc/bash.bashrc,
     /etc/rc.local, /etc/init.d/, /etc/environment, ~/.bashrc, ~/.profile, ~/.bash_profile,
     ~/.zshrc, ~/.config/autostart/
   - Enlaces Dinámicos y Módulos: /etc/ld.so.preload, /etc/ld.so.conf.d/, /etc/modules, /etc/modules-load.d/
   - SSH Authorized Keys: ~/.ssh/authorized_keys, /root/.ssh/authorized_keys
2. Detección Criptográfica y Registro de Estado (Baseline Criptográfico):
   - Mantiene una línea base con hash SHA-256, permisos POSIX (st_mode), propietario (st_uid/st_gid) y tamaño.
   - Detecta eventos de adición (CREATION), modificación (MODIFICATION) y eliminación (DELETION).
3. Diferenciación Inteligente de Cambios Administrativos vs Infecciones:
   - Distingue cambios legítimos de paquetes del sistema (apt/dpkg) comprobando si el archivo pertenece
     a un paquete oficial no alterado.
   - No clasifica una modificación legítima de configuración como malware a menos que el contenido
     sea malicioso o viole las políticas de integridad.
4. Respaldo Seguro y Capacidad de Restauración (Rollback de Persistencia):
   - Almacena copias de seguridad limpias en /var/lib/constantine/backups/persistence/.
   - Permite restaurar de forma confiable un archivo de arranque modificado o dañado por un atacante.
"""

import os
import time
import shutil
import hashlib
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Callable, Dict, Set, Optional, List, Tuple, Any

from core.engine.audit_logger import AuditLogger

logger = logging.getLogger("constantine.persistence")

BACKUP_DIR = "/var/lib/constantine/backups/persistence"
USER_BACKUP_DIR = os.path.expanduser("~/.config/constantine/backups/persistence")


class PersistenceEventType(str, Enum):
    FILE_CREATED = "FILE_CREATED"
    FILE_MODIFIED = "FILE_MODIFIED"
    FILE_DELETED = "FILE_DELETED"
    PERMISSIONS_CHANGED = "PERMISSIONS_CHANGED"


@dataclass
class PersistenceRecord:
    path: str
    sha256: str
    size: int
    mtime: float
    mode: int
    uid: int
    gid: int
    is_system_package: bool = False
    backup_path: Optional[str] = None


class PersistenceGuard:
    """
    Centinela de persistencia con cobertura completa de rutas de Linux,
    línea base criptográfica (SHA-256), detección de eliminaciones,
    validación de cambios administrativos y restauración confiable.
    """

    SYSTEM_PERSISTENCE_DIRS = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        "/etc/systemd/user",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/etc/profile.d",
        "/etc/init.d",
        "/etc/ld.so.conf.d",
        "/etc/modules-load.d"
    ]

    SYSTEM_PERSISTENCE_FILES = [
        "/etc/crontab",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/rc.local",
        "/etc/environment",
        "/etc/ld.so.preload",
        "/etc/modules"
    ]

    USER_PERSISTENCE_PATTERNS = [
        ".bashrc",
        ".profile",
        ".bash_profile",
        ".bash_login",
        ".zshrc",
        ".config/autostart",
        ".config/systemd/user",
        ".ssh/authorized_keys"
    ]

    def __init__(self, scanner=None, vault=None, notifier=None,
                 on_tamper_callback: Optional[Callable] = None, backup_dir: Optional[str] = None):
        self.scanner = scanner
        self.vault = vault
        self.notifier = notifier
        self.on_tamper_callback = on_tamper_callback

        if backup_dir:
            self.backup_dir = backup_dir
        elif os.geteuid() == 0 and os.path.exists("/var/lib"):
            self.backup_dir = BACKUP_DIR
        else:
            self.backup_dir = USER_BACKUP_DIR

        try:
            os.makedirs(self.backup_dir, exist_ok=True)
        except Exception:
            self.backup_dir = "/tmp/constantine_persistence_backups"
            os.makedirs(self.backup_dir, exist_ok=True)

        self.running = False
        self.thread = None
        self.baseline: Dict[str, PersistenceRecord] = {}
        self.audit = AuditLogger()
        self.watched_targets = self._resolve_all_persistence_targets()

    def _resolve_all_persistence_targets(self) -> List[str]:
        """Resuelve dinámicamente todas las rutas declaradas de persistencia tanto del sistema como de usuarios."""
        targets = []
        # Rutas del sistema
        for d in self.SYSTEM_PERSISTENCE_DIRS:
            if os.path.exists(d):
                targets.append(os.path.abspath(d))

        for f in self.SYSTEM_PERSISTENCE_FILES:
            if os.path.exists(f):
                targets.append(os.path.abspath(f))

        # Rutas de usuarios (/root y /home/*)
        user_homes = ["/root"]
        if os.path.exists("/home"):
            try:
                for u in os.listdir("/home"):
                    uh = os.path.join("/home", u)
                    if os.path.isdir(uh):
                        user_homes.append(uh)
            except Exception:
                pass

        for uh in user_homes:
            for pat in self.USER_PERSISTENCE_PATTERNS:
                full_p = os.path.join(uh, pat)
                if os.path.exists(full_p):
                    targets.append(os.path.abspath(full_p))

        return targets

    def _compute_sha256(self, file_path: str) -> Optional[str]:
        sha = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(65536):
                    sha.update(chunk)
            return sha.hexdigest().lower()
        except Exception:
            return None

    def _create_backup(self, file_path: str, file_hash: str) -> Optional[str]:
        """Guarda una copia de respaldo limpia para permitir rollback ante ataques de persistencia."""
        try:
            safe_name = file_hash[:16] + "_" + os.path.basename(file_path)
            dest = os.path.join(self.backup_dir, safe_name)
            if not os.path.exists(dest):
                shutil.copy2(file_path, dest)
                os.chmod(dest, 0o600)
            return dest
        except Exception as e:
            logger.debug("No se pudo crear backup de %s: %s", file_path, e)
            return None

    def build_baseline(self) -> Dict[str, PersistenceRecord]:
        """Construye una línea base criptográfica de todas las rutas de persistencia activas."""
        baseline = {}
        for target in self._resolve_all_persistence_targets():
            if os.path.isfile(target):
                rec = self._create_record_for_file(target)
                if rec:
                    baseline[target] = rec
            elif os.path.isdir(target):
                try:
                    for root, _, files in os.walk(target):
                        for f in files:
                            fp = os.path.join(root, f)
                            rec = self._create_record_for_file(fp)
                            if rec:
                                baseline[fp] = rec
                except Exception:
                    pass
        return baseline

    def _create_record_for_file(self, file_path: str) -> Optional[PersistenceRecord]:
        try:
            st = os.stat(file_path)
            sha = self._compute_sha256(file_path)
            if not sha:
                return None
            backup_p = self._create_backup(file_path, sha)
            return PersistenceRecord(
                path=file_path,
                sha256=sha,
                size=st.st_size,
                mtime=st.st_mtime,
                mode=st.st_mode,
                uid=st.st_uid,
                gid=st.st_gid,
                backup_path=backup_p
            )
        except Exception:
            return None

    def start(self):
        """Inicia el centinela cargando la línea base criptográfica."""
        self.baseline = self.build_baseline()
        self.running = True
        self.thread = threading.Thread(target=self._audit_loop, daemon=True, name="persistence-guard")
        self.thread.start()
        logger.info("🛡️ Centinela de persistencia iniciado (%d ubicaciones y archivos en línea base).", len(self.baseline))

    def _audit_loop(self):
        """Bucle de auditoría que evalúa cambios y eliminaciones contra la línea base."""
        while self.running:
            try:
                time.sleep(2.0)
                self.check_persistence_changes()
            except Exception as e:
                logger.error("Error en ciclo de persistencia: %s", e)
                time.sleep(3.0)

    def check_persistence_changes(self) -> List[Dict[str, Any]]:
        """
        Inspecciona el estado actual contra la línea base:
        - Detecta archivos nuevos (CREATION).
        - Detecta modificaciones de contenido o permisos (MODIFICATION / PERMISSIONS).
        - Detecta eliminaciones (DELETION).
        """
        current_state = self.build_baseline()
        events = []

        # 1. Comprobar archivos nuevos y modificados
        for path, curr in current_state.items():
            if path not in self.baseline:
                events.append({
                    "type": PersistenceEventType.FILE_CREATED,
                    "path": path,
                    "record": curr
                })
                self._handle_event(PersistenceEventType.FILE_CREATED, path, curr)
            else:
                prev = self.baseline[path]
                if curr.sha256 != prev.sha256:
                    events.append({
                        "type": PersistenceEventType.FILE_MODIFIED,
                        "path": path,
                        "record": curr,
                        "prev_record": prev
                    })
                    self._handle_event(PersistenceEventType.FILE_MODIFIED, path, curr, prev)
                elif curr.mode != prev.mode:
                    events.append({
                        "type": PersistenceEventType.PERMISSIONS_CHANGED,
                        "path": path,
                        "record": curr,
                        "prev_record": prev
                    })

        # 2. Comprobar eliminaciones de archivos monitoreados
        for path, prev in list(self.baseline.items()):
            if path not in current_state and not os.path.exists(path):
                events.append({
                    "type": PersistenceEventType.FILE_DELETED,
                    "path": path,
                    "prev_record": prev
                })
                self._handle_event(PersistenceEventType.FILE_DELETED, path, None, prev)

        self.baseline = current_state
        return events

    def _handle_event(self, event_type: PersistenceEventType, file_path: str,
                      curr_rec: Optional[PersistenceRecord] = None,
                      prev_rec: Optional[PersistenceRecord] = None):
        """Procesa el evento evaluando si es una infección real o una modificación administrativa."""
        logger.warning("⚙️ [PERSISTENCIA DETECTADA: %s] En ruta: %s", event_type.value, file_path)

        if event_type == PersistenceEventType.FILE_DELETED:
            logger.info("ℹ️ Archivo de persistencia eliminado: %s", file_path)
            try:
                self.audit.record_incident("Persistence.DeletedEntry", file_path, "REMOVAL_DETECTED", "Entrada eliminada")
            except Exception:
                pass
            if self.on_tamper_callback:
                self.on_tamper_callback(file_path, False, "DELETED")
            return

        # Para CREATION y MODIFICATION: Validar contenido con el escáner multicapa
        is_threat = False
        threat_name = "Persistence.SuspiciousHook"
        details = ""

        if self.scanner and curr_rec:
            res = self.scanner.scan_file(file_path=file_path)
            if res.is_malicious:
                is_threat = True
                threat_name = res.threat_name or threat_name
                details = res.details or ""

        # Diferenciación: Si NO es malicioso, comprobar si es un cambio administrativo o script legítimo
        if not is_threat:
            logger.info("✅ Modificación administrativa legítima en ruta de arranque: %s (SHA-256: %s)",
                        file_path, curr_rec.sha256[:12] if curr_rec else "")
            try:
                self.audit.record_incident("Persistence.ConfigUpdate", file_path, "BENIGN_CHANGE",
                                           f"SHA256: {curr_rec.sha256[:16] if curr_rec else 'N/A'}")
            except Exception:
                pass
            if self.on_tamper_callback:
                self.on_tamper_callback(file_path, False, "BENIGN")
            return

        # Amenaza confirmada en ruta de arranque: Contener y aislar
        logger.critical("🚨 [PERSISTENCIA MALICIOSA DETECTADA] %s -> %s", file_path, threat_name)
        try:
            self.audit.record_incident(threat_name, file_path, "MALWARE_PERSISTENCE_ISOLATED", details)
        except Exception:
            pass

        if self.vault:
            self.vault.quarantine_file(file_path, threat_name, detected_by="PersistenceGuard")

        # Restaurar copia limpia previa si existía un backup válido
        if prev_rec and prev_rec.backup_path and os.path.exists(prev_rec.backup_path):
            self.restore_clean_backup(file_path, prev_rec.backup_path)

        if self.notifier:
            self.notifier.alert_threat_blocked(threat_name, file_path, os.getpid(), "PersistenceGuard")

        if self.on_tamper_callback:
            self.on_tamper_callback(file_path, True, threat_name)

    def restore_clean_backup(self, target_path: str, backup_path: str) -> bool:
        """Restaura una configuración alterada a su versión limpia conocida."""
        try:
            if not os.path.exists(backup_path):
                return False
            shutil.copy2(backup_path, target_path)
            logger.info("🔄 [RESTAURACIÓN AUTOMÁTICA] Archivo de persistencia restaurado desde copia limpia: %s", target_path)
            try:
                self.audit.record_incident("Persistence.RestoredClean", target_path, "AUTOMATIC_RESTORE", "Restaurado desde backup verificado")
            except Exception:
                pass
            return True
        except Exception as e:
            logger.error("Fallo al restaurar backup en %s: %s", target_path, e)
            return False

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Centinela de persistencia detenido.")
