"""
Gestor de Resiliencia, Tolerancia a Fallos y Modo de Mantenimiento para Constantine Antivirus.
Garantiza que el usuario siempre pueda utilizar su computadora incluso ante problemas internos:
1. Protección contra bloqueos de operaciones de archivos (Emergency Circuit Breaker).
2. Modo de mantenimiento con bypass seguro de intercepciones.
3. Desactivación segura y aislada de módulos defectuosos (Safe Module Quarantine).
4. Recuperación automática mediante rollback ante fallos en actualización de firmas.
"""
import os
import time
import json
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("constantine.resilience")

DEFAULT_SNAPSHOT_PATH = "/var/lib/constantine/backups/signatures_snapshot.json"
FALLBACK_SNAPSHOT_PATH = "/tmp/constantine_signatures_snapshot.json"


class ResilienceManager:
    """
    Controlador central de resiliencia y recuperación ante fallos del antivirus.
    Evita la congelación del sistema de archivos y aísla componentes inestables.
    """

    def __init__(self, snapshot_dir: Optional[str] = None):
        self._lock = threading.Lock()
        self.maintenance_mode = False
        self.maintenance_reason = ""
        self.maintenance_activated_at = 0.0

        # Disyuntor de emergencia para operaciones de archivos (fanotify)
        self.consecutive_scan_timeouts = 0
        self.max_consecutive_timeouts = 3
        self.emergency_bypass_active = False
        self.emergency_bypass_activated_at = 0.0

        # Aislamiento seguro de módulos defectuosos
        self.module_failures: Dict[str, List[Dict[str, Any]]] = {}
        self.isolated_modules: Dict[str, Dict[str, Any]] = {}
        self.failure_threshold = 3

        # Directorio de snapshots de firmas para rollback
        self.snapshot_path = os.path.join(snapshot_dir, "signatures_snapshot.json") if snapshot_dir else DEFAULT_SNAPSHOT_PATH
        if not os.path.exists(os.path.dirname(self.snapshot_path)):
            try:
                os.makedirs(os.path.dirname(self.snapshot_path), exist_ok=True)
            except OSError:
                self.snapshot_path = FALLBACK_SNAPSHOT_PATH

    # =========================================================================
    # 1. MODO DE MANTENIMIENTO
    # =========================================================================
    def enable_maintenance_mode(self, reason: str = "Mantenimiento preventivo por usuario") -> Dict[str, Any]:
        """
        Activa el modo de mantenimiento.
        Suspende las intercepciones activas permitiendo todas las operaciones de archivos (FAN_ALLOW).
        """
        with self._lock:
            self.maintenance_mode = True
            self.maintenance_reason = reason
            self.maintenance_activated_at = time.time()
            logger.warning("🛠️ [MODO DE MANTENIMIENTO ACTIVADO] Intercepciones suspendidas. Motivo: %s", reason)
            return {
                "maintenance_mode": True,
                "reason": reason,
                "activated_at": self.maintenance_activated_at
            }

    def disable_maintenance_mode(self) -> Dict[str, Any]:
        """Desactiva el modo de mantenimiento y reanuda la protección activa."""
        with self._lock:
            self.maintenance_mode = False
            self.maintenance_reason = ""
            logger.info("🛡️ [MODO DE MANTENIMIENTO DESACTIVADO] Protección activa reanudada normalmente.")
            return {
                "maintenance_mode": False
            }

    def is_maintenance_mode_active(self) -> bool:
        """Indica si el sistema se encuentra en modo de mantenimiento."""
        with self._lock:
            return self.maintenance_mode

    # =========================================================================
    # 2. PROTECCIÓN CONTRA BLOQUEOS DE ARCHIVOS (Circuit Breaker)
    # =========================================================================
    def record_scan_timeout(self, file_path: str = ""):
        """Registra un timeout en el análisis de archivo y activa bypass de emergencia si supera el umbral."""
        with self._lock:
            self.consecutive_scan_timeouts += 1
            logger.warning("⏱️ [TIMEOUT DE ESCANEO] Operación demorada en '%s'. Consecutivos: %d/%d",
                           file_path, self.consecutive_scan_timeouts, self.max_consecutive_timeouts)
            if self.consecutive_scan_timeouts >= self.max_consecutive_timeouts:
                self.emergency_bypass_active = True
                self.emergency_bypass_activated_at = time.time()
                logger.critical("🚨 [DISYUNTOR DE EMERGENCIA ACTIVADO] Interceptor fanotify conmutado a bypass inmediato. "
                                "Se evita congelar las operaciones de archivos del usuario.")

    def record_scan_success(self):
        """Reinicia el contador de timeouts consecutivos tras un análisis exitoso."""
        with self._lock:
            if self.consecutive_scan_timeouts > 0 and not self.emergency_bypass_active:
                self.consecutive_scan_timeouts = 0

    def is_file_access_permitted_fast(self) -> bool:
        """
        Comprobación ultra-rápida no bloqueante:
        Devuelve True si se debe permitir el archivo de inmediato sin escaneo
        (debido a modo de mantenimiento o disyuntor de emergencia activo).
        """
        with self._lock:
            return self.maintenance_mode or self.emergency_bypass_active

    def reset_emergency_bypass(self):
        """Restablece el disyuntor de emergencia tras verificar la estabilidad del motor."""
        with self._lock:
            self.consecutive_scan_timeouts = 0
            self.emergency_bypass_active = False
            logger.info("✅ Disyuntor de emergencia restablecido. Intercepción normal reactivada.")

    # =========================================================================
    # 3. DESACTIVACIÓN SEGURA DE MÓDULOS DEFECTUOSOS (Safe Module Quarantine)
    # =========================================================================
    def record_module_failure(self, module_name: str, error_msg: str) -> bool:
        """
        Registra una falla o excepción en un subsistema.
        Si alcanza el umbral de 3 fallos consecutivos, aísla de forma segura
        únicamente dicho módulo defectuoso para no afectar al resto del sistema.
        Devuelve True si el módulo acaba de ser aislado.
        """
        with self._lock:
            if module_name not in self.module_failures:
                self.module_failures[module_name] = []

            self.module_failures[module_name].append({
                "timestamp": time.time(),
                "error": str(error_msg)
            })

            fail_count = len(self.module_failures[module_name])
            logger.warning("⚠️ [FALLA DE SUBSISTEMA] Módulo '%s' falló (%d/%d): %s",
                           module_name, fail_count, self.failure_threshold, error_msg)

            if fail_count >= self.failure_threshold and module_name not in self.isolated_modules:
                self.isolated_modules[module_name] = {
                    "isolated_at": time.time(),
                    "reason": f"Alcanzó {fail_count} fallos consecutivos: {error_msg}"
                }
                logger.critical("🛑 [MÓDULO DEFECTUOSO AISLADO] Módulo '%s' puesto en cuarentena operativa segura. "
                                "El resto del antivirus continúa funcionando con normalidad.", module_name)
                return True
            return False

    def is_module_isolated(self, module_name: str) -> bool:
        """Verifica si un módulo ha sido aislado por el gestor de resiliencia."""
        with self._lock:
            return module_name in self.isolated_modules

    def reset_module_fault(self, module_name: str) -> bool:
        """Restablece el estado de un módulo previamente aislado permitiendo reintentar su ejecución."""
        with self._lock:
            if module_name in self.isolated_modules:
                del self.isolated_modules[module_name]
            if module_name in self.module_failures:
                self.module_failures[module_name] = []
            logger.info("🔄 Módulo '%s' restablecido de su aislamiento operativo.", module_name)
            return True

    # =========================================================================
    # 4. RECUPERACIÓN TRAS ACTUALIZACIÓN FALLIDA (Auto-Rollback)
    # =========================================================================
    def create_signature_snapshot(self, rules_metadata: Dict[str, Any]) -> bool:
        """
        Guarda un snapshot de respaldo de las firmas y reglas que funcionan correctamente
        antes de aplicar cualquier actualización.
        """
        try:
            snapshot = {
                "created_at": time.time(),
                "metadata": rules_metadata
            }
            with open(self.snapshot_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f)
            logger.info("💾 Snapshot de firmas funcionales guardado en: %s", self.snapshot_path)
            return True
        except Exception as e:
            logger.error("Error guardando snapshot de firmas: %s", e)
            return False

    def rollback_to_snapshot(self) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
        """
        Restaura el snapshot anterior ante un fallo de compilación o corrupción en la actualización.
        """
        if not os.path.exists(self.snapshot_path):
            return False, "No existe snapshot previo de firmas para rollback", None

        try:
            with open(self.snapshot_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
            logger.warning("🔄 [ROLLBACK AUTOMÁTICO DE FIRMAS] Restaurando firmas desde snapshot previo creado en %s",
                           time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(snapshot.get("created_at", 0))))
            return True, "Rollback ejecutado exitosamente tras fallo de actualización", snapshot.get("metadata")
        except Exception as e:
            logger.critical("Error restaurando snapshot de firmas: %s", e)
            return False, f"Fallo al restaurar snapshot: {e}", None

    # =========================================================================
    # 5. ESTADO INTEGRAL DE RESILIENCIA
    # =========================================================================
    def get_resilience_status(self) -> Dict[str, Any]:
        """Retorna el diagnóstico completo de resiliencia y salud de componentes."""
        with self._lock:
            return {
                "maintenance_mode": self.maintenance_mode,
                "maintenance_reason": self.maintenance_reason,
                "emergency_bypass_active": self.emergency_bypass_active,
                "consecutive_timeouts": self.consecutive_scan_timeouts,
                "isolated_modules": dict(self.isolated_modules),
                "isolated_count": len(self.isolated_modules),
                "snapshot_available": os.path.exists(self.snapshot_path)
            }
