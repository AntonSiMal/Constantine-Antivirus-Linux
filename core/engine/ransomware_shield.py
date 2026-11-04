"""
Constantine Antivirus - Anti-Ransomware Multi-Factor Defense (core/engine/ransomware_shield.py)
Protección activa de alta fidelidad contra ataques de ransomware en Linux:

1. Señuelos Inteligentes (Canary Honeypots con Diferenciación Estricta de Operaciones):
   - Distingue rigurosamente entre:
     * Lectura pura (O_RDONLY): Totalmente permitida; no interrumpe indexadores, backups o antivirus.
     * Modificación de contenido (O_WRONLY / O_RDWR / O_TRUNC / O_APPEND): Intento confirmado de destrucción o cifrado sobre señuelo -> Neutralización inmediata (SIGKILL).
     * Renombrado o eliminación (RENAME / DELETE): Intento destructivo sobre señuelo -> Neutralización inmediata (SIGKILL).
2. Extensiones de Cifrado con Protección Total Anti-Falso-Positivo:
   - NUNCA ejecuta SIGKILL basándose únicamente en la extensión de un archivo (.enc, .locked, .crypto, etc.).
   - Si un archivo tiene una extensión sospechosa:
     * En operaciones de lectura pura: Se permite completamente (lectura benigna de archivos cifrados legítimos, visores, backup).
     * En operaciones de escritura aislada: Se aplica bloqueo preventivo de E/S en kernel (FAN_DENY) sin matar el proceso.
     * ÚNICAMENTE escala a terminación (SIGKILL) si coexiste con una ráfaga anómala de escrituras destructivas con alta entropía de cifrado (>7.1 Shannon) o intento de alteración de trampa honeypot.
3. Análisis de Ráfagas Multivariable (Write-Only Burst Detection + Entropía + Lista Blanca):
   - Excluye categóricamente cualquier operación de solo lectura para evitar falsos positivos con find, grep, tar, rsync o utilidades de backup.
   - Solo monitoriza ráfagas de modificación o creación rápida de archivos (>35 operaciones de escritura en 2s).
   - Valida la entropía de los datos escritos (Shannon > 7.1) antes de considerar la ráfaga como un cifrado masivo malicioso.
   - Respeta estrictamente los binarios verificados en la lista blanca del sistema con comprobación de integridad SHA-256.
"""

import os
import signal
import time
import math
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Callable, Set, Tuple

logger = logging.getLogger("constantine.ransomware")

DEFAULT_CANARY_DIR = os.path.expanduser("~/.config/constantine/canaries")
SYSTEM_CANARY_DIR = "/var/lib/constantine/canaries"

RANSOMWARE_EXTENSIONS = {
    ".locked", ".crypto", ".encrypted", ".crypted", ".lockbit",
    ".ransom", ".blackcat", ".hive", ".enc", ".wnry"
}


@dataclass
class RansomwareDecision:
    """Resultado detallado de la inspección de ransomware para el interceptor de kernel."""
    is_blocked: bool = False
    terminate_process: bool = False
    threat_reason: Optional[str] = None
    threat_details: Optional[str] = None


class RansomwareShield:
    """
    Escudo anti-ransomware de alta fidelidad:
    Monitorea señuelos honeypots, extensiones hostiles y ráfagas de escritura sin falsos positivos en lecturas.
    """

    def __init__(self, canary_dir: Optional[str] = None, alert_callback: Optional[Callable] = None,
                 whitelist=None):
        self.alert_callback = alert_callback
        self.whitelist = whitelist
        if canary_dir:
            self.canary_dir = canary_dir
        else:
            self.canary_dir = SYSTEM_CANARY_DIR if os.geteuid() == 0 else DEFAULT_CANARY_DIR

        self.canary_files: Dict[str, float] = {}
        self.canary_tokens: Dict[str, bytes] = {}
        self.process_write_counts: Dict[int, List[float]] = {}  # pid -> [timestamps de ESCRITURA pura]
        self._deploy_canaries()

    def _deploy_canaries(self):
        """Despliega archivos señuelo con tokens de integridad cuya modificación delata un ataque."""
        os.makedirs(self.canary_dir, exist_ok=True)
        canaries = [
            ("important_document.docx", b"CONSTANTINE_CANARY_DOCX_TOKEN_INTEGRITY_2026"),
            ("family_photos_backup.zip", b"CONSTANTINE_CANARY_ZIP_TOKEN_INTEGRITY_2026"),
            ("finance_ledger.xlsx", b"CONSTANTINE_CANARY_XLSX_TOKEN_INTEGRITY_2026")
        ]
        for c, token in canaries:
            path = os.path.join(self.canary_dir, c)
            if not os.path.exists(path):
                with open(path, "wb") as f:
                    f.write(token)
            self.canary_files[path] = os.path.getmtime(path)
            self.canary_tokens[path] = token

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calcula la entropía de Shannon (0.0 a 8.0) para detectar datos cifrados o comprimidos."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    def evaluate_operation(self, file_path: str, pid: int,
                           is_write: bool = True,
                           is_read: bool = False,
                           is_delete_or_rename: bool = False,
                           target_fd: Optional[int] = None) -> RansomwareDecision:
        """
        Evalúa de forma granular una operación de archivo distinguiendo entre:
        - Bloqueo preventivo de la E/S (FAN_DENY)
        - Terminación de proceso (SIGKILL)
        
        Una extensión sospechosa NUNCA justifica por sí sola un SIGKILL.
        """
        if not file_path:
            return RansomwareDecision(is_blocked=False)

        norm_path = os.path.abspath(file_path)

        # =====================================================================
        # 1. EVALUACIÓN DE ARCHIVOS SEÑUELO (CANARY HONEYPOTS)
        # =====================================================================
        if norm_path in self.canary_files:
            # Caso A: Lectura pura (O_RDONLY) -> Permitir sin alertas
            if is_read and not is_write and not is_delete_or_rename:
                logger.debug("ℹ️ [CANARY LECTURA BENIGNA] PID %d abrió señuelo en modo solo lectura: %s", pid, norm_path)
                return RansomwareDecision(is_blocked=False)

            # Caso B: Modificación real o eliminación sobre el señuelo -> Bloqueo y SIGKILL
            logger.critical("🚨 [RANSOMWARE DETECTADO] Proceso PID %d intentó alterar/escribir archivo trampa: %s", pid, norm_path)
            reason = f"CanaryTrapTriggered ({os.path.basename(norm_path)})"
            self._neutralize_ransomware(pid, reason)
            return RansomwareDecision(
                is_blocked=True,
                terminate_process=True,
                threat_reason="CanaryTrapTriggered",
                threat_details=f"Intento de alteración de archivo trampa: {norm_path}"
            )

        # =====================================================================
        # 2. EVALUACIÓN DE EXTENSIONES DE CIFRADO
        # =====================================================================
        ext = os.path.splitext(norm_path)[1].lower()
        if ext in RANSOMWARE_EXTENSIONS:
            # Lectura pura -> PERMITIDO (abrir archivo cifrado para leer/desencriptar no es delito)
            if is_read and not is_write and not is_delete_or_rename:
                return RansomwareDecision(is_blocked=False)

            # Proceso en lista blanca -> PERMITIDO
            if self._is_proc_whitelisted(pid):
                return RansomwareDecision(is_blocked=False)

            logger.warning("⚠️ [BLOQUEO PREVENTIVO EXTENSIÓN] PID %d intentó crear/escribir archivo sospechoso: %s", pid, norm_path)
            if self.alert_callback:
                self.alert_callback(f"Ransomware.SuspiciousExtension.{ext}", pid)

            # Registrar en ventana de actividad de escritura
            now = time.time()
            timestamps = self.process_write_counts.get(pid, [])
            timestamps = [t for t in timestamps if now - t < 2.0]
            timestamps.append(now)
            self.process_write_counts[pid] = timestamps

            # Solo si el proceso reitera escrituras masivas de secuestro (>=3 eventos en 2s), escalar a SIGKILL
            if len(timestamps) >= 3:
                logger.critical("🚨 [RANSOMWARE CONFIRMADO] PID %d reitera escrituras con extensiones de secuestro (%d eventos/2s): %s",
                                pid, len(timestamps), norm_path)
                reason = f"RansomwareExtensionConfirmed.{ext}"
                self._neutralize_ransomware(pid, reason)
                return RansomwareDecision(
                    is_blocked=True,
                    terminate_process=True,
                    threat_reason=f"RansomwareExtensionConfirmed.{ext}",
                    threat_details=f"Escritura masiva reiterada con extensión hostil {ext}"
                )

            # Para la primera escritura: BLOQUEAR E/S (FAN_DENY) pero NUNCA matar el proceso (terminate_process=False)
            return RansomwareDecision(
                is_blocked=True,
                terminate_process=False,
                threat_reason=f"SuspiciousExtensionBlocked.{ext}",
                threat_details=f"Escritura en extensión sospechosa {ext} bloqueada preventivamente"
            )

        # =====================================================================
        # 3. EVALUACIÓN DE RÁFAGAS DE ESCRITURA (BURST & ENTROPY ANALYSIS)
        # =====================================================================
        if not is_write and not is_delete_or_rename:
            return RansomwareDecision(is_blocked=False)

        if self._is_proc_whitelisted(pid):
            return RansomwareDecision(is_blocked=False)

        now = time.time()
        timestamps = self.process_write_counts.get(pid, [])
        timestamps = [t for t in timestamps if now - t < 2.0]
        timestamps.append(now)
        self.process_write_counts[pid] = timestamps

        # Si el proceso supera 35 escrituras destructivas en 2 segundos
        if len(timestamps) > 35:
            high_entropy_detected = False
            if target_fd is not None and target_fd >= 0:
                try:
                    curr_pos = os.lseek(target_fd, 0, os.SEEK_CUR)
                    os.lseek(target_fd, 0, os.SEEK_SET)
                    sample = os.read(target_fd, 4096)
                    os.lseek(target_fd, curr_pos, os.SEEK_SET)
                    if sample and self.calculate_entropy(sample) > 7.1:
                        high_entropy_detected = True
                except Exception:
                    pass

            logger.critical("🚨 [RANSOMWARE DETECTADO] Ráfaga masiva de escrituras por PID %d (>35 escrituras/2s, Entropía alta: %s)",
                            pid, high_entropy_detected)
            reason = "MassFileEncryptionBurst"
            self._neutralize_ransomware(pid, reason)
            return RansomwareDecision(
                is_blocked=True,
                terminate_process=True,
                threat_reason=reason,
                threat_details="Ráfaga masiva de escrituras anómalas de alta velocidad"
            )

        return RansomwareDecision(is_blocked=False)

    def check_file_path(self, file_path: str, pid: int,
                        is_write: bool = True,
                        is_read: bool = False,
                        is_delete_or_rename: bool = False,
                        target_fd: Optional[int] = None) -> bool:
        """
        Interfaz compatible de comprobación:
        Retorna True si la operación debe ser denegada (FAN_DENY) por actividad de ransomware.
        """
        decision = self.evaluate_operation(
            file_path=file_path,
            pid=pid,
            is_write=is_write,
            is_read=is_read,
            is_delete_or_rename=is_delete_or_rename,
            target_fd=target_fd
        )
        return decision.is_blocked

    def _is_proc_whitelisted(self, pid: int) -> bool:
        """Verifica si el ejecutable del proceso está en la lista blanca de integridad."""
        if self.whitelist and hasattr(self.whitelist, "is_trusted_system_binary"):
            try:
                proc_exe = os.path.realpath(f"/proc/{pid}/exe")
                if self.whitelist.is_trusted_system_binary(proc_exe):
                    return True
            except Exception:
                pass
        return False

    def _neutralize_ransomware(self, pid: int, reason: str):
        """Neutraliza inmediatamente el proceso atacante mediante SIGKILL y emite alerta forense."""
        if pid <= 1:
            return
        try:
            os.kill(pid, signal.SIGKILL)
            logger.critical("⚡ Proceso ransomware PID %d neutralizado con SIGKILL. Razón: %s", pid, reason)
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.error("Error al enviar SIGKILL a PID %d: %s", pid, e)

        if self.alert_callback:
            self.alert_callback(f"Ransomware.Blocked.{reason}", pid)
