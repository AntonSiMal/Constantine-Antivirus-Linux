"""
Constantine Antivirus - Memory RAM Scanner (core/engine/memory_scanner.py)
Auditoría e inspección de procesos en ejecución y memoria RAM:
1. Inspecciona ejecutables de procesos en /proc/<pid>/exe.
2. Detecta binarios eliminados que siguen corriendo en RAM (técnica típica de malware: binary deleted on disk).
3. Inspecciona regiones de memoria en /proc/<pid>/maps buscando permisos anómalos RWX (Read-Write-Execute).
4. Analiza procesos contra firmas YARA y hashes de MalwareBazaar.
"""

import os
import logging
from typing import Dict, List, Optional, Callable

logger = logging.getLogger("constantine.ram")

class MemoryScanner:
    def __init__(self, scanner=None, vault=None):
        self.scanner = scanner
        self.vault = vault

    def get_running_pids(self) -> List[int]:
        pids = []
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    pids.append(int(entry))
                except Exception:
                    pass
        return sorted(pids)

    def scan_ram(self, progress_callback: Optional[Callable] = None, abort_check: Optional[Callable] = None) -> Dict:
        """
        Escanea la memoria RAM auditando todos los procesos activos en /proc.
        Optimizado para rendimiento ultrarrápido con caché de binarios repetidos.
        """
        pids = self.get_running_pids()
        total = len(pids)
        threats_found = []
        scanned_count = 0
        scanned_binaries_cache: Dict[str, Dict] = {}

        for pid in pids:
            if abort_check and abort_check():
                break
            scanned_count += 1
            proc_name = "proceso"
            try:
                comm_path = f"/proc/{pid}/comm"
                if os.path.exists(comm_path):
                    with open(comm_path, "r") as f:
                        proc_name = f.read().strip()
            except Exception:
                pass

            # Excluir procesos propios de Constantine y procesos del kernel
            if pid <= 2 or "constantine" in proc_name.lower() or proc_name in ("python3", "python"):
                cmdline = ""
                try:
                    with open(f"/proc/{pid}/cmdline", "r") as f:
                        cmdline = f.read().lower()
                except Exception:
                    pass
                if "constantine" in cmdline:
                    continue

            is_malicious = False
            reason = ""

            # 1. Comprobar ejecutable en disco
            exe_link = f"/proc/{pid}/exe"
            try:
                if os.path.exists(exe_link):
                    target = os.readlink(exe_link)
                    # Autoprotección: no analizar ejecutables propios de Constantine
                    if "constantine" in target.lower() or "/opt/constantine" in target.lower():
                        continue
                    if " (deleted)" in target:
                        # Excluir binarios oficiales de actualización de paquetes
                        if not target.startswith("/usr/") and not target.startswith("/var/lib/flatpak"):
                            is_malicious = True
                            reason = f"Ejecutable borrado en disco pero activo en RAM ({target})"
                    elif self.scanner and os.path.isfile(target):
                        if target in scanned_binaries_cache:
                            cached = scanned_binaries_cache[target]
                            if cached.get("is_malicious"):
                                is_malicious = True
                                reason = cached.get("reason", "Malware en RAM")
                        else:
                            res = self.scanner.scan_file(file_path=target)
                            is_m = res.is_malicious
                            r_text = res.threat_name or "Malware en RAM"
                            scanned_binaries_cache[target] = {"is_malicious": is_m, "reason": r_text}
                            if is_m:
                                is_malicious = True
                                reason = r_text
            except Exception:
                pass

            # 2. Comprobar mapas de memoria buscando segmentos RWX sospechosos
            if not is_malicious:
                maps_path = f"/proc/{pid}/maps"
                try:
                    if os.path.exists(maps_path):
                        with open(maps_path, "r") as f:
                            lines_checked = 0
                            for line in f:
                                lines_checked += 1
                                if lines_checked > 200: # Límite de seguridad para evitar bloqueos
                                    break
                                parts = line.split()
                                if len(parts) >= 2:
                                    perms = parts[1]
                                    # Permiso rwxp en segmento anónimo suele delatar inyección de shellcode
                                    if perms.startswith("rwx") and len(parts) < 6:
                                        is_malicious = True
                                        reason = "Inyección de memoria detectada (Segmento RWX anónimo)"
                                        break
                except Exception:
                    pass

            if is_malicious:
                threats_found.append({
                    "pid": pid,
                    "comm": proc_name,
                    "reason": reason
                })

            if progress_callback:
                last_thr = threats_found[-1] if is_malicious else None
                progress_callback(pid, proc_name, scanned_count, total, len(threats_found), last_thr)

        return {
            "total_pids": total,
            "scanned": scanned_count,
            "threats_count": len(threats_found),
            "threats": threats_found
        }
