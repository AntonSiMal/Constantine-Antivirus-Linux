"""
Constantine Antivirus - systemd Service Security & Hardening Auditor (core/engine/systemd_hardening.py)
Aprovecha las características nativas de seguridad y aislamiento de systemd (https://github.com/systemd/systemd):
1. NoNewPrivileges=true:
   - Impide que el servicio o sus procesos hijos ganen privilegios adicionales mediante binarios SUID/SGID.
2. ProtectSystem=strict:
   - Monta toda la jerarquía de archivos (/usr, /boot, /etc) en modo de solo lectura estricto.
   - Solo permite escritura en rutas explícitamente declaradas con ReadWritePaths=.
3. ProtectHome=read-only:
   - Restringe el acceso a directorios de usuario (/home, /root) protegiéndolos contra modificaciones no autorizadas.
4. PrivateTmp=true:
   - Aísla /tmp y /var/tmp en un espacio de nombres privado e inaccesible para otros servicios o atacantes.
5. CapabilityBoundingSet & AmbientCapabilities:
   - Reduce las capacidades del kernel de Linux al mínimo indispensable para operar (fanotify, eBPF, firewall),
     eliminando CAP_SYS_BOOT, CAP_SYS_MODULE, CAP_SYS_RAWIO, CAP_MKNOD, etc.
6. Restricciones de Dispositivos (DevicePolicy=closed):
   - Niega el acceso a dispositivos de hardware físicos excepto los declarados explícitamente con DeviceAllow=.
7. Restricciones de Llamadas al Sistema (SystemCallFilter & SystemCallArchitectures):
   - Bloquea syscalls peligrosas o no pertinentes (@system-service, @file-system, bpf, fanotify).
   - Bloquea arquitecturas de syscall no nativas (prevención de ataques de emulación de 32 bits).
"""

import os
import re
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("constantine.systemd_hardening")

MANDATORY_HARDENING_DIRECTIVES = [
    "NoNewPrivileges",
    "ProtectSystem",
    "ProtectHome",
    "PrivateTmp",
    "CapabilityBoundingSet",
    "DevicePolicy",
    "SystemCallFilter",
    "SystemCallArchitectures",
    "ProtectKernelTunables",
    "ProtectKernelModules",
    "ProtectControlGroups",
    "RestrictRealtime",
    "RestrictSUIDSGID",
    "LockPersonality",
    "RestrictAddressFamilies"
]

CANDIDATE_UNIT_PATHS = [
    "/etc/systemd/system/constantine.service",
    "/opt/constantine/service/constantine.service",
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "service", "constantine.service")
]


class SystemdSecurityAuditor:
    """Auditor y validador de directivas de seguridad de systemd para el servicio constantine.service."""

    def __init__(self, unit_path: Optional[str] = None):
        self.unit_path = unit_path or self._discover_unit_path()

    def _discover_unit_path(self) -> Optional[str]:
        for p in CANDIDATE_UNIT_PATHS:
            if p and os.path.isfile(p):
                return p
        return None

    def parse_service_directives(self) -> Dict[str, str]:
        """Parsea las directivas de configuración dentro de la sección [Service]."""
        if not self.unit_path or not os.path.isfile(self.unit_path):
            return {}

        directives = {}
        in_service_section = False
        try:
            with open(self.unit_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith(";"):
                        continue
                    if line.startswith("["):
                        in_service_section = (line.lower() == "[service]")
                        continue
                    if in_service_section and "=" in line:
                        key, val = line.split("=", 1)
                        directives[key.strip()] = val.strip()
        except Exception as e:
            logger.debug("Error leyendo archivo de servicio systemd %s: %s", self.unit_path, e)

        return directives

    def evaluate_security_posture(self) -> Dict[str, Any]:
        """
        Evalúa la postura de seguridad y el cumplimiento de las recomendaciones oficiales de systemd.
        Retorna puntaje de cumplimiento (0-100), directivas activas y evaluación de riesgo.
        """
        directives = self.parse_service_directives()
        if not directives:
            return {
                "unit_found": False,
                "score": 0,
                "rating": "SERVICE_NOT_FOUND",
                "missing_directives": MANDATORY_HARDENING_DIRECTIVES,
                "active_directives": {}
            }

        passed_checks = []
        missing_checks = []

        # 1. NoNewPrivileges
        if directives.get("NoNewPrivileges", "").lower() in ("true", "yes", "1"):
            passed_checks.append("NoNewPrivileges")
        else:
            missing_checks.append("NoNewPrivileges")

        # 2. ProtectSystem
        if directives.get("ProtectSystem", "").lower() in ("strict", "full", "yes", "true"):
            passed_checks.append("ProtectSystem")
        else:
            missing_checks.append("ProtectSystem")

        # 3. ProtectHome
        if directives.get("ProtectHome", "").lower() in ("read-only", "true", "yes", "tmpfs"):
            passed_checks.append("ProtectHome")
        else:
            missing_checks.append("ProtectHome")

        # 4. PrivateTmp
        if directives.get("PrivateTmp", "").lower() in ("true", "yes", "1"):
            passed_checks.append("PrivateTmp")
        else:
            missing_checks.append("PrivateTmp")

        # 5. CapabilityBoundingSet
        caps = directives.get("CapabilityBoundingSet", "")
        if caps and "CAP_SYS_ADMIN" in caps and "CAP_SYS_BOOT" not in caps:
            passed_checks.append("CapabilityBoundingSet")
        else:
            missing_checks.append("CapabilityBoundingSet")

        # 6. DevicePolicy
        if directives.get("DevicePolicy", "").lower() in ("closed", "strict"):
            passed_checks.append("DevicePolicy")
        else:
            missing_checks.append("DevicePolicy")

        # 7. SystemCallFilter
        if "@system-service" in directives.get("SystemCallFilter", "") or "fanotify" in directives.get("SystemCallFilter", ""):
            passed_checks.append("SystemCallFilter")
        else:
            missing_checks.append("SystemCallFilter")

        # 8. SystemCallArchitectures
        if directives.get("SystemCallArchitectures", "").lower() == "native":
            passed_checks.append("SystemCallArchitectures")
        else:
            missing_checks.append("SystemCallArchitectures")

        # 9. ProtectKernelTunables & Modules & ControlGroups
        for k in ["ProtectKernelTunables", "ProtectKernelModules", "ProtectControlGroups", "RestrictRealtime", "RestrictSUIDSGID", "LockPersonality", "RestrictAddressFamilies"]:
            if k in directives and directives[k].lower() not in ("false", "no", "0"):
                passed_checks.append(k)
            else:
                missing_checks.append(k)

        total_checks = len(MANDATORY_HARDENING_DIRECTIVES)
        score = int((len(passed_checks) / total_checks) * 100)

        rating = "HARDENED_EXCELLENT" if score >= 90 else ("HARDENED_GOOD" if score >= 70 else "NEEDS_IMPROVEMENT")

        return {
            "unit_found": True,
            "unit_path": self.unit_path,
            "score": score,
            "rating": rating,
            "passed_checks": passed_checks,
            "missing_directives": missing_checks,
            "read_write_paths": directives.get("ReadWritePaths", "").split(),
            "details": f"Postura de seguridad systemd: {len(passed_checks)}/{total_checks} directivas activas (Puntaje: {score}/100)"
        }
