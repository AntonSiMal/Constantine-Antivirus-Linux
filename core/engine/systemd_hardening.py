"""
Auditor y Verificador de Seguridad para Unidades systemd de Constantine Antivirus.
"""
import os
import logging
from typing import Dict, Any, List

logger = logging.getLogger("constantine.systemd_hardening")

class SystemdSecurityAuditor:
    """Audita las directivas de seguridad y aislamiento del archivo de servicio systemd."""

    def __init__(self, unit_path: str = "/etc/systemd/system/constantine.service"):
        self.unit_path = unit_path

    def _parse_unit(self) -> Dict[str, str]:
        """Extrae directivas clave de la unidad systemd."""
        directives = {}
        if not os.path.exists(self.unit_path):
            return directives

        with open(self.unit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, val = line.split("=", 1)
                    directives[key.strip()] = val.strip()
        return directives

    def evaluate_security_posture(self) -> Dict[str, Any]:
        """
        Evalúa el cumplimiento de directivas de hardening del servicio:
        - NoNewPrivileges
        - ProtectSystem=strict
        - ProtectHome=read-only (Verificando que no esté anulado por ReadWritePaths)
        - PrivateTmp=true
        - CapabilityBoundingSet delimitado (Sin CAP_DAC_OVERRIDE ni CAP_SYS_BOOT)
        - DevicePolicy=closed
        - SystemCallFilter restrictivo
        """
        directives = self._parse_unit()
        if not directives:
            return {
                "unit_found": False,
                "score": 0,
                "rating": "SERVICE_NOT_FOUND",
                "passed_checks": [],
                "missing_checks": ["Unit file not found"]
            }

        passed_checks: List[str] = []
        missing_checks: List[str] = []

        # 1. NoNewPrivileges
        if directives.get("NoNewPrivileges", "").lower() in ("true", "yes", "1"):
            passed_checks.append("NoNewPrivileges")
        else:
            missing_checks.append("NoNewPrivileges")

        # 2. ProtectSystem
        if directives.get("ProtectSystem", "").lower() in ("strict", "full", "true"):
            passed_checks.append("ProtectSystem")
        else:
            missing_checks.append("ProtectSystem")

        # 3. ProtectHome
        if directives.get("ProtectHome", "").lower() in ("read-only", "true", "yes", "tmpfs"):
            rw_paths = directives.get("ReadWritePaths", "").split()
            if any(p == "/home" or p.startswith("/home/") for p in rw_paths):
                missing_checks.append("ProtectHome (Anulado por /home en ReadWritePaths)")
            else:
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
        if caps and "CAP_SYS_ADMIN" in caps and "CAP_SYS_BOOT" not in caps and "CAP_DAC_OVERRIDE" not in caps:
            passed_checks.append("CapabilityBoundingSet")
        else:
            missing_checks.append("CapabilityBoundingSet")

        # 6. DevicePolicy
        if directives.get("DevicePolicy", "").lower() == "closed":
            passed_checks.append("DevicePolicy")
        else:
            missing_checks.append("DevicePolicy")

        # 7. SystemCallFilter
        if "@system-service" in directives.get("SystemCallFilter", ""):
            passed_checks.append("SystemCallFilter")
        else:
            missing_checks.append("SystemCallFilter")

        # 8. SystemCallArchitectures
        if "native" in directives.get("SystemCallArchitectures", "").lower():
            passed_checks.append("SystemCallArchitectures")
        else:
            missing_checks.append("SystemCallArchitectures")

        # 9. RestrictSUIDSGID
        if directives.get("RestrictSUIDSGID", "").lower() in ("true", "yes", "1"):
            passed_checks.append("RestrictSUIDSGID")

        # 10. ProtectKernelTunables
        if directives.get("ProtectKernelTunables", "").lower() in ("true", "yes", "1"):
            passed_checks.append("ProtectKernelTunables")

        score = min(100, int((len(passed_checks) / 8.0) * 100))
        rating = "HARDENED_EXCELLENT" if score >= 90 else ("MODERATE" if score >= 70 else "INSECURE")

        return {
            "unit_found": True,
            "score": score,
            "rating": rating,
            "passed_checks": passed_checks,
            "missing_checks": missing_checks,
            "directives_count": len(directives)
        }
