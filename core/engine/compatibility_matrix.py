"""
Matriz Oficial de Compatibilidad de Sistemas Operativos y Kernels para Constantine Antivirus.
Evalúa con precisión las capacidades del kernel y la distribución en ejecución,
clasificando el entorno en niveles oficiales (Tiers) de soporte.
"""
import os
import re
import sys
import logging
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger("constantine.compatibility")

TIER_1_OPTIMAL = "TIER_1_FULL_SUPPORT"
TIER_2_DEGRADED = "TIER_2_DEGRADED_FALLBACK"
TIER_3_UNSUPPORTED = "TIER_3_UNSUPPORTED"

# Matriz Oficial de Distribuciones Homologadas
OFFICIAL_DISTROS_TIER_1 = {
    "ubuntu": ["22.04", "24.04"],
    "debian": ["12"],
    "fedora": ["38", "39", "40"],
    "rhel": ["9.0", "9.1", "9.2", "9.3", "9.4"],
    "rocky": ["9.0", "9.1", "9.2", "9.3", "9.4"],
    "almalinux": ["9.0", "9.1", "9.2", "9.3", "9.4"],
    "arch": ["rolling"],
    "opensuse-tumbleweed": ["rolling"],
    "opensuse-leap": ["15.5", "15.6"]
}

OFFICIAL_DISTROS_TIER_2 = {
    "ubuntu": ["20.04"],
    "debian": ["11"],
    "rhel": ["8.6", "8.7", "8.8", "8.9"],
    "rocky": ["8.6", "8.7", "8.8", "8.9"],
    "almalinux": ["8.6", "8.7", "8.8", "8.9"]
}

REQUIRED_KERNEL_CONFIGS = [
    ("CONFIG_FANOTIFY", "Requerido para supervisión on-access de accesos a archivos"),
    ("CONFIG_FANOTIFY_ACCESS_PERMISSIONS", "Requerido para bloqueo síncrono FAN_DENY"),
    ("CONFIG_BPF", "Requerido para la máquina virtual eBPF del kernel"),
    ("CONFIG_BPF_SYSCALL", "Requerido para ganchos de llamadas al sistema eBPF"),
    ("CONFIG_SECURITY", "Requerido para ganchos de seguridad LSM en kernel")
]

RECOMMENDED_KERNEL_CONFIGS = [
    ("CONFIG_BPF_LSM", "Requerido para bloqueo preventivo en kernel antes de execve (-EPERM)")
]


def parse_kernel_version(release_str: str) -> Tuple[int, int, int]:
    """Extrae la tupla (major, minor, patch) de la versión del kernel."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release_str)
    if not m:
        return (0, 0, 0)
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


class CompatibilityMatrix:
    """
    Evaluador oficial de compatibilidad para Constantine Antivirus.
    Analiza versión de kernel, distribución y configuración de seguridad del sistema.
    """

    def __init__(self, os_release_path: str = "/etc/os-release"):
        self.os_release_path = os_release_path

    def get_distro_info(self) -> Dict[str, str]:
        """Obtiene la distribución Linux y su versión desde os-release."""
        info = {"id": "unknown", "version_id": "0", "name": "Linux Desconocido"}
        if not os.path.exists(self.os_release_path):
            return info

        try:
            with open(self.os_release_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        v = v.strip("\"'")
                        if k == "ID":
                            info["id"] = v.lower()
                        elif k == "VERSION_ID":
                            info["version_id"] = v.lower()
                        elif k == "NAME":
                            info["name"] = v
        except Exception as e:
            logger.warning("Error leyendo %s: %s", self.os_release_path, e)
        return info

    def check_bpf_lsm_support(self) -> bool:
        """Verifica si el kernel activo tiene BPF LSM habilitado en /sys/kernel/security/lsm."""
        lsm_path = "/sys/kernel/security/lsm"
        if os.path.exists(lsm_path):
            try:
                with open(lsm_path, "r") as f:
                    return "bpf" in f.read().lower()
            except Exception:
                pass
        return False

    def evaluate_system(self, override_kernel: Optional[str] = None,
                        override_distro_id: Optional[str] = None,
                        override_distro_ver: Optional[str] = None) -> Dict[str, Any]:
        """
        Ejecuta la evaluación integral de compatibilidad del sistema frente a la matriz oficial.
        """
        # 1. Información del kernel
        kernel_release = override_kernel or (os.uname().release if hasattr(os, "uname") else "5.15.0")
        k_tuple = parse_kernel_version(kernel_release)

        # 2. Información de distribución
        distro = self.get_distro_info()
        distro_id = override_distro_id or distro["id"]
        distro_ver = override_distro_ver or distro["version_id"]

        # 3. Comprobación de BPF LSM
        bpf_lsm_active = self.check_bpf_lsm_support()

        missing_requirements = []
        recommendations = []

        # 4. Evaluación de Nivel de Compatibilidad (Tier)
        # Regla de Kernel Mínimo:
        # - Tier 1: Kernel >= 5.15 con BPF LSM
        # - Tier 2: Kernel >= 5.8 hasta 5.14 (o >= 5.15 sin BPF LSM activo)
        # - Tier 3: Kernel < 5.4 o entornos no Linux/WSL1
        if k_tuple < (5, 4, 0):
            tier = TIER_3_UNSUPPORTED
            status = "INCOMPATIBLE"
            missing_requirements.append(f"Kernel {kernel_release} inferior al mínimo absoluto requerido (5.4 LTS)")
            recommendations.append("Actualice su sistema operativo o kernel a una versión 5.15 LTS o superior.")
        elif k_tuple >= (5, 15, 0) and bpf_lsm_active:
            tier = TIER_1_OPTIMAL
            status = "COMPATIBLE_OPTIMAL"
            recommendations.append("El sistema cuenta con soporte completo. Se utilizará BPF LSM preventivo en kernel.")
        elif k_tuple >= (5, 8, 0):
            tier = TIER_2_DEGRADED
            status = "COMPATIBLE_DEGRADED"
            if not bpf_lsm_active:
                recommendations.append("BPF LSM no está activo en kernel. Constantine operará con intercepción fanotify on-access y contención reactiva SIGKILL.")
                recommendations.append("Para habilitar BPF LSM completo, agregue 'lsm=...,bpf' a los parámetros de arranque de GRUB.")
        else:
            tier = TIER_2_DEGRADED
            status = "COMPATIBLE_BASIC"
            recommendations.append(f"Kernel {kernel_release} admite fanotify básico. Los monitores eBPF operarán en modo de usuario.")

        # Verificación contra distribuciones oficiales
        is_official_distro = False
        if distro_id in OFFICIAL_DISTROS_TIER_1:
            allowed_vers = OFFICIAL_DISTROS_TIER_1[distro_id]
            if "rolling" in allowed_vers or any(distro_ver.startswith(v) for v in allowed_vers):
                is_official_distro = True
        elif distro_id in OFFICIAL_DISTROS_TIER_2:
            allowed_vers = OFFICIAL_DISTROS_TIER_2[distro_id]
            if any(distro_ver.startswith(v) for v in allowed_vers):
                is_official_distro = True

        return {
            "tier": tier,
            "status": status,
            "kernel_release": kernel_release,
            "kernel_version_tuple": k_tuple,
            "distro_id": distro_id,
            "distro_version": distro_ver,
            "distro_name": distro.get("name", distro_id),
            "is_official_distro": is_official_distro,
            "bpf_lsm_supported": bpf_lsm_active,
            "fanotify_supported": (k_tuple >= (5, 4, 0)),
            "missing_requirements": missing_requirements,
            "recommendations": recommendations
        }
