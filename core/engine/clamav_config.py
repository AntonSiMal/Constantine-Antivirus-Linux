"""
# ==============================================================================
# CONFIGURACIÓN OPTIMIZADA DE CLAMAV Y CLAMONACC PARA CONSTANTINE ANTIVIRUS
# ==============================================================================
# Este archivo contiene las plantillas oficiales de configuración para clamd y clamonacc
# diseñadas para integrarse armónicamente con Constantine Antivirus.
"""
import os
import logging
from typing import Dict, Any

logger = logging.getLogger("constantine.clamav_config")

CLAMD_CONF_TEMPLATE = """# Constantine Antivirus - clamd.conf Optimizado
# Socket Unix local de alto rendimiento
LocalSocket /run/clamav/clamd.ctl
FixStaleSocket yes
LocalSocketGroup constantine-users
LocalSocketMode 660

# Configuración de rendimiento y concurrencia
MaxThreads 8
MaxQueue 100
IdleTimeout 60
MaxConnectionQueueLength 30

# Límites de análisis seguros (Protección contra bombas de descompresión)
MaxFileSize 100M
MaxScanSize 250M
MaxFiles 5000
MaxRecursion 16

# Rutas de base de datos de firmas oficiales y comunitarias (CVD)
DatabaseDirectory /var/lib/clamav
OfficialDatabaseOnly no

# Integración con On-Access
ScanOnAccess yes
"""

CLAMONACC_CONF_TEMPLATE = """# Constantine Antivirus - ClamOnAcc Configuración Coordinada
# Comunicación directa con el socket de clamd
# Excluye directorios internos de Constantine para evitar doble enganche fanotify
OnAccessExcludePath /var/lib/constantine
OnAccessExcludePath /var/log/constantine
OnAccessExcludePath /run/constantine
OnAccessExcludePath /etc/constantine
OnAccessExcludePath /opt/constantine
OnAccessExcludePath /var/lib/clamav
OnAccessExcludePath /run/clamav

# Configuración de bloqueo en acceso (Prevention)
# En Modelo Híbrido:
# Si Constantine es primario, clamonacc opera como notificador o respaldo
# Si está en modo DELEGATED_CLAMONACC, OnAccessPrevention bloquea antes de I/O
OnAccessPrevention yes
OnAccessExtraScanning yes

# Rutas del sistema a proteger on-access
OnAccessIncludePath /home
OnAccessIncludePath /tmp
OnAccessIncludePath /var/tmp
"""

def generate_default_configs(target_dir: str = "/etc/constantine/clamav"):
    """Genera las plantillas de configuración recomendadas para ClamAV y ClamOnAcc."""
    os.makedirs(target_dir, exist_ok=True)
    clamd_path = os.path.join(target_dir, "clamd.conf")
    onacc_path = os.path.join(target_dir, "clamonacc.conf")

    with open(clamd_path, "w", encoding="utf-8") as f:
        f.write(CLAMD_CONF_TEMPLATE.strip() + "\n")

    with open(onacc_path, "w", encoding="utf-8") as f:
        f.write(CLAMONACC_CONF_TEMPLATE.strip() + "\n")

    logger.info("📄 [CONFIGURACIÓN CLAMAV] Plantillas generadas en %s", target_dir)
    return {"clamd_conf": clamd_path, "clamonacc_conf": onacc_path}
