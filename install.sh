#!/bin/bash
# ==============================================================================
# CONSTANTINE ANTIVIRUS - INSTALADOR OFICIAL DEL SISTEMA
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(tr -d '\r\n' < "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "5.2.2")

if [ "$VERSION" != "5.2.2" ]; then
    echo "⚠️ Inconsistencia de versión detectada. Versión canónica: $VERSION"
fi

echo "============================================================================"
echo "⚔️ Instalando Constantine Antivirus EDR v${VERSION}"
echo "============================================================================"

# Comprobación de privilegios root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Este script debe ejecutarse con privilegios de superusuario (sudo ./install.sh)"
    exit 1
fi

# 1. Crear grupo de usuarios de Constantine para comunicación segura por socket IPC
if ! getent group constantine-users >/dev/null 2>&1; then
    echo "👥 Creando grupo de sistema 'constantine-users'..."
    groupadd -r constantine-users || true
else
    echo "👥 Grupo 'constantine-users' ya existe en el sistema."
fi

# Asignar usuario real no-root al grupo de usuarios de Constantine
REAL_USER="${SUDO_USER:-}"
if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    echo "👤 Agregando usuario '$REAL_USER' al grupo 'constantine-users'..."
    usermod -a -G constantine-users "$REAL_USER" || true
    echo "✅ Usuario '$REAL_USER' agregado. Tendrá acceso no privilegiado a la GUI y al socket."
fi

# 2. Creación de directorios del sistema con permisos estrictos
echo "📁 Configurando directorios del sistema..."
mkdir -p /opt/constantine
mkdir -p /var/lib/constantine/vault/payloads
mkdir -p /var/lib/constantine/vault/metadata
mkdir -p /var/lib/constantine/intel
mkdir -p /var/log/constantine
mkdir -p /run/constantine
mkdir -p /etc/constantine

chmod 750 /var/lib/constantine
chmod 700 /var/lib/constantine/vault
chmod 750 /var/log/constantine
chmod 770 /run/constantine
chown root:constantine-users /run/constantine

# 3. Copia de archivos de la aplicación
echo "📦 Desplegando archivos del sistema en /opt/constantine..."
cp -r "$SCRIPT_DIR"/* /opt/constantine/
chmod +x /opt/constantine/daemon.py
chmod +x /opt/constantine/install.sh
chmod +x /opt/constantine/uninstall.sh

# 4. Instalación del servicio systemd
echo "⚙️ Configurando servicio systemd de Constantine..."
cp "$SCRIPT_DIR/service/constantine.service" /etc/systemd/system/constantine.service
chmod 644 /etc/systemd/system/constantine.service

systemctl daemon-reload || true
systemctl enable constantine.service || true

echo "============================================================================"
echo "✅ Constantine Antivirus v${VERSION} instalado con éxito."
echo "💡 Para iniciar el servicio: sudo systemctl start constantine"
echo "============================================================================"
