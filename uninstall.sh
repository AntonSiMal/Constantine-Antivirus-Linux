#!/bin/bash
# ==============================================================================
# CONSTANTINE ANTIVIRUS - DESINSTALADOR OFICIAL DEL SISTEMA
# ==============================================================================
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Debe ejecutarse como root (sudo ./uninstall.sh)"
    exit 1
fi

echo "Deteniendo y deshabilitando servicio constantine.service..."
systemctl stop constantine.service 2>/dev/null || true
systemctl disable constantine.service 2>/dev/null || true
rm -f /etc/systemd/system/constantine.service
systemctl daemon-reload 2>/dev/null || true

echo "Eliminando archivos del programa y enlaces globales..."
rm -f /usr/local/bin/constantine
rm -rf /opt/constantine
rm -rf /run/constantine

echo "✅ Constantine Antivirus ha sido desinstalado con éxito."
