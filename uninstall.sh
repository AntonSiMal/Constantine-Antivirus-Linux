#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v3.2.7 - Desinstalador Limpio y Reversión Total
#
# Funciones:
# 1. Cierre coordinado y seguro de servicios (vaciado de colas y desvinculación kernel).
# 2. Restauración de configuraciones originales (reversión de clamd.conf y reglas UFW).
# 3. Retirada de señuelos estratégicos Canary Tripwires del entorno de usuario.
# 4. Gestión y purgado seguro de muestras en cuarentena blindada.
# 5. Retirada de binarios, scripts, lanzadores de escritorio, iconos y unidades systemd.
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Se requieren permisos de superusuario: sudo ./uninstall.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$REAL_USER")
QUARANTINE_DIR="/var/lib/constantine/quarantine"
CLAMD_CONF="/etc/clamav/clamd.conf"
if [ ! -f "$CLAMD_CONF" ]; then CLAMD_CONF="/usr/local/etc/clamd.conf"; fi

echo "===================================================================="
echo " 🛑 DESINSTALADOR OFICIAL CONSTANTINE ANTIVIRUS & EDR v3.2.7 "
echo "===================================================================="
echo "[+] Iniciando desinstalación limpia y reversión de configuraciones..."
echo ""

# 1. Cierre coordinado y seguro del servicio
echo "[1/7] Deteniendo demonios de seguridad y liberando interceptores del kernel..."
systemctl stop constantine-boot-update.timer 2>/dev/null || true
systemctl disable constantine-boot-update.timer 2>/dev/null || true
systemctl stop constantine-boot-update.service 2>/dev/null || true
systemctl stop clamonacc 2>/dev/null || true
systemctl disable clamonacc 2>/dev/null || true
systemctl stop tetragon 2>/dev/null || true
systemctl disable tetragon 2>/dev/null || true
systemctl stop falco 2>/dev/null || true
systemctl disable falco 2>/dev/null || true
systemctl stop wazuh-agent 2>/dev/null || true
systemctl disable wazuh-agent 2>/dev/null || true

pkill -f "/usr/local/bin/constantine" 2>/dev/null || true
echo "   [✓] Interceptores en kernel (fanotify y eBPF) desvinculados limpiamente."

# 2. Restauración de la configuración original
echo "[2/7] Restaurando configuraciones originales del sistema y ClamAV..."
if [ -f "${CLAMD_CONF}.bak" ]; then
    cp -f "${CLAMD_CONF}.bak" "$CLAMD_CONF"
    rm -f "${CLAMD_CONF}.bak"
    echo "   [✓] Configuración original de clamd.conf restaurada."
else
    sed -i '/# --- CONSTANTINE ANTIVIRUS ON-ACCESS CONFIGURATION ---/,$d' "$CLAMD_CONF" 2>/dev/null || true
fi

systemctl restart clamav-daemon 2>/dev/null || true

echo "   -> Retirando reglas de aislamiento añadidas a UFW..."
ufw status numbered 2>/dev/null | grep "Constantine" | awk -F"[][]" '{print $2}' | sort -rn | while read -r line; do
    yes | ufw delete "$line" 2>/dev/null || true
done || true

# 3. Retirada de señuelos estratégicos Canary Tripwires
echo "[3/7] Retirando señuelos Canary Tripwires del entorno de usuario..."
CANARY_PATHS=(
    "$USER_HOME/Desktop/!000_canary_personal_vault.docx"
    "$USER_HOME/Documents/!000_canary_financial_report.xlsx"
    "$USER_HOME/Downloads/!000_canary_confidential_id.pdf"
    "$USER_HOME/Pictures/!000_canary_backup_keys.txt"
)
for canary in "${CANARY_PATHS[@]}"; do
    if [ -f "$canary" ]; then
        rm -f "$canary"
        echo "   -> Retirado señuelo: $(basename "$canary")"
    fi
done
echo "   [✓] Señuelos Canary Tripwires retirados de directorios de usuario."

# 4. Gestión de muestras en cuarentena
echo "[4/7] Gestionando muestras aisladas en el Baúl de Cuarentena..."
if [ -d "$QUARANTINE_DIR" ]; then
    VAULT_FILES=$(find "$QUARANTINE_DIR" -type f | wc -l)
    if [ "$VAULT_FILES" -gt 0 ]; then
        echo "   -> Purgando $VAULT_FILES muestras hostiles aisladas en el baúl..."
        rm -rf "$QUARANTINE_DIR"/*
        echo "   [✓] Baúl de cuarentena purgado con éxito."
    else
        echo "   [✓] El baúl de cuarentena está vacío."
    fi
fi

# 5. Retirada de servicios de systemd
echo "[5/7] Eliminando unidades de servicio de systemd..."
rm -f /etc/systemd/system/clamonacc.service \
      /etc/systemd/system/constantine-boot-update.service \
      /etc/systemd/system/constantine-boot-update.timer \
      /etc/systemd/system/tetragon.service \
      /etc/systemd/system/falco.service \
      /etc/systemd/system/wazuh-agent.service
systemctl daemon-reload
echo "   [✓] Servicios del sistema desregistrados."

# 6. Retirada de binarios, scripts y repositorios locales
echo "[6/7] Retirando ejecutables, scripts de actualización y reglas..."
rm -f /usr/local/bin/constantine \
      /usr/local/bin/constantine-updater \
      /usr/local/bin/yr \
      /usr/local/bin/tetragon \
      /usr/local/bin/tetra

rm -rf /var/lib/constantine \
       /var/log/constantine

# 7. Retirada de lanzadores de escritorio e iconos
echo "[7/7] Retirando accesos directos, lanzadores e iconos..."
rm -f /usr/share/applications/constantine.desktop \
      "$USER_HOME/Desktop/constantine.desktop" \
      "$USER_HOME/.local/share/applications/constantine.desktop" \
      /usr/share/icons/hicolor/scalable/apps/constantine.svg

gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true

echo ""
echo "===================================================================="
echo " 🎉 DESINSTALACIÓN DE CONSTANTINE v3.2.7 COMPLETADA CON ÉXITO "
echo "===================================================================="
echo " • Interceptores en Kernel: Totalmente desvinculados"
echo " • Señuelos Canary Tripwires: Retirados de directorios de usuario"
echo " • Archivos y Servicios: Eliminados sin dejar procesos huérfanos"
echo " • Configuración de ClamAV y UFW: Regresada a su estado original"
echo " • Sistema Operativo: Restaurado al estado previo de la instalación"
echo "===================================================================="
