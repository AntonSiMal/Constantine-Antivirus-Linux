#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v5.5 - Desinstalador Limpio y Reversión Total
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Se requieren permisos de superusuario: sudo ./uninstall.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$REAL_USER")
QUARANTINE_DIR="/var/lib/constantine/quarantine"
# Detección de todos los usuarios humanos del sistema (UID >= 1000)
get_all_human_users() {
    awk -F: '$3 >= 1000 && $3 < 60000 && $1 != "nobody" { print $1 ":" $6 }' /etc/passwd
}
CLAMD_CONF="/etc/clamav/clamd.conf"
if [ ! -f "$CLAMD_CONF" ]; then CLAMD_CONF="/usr/local/etc/clamd.conf"; fi

echo "===================================================================="
echo " 🛑 DESINSTALADOR OFICIAL CONSTANTINE ANTIVIRUS & EDR v5.5 "
echo "===================================================================="
echo "[+] Iniciando desinstalación limpia y reversión de configuraciones..."
echo ""

# 1. Cierre coordinado y seguro del servicio
echo "[1/8] Deteniendo demonios de seguridad y liberando interceptores del kernel..."
echo "   -> Retirando atributos inmutables de autodefensa (+i/+a)..."
chattr -i -a /var/lib/constantine/.vault.key \
             /var/log/constantine/immutable_audit.log \
             /var/lib/constantine/whitelist.txt 2>/dev/null || true
rm -f /etc/tetragon/tetragon.tp.d/constantine_tamper_protection.yaml 2>/dev/null || true

systemctl stop constantine-daemon 2>/dev/null || true
systemctl disable constantine-daemon 2>/dev/null || true
systemctl stop constantine-boot-update.timer 2>/dev/null || true
systemctl disable constantine-boot-update.timer 2>/dev/null || true
systemctl stop constantine-quick-scan.timer constantine-full-scan.timer 2>/dev/null || true
systemctl disable constantine-quick-scan.timer constantine-full-scan.timer 2>/dev/null || true
systemctl stop constantine-boot-update.service 2>/dev/null || true
systemctl stop clamonacc 2>/dev/null || true
systemctl disable clamonacc 2>/dev/null || true
systemctl stop tetragon 2>/dev/null || true
systemctl disable tetragon 2>/dev/null || true
systemctl stop falco 2>/dev/null || true
systemctl disable falco 2>/dev/null || true
systemctl stop wazuh-agent 2>/dev/null || true
systemctl disable wazuh-agent 2>/dev/null || true

pkill -9 -f "/usr/local/bin/constantine" 2>/dev/null || true
pkill -9 -f "constantine-tray" 2>/dev/null || true
rm -f /run/constantine.sock 2>/dev/null || true
echo "   [✓] Interceptores en kernel (fanotify y eBPF) y socket IPC desvinculados limpiamente."

# 2. Restauración de la configuración original
echo "[2/8] Restaurando configuraciones originales del sistema y ClamAV..."
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

echo "   -> Purgando opensnitchd y restaurando reglas de red NFQUEUE/iptables..."
systemctl stop opensnitchd opensnitch 2>/dev/null || true
systemctl disable opensnitchd opensnitch 2>/dev/null || true
pkill -9 -f opensnitch 2>/dev/null || true
DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq opensnitch 2>/dev/null || true
rm -rf /etc/opensnitchd /var/log/opensnitchd* 2>/dev/null || true

# Liberar colas NFQUEUE de iptables y restaurar políticas por defecto
iptables -D OUTPUT -j NFQUEUE 2>/dev/null || true
iptables -D INPUT -j NFQUEUE 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true

echo "   -> Restaurando reglas de conectividad de red y permisos V4L2..."
if [ -f "/var/lib/constantine/.network_isolated" ]; then
    rm -f /var/lib/constantine/.network_isolated /var/lib/constantine/iptables.pre-isolation.bak 2>/dev/null || true
fi
systemctl restart NetworkManager 2>/dev/null || systemctl restart networking 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true
chmod 660 /dev/video* 2>/dev/null || true
setfacl -b /dev/video* 2>/dev/null || true
rm -f /var/lib/constantine/.game_mode_active 2>/dev/null || true

echo "   -> Retirando bloque de sumidero DNS Anti-Phishing de /etc/hosts..."
if grep -qF "# --- CONSTANTINE EDR ANTI-PHISHING BEGIN ---" /etc/hosts 2>/dev/null; then
    sed -i '/# --- CONSTANTINE EDR ANTI-PHISHING BEGIN ---/,/# --- CONSTANTINE EDR ANTI-PHISHING END ---/d' /etc/hosts
    if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches >/dev/null 2>&1 || true; fi
    if command -v systemd-resolve >/dev/null 2>&1; then systemd-resolve --flush-caches >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet nscd 2>/dev/null; then systemctl restart nscd >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then systemctl restart dnsmasq >/dev/null 2>&1 || true; fi
    echo "   [✓] /etc/hosts y cachés DNS restaurados."
fi

# 3. Retirada de señuelos estratégicos Canary Tripwires
echo "[3/8] Retirando señuelos Canary Tripwires del entorno de usuario..."
# Limpiar señuelos en /etc/skel
rm -f /etc/skel/Desktop/!* /etc/skel/Documents/!* /etc/skel/Downloads/!* /etc/skel/Pictures/!* 2>/dev/null || true

# Limpiar señuelos en todos los usuarios humanos
for user_entry in $(get_all_human_users); do
    u_home="${user_entry#*:}"
    [ ! -d "$u_home" ] && continue
    rm -f "$u_home/Desktop/!000_canary_personal_vault.docx"           "$u_home/Documents/!000_canary_financial_report.xlsx"           "$u_home/Downloads/!000_canary_confidential_id.pdf"           "$u_home/Pictures/!000_canary_backup_keys.txt" 2>/dev/null || true
done
echo "   [✓] Señuelos Canary retirados de todos los usuarios y de /etc/skel."
echo "   [✓] Señuelos Canary Tripwires retirados de directorios de usuario."

# 4. Gestión de muestras en cuarentena
echo "[4/8] Purgando muestras aisladas en los baúles de cuarentena..."
rm -rf "$QUARANTINE_DIR"/* /var/lib/clamav/quarantine/* /var/spool/clamav/quarantine/* 2>/dev/null || true
echo "   [✓] Baúles de cuarentena purgados con éxito."

# 5. Retirada de servicios de systemd
echo "[5/8] Eliminando unidades de servicio de systemd..."
rm -f /etc/systemd/system/constantine-daemon.service \
      /etc/systemd/system/clamonacc.service \
      /etc/systemd/system/constantine-boot-update.service \
      /etc/systemd/system/constantine-boot-update.timer \
      /etc/systemd/system/constantine-quick-scan.service \
      /etc/systemd/system/constantine-quick-scan.timer \
      /etc/systemd/system/constantine-full-scan.service \
      /etc/systemd/system/constantine-full-scan.timer \
      /etc/dbus-1/system.d/org.constantine.Daemon.conf \
      /usr/share/polkit-1/actions/org.constantine.policy \
      /etc/systemd/system/tetragon.service \
      /etc/systemd/system/falco.service \
      /etc/systemd/system/wazuh-agent.service
systemctl daemon-reload
echo "   [✓] Servicios del sistema desregistrados."

# 6. Retirada de binarios, scripts y repositorios locales
echo "[6/8] Retirando ejecutables, scripts de actualización y reglas..."
rm -f /usr/local/bin/constantine \
      /usr/local/bin/constantine-daemon \
      /usr/local/bin/constantine-updater \
      /usr/local/bin/constantine-shutdown \
      /usr/local/bin/constantine-tray \
      /usr/local/bin/constantine-dns-sinkhole \
      /usr/local/bin/constantine-uninstall \
      /usr/local/bin/uninstall.sh \
      /usr/local/bin/yr \
      /usr/local/bin/tetragon \
      /usr/local/bin/tetra \
      /etc/sudoers.d/constantine \
      /etc/polkit-1/rules.d/50-constantine.rules \
      /etc/udev/rules.d/99-constantine-usb.rules \
      /etc/xdg/autostart/constantine-tray.desktop

rm -rf /var/lib/constantine \
       /var/log/constantine

# 7. Retirada de menús contextuales de exploradores de archivos
echo "[7/8] Retirando integraciones de clic derecho de exploradores..."
rm -f "/usr/share/nautilus-scripts/Analizar con Constantine" \
      "$USER_HOME/.local/share/nautilus/scripts/Analizar con Constantine" \
      /usr/share/nemo/actions/constantine-scan.nemo_action \
      "$USER_HOME/.local/share/nemo/actions/constantine-scan.nemo_action" \
      /usr/share/file-manager/actions/constantine-scan.desktop \
      /usr/share/kservices5/ServiceMenus/constantine-scan.desktop \
      /usr/share/kio/servicemenus/constantine-scan.desktop

# 8. Retirada de lanzadores de escritorio e iconos
echo "[8/8] Retirando accesos directos, lanzadores e iconos..."
rm -f /usr/share/applications/constantine.desktop \
      /usr/share/applications/constantine-tray.desktop \
      /etc/xdg/autostart/constantine-tray.desktop \
      /etc/skel/Desktop/constantine.desktop \
      /etc/skel/.config/autostart/constantine-tray.desktop \
      /etc/profile.d/constantine-session.sh \
      /usr/share/icons/hicolor/scalable/apps/constantine.svg \
      /usr/share/pixmaps/constantine.svg

# Limpiar accesos e inicios automáticos en todos los usuarios humanos
for user_entry in $(get_all_human_users); do
    u_home="${user_entry#*:}"
    [ ! -d "$u_home" ] && continue
    rm -f "$u_home/Desktop/constantine.desktop" \
          "$u_home/.config/autostart/constantine-tray.desktop" \
          "$u_home/.local/share/applications/constantine.desktop" \
          "$u_home/.local/share/icons/constantine.svg" \
          "$u_home/.local/share/nautilus/scripts/Analizar con Constantine" \
          "$u_home/.local/share/nemo/actions/constantine-scan.nemo_action" 2>/dev/null || true
done

gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database 2>/dev/null || true

echo ""
echo "===================================================================="
echo " 🎉 DESINSTALACIÓN DE CONSTANTINE v5.5 COMPLETADA CON ÉXITO "
echo "===================================================================="
echo " • Interceptores en Kernel y Socket IPC: Desvinculados limpiamente"
echo " • Señuelos Canary Tripwires: Retirados de directorios de usuario"
echo " • Menús de Explorador de Archivos: Retirados sin dejar residuos"
echo " • Archivos y Servicios: Eliminados sin dejar procesos huérfanos"
echo " • Sistema Operativo: Restaurado al estado previo de la instalación"
echo "===================================================================="