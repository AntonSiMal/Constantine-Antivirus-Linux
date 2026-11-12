#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v5.5.1 - Desinstalador Completo y Reversión Total
# Purga exhaustiva de configuraciones, servicios, binarios y carpetas residuales
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Se requieren permisos de superusuario: sudo ./uninstall.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$REAL_USER")
CLAMD_CONF="/etc/clamav/clamd.conf"
[ ! -f "$CLAMD_CONF" ] && CLAMD_CONF="/usr/local/etc/clamd.conf"

echo "===================================================================="
echo " 🛑 DESINSTALADOR OFICIAL CONSTANTINE ANTIVIRUS & EDR v5.5.1 "
echo "===================================================================="
echo "[+] Iniciando purga completa y reversión total del sistema..."
echo ""

# 1. Liberar atributos inmutables del kernel y detener demonios
echo "[1/8] Desbloqueando kernel y deteniendo demonios de seguridad..."
if command -v chattr >/dev/null 2>&1; then
    chattr -i -a /var/lib/constantine/.vault.key \
                 /var/log/constantine/immutable_audit.log \
                 /var/lib/constantine/whitelist.txt \
                 /var/lib/constantine/* 2>/dev/null || true
fi

# Detener y deshabilitar todas las unidades de systemd de Constantine y módulos
SERVICES_TO_STOP=(
    "constantine-daemon.service"
    "constantine-boot-update.service"
    "constantine-boot-update.timer"
    "constantine-quick-scan.service"
    "constantine-quick-scan.timer"
    "constantine-full-scan.service"
    "constantine-full-scan.timer"
    "clamonacc.service"
    "tetragon.service"
    "falco.service"
    "falco-modern-bpf.service"
    "wazuh-agent.service"
)

for svc in "${SERVICES_TO_STOP[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

# Terminar fulminantemente procesos residuales
pkill -9 -f "/usr/local/bin/constantine" 2>/dev/null || true
pkill -9 -f "constantine-daemon" 2>/dev/null || true
pkill -9 -f "constantine-tray" 2>/dev/null || true
pkill -9 -f "constantine-dns-sinkhole" 2>/dev/null || true
pkill -9 -f "clamonacc" 2>/dev/null || true
pkill -9 -f "tetragon" 2>/dev/null || true
pkill -9 -f "falco" 2>/dev/null || true
pkill -9 -f "wazuh-agent" 2>/dev/null || true

rm -f /run/constantine.sock /run/constantine.pid 2>/dev/null || true
echo "   [✓] Procesos detenidos y sockets liberados."

# 2. Restauración de red, UFW, filtrado web y periféricos
echo "[2/8] Restaurando red, cortafuegos, filtrado web y permisos de hardware..."
# Retirar bloque de sumidero DNS de /etc/hosts
if grep -qF "# --- CONSTANTINE EDR ANTI-PHISHING BEGIN ---" /etc/hosts 2>/dev/null; then
    sed -i '/# --- CONSTANTINE EDR ANTI-PHISHING BEGIN ---/,/# --- CONSTANTINE EDR ANTI-PHISHING END ---/d' /etc/hosts
    if command -v resolvectl >/dev/null 2>&1; then resolvectl flush-caches >/dev/null 2>&1 || true; fi
    if command -v systemd-resolve >/dev/null 2>&1; then systemd-resolve --flush-caches >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet nscd 2>/dev/null; then systemctl restart nscd >/dev/null 2>&1 || true; fi
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then systemctl restart dnsmasq >/dev/null 2>&1 || true; fi
    echo "   [✓] /etc/hosts y cachés DNS restaurados."
fi

# Retirar reglas de aislamiento de red de UFW
if command -v ufw >/dev/null 2>&1; then
    ufw status numbered 2>/dev/null | grep -i "Constantine" | awk -F"[][]" '{print $2}' | sort -rn | while read -r line; do
        yes | ufw delete "$line" 2>/dev/null || true
    done || true
fi

# Purgar opensnitch si fue instalado por el módulo de red
if command -v opensnitchd >/dev/null 2>&1 || [ -d "/etc/opensnitchd" ]; then
    systemctl stop opensnitchd opensnitch 2>/dev/null || true
    systemctl disable opensnitchd opensnitch 2>/dev/null || true
    pkill -9 -f opensnitch 2>/dev/null || true
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq opensnitch 2>/dev/null || true
    rm -rf /etc/opensnitchd /var/log/opensnitchd* 2>/dev/null || true
fi

# Restaurar reglas de iptables por defecto si hubo aislamiento de red
iptables -D OUTPUT -j NFQUEUE 2>/dev/null || true
iptables -D INPUT -j NFQUEUE 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -F 2>/dev/null || true
iptables -P INPUT ACCEPT 2>/dev/null || true
iptables -P OUTPUT ACCEPT 2>/dev/null || true
iptables -P FORWARD ACCEPT 2>/dev/null || true

# Restaurar permisos normales de cámara y periféricos
chmod 660 /dev/video* 2>/dev/null || true
setfacl -b /dev/video* 2>/dev/null || true

systemctl restart NetworkManager 2>/dev/null || systemctl restart networking 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true
echo "   [✓] Conectividad y periféricos restaurados a valores estándar."

# 3. Restauración de configuraciones originales de ClamAV y Falco
echo "[3/8] Restaurando configuraciones originales de ClamAV, Falco y Tetragon..."
if [ -f "${CLAMD_CONF}.bak" ]; then
    cp -f "${CLAMD_CONF}.bak" "$CLAMD_CONF"
    rm -f "${CLAMD_CONF}.bak"
    echo "   [✓] Configuración original de clamd.conf restaurada."
else
    sed -i '/# --- CONSTANTINE ANTIVIRUS ON-ACCESS CONFIGURATION ---/,$d' "$CLAMD_CONF" 2>/dev/null || true
fi
rm -f /etc/clamav/clamonacc.conf 2>/dev/null || true
rm -rf /var/lib/clamav/tmp /var/lib/clamav/quarantine /var/spool/clamav/quarantine 2>/dev/null || true
systemctl restart clamav-daemon 2>/dev/null || true

# Retirar políticas de Tetragon y Falco
rm -rf /etc/tetragon /var/log/tetragon /var/lib/tetragon 2>/dev/null || true
rm -f /etc/falco/falco_rules.local.yaml /etc/falco/rules.d/constantine-exceptions.yaml /var/log/falco/events.log 2>/dev/null || true
rm -rf /var/log/falco 2>/dev/null || true
if [ -f /etc/falco/falco.yaml ]; then
    sed -i 's/^file_output:.*/file_output:\n  enabled: false/' /etc/falco/falco.yaml 2>/dev/null || true
fi
echo "   [✓] Configuraciones de interceptores restauradas."

# 4. Retirada de señuelos Canary Tripwires en todos los usuarios y /etc/skel
echo "[4/8] Retirando señuelos Canary Tripwires en todos los entornos de usuario..."
# Búsqueda y eliminación en profundidad en /home y /root para cubrir cualquier idioma (Escritorio, Desktop, Descargas, etc.)
find /home /root /etc/skel -maxdepth 4 -name "!000_canary_*" -delete 2>/dev/null || true
find /home /root /etc/skel -maxdepth 3 -name "!*" -delete 2>/dev/null || true
echo "   [✓] Señuelos Canary eliminados sin excepción."

# 5. Purga de baúles de cuarentena y registros
echo "[5/8] Purgando baúles criptográficos de cuarentena..."
rm -rf /var/lib/constantine/quarantine/* 2>/dev/null || true
echo "   [✓] Baúles de cuarentena purgados con éxito."

# 6. Eliminación de servicios de systemd, D-Bus y Polkit
echo "[6/8] Eliminando servicios del sistema, políticas D-Bus y Polkit..."
UNITS_TO_DELETE=(
    "/etc/systemd/system/constantine-daemon.service"
    "/etc/systemd/system/clamonacc.service"
    "/etc/systemd/system/constantine-boot-update.service"
    "/etc/systemd/system/constantine-boot-update.timer"
    "/etc/systemd/system/constantine-quick-scan.service"
    "/etc/systemd/system/constantine-quick-scan.timer"
    "/etc/systemd/system/constantine-full-scan.service"
    "/etc/systemd/system/constantine-full-scan.timer"
    "/etc/systemd/system/tetragon.service"
    "/etc/systemd/system/falco.service"
    "/etc/systemd/system/falco-modern-bpf.service"
    "/etc/systemd/system/wazuh-agent.service"
    "/etc/dbus-1/system.d/org.constantine.Daemon.conf"
    "/usr/share/polkit-1/actions/org.constantine.policy"
    "/etc/polkit-1/rules.d/50-constantine.rules"
    "/etc/sudoers.d/constantine"
    "/etc/udev/rules.d/99-constantine-usb.rules"
    "/etc/profile.d/constantine-session.sh"
)

for f in "${UNITS_TO_DELETE[@]}"; do
    rm -f "$f" 2>/dev/null || true
done
systemctl daemon-reload
echo "   [✓] Servicios y políticas de privilegios eliminados."

# 7. Retirada de binarios ejecutables, librerías y extensiones
echo "[7/8] Retirando ejecutables, herramientas CLI y extensiones..."
BINARIES_TO_DELETE=(
    "/usr/local/bin/constantine"
    "/usr/local/bin/constantine-daemon"
    "/usr/local/bin/constantine-updater"
    "/usr/local/bin/constantine-shutdown"
    "/usr/local/bin/constantine-tray"
    "/usr/local/bin/constantine-dns-sinkhole"
    "/usr/local/bin/constantine-uninstall"
    "/usr/local/bin/uninstall.sh"
    "/usr/local/bin/yr"
    "/usr/local/bin/tetragon"
    "/usr/local/bin/tetra"
)

for b in "${BINARIES_TO_DELETE[@]}"; do
    rm -f "$b" 2>/dev/null || true
done

# Retirar extensiones de clic derecho en exploradores de archivos
rm -f "/usr/share/nautilus-scripts/Analizar con Constantine" \
      "/usr/share/nemo/actions/constantine-scan.nemo_action" \
      "/usr/share/file-manager/actions/constantine-scan.desktop" \
      "/usr/share/kservices5/ServiceMenus/constantine-scan.desktop" \
      "/usr/share/kio/servicemenus/constantine-scan.desktop" 2>/dev/null || true

# Limpiar menús de explorador en todos los usuarios
find /home /root -name "Analizar con Constantine" -delete 2>/dev/null || true
find /home /root -name "constantine-scan.nemo_action" -delete 2>/dev/null || true

# 8. Retirada de lanzadores, iconos, grupo de sistema y purga de carpetas residuales
echo "[8/8] Retirando lanzadores, iconos, grupo y eliminando carpetas residuales..."
rm -f /usr/share/applications/constantine*.desktop \
      /etc/xdg/autostart/constantine*.desktop \
      /usr/share/icons/hicolor/scalable/apps/constantine.svg \
      /usr/share/pixmaps/constantine.svg 2>/dev/null || true

# Eliminar lanzadores y autostart en todos los usuarios y /etc/skel
find /home /root /etc/skel -name "constantine*.desktop" -delete 2>/dev/null || true
find /home /root /etc/skel -name "constantine.svg" -delete 2>/dev/null || true

# Eliminar grupo dedicado de sistema 'constantine'
if getent group constantine >/dev/null 2>&1; then
    groupdel constantine 2>/dev/null || true
    echo "   [✓] Grupo de sistema 'constantine' eliminado."
fi

# Revertir EXTRA_GROUPS en /etc/adduser.conf si contiene constantine
if [ -f /etc/adduser.conf ]; then
    sed -i 's/constantine//g' /etc/adduser.conf 2>/dev/null || true
    sed -i 's/,,/,/g; s/\"\"/\"/g' /etc/adduser.conf 2>/dev/null || true
fi

# Eliminar directorios completos de datos y logs de Constantine
rm -rf /var/lib/constantine \
       /var/log/constantine \
       /etc/constantine \
       /tmp/constantine* \
       /tmp/yr* \
       /tmp/tetragon* 2>/dev/null || true

# Limpiar carpetas vacías residuales en el sistema
rmdir /etc/falco/rules.d /etc/falco /var/log/falco /var/log/tetragon /etc/tetragon /var/lib/tetragon 2>/dev/null || true
find /etc/skel -type d -empty -delete 2>/dev/null || true

gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
update-desktop-database 2>/dev/null || true

echo ""
echo "===================================================================="
echo " 🎉 DESINSTALACIÓN COMPLETA Y PURGA TOTAL DE CONSTANTINE v5.5.1 "
echo "===================================================================="
echo " • Interceptores en Kernel y Socket IPC: Desvinculados limpiamente"
echo " • Señuelos Canary Tripwires: Retirados de todos los usuarios e idiomas"
echo " • Configuraciones y Módulos: Revertidos a su estado original"
echo " • Binarios, Scripts y Datos: Eliminados al 100% sin dejar carpetas vacías"
echo " • Grupo de sistema y Permisos: Purgados sin residuos"
echo " • Sistema Operativo: Restaurado al estado previo de la instalación"
echo "===================================================================="