#!/usr/bin/env bash
set -e

echo "⚔️ Instalando Constantine Antivirus (Despliegue Multi-Usuario con Autenticación Sudo/Root)..."
echo "=========================================================================================="

if [ "$EUID" -ne 0 ]; then
  echo "Por favor ejecuta este instalador como root: sudo ./install.sh"
  exit 1
fi

echo "1. Instalando dependencias del sistema apt..."
apt-get update -qq || true
apt-get install -y -qq \
    python3 python3-pip python3-gi python3-gi-cairo python3-cryptography gir1.2-gtk-3.0 \
    gir1.2-appindicator3-0.1 gir1.2-ayatanaappindicator3-0.1 \
    libnotify-bin yara bpfcc-tools linux-headers-$(uname -r) 2>/dev/null \
    nftables iproute2 ufw gufw udisks2 policykit-1 \
    openvpn network-manager-openvpn network-manager-openvpn-gnome wireguard wireguard-tools || true

echo "2. Instalando cliente oficial y soporte para Proton VPN..."
# Si se dispone de conectividad a internet, intentar instalar repositorio oficial deb de Proton VPN
if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
    PROTON_DEB="/tmp/protonvpn-stable-release_1.0.6_all.deb"
    wget -q -O "$PROTON_DEB" "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.6_all.deb" 2>/dev/null || \
    curl -sSL -o "$PROTON_DEB" "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.6_all.deb" 2>/dev/null || true
    
    if [ -f "$PROTON_DEB" ] && [ -s "$PROTON_DEB" ]; then
        dpkg -i "$PROTON_DEB" 2>/dev/null || true
        apt-get update -qq 2>/dev/null || true
        apt-get install -y -qq protonvpn-cli proton-vpn-gnome-desktop 2>/dev/null || apt-get install -y -qq protonvpn-cli 2>/dev/null || true
        rm -f "$PROTON_DEB"
    fi
fi
# Respaldo si no se instaló por repo oficial
apt-get install -y -qq protonvpn-cli 2>/dev/null || pip3 install protonvpn-cli --break-system-packages 2>/dev/null || pip3 install protonvpn-cli 2>/dev/null || true

echo "3. Instalando librerías de Python requeridas..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null || true

echo "4. Desplegando archivos con permisos multi-usuario en /opt/constantine..."
mkdir -p /opt/constantine /var/lib/constantine/vault/payloads /etc/constantine /var/lib/constantine/canaries /var/log/constantine
cp -r core gui service scripts assets daemon.py requirements.txt VERSION uninstall.sh /opt/constantine/
chmod -R 755 /opt/constantine/
chmod +x /opt/constantine/uninstall.sh /opt/constantine/daemon.py /opt/constantine/scripts/* 2>/dev/null || true
chmod -R 700 /var/lib/constantine/vault

echo "5. Instalando icono oficial del sistema para todos los usuarios..."
mkdir -p /usr/share/pixmaps /usr/share/icons/hicolor/scalable/apps
cp assets/constantine.svg /usr/share/pixmaps/constantine.svg
cp assets/constantine.svg /usr/share/icons/hicolor/scalable/apps/constantine.svg
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

echo "6. Creando acceso directo global en el Menú de Aplicaciones (/usr/share/applications)..."
cat << 'DESKTOP' > /usr/share/applications/constantine.desktop
[Desktop Entry]
Name=Constantine Antivirus
Comment=Centro de Seguridad Activa, Anti-Ransomware y Cortafuegos
Exec=python3 /opt/constantine/gui/app.py
Icon=constantine
Terminal=false
Type=Application
Categories=System;Security;Network;
StartupNotify=true
Actions=ScanFile;

[Desktop Action ScanFile]
Name=Analizar con Constantine Antivirus
Exec=python3 /opt/constantine/gui/app.py --scan %F
DESKTOP
chmod 644 /usr/share/applications/constantine.desktop

echo "7. Configurando plantilla de nuevos usuarios (/etc/skel) para despliegue futuro automático..."
mkdir -p /etc/skel/Escritorio /etc/skel/Desktop /etc/skel/.local/share/nautilus/scripts
cp /usr/share/applications/constantine.desktop /etc/skel/Escritorio/constantine.desktop
cp /usr/share/applications/constantine.desktop /etc/skel/Desktop/constantine.desktop
cp scripts/constantine-nautilus-scan.sh "/etc/skel/.local/share/nautilus/scripts/Analizar con Constantine"
chmod +x /etc/skel/Escritorio/constantine.desktop /etc/skel/Desktop/constantine.desktop "/etc/skel/.local/share/nautilus/scripts/Analizar con Constantine"

echo "8. Configurando accesos directos y menús para TODOS los usuarios actuales..."
mkdir -p /usr/share/nemo/actions
cp service/constantine-scan.nemo_action /usr/share/nemo/actions/ 2>/dev/null || true

for user_home in /home/*; do
  if [ -d "$user_home" ]; then
    user_name=$(basename "$user_home")
    
    # Accesos en Escritorio de cada usuario
    for desk in "$user_home/Escritorio" "$user_home/Desktop"; do
      if [ -d "$desk" ]; then
        cp /usr/share/applications/constantine.desktop "$desk/constantine.desktop"
        chown "$user_name:$user_name" "$desk/constantine.desktop" 2>/dev/null || true
        chmod +x "$desk/constantine.desktop"
        su - "$user_name" -c "gio set '$desk/constantine.desktop' metadata::trusted true 2>/dev/null" 2>/dev/null || true
      fi
    done

    # Clic derecho en Nautilus para cada usuario
    nautilus_scripts="$user_home/.local/share/nautilus/scripts"
    mkdir -p "$nautilus_scripts"
    cp scripts/constantine-nautilus-scan.sh "$nautilus_scripts/Analizar con Constantine"
    chown -R "$user_name:$user_name" "$nautilus_scripts" 2>/dev/null || true
    chmod +x "$nautilus_scripts/Analizar con Constantine"
    echo "   -> Configurado para usuario: $user_name"
  fi
done

echo "9. Configurando inicio automático global en la barra de tareas (/etc/xdg/autostart)..."
mkdir -p /etc/xdg/autostart
cat << 'AUTOSTART' > /etc/xdg/autostart/constantine-tray.desktop
[Desktop Entry]
Name=Constantine Tray Icon
Comment=Protección Activa en la Bandeja del Sistema
Exec=python3 /opt/constantine/gui/app.py
Icon=constantine
Terminal=false
Type=Application
X-GNOME-Autostart-enabled=true
AUTOSTART
chmod 644 /etc/xdg/autostart/constantine-tray.desktop

echo "10. Creando comandos globales en el terminal (/usr/local/bin/constantine-gui y constantine)..."
mkdir -p /usr/local/bin
cat << 'BIN_WRAPPER' > /usr/local/bin/constantine-gui
#!/bin/bash
# Garantizar que no haya instancias huérfanas ocultas bloqueando la interfaz
pkill -f "/opt/constantine/gui/app.py" 2>/dev/null || true
exec python3 /opt/constantine/gui/app.py "$@"
BIN_WRAPPER
chmod +x /usr/local/bin/constantine-gui
ln -sf /usr/local/bin/constantine-gui /usr/bin/constantine-gui 2>/dev/null || true
ln -sf /usr/local/bin/constantine-gui /usr/local/bin/constantine 2>/dev/null || true
ln -sf /usr/local/bin/constantine-gui /usr/bin/constantine 2>/dev/null || true

echo "11. Activando política de autorización Polkit (sudo/root nativo)..."
cp service/constantine.service /etc/systemd/system/ 2>/dev/null || true
cp service/org.constantine.antivirus.policy /usr/share/polkit-1/actions/ 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
systemctl enable constantine.service 2>/dev/null || true
systemctl restart constantine.service 2>/dev/null || true

echo ""
echo "✅ ¡Instalación Multi-Usuario Completada (v3.6.0)!"
echo "• Soporte Proton VPN, OpenVPN y WireGuard configurado."
echo "• Autenticación del Sistema: Los usuarios administradores usan su propia contraseña de sudo."
echo "• Disponible para TODOS los usuarios actuales y futuros (vía /etc/skel y /usr/share)."
echo "• Icono en bandeja junto al reloj: Activo para cualquier usuario al iniciar sesión."
