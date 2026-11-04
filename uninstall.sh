#!/usr/bin/env bash
set -e

echo "⚔️ Desinstalador Seguro de Constantine Antivirus"
echo "==============================================="

if [ "$EUID" -ne 0 ]; then
  echo "Por favor ejecuta este desinstalador como root: sudo ./uninstall.sh"
  exit 1
fi

# Preguntar confirmación al usuario
echo "Este asistente eliminará Constantine Antivirus de tu sistema."
read -p "¿Estás seguro de que deseas desinstalar Constantine? (s/N): " confirm
if [[ ! "$confirm" =~ ^[sS]$ ]]; then
  echo "Desinstalación cancelada por el usuario."
  exit 0
fi

echo ""
echo "1. Deteniendo y deshabilitando el servicio del sistema (constantine.service)..."
systemctl stop constantine.service 2>/dev/null || true
systemctl disable constantine.service 2>/dev/null || true
rm -f /etc/systemd/system/constantine.service
systemctl daemon-reload

echo "2. Restaurando configuración de red y cortafuegos (limpieza de nftables)..."
nft delete table inet constantine 2>/dev/null || true

echo "3. Eliminando política de autorización Polkit..."
rm -f /usr/share/polkit-1/actions/org.constantine.antivirus.policy

echo "4. Eliminando accesos directos del Menú de Aplicaciones e inicio automático..."
rm -f /usr/share/applications/constantine.desktop
rm -f /etc/xdg/autostart/constantine-tray.desktop
rm -f /usr/share/nemo/actions/constantine-scan.nemo_action

echo "5. Eliminando iconos del sistema..."
rm -f /usr/share/pixmaps/constantine.svg
rm -f /usr/share/icons/hicolor/scalable/apps/constantine.svg
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true

echo "6. Eliminando accesos directos de los Escritorios de los usuarios..."
for user_home in /home/*; do
  if [ -d "$user_home" ]; then
    rm -f "$user_home/Escritorio/constantine.desktop"
    rm -f "$user_home/Desktop/constantine.desktop"
    rm -f "$user_home/.local/share/nautilus/scripts/Analizar con Constantine"
  fi
done
rm -f /etc/skel/Escritorio/constantine.desktop
rm -f /etc/skel/Desktop/constantine.desktop
rm -f "/etc/skel/.local/share/nautilus/scripts/Analizar con Constantine"

echo "7. Eliminando binarios y archivos del programa (/opt/constantine)..."
rm -rf /opt/constantine
rm -f /usr/local/bin/constantine-gui /usr/bin/constantine-gui /usr/local/bin/constantine /usr/bin/constantine

# Preguntar qué hacer con el Baúl de Cuarentena
echo ""
echo "--------------------------------------------------------"
echo "📦 GESTIÓN DE AMENAZAS EN EL BAÚL DE CUARENTENA"
echo "Actualmente los archivos maliciosos aislados están en: /var/lib/constantine/vault/"
read -p "¿Deseas eliminar definitivamente todas las muestras del Baúl de Cuarentena? (s/N): " purge_vault

if [[ "$purge_vault" =~ ^[sS]$ ]]; then
  echo "Destruyendo de forma segura todos los archivos del baúl..."
  rm -rf /var/lib/constantine /etc/constantine
  echo "Baúl de cuarentena eliminado por completo."
else
  echo "Los archivos del baúl se conservarán de forma segura en /var/lib/constantine/vault/ (cifrados y con permisos 000)."
fi

echo ""
echo "✅ ¡Constantine Antivirus ha sido desinstalado de forma segura y limpia de tu equipo!"
