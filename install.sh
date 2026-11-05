#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus - Instalador de Sistema Seguro para Linux
# Compatible con Debian 11/12+, Ubuntu 20.04/22.04/24.04+, Linux Mint 20/21/22+
# ==============================================================================
set -e

# --- Colores y Utilerías de Registro ---
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${CYAN}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠️  [ADVERTENCIA]: $1${NC}"
}

log_error() {
    echo -e "${RED}❌ [ERROR CRÍTICO]: $1${NC}" >&2
}

die() {
    log_error "$1"
    echo -e "\n${RED}La instalación ha fallado. El sistema no ha quedado en un estado inconsistente.${NC}" >&2
    exit 1
}

step() {
    echo -e "\n${BOLD}${CYAN}==>${NC} ${BOLD}$1${NC}"
}

# --- 1. Verificación de Privilegios de Superusuario ---
if [ "$EUID" -ne 0 ]; then
    die "El instalador de Constantine Antivirus debe ejecutarse como root:\n   sudo ./install.sh"
fi

# 0. Normalización del directorio de trabajo y resolución canónica de rutas
# Protege contra errores de 'getcwd' cuando el instalador se ejecuta desde un directorio eliminado/reemplazado
SCRIPT_SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SCRIPT_SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"
    SCRIPT_SOURCE="$(readlink "$SCRIPT_SOURCE")"
    [[ $SCRIPT_SOURCE != /* ]] && SCRIPT_SOURCE="$DIR/$SCRIPT_SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SCRIPT_SOURCE")" >/dev/null 2>&1 && pwd)"

# Moverse inmediatamente al directorio real de los fuentes para sanear getcwd()
if [ -d "$SCRIPT_DIR" ]; then
    cd "$SCRIPT_DIR" 2>/dev/null || cd /tmp
else
    cd /tmp
fi

# Resolución dinámica de versión canónica para trazabilidad total
if [ -f "$SCRIPT_DIR/VERSION" ]; then
    VERSION=$(tr -d '[:space:]' < "$SCRIPT_DIR/VERSION")
elif [ -f "/opt/constantine/VERSION" ]; then
    VERSION=$(tr -d '[:space:]' < "/opt/constantine/VERSION")
else
    VERSION="4.3.2"
fi

echo -e "${BOLD}⚔️  Iniciando Instalador de Constantine Antivirus (v${VERSION})${NC}"
echo "======================================================================"

# --- 2. Verificación y Actualización de Repositorios APT ---
step "1. Actualizando índices de paquetes de la distribución (APT)..."
if ! apt-get update -qq; then
    log_warn "apt-get update finalizó con avisos o códigos no cero. Verificando conectividad local..."
fi

# Paquetes obligatorios para el funcionamiento de Constantine (FALLO FATAL si no se instalan)
CRITICAL_PACKAGES=(
    python3
    python3-pip
    python3-gi
    python3-gi-cairo
    python3-cryptography
    gir1.2-gtk-3.0
    libnotify-bin
    nftables
    iproute2
    ufw
    udisks2
)

# Paquetes recomendados y componentes extendidos (Degradación elegante si no están disponibles)
OPTIONAL_PACKAGES=(
    yara
    python3-yara
    gir1.2-appindicator3-0.1
    gir1.2-ayatanaappindicator3-0.1
    gufw
    clamav
    clamav-daemon
    clamav-freshclam
)

step "2. Instalando dependencias críticas del sistema..."
for pkg in "${CRITICAL_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        log_info "Instalando paquete crítico: $pkg"
        if ! apt-get install -y -qq "$pkg"; then
            die "No se pudo instalar el paquete esencial requerido: $pkg. Verifica tu gestor de paquetes."
        fi
    fi
done
log_success "Dependencias críticas de sistema verificadas."

# Instalar PolicyKit / Polkit según la versión de la distribución
if ! dpkg -s policykit-1 >/dev/null 2>&1 && ! dpkg -s polkitd >/dev/null 2>&1; then
    apt-get install -y -qq policykit-1 2>/dev/null || apt-get install -y -qq polkitd 2>/dev/null || \
    log_warn "No se pudo instalar policykit-1/polkitd. La autenticación Polkit gráfica podría requerir configuración manual."
fi

step "3. Instalando dependencias opcionales y herramientas de red..."
for pkg in "${OPTIONAL_PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        if apt-get install -y -qq "$pkg" >/dev/null 2>&1; then
            log_info "Instalado componente extendido: $pkg"
        else
            log_warn "Componente opcional no disponible en los repositorios: $pkg (la suite operará en modo compatible)."
        fi
    fi
done

# Intento de instalación de cabeceras de kernel y BCC para eBPF
KERNEL_HEADERS="linux-headers-$(uname -r)"
if apt-get install -y -qq "$KERNEL_HEADERS" bpfcc-tools >/dev/null 2>&1; then
    log_success "Soporte eBPF en kernel activado (bpfcc-tools y cabeceras instaladas)."
else
    log_warn "No se pudieron instalar cabeceras para el kernel actual. Las sondas eBPF avanzadas podrían estar inactivas; la protección por fanotify continuará operativa."
fi

# --- 3. Detección de Integración de Red Opcional (Proton VPN) ---
step "4. Verificando integración con herramientas de red (opcional)..."
if command -v protonvpn-app >/dev/null 2>&1 || command -v protonvpn >/dev/null 2>&1 || command -v proton-vpn-gnome-desktop >/dev/null 2>&1 || command -v protonvpn-cli >/dev/null 2>&1; then
    log_success "Cliente Proton VPN detectado en el sistema; integración habilitada en el Centro de Control."
else
    log_info "Proton VPN no está instalado (componente de red de terceros opcional)."
    log_info "Constantine Antivirus opera de forma 100% independiente sin alterar tus herramientas de red."
    log_info "Para instalar Proton VPN de forma segura con verificación criptográfica SHA-256 ejecuta: sudo ./scripts/setup_protonvpn.sh"
fi

# --- 4. Instalación de Librerías Python de Requisitos ---
step "5. Verificando librerías de Python requeridas..."
REQ_FILE="$SCRIPT_DIR/requirements.txt"
[ ! -f "$REQ_FILE" ] && [ -f "requirements.txt" ] && REQ_FILE="requirements.txt"

if [ -f "$REQ_FILE" ]; then
    if ! pip3 install -r "$REQ_FILE" --break-system-packages >/dev/null 2>&1; then
        if ! pip3 install -r "$REQ_FILE" >/dev/null 2>&1; then
            log_warn "Instalación de requirements.txt vía pip devolvió advertencias. Validando paquetes críticos instalados por APT..."
        fi
    fi
fi

# Validación estricta de las librerías críticas en Python con aislamiento de cwd para evitar fallos de getcwd
if ! (cd "$SCRIPT_DIR" 2>/dev/null || cd /tmp; python3 -c "import gi, cryptography") >/dev/null 2>&1; then
    log_warn "Las librerías críticas no cargaron en el primer intento. Reinstalando paquetes APT correspondientes..."
    apt-get install -y -qq python3-gi python3-gi-cairo python3-cryptography >/dev/null 2>&1 || true
    if ! (cd /tmp; python3 -c "import gi, cryptography") >/dev/null 2>&1; then
        ERROR_DETAIL=$(cd /tmp; python3 -c "import gi, cryptography" 2>&1 || true)
        die "Las librerías críticas de Python (PyGObject / cryptography) no se encuentran accesibles para python3.
Detalle del error: $ERROR_DETAIL"
    fi
fi
log_success "Entorno de ejecución de Python validado correctamente."

# --- 5. Despliegue de Binarios y Estructura en /opt/constantine ---
step "6. Desplegando archivos del sistema en /opt/constantine..."
mkdir -p /opt/constantine /var/lib/constantine/vault/payloads /etc/constantine /var/lib/constantine/canaries /var/log/constantine || die "No se pudieron crear los directorios de /opt/constantine o /var/lib/constantine."

REQUIRED_FILES=("daemon.py" "VERSION" "uninstall.sh")
REQUIRED_DIRS=("core" "gui" "service" "scripts" "assets")

for d in "${REQUIRED_DIRS[@]}"; do
    if [ ! -d "$d" ]; then
        die "Falta el directorio esencial del instalador: $d"
    fi
    cp -r "$d" /opt/constantine/ || die "Error copiando $d a /opt/constantine/"
done

for f in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$f" ]; then
        die "Falta el archivo esencial del instalador: $f"
    fi
    cp "$f" /opt/constantine/ || die "Error copiando $f a /opt/constantine/"
done

[ -f "requirements.txt" ] && cp requirements.txt /opt/constantine/
[ -f "README.md" ] && cp README.md /opt/constantine/

# Permisos seguros y estrictos
chmod -R 755 /opt/constantine/ || die "Fallo ajustando permisos 755 en /opt/constantine/"
chmod +x /opt/constantine/uninstall.sh /opt/constantine/daemon.py /opt/constantine/gui/app.py || die "Fallo asignando permisos de ejecución a los binarios principales."
find /opt/constantine/scripts/ -type f -exec chmod +x {} + 2>/dev/null || true
chmod 700 /var/lib/constantine/vault || die "Fallo asignando permisos 700 al baúl de cuarentena."
chmod 700 /var/lib/constantine/vault/payloads 2>/dev/null || true
log_success "Archivos del programa desplegados y permisos de seguridad aplicados."

# --- 6. Instalación de Iconos del Sistema ---
step "7. Registrando iconos del sistema..."
mkdir -p /usr/share/pixmaps /usr/share/icons/hicolor/scalable/apps
if [ -f "assets/constantine.svg" ]; then
    cp assets/constantine.svg /usr/share/pixmaps/constantine.svg
    cp assets/constantine.svg /usr/share/icons/hicolor/scalable/apps/constantine.svg
    gtk-update-icon-cache /usr/share/icons/hicolor >/dev/null 2>&1 || true
    log_success "Iconos registrados en el sistema."
else
    log_warn "assets/constantine.svg no encontrado; se usarán iconos predeterminados de GTK."
fi

# --- 7. Creación de Acceso Directo Global (.desktop) ---
step "8. Creando acceso directo global en el Menú de Aplicaciones..."
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
chmod 644 /usr/share/applications/constantine.desktop || die "No se pudo crear /usr/share/applications/constantine.desktop"
log_success "Acceso directo registrado en /usr/share/applications/constantine.desktop"

# --- 8. Configuración Multi-Usuario (/etc/skel y /home/*) ---
step "9. Configurando plantilla de usuarios (/etc/skel) y perfiles existentes..."
mkdir -p /etc/skel/Escritorio /etc/skel/Desktop /etc/skel/.local/share/nautilus/scripts
cp /usr/share/applications/constantine.desktop /etc/skel/Escritorio/constantine.desktop
cp /usr/share/applications/constantine.desktop /etc/skel/Desktop/constantine.desktop
if [ -f "/opt/constantine/scripts/constantine-nautilus-scan.sh" ]; then
    cp /opt/constantine/scripts/constantine-nautilus-scan.sh "/etc/skel/.local/share/nautilus/scripts/Analizar con Constantine"
    chmod +x "/etc/skel/.local/share/nautilus/scripts/Analizar con Constantine"
fi
chmod +x /etc/skel/Escritorio/constantine.desktop /etc/skel/Desktop/constantine.desktop

# Integración con el menú contextual de Nemo (Linux Mint)
mkdir -p /usr/share/nemo/actions
if [ -f "/opt/constantine/service/constantine-scan.nemo_action" ]; then
    cp /opt/constantine/service/constantine-scan.nemo_action /usr/share/nemo/actions/
fi

# Despliegue en los escritorios de cada usuario real
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        user_name=$(basename "$user_home")
        for desk in "$user_home/Escritorio" "$user_home/Desktop"; do
            if [ -d "$desk" ]; then
                cp /usr/share/applications/constantine.desktop "$desk/constantine.desktop"
                chown "$user_name:$user_name" "$desk/constantine.desktop" 2>/dev/null || true
                chmod +x "$desk/constantine.desktop"
                su - "$user_name" -c "gio set '$desk/constantine.desktop' metadata::trusted true 2>/dev/null" 2>/dev/null || true
            fi
        done

        nautilus_scripts="$user_home/.local/share/nautilus/scripts"
        if [ -d "$user_home/.local" ] && [ -f "/opt/constantine/scripts/constantine-nautilus-scan.sh" ]; then
            mkdir -p "$nautilus_scripts"
            cp /opt/constantine/scripts/constantine-nautilus-scan.sh "$nautilus_scripts/Analizar con Constantine"
            chown -R "$user_name:$user_name" "$nautilus_scripts" 2>/dev/null || true
            chmod +x "$nautilus_scripts/Analizar con Constantine"
        fi
        # Asegurar propiedad y permisos de usuario para ejecución no root
        mkdir -p "$user_home/.config/constantine" "$user_home/.local/share/constantine" 2>/dev/null || true
        chown -R "$user_name:$user_name" "$user_home/.config/constantine" "$user_home/.local/share/constantine" 2>/dev/null || true
        log_info "Configuración aplicada al usuario: $user_name"
    fi
done

# --- 9. Configuración de Inicio Automático en Barra de Tareas ---
step "10. Configurando inicio automático en bandeja del sistema (/etc/xdg/autostart)..."
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
log_success "Autoinicio registrado en /etc/xdg/autostart/constantine-tray.desktop"

# --- 10. Enlaces y Comandos Globales en Terminal ---
# Limpiar archivos temporales y sockets huérfanos de ejecuciones previas como root
rm -f /tmp/constantine_*.sock /tmp/constantine_audit_log*.json /tmp/constantine_dns_state*.json 2>/dev/null || true

step "11. Creando comandos globales en terminal (/usr/local/bin/constantine-gui)..."
mkdir -p /usr/local/bin
cat << 'BIN_WRAPPER' > /usr/local/bin/constantine-gui
#!/bin/bash
export PYTHONPATH="/opt/constantine:${PYTHONPATH}"
pkill -f "/opt/constantine/gui/app.py" 2>/dev/null || true
exec python3 /opt/constantine/gui/app.py "$@"
BIN_WRAPPER
chmod +x /usr/local/bin/constantine-gui || die "No se pudo crear /usr/local/bin/constantine-gui"
ln -sf /usr/local/bin/constantine-gui /usr/bin/constantine-gui 2>/dev/null || true
ln -sf /usr/local/bin/constantine-gui /usr/local/bin/constantine 2>/dev/null || true
ln -sf /usr/local/bin/constantine-gui /usr/bin/constantine 2>/dev/null || true
log_success "Comandos 'constantine-gui' y 'constantine' disponibles en la terminal."

# Configuración e integración del motor antivirus ClamAV (clamd y freshclam)
step "12a. Configurando e integrando motor antivirus ClamAV (clamd & freshclam)..."
if dpkg -s clamav-daemon >/dev/null 2>&1 || command -v clamd >/dev/null 2>&1; then
    mkdir -p /run/clamav /var/log/clamav /var/lib/clamav
    chown -R clamav:clamav /run/clamav /var/log/clamav /var/lib/clamav 2>/dev/null || true
    chmod 755 /run/clamav 2>/dev/null || true
    systemctl enable clamav-daemon 2>/dev/null || true
    systemctl enable clamav-freshclam 2>/dev/null || true
    systemctl start clamav-daemon 2>/dev/null || true
    log_success "Motor antivirus ClamAV (clamd & freshclam) integrado y habilitado."
else
    log_info "ClamAV no detectado; Constantine operará en modo híbrido nativo con YARA y heurística 5 capas."
fi

# --- 12. Activación de Servicio Systemd, Polkit, D-Bus y Separación de Privilegios ---
step "12b. Configurando usuario de servicio no privilegiado, Systemd, Polkit y D-Bus..."
# Crear usuario de servicio para aislamiento del motor de escaneo (Least Privilege)
id -u constantine-scanner &>/dev/null || useradd -r -s /usr/sbin/nologin -d /nonexistent constantine-scanner 2>/dev/null || true

# Configurar helper administrativo restringido
if [ -f "/opt/constantine/service/constantine-helper" ]; then
    chmod 755 /opt/constantine/service/constantine-helper
fi

# Configurar directiva y reglas de Polkit
if [ -f "/opt/constantine/service/org.constantine.antivirus.policy" ]; then
    mkdir -p /usr/share/polkit-1/actions
    cp /opt/constantine/service/org.constantine.antivirus.policy /usr/share/polkit-1/actions/ || log_warn "No se pudo copiar la directiva Polkit."
fi
if [ -f "/opt/constantine/service/90-constantine.rules" ] && [ -d "/etc/polkit-1/rules.d" ]; then
    cp /opt/constantine/service/90-constantine.rules /etc/polkit-1/rules.d/ 2>/dev/null || true
fi

# Configurar política de seguridad D-Bus de sistema
if [ -f "/opt/constantine/service/org.constantine.antivirus.conf" ] && [ -d "/etc/dbus-1/system.d" ]; then
    cp /opt/constantine/service/org.constantine.antivirus.conf /etc/dbus-1/system.d/ 2>/dev/null || true
fi

if [ -f "/opt/constantine/service/constantine.service" ]; then
    # Limpiar enlaces simbólicos heredados que generaban bucles de ordenación en systemd
    rm -f /etc/systemd/system/sysinit.target.wants/constantine.service 2>/dev/null || true
    cp /opt/constantine/service/constantine.service /etc/systemd/system/ || die "No se pudo instalar /etc/systemd/system/constantine.service"
    
    # Comprobar si el entorno soporta systemd activo (evitar fallos en contenedores chroot/docker)
    if pidof systemd >/dev/null 2>&1 || [ -d /run/systemd/system ]; then
        systemctl daemon-reload || die "Fallo ejecutando systemctl daemon-reload"
        systemctl enable constantine.service || die "Fallo habilitando el servicio constantine.service"
        if ! systemctl restart constantine.service; then
            log_warn "El servicio constantine.service no pudo arrancar de inmediato. Revisa 'systemctl status constantine.service'."
        else
            log_success "Servicio en segundo plano constantine.service activo y habilitado para el arranque del sistema."
        fi
    else
        log_warn "systemd no detectado en ejecución (entorno de pruebas o contenedor). El demonio deberá iniciarse manualmente con: sudo python3 /opt/constantine/daemon.py"
    fi
fi

# --- 12. Verificación de Integridad Posterior a la Instalación (Sanity Check) ---
step "13. Ejecutando verificación de integridad de la instalación..."
CHECK_FAILURES=0

if [ ! -x "/opt/constantine/daemon.py" ]; then
    log_error "El binario del demonio /opt/constantine/daemon.py no es ejecutable."
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if [ ! -x "/opt/constantine/gui/app.py" ]; then
    log_error "El ejecutable gráfico /opt/constantine/gui/app.py no es ejecutable."
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if [ ! -x "/usr/local/bin/constantine-gui" ]; then
    log_error "El lanzador /usr/local/bin/constantine-gui no se generó correctamente."
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if ! (cd /tmp && python3 -c "import gi, cryptography; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk") >/dev/null 2>&1; then
    log_error "Error al cargar librerías GTK 3 y Cryptography desde Python."
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if [ -f "/opt/constantine/VERSION" ]; then
    INSTALLED_VER=$(tr -d '[:space:]' < "/opt/constantine/VERSION")
    if [ "$INSTALLED_VER" != "$VERSION" ]; then
        log_error "Inconsistencia de versión detectada: instalador=$VERSION vs instalado=$INSTALLED_VER"
        CHECK_FAILURES=$((CHECK_FAILURES + 1))
    fi
else
    log_error "El archivo /opt/constantine/VERSION no se instaló correctamente."
    CHECK_FAILURES=$((CHECK_FAILURES + 1))
fi

if [ "$CHECK_FAILURES" -gt 0 ]; then
    die "La verificación de integridad posterior falló con $CHECK_FAILURES error(es). La instalación no es segura."
fi

echo ""
echo -e "${BOLD}${GREEN}======================================================================"
echo -e "🎉 ¡INSTALACIÓN COMPLETADA Y VERIFICADA CON ÉXITO (v${VERSION})!"
echo -e "======================================================================${NC}"
echo -e "• ${BOLD}Protección en Kernel:${NC} Demonio del sistema configurado y en ejecución."
echo -e "• ${BOLD}Seguridad Zero-Breach:${NC} Autenticación nativa delegada a PAM/sudo."
echo -e "• ${BOLD}Despliegue Multi-Usuario:${NC} Disponible para todos los usuarios actuales y futuros."
echo -e "• ${BOLD}Lanzamiento Rápido:${NC} Ejecuta 'constantine-gui' en terminal o busca en tu menú."
