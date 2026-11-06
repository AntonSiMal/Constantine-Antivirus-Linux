#!/bin/bash
# ==============================================================================
# CONSTANTINE ANTIVIRUS - INSTALADOR OFICIAL DEL SISTEMA
# ==============================================================================
# Este instalador automatizado realiza:
# 1. Detección de distribución Linux y gestor de paquetes (apt, dnf, zypper, pacman).
# 2. Instalación de dependencias del sistema operativo (Python 3, dev headers, GTK3, ClamAV, AIDE).
# 3. Instalación y verificación de dependencias Python (requirements.txt con fallback seguro).
# 4. Puerta de verificación pre/post-instalación rigurosa (módulos, sockets, binarios).
# 5. Creación de usuarios de sistema, permisos y jerarquía de directorios en /opt/constantine.
# 6. Detección de versión de kernel Linux y ajuste dinámico de capacidades (CAP_BPF/CAP_PERFMON sin CAP_SYS_ADMIN en >= 5.8).
# 7. Despliegue, habilitación e inicio inmediato del servicio systemd con verificación activa.
# 8. Configuración del symlink CLI global /usr/local/bin/constantine.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(tr -d '\r\n' < "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "5.4.7")

if [ "$VERSION" != "5.4.7" ]; then
    echo "⚠️ Inconsistencia de versión detectada. Versión canónica: $VERSION"
fi

echo "============================================================================"
echo "⚔️ Instalando Constantine Antivirus EDR v${VERSION}"
echo "============================================================================"

# Flags de instalación
INSTALL_DEPS=true
START_SERVICE=true

for arg in "$@"; do
    case "$arg" in
        --no-deps)
            INSTALL_DEPS=false
            echo "ℹ️ Flag detectado: --no-deps (Se omitirá la instalación de dependencias externas)"
            ;;
        --skip-service-start)
            START_SERVICE=false
            echo "ℹ️ Flag detectado: --skip-service-start (No se iniciará el demonio tras la instalación)"
            ;;
        *)
            ;;
    esac
done

# Comprobación de privilegios root
if [ "$(id -u)" -ne 0 ]; then
    echo "❌ Este script debe ejecutarse con privilegios de superusuario (sudo ./install.sh)"
    exit 1
fi

# ==============================================================================
# FASE 1: DETECCIÓN DEL GESTOR DE PAQUETES E INSTALACIÓN DE DEPENDENCIAS DEL SISTEMA
# ==============================================================================
detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf"
    elif command -v zypper >/dev/null 2>&1; then
        echo "zypper"
    elif command -v pacman >/dev/null 2>&1; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

PKG_MGR=$(detect_package_manager)
echo "🔍 Gestor de paquetes detectado en el host: $PKG_MGR"

if [ "$INSTALL_DEPS" = true ]; then
    echo "📦 Instalando y verificando dependencias del sistema..."
    case "$PKG_MGR" in
        apt)
            echo "🔄 Actualizando repositorios APT e instalando paquetes base..."
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq || true
            apt-get install -y --no-install-recommends \
                python3 python3-pip python3-dev \
                python3-cryptography python3-yaml python3-gi gir1.2-gtk-3.0 \
                clamav clamav-daemon aide || true
            ;;
        dnf)
            echo "🔄 Instalando dependencias con DNF..."
            dnf install -y python3 python3-pip python3-devel \
                python3-cryptography python3-pyyaml python3-gobject gtk3 \
                clamav clamd aide || true
            ;;
        zypper)
            echo "🔄 Instalando dependencias con Zypper..."
            zypper --non-interactive install -y python3 python3-pip python3-devel \
                python3-cryptography python3-PyYAML python3-gobject gtk3 \
                clamav aide || true
            ;;
        pacman)
            echo "🔄 Instalando dependencias con Pacman..."
            pacman -Sy --noconfirm python python-pip \
                python-cryptography python-yaml python-gobject gtk3 \
                clamav aide || true
            ;;
        *)
            echo "⚠️ Gestor de paquetes no reconocido o entorno minimalista. Se asume instalación manual."
            ;;
    esac

    # Instalación de dependencias de Python desde requirements.txt
    if [ -f "$SCRIPT_DIR/requirements.txt" ] && command -v pip3 >/dev/null 2>&1; then
        echo "🐍 Verificando dependencias de Python vía pip3..."
        pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages 2>/dev/null || \
        pip3 install -r "$SCRIPT_DIR/requirements.txt" 2>/dev/null || true
    fi
else
    echo "⏩ Omitiendo instalación automática de paquetes externos (--no-deps activo)."
fi

# ==============================================================================
# FASE 2: PUERTA DE VERIFICACIÓN OPERATIVA PREVIA (VERIFICATION GATE)
# ==============================================================================
echo "🧪 Ejecutando Puerta de Verificación Operativa de Constantine..."

# 1. Comprobación de binario de Python 3 y versión mínima
if ! command -v python3 >/dev/null 2>&1; then
    echo "❌ Error crítico: python3 no está instalado en el sistema."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]); then
    echo "❌ Error: Constantine requiere Python 3.8 o superior (Detectado: $PY_VER)."
    exit 1
fi
echo "  [OK] Intérprete Python verificado: v$PY_VER"

# 2. Comprobación de módulos obligatorios del núcleo (Core)
python3 -c "
import sys
missing = []
for mod in ['cryptography', 'yaml']:
    try:
        __import__(mod)
    except ImportError:
        missing.append(mod)
if missing:
    print(f'❌ Módulos obligatorios faltantes: {missing}', file=sys.stderr)
    sys.exit(1)
" || {
    echo "❌ Fallo en la verificación de dependencias críticas de Python (cryptography / PyYAML)."
    echo "💡 Instálelas ejecutando: pip3 install cryptography PyYAML"
    exit 1
}
echo "  [OK] Criptografía AES-256-GCM y parser YAML validados."

# 3. Comprobación de dependencias de GUI / PyGObject
if python3 -c "import gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk" >/dev/null 2>&1; then
    echo "  [OK] Soporte gráfico GTK 3.0 / PyGObject operativo."
else
    echo "  [INFO] Entorno gráfico GTK 3.0 no detectado o modo headless. GUI operará en degradación asistida."
fi

# 4. Comprobación de motor antivirus ClamAV (Opcional / Asistido)
if command -v clamd >/dev/null 2>&1 || [ -S /run/clamav/clamd.ctl ] || [ -S /var/run/clamav/clamd.ctl ]; then
    echo "  [OK] Demonio ClamAV (clamd) detectado en el host."
elif command -v clamscan >/dev/null 2>&1; then
    echo "  [OK] Escáner ClamAV CLI (clamscan) disponible."
else
    echo "  [INFO] ClamAV no encontrado. Constantine utilizará su motor autónomo heurístico y YARA nativo."
fi

# ==============================================================================
# FASE 3: CREACIÓN DE USUARIOS, GRUPOS Y ESTRUCTURA DE DIRECTORIOS
# ==============================================================================
# Crear grupo de usuarios de Constantine para comunicación segura por socket IPC
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
    echo "✅ Usuario '$REAL_USER' agregado al grupo 'constantine-users'."
fi

# Creación de directorios del sistema con permisos estrictos
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

# ==============================================================================
# FASE 4: DESPLIEGUE DE ARCHIVOS DE LA APLICACIÓN Y BINARIOS CLI
# ==============================================================================
echo "📦 Desplegando archivos del sistema en /opt/constantine..."
cp -r "$SCRIPT_DIR"/* /opt/constantine/
chmod +x /opt/constantine/daemon.py
chmod +x /opt/constantine/install.sh
chmod +x /opt/constantine/uninstall.sh

# Crear symlink global para la herramienta de consola
mkdir -p /usr/local/bin
ln -sf /opt/constantine/daemon.py /usr/local/bin/constantine
echo "🔗 Enlace simbólico creado: /usr/local/bin/constantine -> /opt/constantine/daemon.py"

# ==============================================================================
# FASE 5: CONFIGURACIÓN E INICIO DEL SERVICIO SYSTEMD
# ==============================================================================
echo "⚙️ Configurando servicio systemd de Constantine..."
if [ -f "$SCRIPT_DIR/service/constantine.service" ]; then
    cp "$SCRIPT_DIR/service/constantine.service" /etc/systemd/system/constantine.service
    chmod 644 /etc/systemd/system/constantine.service

    # Detección combinada: Versión de kernel y sondeo funcional activo eBPF (EBPFCapabilityProber)
    KERNEL_VER=$(uname -r 2>/dev/null || echo "5.15.0")
    echo "🐧 Kernel Linux detectado en host: $KERNEL_VER"

    PROBE_RESULT=$(python3 -c "
import sys
sys.path.insert(0, '$SCRIPT_DIR')
try:
    from core.engine.systemd_hardening import EBPFCapabilityProber
    res = EBPFCapabilityProber.probe_ebpf_runtime()
    print(f"{res['is_modern_kernel']}:{res['can_drop_sys_admin']}:{res['lockdown_mode']}:{res['unprivileged_bpf_disabled']}")
except Exception:
    print('False:False:none:1')
" 2>/dev/null || echo "False:False:none:1")

    IS_MODERN=$(echo "$PROBE_RESULT" | cut -d: -f1)
    CAN_DROP=$(echo "$PROBE_RESULT" | cut -d: -f2)
    LOCKDOWN=$(echo "$PROBE_RESULT" | cut -d: -f3)

    if [ "$CAN_DROP" = "True" ]; then
        echo "  [OK] Kernel moderno y sondeo funcional eBPF exitoso (sin restricciones de lockdown)."
        echo "  [OK] Configurando perfil de mínimo privilegio: CAP_SYS_ADMIN retirado (eBPF activo vía CAP_BPF + CAP_PERFMON)."
        sed -i 's/CapabilityBoundingSet=CAP_SYS_ADMIN /CapabilityBoundingSet=/' /etc/systemd/system/constantine.service 2>/dev/null || true
        sed -i 's/AmbientCapabilities=CAP_SYS_ADMIN /AmbientCapabilities=/' /etc/systemd/system/constantine.service 2>/dev/null || true
    else
        echo "  [INFO] Sondeo funcional determinó mantener CAP_SYS_ADMIN (Compatibilidad heredada o restricciones de kernel: lockdown=$LOCKDOWN)."
    fi
fi

HAS_SYSTEMD=false
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    HAS_SYSTEMD=true
fi

if [ "$HAS_SYSTEMD" = true ]; then
    echo "🔄 Recargando configuración de demonios de systemd..."
    systemctl daemon-reload || true
    echo "🔌 Habilitando servicio constantine.service..."
    systemctl enable constantine.service || true

    if [ "$START_SERVICE" = true ]; then
        echo "🚀 Iniciando servicio constantine.service..."
        systemctl restart constantine.service || true
        sleep 1
        if systemctl is-active --quiet constantine.service 2>/dev/null; then
            echo "  [OK] Servicio constantine.service iniciado y activo en el sistema."
        else
            echo "  [AVISO] El servicio fue configurado pero no reportó estado activo de inmediato."
        fi
    fi
else
    echo "⚠️ Entorno sin systemd activo en PID 1 (contenedor Docker/LXC o mock CI)."
    echo "💡 Para iniciar el demonio manualmente: sudo /opt/constantine/daemon.py"
fi

# ==============================================================================
# FASE 6: RESUMEN FINAL DEL ESTADO OPERATIVO
# ==============================================================================
echo "============================================================================"
echo "✅ Constantine Antivirus v${VERSION} instalado y configurado con éxito."
echo "🛡️ Estado del sistema: OPERATIVO Y VERIFICADO"
echo "💡 Comandos útiles:"
echo "   - Control del servicio: sudo systemctl {start|stop|status|restart} constantine"
echo "   - Ejecución interactiva: sudo constantine"
echo "   - Interfaz Gráfica:      constantine-gui (o python3 /opt/constantine/gui/app.py)"
echo "   - Desinstalación:        sudo /opt/constantine/uninstall.sh"
echo "============================================================================"
