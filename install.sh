#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v3.2.7 - Instalador Automatizado (Debian / Ubuntu / Mint)
#
# Novedades Anti-Ransomware en v3.2.7:
# 1. Siembra de Señuelos Estratégicos (Canary Tripwires) en Desktop, Documents, Downloads y Pictures.
# 2. Vigilancia Pasiva de Modificaciones y Borrados sobre Archivos Trampa.
# 3. Detección de Ráfagas Anómalas de Cifrado y Entropía Elevada (H > 7.55).
# 4. Neutralización Atómica de Procesos Ransomware con SIGKILL y Bloqueo de Red UFW.
# 5. Suite completa de 16 motores, Fail-Secure estricto y desinstalador limpio en './uninstall.sh'.
# ==============================================================================
set -e

# ==============================================================================
# ASISTENTE GRÁFICO DE INSTALACIÓN (ESTILO WINDOWS / macOS) CON CONSOLA EN VIVO
# ==============================================================================
if [ "$1" != "--backend-worker" ]; then
    # Si se ejecuta en entorno gráfico y python3 está disponible, lanzar Asistente Visual
    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v python3 >/dev/null 2>&1; then
        export SCRIPT_ABS_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
        export TARGET_USER="${SUDO_USER:-$USER}"
        export TARGET_DISPLAY="${DISPLAY:-:0}"

        # Permitir conexión local X11 si se invocó con sudo
        if [ "$EUID" -eq 0 ] && command -v xhost >/dev/null 2>&1; then
            su - "$TARGET_USER" -c "DISPLAY=$TARGET_DISPLAY xhost +SI:localuser:root" >/dev/null 2>&1 || true
        fi

        python3 - << 'PYEOF'
import sys, os, subprocess, threading, re

try:
    import gi
    try:
        gi.require_version("Gtk", "4.0")
        from gi.repository import Gtk, GLib
        GTK_VER = 4
    except ValueError:
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk, GLib
        GTK_VER = 3
except Exception:
    sys.exit(99) # Fallback limpio a terminal si no hay entorno gráfico GTK

SCRIPT_PATH = os.environ.get("SCRIPT_ABS_PATH", "./install.sh")
REAL_USER = os.environ.get("TARGET_USER", "root")

CSS = b"""
window, .background {
    background-color: #1c1c1e;
    color: #f5f5f7;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Ubuntu", "Cantarell", sans-serif;
}
.title-banner {
    font-size: 16pt;
    font-weight: 700;
    color: #ffffff;
}
.subtitle-banner {
    font-size: 10pt;
    color: #98989d;
}
.step-label {
    font-size: 11pt;
    font-weight: 600;
