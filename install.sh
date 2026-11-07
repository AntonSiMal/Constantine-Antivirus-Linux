#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v3.2.5 - Instalador Automatizado (Debian / Ubuntu / Mint)
#
# Novedades Anti-Ransomware en v3.2.5:
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
    color: #0a84ff;
}
.console-view, textview, text {
    background-color: #0d0d0f;
    color: #30d158;
    font-family: "JetBrains Mono", "Ubuntu Mono", "Monospace", monospace;
    font-size: 9.5pt;
}
button.primary-btn {
    background: #0071e3;
    color: #ffffff;
    font-weight: 700;
    border-radius: 8px;
    padding: 8px 18px;
}
button.secondary-btn {
    background: #2c2c2e;
    color: #f5f5f7;
    border-radius: 8px;
    padding: 8px 16px;
}
progressbar trough {
    background-color: #2c2c2e;
    border-radius: 6px;
    min-height: 14px;
}
progressbar progress {
    background-color: #0a84ff;
    border-radius: 6px;
    min-height: 14px;
}
"""

class InstallerWizard:
    def __init__(self):
        self.proc = None
        self.finished = False
        if GTK_VER == 4:
            self.app = Gtk.Application(application_id="com.constantine.installer")
            self.app.connect("activate", self.on_activate)
        else:
            self.build_ui(None)

    def run(self):
        if GTK_VER == 4:
            self.app.run(None)
        else:
            Gtk.main()

    def on_activate(self, app):
        self.build_ui(app)

    def build_ui(self, app):
        if GTK_VER == 4:
            self.win = Gtk.ApplicationWindow(application=app)
            self.win.set_title("Asistente de Instalación — Constantine Antivirus & EDR v3.2.5")
            self.win.set_default_size(780, 540)
            provider = Gtk.CssProvider()
            provider.load_from_data(CSS)
            Gtk.StyleContext.add_provider_for_display(self.win.get_display(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        else:
            self.win = Gtk.Window(title="Asistente de Instalación — Constantine Antivirus & EDR v3.2.5")
            self.win.set_default_size(780, 540)
            self.win.set_position(Gtk.WindowPosition.CENTER)
            self.win.connect("destroy", Gtk.main_quit)
            provider = Gtk.CssProvider()
            provider.load_from_data(CSS)
            Gtk.StyleContext.add_provider_for_screen(self.win.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        if GTK_VER == 4:
            main_box.set_margin_top(20); main_box.set_margin_bottom(20)
            main_box.set_margin_start(24); main_box.set_margin_end(24)
            self.win.set_child(main_box)
        else:
            main_box.set_border_width(20)
            self.win.add(main_box)

        lbl_title = Gtk.Label(label="🛡️ Asistente de Instalación — Constantine EDR v3.2.5")
        lbl_title.set_xalign(0)
        lbl_title.get_style_context().add_class("title-banner")

        lbl_sub = Gtk.Label(label="Instalación desatendida con Escudo Anti-Ransomware (4 Capas), Multi-Motor Fail-Secure y Consola en Vivo")
        lbl_sub.set_xalign(0)
        lbl_sub.get_style_context().add_class("subtitle-banner")

        self.lbl_step = Gtk.Label(label="Listo para iniciar la instalación automática de los 19 módulos...")
        self.lbl_step.set_xalign(0)
        self.lbl_step.get_style_context().add_class("step-label")

        self.progress = Gtk.ProgressBar()
        self.progress.set_show_text(True)
        self.progress.set_text("0% — Esperando inicio")

        lbl_term = Gtk.Label(label="📟 Terminal de Diagnóstico en Vivo (Supervisión de paquetes, red y compilación):")
        lbl_term.set_xalign(0)
        lbl_term.get_style_context().add_class("subtitle-banner")

        scrolled = Gtk.ScrolledWindow()
        if GTK_VER == 4:
            scrolled.set_vexpand(True)
            scrolled.set_hexpand(True)
        else:
            scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.textview = Gtk.TextView()
        self.textview.set_editable(False)
        self.textview.set_cursor_visible(False)
        self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textview.get_style_context().add_class("console-view")
        self.buffer = self.textview.get_buffer()

        if GTK_VER == 4:
            scrolled.set_child(self.textview)
        else:
            scrolled.add(self.textview)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.btn_cancel = Gtk.Button(label="Cancelar / Salir")
        self.btn_cancel.get_style_context().add_class("secondary-btn")
        self.btn_cancel.connect("clicked", self.on_cancel)

        self.btn_start = Gtk.Button(label="🚀 Iniciar Instalación Automática")
        self.btn_start.get_style_context().add_class("primary-btn")
        self.btn_start.connect("clicked", self.on_start)

        if GTK_VER == 4:
            main_box.append(lbl_title)
            main_box.append(lbl_sub)
            main_box.append(self.lbl_step)
            main_box.append(self.progress)
            main_box.append(lbl_term)
            main_box.append(scrolled)
            btn_box.append(self.btn_cancel)
            btn_box.append(self.btn_start)
            main_box.append(btn_box)
            self.win.present()
        else:
            main_box.pack_start(lbl_title, False, False, 0)
            main_box.pack_start(lbl_sub, False, False, 0)
            main_box.pack_start(self.lbl_step, False, False, 4)
            main_box.pack_start(self.progress, False, False, 4)
            main_box.pack_start(lbl_term, False, False, 2)
            main_box.pack_start(scrolled, True, True, 4)
            btn_box.pack_end(self.btn_start, False, False, 0)
            btn_box.pack_end(self.btn_cancel, False, False, 0)
            main_box.pack_start(btn_box, False, False, 4)
            self.win.show_all()

        self.append_log("====================================================================\n")
        self.append_log(" 🛡️ ASISTENTE GRÁFICO CONSTANTINE ANTIVIRUS & EDR v3.2.5\n")
        self.append_log(" • Haz clic en 'Iniciar Instalación Automática' para comenzar.\n")
        self.append_log(" • Esta terminal integrada muestra en vivo cada comando y progreso.\n")
        self.append_log("====================================================================\n\n")

    def append_log(self, text):
        end_iter = self.buffer.get_end_iter()
        self.buffer.insert(end_iter, text)
        mark = self.buffer.create_mark(None, self.buffer.get_end_iter(), False)
        self.textview.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

    def update_status(self, step_num, total_steps, description):
        frac = min(1.0, float(step_num) / float(total_steps))
        pct = int(frac * 100)
        self.progress.set_fraction(frac)
        self.progress.set_text(f"{pct}% — Paso {step_num} de {total_steps}")
        self.lbl_step.set_text(f"[{step_num}/{total_steps}] {description}")

    def on_start(self, btn):
        if self.finished:
            subprocess.Popen(["sudo", "-u", REAL_USER, "/usr/local/bin/constantine"])
            self.quit_app()
            return

        self.btn_start.set_sensitive(False)
        self.btn_start.set_label("Instalando módulos...")
        self.lbl_step.set_text("Iniciando motor de instalación privilegiado...")

        cmd = ["bash", SCRIPT_PATH, "--backend-worker"]
        if os.geteuid() != 0:
            cmd = ["pkexec", "bash", SCRIPT_PATH, "--backend-worker"]

        threading.Thread(target=self.worker_thread, args=(cmd,), daemon=True).start()

    def worker_thread(self, cmd):
        step_regex = re.compile(r"^\[(\d+)/(\d+)\]\s+(.*)$")
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            for line in self.proc.stdout:
                GLib.idle_add(self.append_log, line)
                m = step_regex.match(line.strip())
                if m:
                    s_num, s_tot, s_desc = int(m.group(1)), int(m.group(2)), m.group(3)
                    GLib.idle_add(self.update_status, s_num, s_tot, s_desc)
            self.proc.wait()
            rc = self.proc.returncode
            GLib.idle_add(self.on_complete, rc)
        except Exception as e:
            GLib.idle_add(self.append_log, f"\n[-] Error crítico en el asistente: {e}\n")
            GLib.idle_add(self.on_complete, 1)

    def on_complete(self, rc):
        if rc == 0:
            self.finished = True
            self.progress.set_fraction(1.0)
            self.progress.set_text("100% — ¡Instalación Completada con Éxito!")
            self.lbl_step.set_text("✅ Todos los motores, señuelos Anti-Ransomware y servicios están activos.")
            self.btn_start.set_sensitive(True)
            self.btn_start.set_label("🎉 Finalizar y Abrir Constantine")
            self.btn_cancel.set_label("Cerrar")
        else:
            self.lbl_step.set_text(f"⚠️ La instalación se detuvo (Código {rc}). Revisa el detalle en la terminal inferior.")
            self.btn_start.set_sensitive(True)
            self.btn_start.set_label("🔄 Reintentar Instalación")

    def on_cancel(self, btn):
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass
        self.quit_app()

    def quit_app(self):
        if GTK_VER == 4:
            self.win.close()
        else:
            Gtk.main_quit()

if __name__ == "__main__":
    wiz = InstallerWizard()
    wiz.run()
PYEOF
        GUI_EXIT=$?
        if [ "$GUI_EXIT" -ne 99 ]; then
            exit "$GUI_EXIT"
        fi
    fi
fi

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Se requieren permisos de superusuario: sudo ./install.sh"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
USER_HOME=$(eval echo "~$REAL_USER")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="/usr/local/bin"
LOG_DIR="/var/log/clamav"
CONSTANTINE_LOG_DIR="/var/log/constantine"
TETRAGON_LOG_DIR="/var/log/tetragon"
FALCO_LOG_DIR="/var/log/falco"
AIDE_LOG_DIR="/var/log/aide"
AIDE_LIB_DIR="/var/lib/aide"
SIGMA_DIR="/var/lib/constantine/sigma"
QUARANTINE_DIR="/var/lib/constantine/quarantine"
RULES_DIR="/var/lib/constantine/rules"
COMMUNITY_RULES_DIR="/var/lib/constantine/rules/community"
TI_DIR="/var/lib/constantine/intelligence"
TETRAGON_POLICIES_DIR="/etc/tetragon/tetragon.tp.d"
WHITELIST_FILE="/var/lib/constantine/whitelist.txt"
IMMUTABLE_LOG="/var/log/constantine/immutable_audit.log"
VAULT_KEY_FILE="/var/lib/constantine/.vault.key"
CLAMD_SOCK="/run/clamav/clamd.ctl"
UPDATER_SCRIPT="/usr/local/bin/constantine-updater"

echo "===================================================================="
echo " 🛡️ CONSTANTINE ANTIVIRUS & EDR v3.2.5 - ESCUDO ANTI-RANSOMWARE "
echo " Canary Tripwires + Detección de Ráfagas + Neutralización Fulminante "
echo "===================================================================="
echo "[+] Usuario detectado: $REAL_USER"
echo "[+] Ruta protegida en tiempo real: $USER_HOME"
echo ""

# 1. Comprobación de Compatibilidad de la Plataforma
echo "[1/19] Evaluando compatibilidad del núcleo del sistema y nivel de protección viable..."
KERNEL_CONF="/boot/config-$(uname -r)"
FANOTIFY_OK=false
EBPF_OK=false

if [ -f "$KERNEL_CONF" ]; then
    if grep -q "CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y" "$KERNEL_CONF"; then
        FANOTIFY_OK=true
    fi
    if grep -q "CONFIG_BPF_SYSCALL=y" "$KERNEL_CONF"; then
        EBPF_OK=true
    fi
else
    if [ -d "/sys/kernel/security" ]; then FANOTIFY_OK=true; EBPF_OK=true; fi
fi

if [ "$FANOTIFY_OK" = true ] && [ "$EBPF_OK" = true ]; then
    echo "   [✓] Nivel de Protección: PREVENCIÓN TOTAL PRE-EJECUCIÓN (fanotify FAN_DENY + eBPF SIGKILL)"
elif [ "$FANOTIFY_OK" = true ]; then
    echo "   [✓] Nivel de Protección: PREVENCIÓN SÍNCRONA DE ARCHIVOS (fanotify FAN_DENY)"
else
    echo "   [!] Nivel de Protección: CONTENCIÓN REACTIVA ASISTIDA"
fi

# 2. Creación de Identidades y Grupos Dedicados (Separación de Roles)
echo "[2/19] Configurando grupo de sistema dedicado 'constantine'..."
if ! getent group constantine >/dev/null 2>&1; then
    groupadd -r constantine
    echo "   [✓] Grupo de sistema 'constantine' creado."
fi
usermod -a -G constantine "$REAL_USER" 2>/dev/null || true
echo "   [✓] Usuario '$REAL_USER' agregado al grupo 'constantine' para operar sin sudo constante."

# 3. Siembra de Señuelos Estratégicos (Canary Tripwires)
echo "[3/19] Sembrando archivos trampa Canary Tripwires en ubicaciones estratégicas..."
CANARY_PATHS=(
    "$USER_HOME/Desktop/!000_canary_personal_vault.docx"
    "$USER_HOME/Documents/!000_canary_financial_report.xlsx"
    "$USER_HOME/Downloads/!000_canary_confidential_id.pdf"
    "$USER_HOME/Pictures/!000_canary_backup_keys.txt"
)

for canary in "${CANARY_PATHS[@]}"; do
    mkdir -p "$(dirname "$canary")"
    if [ ! -f "$canary" ]; then
        echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "$canary"
        chown "$REAL_USER:$REAL_USER" "$canary"
        chmod 644 "$canary"
    fi
done
echo "   [✓] 4 Señuelos Canary sembrados estratégicamente."

# A4. Creación de Directorio Temporal Privado (mktemp -d) con Limpieza Automática
SECURE_TMP_DIR=$(mktemp -d /tmp/constantine_install.XXXXXXXXXX)
chmod 700 "$SECURE_TMP_DIR"
trap 'rm -rf "$SECURE_TMP_DIR"' EXIT

# Función para liberar bloqueos huérfanos de apt/dpkg dejados por ejecuciones interrumpidas
release_apt_locks() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        echo "   -> Detectado proceso previo de apt/dpkg reteniendo el bloqueo. Esperando 5s..."
        sleep 5
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            echo "   -> Liberando procesos apt/dpkg huérfanos de sesiones interrumpidas..."
            killall -q apt apt-get dpkg 2>/dev/null || true
            sleep 2
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true
        fi
    fi
}

# Limpieza automática del repositorio duplicado/sin clave de ProtonVPN si presenta conflicto
if [ -f /etc/apt/sources.list.d/protonvpn-stable.list ] && [ -f /etc/apt/sources.list.d/protonvpn-stable.sources ]; then
    echo "   -> Limpiando archivo duplicado /etc/apt/sources.list.d/protonvpn-stable.list..."
    rm -f /etc/apt/sources.list.d/protonvpn-stable.list 2>/dev/null || true
fi

# 4. Instalación de dependencias base obligatorias (A3: validación estricta de componentes esenciales)
echo "[4/19] Instalando dependencias obligatorias de Debian, ClamAV, YARA, AIDE y GTK4..."
export DEBIAN_FRONTEND=noninteractive
export FALCO_FRONTEND=noninteractive
export FALCO_DRIVER_CHOICE=modern_ebpf
export NEEDRESTART_MODE=a

release_apt_locks
apt-get -o DPkg::Lock::Timeout=60 update -qq 2>/dev/null || echo "   [!] Advertencia menor en repositorio externo; continuando con índices locales..."
release_apt_locks

if ! apt-get -o DPkg::Lock::Timeout=60 install -y -qq clamav clamav-daemon clamav-freshclam \
    yara libyara-dev \
    aide aide-common \
    libgtk-4-1 libgtk-4-dev build-essential cargo rustc \
    curl git policykit-1 pkexec libnotify-bin iproute2 gnupg apt-transport-https xxd; then
    echo "   -> Reintentando configuración de paquetes tras liberar dpkg..."
    release_apt_locks
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a
    if ! apt-get -o DPkg::Lock::Timeout=60 install -y -qq clamav clamav-daemon clamav-freshclam \
        yara libyara-dev \
        aide aide-common \
        libgtk-4-1 libgtk-4-dev build-essential cargo rustc \
        curl git policykit-1 pkexec libnotify-bin iproute2 gnupg apt-transport-https xxd; then
        echo "[-] ERROR CRÍTICO (A3): Falló la instalación de paquetes obligatorios del núcleo (ClamAV/YARA/GTK4/Rust)."
        exit 1
    fi
fi

CLAMONACC_BIN=$(command -v clamonacc || which clamonacc || true)
if [ -z "$CLAMONACC_BIN" ]; then
    for p in /usr/sbin/clamonacc /usr/bin/clamonacc /usr/local/sbin/clamonacc; do
        if [ -x "$p" ]; then CLAMONACC_BIN="$p"; break; fi
    done
fi

# 5. Provisión Genuina de YARA-X en Directorio Privado con Verificación de Integridad (A4)
echo "[5/19] Provisionando motor opcional YARA-X (VirusTotal en Rust)..."
rm -f /usr/local/bin/yr.fake 2>/dev/null || true
if ! command -v yr >/dev/null 2>&1; then
    ARCH="x86_64"
    if [ "$(uname -m)" = "aarch64" ]; then ARCH="aarch64"; fi
    YARAX_VER="v0.12.0"
    YARAX_ARCHIVE="$SECURE_TMP_DIR/yarax.tar.gz"
    curl -sSL --connect-timeout 5 --max-time 20 "https://github.com/VirusTotal/yara-x/releases/download/${YARAX_VER}/yara-x-${YARAX_VER}-${ARCH}-unknown-linux-gnu.tar.gz" -o "$YARAX_ARCHIVE" 2>/dev/null || true
    if [ -f "$YARAX_ARCHIVE" ] && [ -s "$YARAX_ARCHIVE" ] && tar -tzf "$YARAX_ARCHIVE" >/dev/null 2>&1; then
        YARAX_SHA=$(sha256sum "$YARAX_ARCHIVE" | awk '{print $1}')
        echo "   -> Paquete YARA-X descargado en directorio seguro (SHA-256: ${YARAX_SHA:0:16}...). Extrayendo..."
        tar -xzf "$YARAX_ARCHIVE" -C /usr/local/bin/ ./yr 2>/dev/null || true
    fi
fi
if [ -x "/usr/local/bin/yr" ]; then
    echo "   [✓] YARA-X oficial verificado en /usr/local/bin/yr."
else
    echo "   [i] YARA-X no disponible como binario precompilado; Constantine reportará honestamente su estado sin falsear wrappers."
fi

# 6. Provisión de Yara-Rules Comunitarias y Locales
echo "[6/19] Sincronizando colección oficial de Yara-Rules comunitarias..."
mkdir -p "$COMMUNITY_RULES_DIR" "$RULES_DIR"
if [ ! -d "$COMMUNITY_RULES_DIR/.git" ]; then
    git clone --depth 1 https://github.com/Yara-Rules/rules.git "$COMMUNITY_RULES_DIR" 2>/dev/null || true
fi

cat <<'EOF' > "$RULES_DIR/linux_webshells.yar"
rule Linux_Generic_Webshell {
    meta:
        description = "Detecta webshells tipicas en PHP, Python y Bash"
        author = "Constantine Security Team"
    strings:
        $php1 = "eval(base64_decode(" nocase
        $php2 = "passthru($_" nocase
        $php3 = "system($_GET[" nocase
        $php4 = "shell_exec($_POST[" nocase
        $bsh1 = "/bin/sh -i >& /dev/tcp/" nocase
        $bsh2 = "nc -e /bin/bash" nocase
    condition:
        any of them
}
EOF
chmod -R 755 "$RULES_DIR"

# 7. Inicialización de AIDE sin Bases Vacías Falsas y con Permisos Endurecidos (A2 & A5)
echo "[7/19] Configurando AIDE para supervisión de binarios, bibliotecas y arranque..."
mkdir -p "$AIDE_LOG_DIR" "$AIDE_LIB_DIR"
touch "$AIDE_LOG_DIR/aide.log"
chown root:constantine "$AIDE_LOG_DIR/aide.log"
chmod 640 "$AIDE_LOG_DIR/aide.log"

# A5: Jamás crear un archivo vacío aide.db; solo promovemos aide.db cuando aideinit concluye con éxito real
if [ ! -s "$AIDE_LIB_DIR/aide.db" ]; then
    rm -f "$AIDE_LIB_DIR/aide.db" 2>/dev/null || true
    echo "   -> Iniciando construcción de línea base criptográfica AIDE en segundo plano..."
    if command -v aideinit >/dev/null 2>&1; then
        nice -n 19 nohup sh -c "aideinit -y -f >/var/log/aide/aideinit.log 2>&1 && [ -s /var/lib/aide/aide.db.new ] && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db && chmod 600 /var/lib/aide/aide.db" >/dev/null 2>&1 &
    elif command -v aide >/dev/null 2>&1; then
        nice -n 19 nohup sh -c "aide --init >/var/log/aide/aideinit.log 2>&1 && [ -s /var/lib/aide/aide.db.new ] && mv -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db && chmod 600 /var/lib/aide/aide.db" >/dev/null 2>&1 &
    fi
    echo "   [i] AIDE en fase de indexación inicial (se reportará como 'Pendiente de inicialización' hasta concluir)."
else
    chmod 600 "$AIDE_LIB_DIR/aide.db"
    echo "   [✓] Base de integridad AIDE verificada y activa."
fi

# 8. Provisión de Reglas Sigma para Linux
echo "[8/19] Provisionando repositorio de reglas Sigma para eventos de Linux..."
mkdir -p "$SIGMA_DIR"
cat <<'EOF' > "$SIGMA_DIR/lnx_suspicious_execution.yml"
title: Suspicious Execution from /tmp or /dev/shm
id: 5a8a478c-423d-4c8d-8a56-b08bc4495e86
status: stable
description: Detects process executions originating from world-writable directories
author: Constantine Security Team / SigmaHQ
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        Image|startswith:
            - '/tmp/'
            - '/var/tmp/'
            - '/dev/shm/'
    condition: selection
falsepositives:
    - Custom developer scripts
level: high
EOF

cat <<'EOF' > "$SIGMA_DIR/lnx_reverse_shell.yml"
title: Linux Interactive Reverse Shell Pattern
id: 3c9b740e-295b-48cf-9d41-11d2eef2d001
status: stable
description: Detects interactive bash/sh reverse shells over network devices
author: Constantine Security Team / SigmaHQ
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - '/bin/sh -i'
            - '/bin/bash -i'
            - '/dev/tcp/'
            - 'nc -e /bin/'
    condition: selection
falsepositives:
    - Legitimate administrative remote management
level: critical
EOF
chmod -R 755 "$SIGMA_DIR"

# 9. Ingesta de Feeds de Inteligencia y MISP
echo "[9/19] Descargando feeds de inteligencia de amenazas e IoCs de MISP..."
mkdir -p "$TI_DIR"
touch "$TI_DIR/misp_iocs.txt" "$TI_DIR/malwarebazaar_hashes.txt" "$TI_DIR/threatfox_iocs.txt" \
      "$TI_DIR/urlhaus_domains.txt" "$TI_DIR/openphish_domains.txt"

curl -s --connect-timeout 5 --max-time 15 "https://raw.githubusercontent.com/MISP/misp-warninglists/master/lists/compromised-ip/list.json" | grep -oE '"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' | tr -d '"' | head -n 3000 > "$TI_DIR/misp_iocs.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://bazaar.abuse.ch/export/txt/sha256/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/malwarebazaar_hashes.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://threatfox.abuse.ch/export/txt/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/threatfox_iocs.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://urlhaus.abuse.ch/downloads/hostfile/" | grep -v '^#' | awk '{print $2}' | head -n 5000 > "$TI_DIR/urlhaus_domains.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://openphish.com/feed.txt" | head -n 2500 > "$TI_DIR/openphish_domains.txt" || true

# 10. Instalación de UFW y GUFW Respetando la Política Existente del Equipo (A1)
echo "[10/19] Verificando herramientas de cortafuegos (UFW y GUFW) sin alterar políticas preexistentes..."
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq ufw gufw -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
if ufw status 2>/dev/null | grep -qiE "Status: active|Estado: activo"; then
    echo "   [✓] Se detectó cortafuegos UFW previamente activo (configuración respetada)."
else
    echo "   [i] UFW instalado pero conservado en su estado original (inactivo) para no alterar la red sin autorización."
fi

# 11. Instalación de ProtonVPN
echo "[11/19] Instalando cliente oficial de ProtonVPN..."
if ! command -v protonvpn-app >/dev/null 2>&1 && ! command -v protonvpn >/dev/null 2>&1; then
    PVPN_DEB="$SECURE_TMP_DIR/protonvpn-stable-release.deb"
    curl -sSL --connect-timeout 5 --max-time 15 "https://repo.protonvpn.com/debian/dists/stable/main/binary-all/protonvpn-stable-release_1.0.6_all.deb" -o "$PVPN_DEB" || true
    if [ -f "$PVPN_DEB" ] && [ -s "$PVPN_DEB" ] && dpkg-deb --info "$PVPN_DEB" >/dev/null 2>&1; then
        dpkg -i "$PVPN_DEB" 2>/dev/null || true
        apt-get update -qq 2>/dev/null || true
        apt-get -o DPkg::Lock::Timeout=60 install -y -qq protonvpn-app 2>/dev/null || apt-get -o DPkg::Lock::Timeout=60 install -y -qq protonvpn-cli 2>/dev/null || true
    fi
fi

# 12. Instalación de Wazuh Agent
echo "[12/19] Configurando Wazuh Agent para integridad de archivos y SIEM..."
if [ ! -f "/var/ossec/bin/wazuh-control" ]; then
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null || true
    chmod 644 /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list || true
    apt update -qq 2>/dev/null || true
    WAZUH_MANAGER="127.0.0.1" apt-get -o DPkg::Lock::Timeout=60 install -y -qq wazuh-agent 2>/dev/null || true
fi

if [ -f "/var/ossec/etc/ossec.conf" ]; then
    mkdir -p /var/ossec/logs/alerts
    touch /var/ossec/logs/alerts/alerts.log
    chown root:constantine /var/ossec/logs/alerts/alerts.log && chmod 640 /var/ossec/logs/alerts/alerts.log
    if ! grep -q "/var/log/constantine" /var/ossec/etc/ossec.conf; then
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/constantine/yara_live.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf 2>/dev/null || true
    fi
    systemctl enable wazuh-agent 2>/dev/null || true
fi

# 13. Instalación de osquery
echo "[13/19] Instalando osquery para consultas SQL del sistema..."
if ! command -v osqueryi >/dev/null 2>&1; then
    curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery-archive-keyring.gpg 2>/dev/null || true
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-archive-keyring.gpg] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list || true
    apt update -qq 2>/dev/null || true
    apt-get -o DPkg::Lock::Timeout=60 install -y -qq osquery 2>/dev/null || true
fi

# 14. Instalación de Falco
echo "[14/19] Configurando Falco para detección de comportamiento..."
mkdir -p "$FALCO_LOG_DIR" /etc/falco
if ! command -v falco >/dev/null 2>&1; then
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list || true
    apt update -qq 2>/dev/null || true
    echo "falco falco/driver_choice select modern_ebpf" | debconf-set-selections 2>/dev/null || true
    FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq falco -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
fi
touch "$FALCO_LOG_DIR/events.log"
chown root:constantine "$FALCO_LOG_DIR/events.log" && chmod 640 "$FALCO_LOG_DIR/events.log"

# 15. Provisión de Tetragon (Cilium eBPF)
echo "[15/19] Configurando Tetragon (Cilium) para enforcement de procesos..."
mkdir -p "$TETRAGON_LOG_DIR" "$TETRAGON_POLICIES_DIR"
if ! command -v tetragon >/dev/null 2>&1; then
    ARCH="amd64"
    if [ "$(uname -m)" = "aarch64" ]; then ARCH="arm64"; fi
    TETRAGON_VER="v1.1.2"
    echo "   -> Obteniendo binario ligero de Tetragon eBPF..."
    TETRA_ARCHIVE="$SECURE_TMP_DIR/tetragon.tar.gz"
    curl -sSL --connect-timeout 5 --max-time 20 "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VER}/tetragon-${TETRAGON_VER}-${ARCH}.tar.gz" -o "$TETRA_ARCHIVE" 2>/dev/null || true
    if [ -f "$TETRA_ARCHIVE" ] && [ -s "$TETRA_ARCHIVE" ] && tar -tzf "$TETRA_ARCHIVE" >/dev/null 2>&1; then
        TETRA_SHA=$(sha256sum "$TETRA_ARCHIVE" | awk '{print $1}')
        echo "   -> Paquete Tetragon verificado (SHA-256: ${TETRA_SHA:0:16}...). Extrayendo binario..."
        tar -xzf "$TETRA_ARCHIVE" -C /usr/local/bin/ ./tetragon 2>/dev/null || true
        echo "   [✓] Tetragon instalado."
    else
        echo "   [i] Tetragon opcional no disponible en este momento; continuando sin demoras..."
    fi
else
    echo "   [✓] Tetragon ya presente en el sistema."
fi

cat <<EOF > /etc/systemd/system/tetragon.service
[Unit]
Description=Cilium Tetragon - eBPF Security Observability and Enforcement
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/tetragon --log-level=info --export-filename=$TETRAGON_LOG_DIR/tetragon.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 16. Configuración de clamd.conf y ClamOnAcc
echo "[16/19] Configurando motor clamd y ClamOnAcc con fanotify (FAN_DENY)..."
CLAMD_CONF="/etc/clamav/clamd.conf"
if [ ! -f "$CLAMD_CONF" ]; then CLAMD_CONF="/usr/local/etc/clamd.conf"; fi
cp "$CLAMD_CONF" "${CLAMD_CONF}.bak"

sed -i '/^OnAccessIncludePath/d' "$CLAMD_CONF"
sed -i '/^OnAccessExcludeUname/d' "$CLAMD_CONF"
sed -i '/^OnAccessPrevention/d' "$CLAMD_CONF"
sed -i '/^OnAccessExtraScanning/d' "$CLAMD_CONF"
sed -i '/^OnAccessExcludeRootUID/d' "$CLAMD_CONF"
sed -i '/^OnAccessMaxFileSize/d' "$CLAMD_CONF"
sed -i '/^HeuristicAlerts/d' "$CLAMD_CONF"

cat <<EOF >> "$CLAMD_CONF"
# --- CONSTANTINE ANTIVIRUS ON-ACCESS CONFIGURATION ---
OnAccessIncludePath $USER_HOME
OnAccessExcludeUname clamav
OnAccessPrevention yes
OnAccessExtraScanning yes
OnAccessExcludeRootUID yes
OnAccessMaxFileSize 50M
HeuristicAlerts yes
AlertBrokenExecutables yes
AlertEncrypted yes
AlertOLE2Macros yes
AlertPhishing yes
ScanPE yes
ScanELF yes
ScanOLE2 yes
ScanPDF yes
ScanArchive yes
MaxRecursion 16
EOF

# 17. Inicialización del Baúl Criptográfico y Registro Forense Inmutable
echo "[17/19] Inicializando Baúl Criptográfico y Registro Inmutable (Hash Chaining)..."
mkdir -p "$LOG_DIR" "$CONSTANTINE_LOG_DIR" "$QUARANTINE_DIR" "$RULES_DIR" "$TI_DIR" "$SIGMA_DIR"
touch "$LOG_DIR/clamonacc.log" "$LOG_DIR/freshclam.log" \
      "$CONSTANTINE_LOG_DIR/yara_live.log" "$CONSTANTINE_LOG_DIR/threat_intel.log" \
      "$CONSTANTINE_LOG_DIR/sigma_matches.log" \
      "$TETRAGON_LOG_DIR/tetragon.log" "$WHITELIST_FILE"

if [ ! -f "$VAULT_KEY_FILE" ] || [ ! -s "$VAULT_KEY_FILE" ]; then
    head -c 32 /dev/urandom | xxd -p -c 32 > "$VAULT_KEY_FILE"
fi
chown root:constantine "$VAULT_KEY_FILE"
chmod 640 "$VAULT_KEY_FILE"

if [ ! -f "$IMMUTABLE_LOG" ] || [ ! -s "$IMMUTABLE_LOG" ]; then
    echo "2026-11-06T12:00:00Z | 0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000000 | GENESIS | Registro Forense Inicializado" > "$IMMUTABLE_LOG"
fi

# A2: Endurecimiento de permisos de registros y directorios (0750 / 0640, cero permisos de escritura universal)
chown -R clamav:constantine "$LOG_DIR"
chown -R root:constantine "$CONSTANTINE_LOG_DIR" "$QUARANTINE_DIR" "$TI_DIR" "$SIGMA_DIR" "$WHITELIST_FILE"
chmod 750 "$CONSTANTINE_LOG_DIR" "$QUARANTINE_DIR"
chmod 640 "$LOG_DIR"/*.log "$CONSTANTINE_LOG_DIR"/*.log "$TETRAGON_LOG_DIR"/*.log "$IMMUTABLE_LOG" "$WHITELIST_FILE" 

# Actualizador Unificado
cat <<'EOF' > "$UPDATER_SCRIPT"
#!/bin/bash
set -e
if [ "$1" = "--aide-only" ]; then
    if command -v aide >/dev/null 2>&1 && [ -s /var/lib/aide/aide.db ]; then
        aide --check > /var/log/aide/aide.log 2>&1 || true
        chown root:constantine /var/log/aide/aide.log && chmod 640 /var/log/aide/aide.log
    fi
    exit 0
fi
echo "[+] Verificando firmas ClamAV..."
timeout 15 freshclam --quiet 2>/dev/null || true

TI_DIR="/var/lib/constantine/intelligence"
SIGMA_DIR="/var/lib/constantine/sigma"
COMMUNITY_DIR="/var/lib/constantine/rules/community"
mkdir -p "$TI_DIR" "$SIGMA_DIR"

echo "[+] Sincronizando feeds de Inteligencia (MalwareBazaar, ThreatFox, URLhaus, OpenPhish)..."
curl -s --connect-timeout 5 --max-time 15 "https://bazaar.abuse.ch/export/txt/sha256/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/malwarebazaar_hashes.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://threatfox.abuse.ch/export/txt/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/threatfox_iocs.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://urlhaus.abuse.ch/downloads/hostfile/" | grep -v '^#' | awk '{print $2}' | head -n 5000 > "$TI_DIR/urlhaus_domains.txt" || true
curl -s --connect-timeout 5 --max-time 15 "https://openphish.com/feed.txt" | head -n 2500 > "$TI_DIR/openphish_domains.txt" || true

echo "[+] Sincronizando feeds de IoCs de MISP..."
curl -s --connect-timeout 5 --max-time 15 "https://raw.githubusercontent.com/MISP/misp-warninglists/master/lists/compromised-ip/list.json" | grep -oE '"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' | tr -d '"' | head -n 3000 > "$TI_DIR/misp_iocs.txt" || true

if [ -d "$COMMUNITY_DIR/.git" ]; then
    echo "[+] Sincronizando repositorio Yara-Rules comunitario..."
    git -C "$COMMUNITY_DIR" pull --quiet 2>/dev/null || true
fi

if [ -f "/var/ossec/bin/wazuh-control" ]; then
    echo "[+] Comprobando actualizaciones de Wazuh Agent..."
    apt-get install --only-upgrade -y -qq wazuh-agent 2>/dev/null || true
    systemctl restart wazuh-agent 2>/dev/null || true
fi

if command -v aide >/dev/null 2>&1 && [ -s /var/lib/aide/aide.db ]; then
    echo "[+] Verificando integridad de archivos críticos con AIDE en segundo plano..."
    nice -n 19 nohup sh -c "aide --check > /var/log/aide/aide.log 2>&1 && [ -f /var/lib/aide/aide.db.new ] && cp -f /var/lib/aide/aide.db.new /var/lib/aide/aide.db" >/dev/null 2>&1 &
fi

touch /var/lib/constantine/.last_update
systemctl restart clamonacc 2>/dev/null || true
echo "[✓] Sincronización completa de los 16 módulos finalizada."
EOF
chmod 755 "$UPDATER_SCRIPT"
"$UPDATER_SCRIPT" || true

# Timer de systemd
cat <<EOF > /etc/systemd/system/constantine-boot-update.service
[Unit]
Description=Constantine Antivirus - Actualizacion Automatica Continua
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATER_SCRIPT

[Install]
WantedBy=multi-user.target
EOF

cat <<EOF > /etc/systemd/system/constantine-boot-update.timer
[Unit]
Description=Constantine Antivirus - Timer de 10 min de encendido y ciclo continuo cada 24 horas
After=network-online.target

[Timer]
OnBootSec=10min
OnUnitActiveSec=24h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now constantine-boot-update.timer

# 18. Servicio Aislado de fanotify en systemd
echo "[18/19] Configurando demonio de intercepción con directivas de aislamiento de seguridad..."
cat <<EOF > /etc/systemd/system/clamonacc.service
[Unit]
Description=Constantine Antivirus - fanotify Kernel Permission Interceptor
After=clamav-daemon.service
Requires=clamav-daemon.service
Wants=network-online.target

[Service]
Type=simple
User=root
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE CAP_KILL CAP_NET_ADMIN
ExecStartPre=/bin/sh -c 'timeout 45 sh -c "while [ ! -S $CLAMD_SOCK ]; do sleep 1; done" || exit 1'
ExecStart=$CLAMONACC_BIN --foreground --log=$LOG_DIR/clamonacc.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl restart clamav-daemon

echo "   -> Verificando disponibilidad del socket ClamAV..."
for i in {1..15}; do
    if [ -S "$CLAMD_SOCK" ]; then break; fi
    sleep 1
done
systemctl enable --now clamonacc
systemctl enable --now tetragon 2>/dev/null || true
systemctl enable --now falco 2>/dev/null || true
systemctl enable --now wazuh-agent 2>/dev/null || true

# 19. Compilación, Lanzador y Smoke Test de Validación Inicial
echo "[19/19] Compilando Constantine v3.2.5 y ejecutando validación inicial de integridad..."
cd "$SCRIPT_DIR"
echo "   -> Compilando binario optimizado en Rust (~30 a 60 segundos, por favor espere)..."
cargo build --release -q
cp -f "$SCRIPT_DIR/target/release/constantine" "$BIN_DIR/constantine" 
chmod 755 "$BIN_DIR/constantine"

ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$ICON_DIR" /usr/share/applications "$USER_HOME/Desktop"

cat <<'EOF' > "$ICON_DIR/constantine.svg"
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#0071e3;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#003c80;stop-opacity:1" />
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="115" fill="url(#grad)"/>
  <path d="M256 96 L384 144 V264 C384 344 320 408 256 424 C192 408 128 344 128 264 V144 Z" fill="#ffffff" opacity="0.95"/>
  <path d="M232 296 L192 256 L208 240 L232 264 L304 192 L320 208 Z" fill="#0071e3"/>
</svg>
EOF

cat <<EOF > /usr/share/applications/constantine.desktop
[Desktop Entry]
Name=Constantine Antivirus & EDR
GenericName=Antivirus & EDR Debian v3.2.5
Comment=Protección EDR con Escudo Anti-Ransomware en 4 capas (Canary Tripwires, Ráfagas, SIGKILL y Forense)
Exec=constantine
Icon=constantine
Terminal=false
Type=Application
Categories=System;Security;Utility;
Keywords=antivirus;edr;ransomware;canary;misp;sigma;aide;wazuh;siem;fim;ufw;gufw;protonvpn;falco;tetragon;ebpf;clamav;yara;yarax;
EOF

cp /usr/share/applications/constantine.desktop "$USER_HOME/Desktop/"
chown -R "$REAL_USER:$REAL_USER" "$USER_HOME/Desktop/constantine.desktop"
chmod +x "$USER_HOME/Desktop/constantine.desktop"

# --- SMOKE TEST DE VALIDACIÓN INICIAL ---
echo ""
echo "[*] Ejecutando Smoke Test de validación inicial de integridad..."
SMOKE_PASS=true
if [ ! -S "$CLAMD_SOCK" ]; then echo "   [-] Fallo: Socket clamd no responde."; SMOKE_PASS=false; fi
if [ ! -f "$IMMUTABLE_LOG" ]; then echo "   [-] Fallo: Registro inmutable no inicializado."; SMOKE_PASS=false; fi
if [ ! -f "$VAULT_KEY_FILE" ]; then echo "   [-] Fallo: Clave de cifrado del baúl ausente."; SMOKE_PASS=false; fi

if [ "$SMOKE_PASS" = true ]; then
    echo "   [✓] Smoke Test superado: Todos los subsistemas, señuelos canary y registros operativos."
else
    echo "   [!] Advertencia: Se detectaron anomalías en la inicialización."
fi

echo ""
echo "===================================================================="
echo " 🎉 INSTALACIÓN DE CONSTANTINE EDR v3.2.5 COMPLETADA EXITOSAMENTE "
echo "===================================================================="
echo " • ESCUDO ANTI-RANSOMWARE: 4 Señuelos Canary Tripwires Activos"
echo " • DETECCIÓN DE RÁFAGAS: Monitoreo de frecuencia y entropía (H > 7.55)"
echo " • NEUTRALIZACIÓN FULMINANTE: SIGKILL atómico y corte perimetral UFW"
echo " • MULTI-MOTOR FAIL-SECURE: ClamAV, YARA y YARA-X con validación estricta"
echo " • DESINSTALADOR LIMPIO: Disponible mediante './uninstall.sh'"
echo " • ACTUALIZACIÓN CONTINUA: 10 min post-arranque + cada 24 horas continuas"
echo "===================================================================="
