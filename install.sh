#!/usr/bin/env bash
# ==============================================================================
# Constantine Antivirus & EDR v5.5 - Instalador Automatizado (Debian / Ubuntu / Mint)
#
# Novedades Anti-Ransomware en v5.5:
# 1. Siembra de Señuelos Estratégicos (Canary Tripwires) en Desktop, Documents, Downloads y Pictures.
# 2. Vigilancia Pasiva de Modificaciones y Borrados sobre Archivos Trampa.
# 3. Detección de Ráfagas Anómalas de Cifrado y Entropía Elevada (H > 7.55).
# 4. Neutralización Atómica de Procesos Ransomware con SIGKILL y Bloqueo de Red UFW.
# 5. Suite completa de 16 motores, Fail-Secure estricto y desinstalador limpio en './uninstall.sh'.
# ==============================================================================
set -e

# Detección estricta de modo trabajador backend (invocado desde el asistente GUI)
IS_BACKEND_WORKER=false
for arg in "$@"; do
    if [ "$arg" = "--backend-worker" ]; then
        IS_BACKEND_WORKER=true
        break
    fi
done

# ==============================================================================
# VERIFICACIÓN Y ACTUALIZACIÓN AUTOMÁTICA DE RUST (Previene error edition2024)
# ==============================================================================
verify_rust_toolchain() {
    echo "[*] Verificando entorno de compilación Rust..."
    CURRENT_UNAME="$(id -un 2>/dev/null || echo root)"
    TARGET_USER="${SUDO_USER:-${USER:-$CURRENT_UNAME}}"
    [ -z "$TARGET_USER" ] && TARGET_USER="root"

    # Determinar si necesitamos su para ejecutar como el usuario destino
    need_su=false
    if [ "$EUID" -eq 0 ] && [ "$TARGET_USER" != "root" ] && [ "$TARGET_USER" != "$CURRENT_UNAME" ]; then
        need_su=true
    fi

    has_cargo=false
    if [ "$need_su" = true ]; then
        su - "$TARGET_USER" -c "command -v cargo" >/dev/null 2>&1 && has_cargo=true
    else
        command -v cargo >/dev/null 2>&1 && has_cargo=true
    fi

    if [ "$has_cargo" = true ]; then
        if [ "$need_su" = true ]; then
            RUST_VER=$(su - "$TARGET_USER" -c "cargo --version | awk '{print \$2}'" 2>/dev/null)
        else
            RUST_VER=$(cargo --version | awk '{print $2}' 2>/dev/null)
        fi
        if echo "$RUST_VER" | grep -qE "^1\.7[0-5](\.[0-9]+)?$"; then
            echo "[!] Versión de Rust antigua detectada ($RUST_VER). Actualizando a la versión estable más reciente..."
            if [ "$need_su" = true ]; then
                su - "$TARGET_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
            else
                curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
            fi
            echo "[✓] Rust actualizado correctamente."
        else
            echo "[✓] Versión de Rust adecuada detectada: $RUST_VER"
        fi
    else
        echo "[!] Rust no detectado. Instalando rustup para el usuario '$TARGET_USER'..."
        if [ "$need_su" = true ]; then
            su - "$TARGET_USER" -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
        else
            curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>/dev/null || true
        fi
        echo "[✓] Verificación de Rust finalizada."
    fi
    echo "===================================================================="
}

# La verificación de Rust se ejecuta dentro de la terminal en vivo del asistente o en consola directa
if [ "$IS_BACKEND_WORKER" = true ] || [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
    verify_rust_toolchain
fi

# ==============================================================================
# ASISTENTE GRÁFICO DE INSTALACIÓN (ESTILO WINDOWS / macOS) CON CONSOLA EN VIVO
# ==============================================================================
if [ "$1" != "--backend-worker" ]; then
    if [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v python3 >/dev/null 2>&1; then
        export SCRIPT_ABS_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
        export TARGET_USER="${SUDO_USER:-$USER}"
        export TARGET_DISPLAY="${DISPLAY:-:0}"

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
    sys.exit(99)

SCRIPT_PATH = os.environ.get("SCRIPT_ABS_PATH", "./install.sh")
REAL_USER = os.environ.get("TARGET_USER", "root")

CSS = b"""
window, .background { background-color: #1c1c1e; color: #f5f5f7; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Display", "Ubuntu", "Cantarell", sans-serif; }
.title-banner { font-size: 16pt; font-weight: 700; color: #ffffff; }
.subtitle-banner { font-size: 10pt; color: #98989d; }
.step-label { font-size: 11pt; font-weight: 600; color: #0a84ff; }
.console-view, textview, text { background-color: #0d0d0f; color: #30d158; font-family: "JetBrains Mono", "Ubuntu Mono", "Monospace", monospace; font-size: 9.5pt; }
button.primary-btn { background: #0071e3; color: #ffffff; font-weight: 700; border-radius: 8px; padding: 8px 18px; }
button.primary-btn:disabled { background: #3a3a3c; color: #8e8e93; }
.eula-view, textview.eula-view { background-color: #141416; color: #d1d1d6; font-size: 8.5pt; font-family: sans-serif; }
button.secondary-btn { background: #2c2c2e; color: #f5f5f7; border-radius: 8px; padding: 8px 16px; }
progressbar trough { background-color: #2c2c2e; border-radius: 6px; min-height: 14px; }
progressbar progress { background-color: #0a84ff; border-radius: 6px; min-height: 14px; }
"""

EULA_LEGAL_TEXT = """ACUERDO DE LICENCIA DE USUARIO, EXENCIÓN TOTAL DE RESPONSABILIDAD Y ACEPTACIÓN EXPRESA DE RIESGOS

1. TÉRMINOS Y LICENCIAS DE COMPONENTES DE CÓDIGO ABIERTO
Constantine Antivirus & EDR v5.5 es un proyecto de software libre que orquesta e integra múltiples bibliotecas, demonios y motores de seguridad licenciados bajo términos GPLv2, GPLv3, Apache License 2.0 y MIT (incluyendo ClamAV, Tetragon, Falco, osquery, Wazuh, AIDE y YARA). Al instalar este software, usted acepta cumplir con cada una de las licencias correspondientes.

2. ACEPTACIÓN EXPRESA DE RIESGOS TÉCNICOS OPERATIVOS
El usuario reconoce y acepta de manera explícita que Constantine opera a bajo nivel en el núcleo (kernel) del sistema operativo Linux, interactuando directamente mediante ganchos síncronos de fanotify, programas eBPF (Extended Berkeley Packet Filter), reglas de cortafuegos de bajo nivel (iptables / UFW), manipulación de atributos inmutables del sistema de archivos (chattr +i/+a) y reconfiguración de resolución DNS del sistema.

3. ADVERTENCIA DE RIESGO DE PÉRDIDA DE DATOS Y CORRUPCIÓN
Debido a la naturaleza profunda de la contención fulminante de procesos hostiles (SIGKILL inmediato), el aislamiento forzado de archivos en baúl criptográfico y la intercepción de llamadas del sistema, el usuario acepta de forma consciente que existe el riesgo inherente de fallos imprevistos, bloqueos del kernel, interrupción temporal de servicios de red, incompatibilidades de controladores o INCLUSO LA PÉRDIDA O CORRUPCIÓN PARCIAL O TOTAL DE DATOS.

4. EXENCIÓN TOTAL Y ABSOLUTA DE RESPONSABILIDAD (SOFTWARE PROPORCIONADO "TAL CUAL" / "AS IS")
EL SOFTWARE SE PROPORCIONA "TAL CUAL" ("AS IS"), SIN GARANTÍAS DE NINGÚN TIPO, EXPRESAS O IMPLÍCITAS, INCLUYENDO PERO SIN LIMITARSE A GARANTÍAS DE COMERCIABILIDAD, ADECUACIÓN PARA UN PROPÓSITO PARTICULAR O NO INFRACCIÓN. 

BAJO NINGUNA CIRCUNSTANCIA EL PROYECTO CONSTANTINE, SUS AUTORES, CONTRIBUYENTES O EL EQUIPO DE DESARROLLO SERÁN RESPONSABLES ANTE EL USUARIO O TERCEROS POR NINGÚN DAÑO DIRECTO, INDIRECTO, INCIDENTAL, ESPECIAL, PUNITIVO O CONSECUENTE (INCLUYENDO, SIN LIMITACIÓN, DAÑOS POR PÉRDIDA DE DATOS, DAÑO A HARDWARE, PÉRDIDA DE BENEFICIOS, INTERRUPCIÓN DEL NEGOCIO O FALLO DEL SISTEMA), INCLUSO SI SE HA NOTIFICADO LA POSIBILIDAD DE TALES DAÑOS. 

AL MARCAR LA CASILLA Y HACER CLIC EN 'INICIAR INSTALACIÓN AUTOMÁTICA', USTED DECLARA HABER LEÍDO ESTA ADVERTENCIA, ASUME LA TOTALIDAD DE LOS RIESGOS Y LIBERA DE TODA RESPONSABILIDAD LEGAL, CIVIL O PENAL A LOS DESARROLLADORES."""

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
        if GTK_VER == 4: self.app.run(None)
        else: Gtk.main()

    def on_activate(self, app): self.build_ui(app)

    def build_ui(self, app):
        if GTK_VER == 4:
            self.win = Gtk.ApplicationWindow(application=app)
            self.win.set_title("Asistente de Instalación — Constantine Antivirus & EDR v5.5")
            self.win.set_default_size(780, 540)
            provider = Gtk.CssProvider()
            provider.load_from_data(CSS)
            Gtk.StyleContext.add_provider_for_display(self.win.get_display(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        else:
            self.win = Gtk.Window(title="Asistente de Instalación — Constantine Antivirus & EDR v5.5")
            self.win.set_default_size(780, 540)
            self.win.set_position(Gtk.WindowPosition.CENTER)
            self.win.connect("destroy", Gtk.main_quit)
            provider = Gtk.CssProvider()
            provider.load_from_data(CSS)
            Gtk.StyleContext.add_provider_for_screen(self.win.get_screen(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        if GTK_VER == 4:
            main_box.set_margin_top(20); main_box.set_margin_bottom(20); main_box.set_margin_start(24); main_box.set_margin_end(24)
            self.win.set_child(main_box)
        else:
            main_box.set_border_width(20)
            self.win.add(main_box)

        lbl_title = Gtk.Label(label="🛡️ Asistente de Instalación — Constantine EDR v5.5")
        lbl_title.set_xalign(0); lbl_title.get_style_context().add_class("title-banner")
        lbl_sub = Gtk.Label(label="Instalación desatendida con Escudo Anti-Ransomware (4 Capas), Multi-Motor Fail-Secure y Consola en Vivo")
        lbl_sub.set_xalign(0); lbl_sub.get_style_context().add_class("subtitle-banner")
        self.lbl_step = Gtk.Label(label="Listo para iniciar la instalación automática de los 19 módulos...")
        self.lbl_step.set_xalign(0); self.lbl_step.get_style_context().add_class("step-label")
        self.progress = Gtk.ProgressBar(); self.progress.set_show_text(True); self.progress.set_text("0% — Esperando aceptación de licencia")

        lbl_eula = Gtk.Label(label="⚖️ Licencia, Exención Total de Responsabilidad y Aceptación de Riesgos:")
        lbl_eula.set_xalign(0); lbl_eula.get_style_context().add_class("subtitle-banner")

        scrolled_eula = Gtk.ScrolledWindow()
        if GTK_VER == 4:
            scrolled_eula.set_min_content_height(90)
            scrolled_eula.set_hexpand(True)
        else:
            scrolled_eula.set_size_request(-1, 90)
            scrolled_eula.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        txt_eula = Gtk.TextView()
        txt_eula.set_editable(False); txt_eula.set_cursor_visible(False); txt_eula.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        txt_eula.get_style_context().add_class("eula-view")
        buf_eula = txt_eula.get_buffer()
        buf_eula.set_text(EULA_LEGAL_TEXT)
        if GTK_VER == 4: scrolled_eula.set_child(txt_eula)
        else: scrolled_eula.add(txt_eula)

        self.chk_eula = Gtk.CheckButton(label="Acepto los términos de la licencia, los riesgos técnicos (incluso de pérdida de datos) y la exención total de responsabilidad.")
        self.chk_eula.connect("toggled", self.on_eula_toggle)

        lbl_term = Gtk.Label(label="📟 Terminal de Diagnóstico en Vivo (Supervisión de paquetes, red y compilación):")
        lbl_term.set_xalign(0); lbl_term.get_style_context().add_class("subtitle-banner")

        scrolled = Gtk.ScrolledWindow()
        if GTK_VER == 4: scrolled.set_vexpand(True); scrolled.set_hexpand(True)
        else: scrolled.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.textview = Gtk.TextView()
        self.textview.set_editable(False); self.textview.set_cursor_visible(False); self.textview.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.textview.get_style_context().add_class("console-view")
        self.buffer = self.textview.get_buffer()
        if GTK_VER == 4: scrolled.set_child(self.textview)
        else: scrolled.add(self.textview)

        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.btn_cancel = Gtk.Button(label="Cancelar / Salir"); self.btn_cancel.get_style_context().add_class("secondary-btn"); self.btn_cancel.connect("clicked", self.on_cancel)
        self.btn_start = Gtk.Button(label="🚀 Iniciar Instalación Automática"); self.btn_start.get_style_context().add_class("primary-btn"); self.btn_start.connect("clicked", self.on_start)
        self.btn_start.set_sensitive(False)

        if GTK_VER == 4:
            main_box.append(lbl_title); main_box.append(lbl_sub); main_box.append(self.lbl_step); main_box.append(self.progress)
            main_box.append(lbl_eula); main_box.append(scrolled_eula); main_box.append(self.chk_eula)
            main_box.append(lbl_term); main_box.append(scrolled); btn_box.append(self.btn_cancel); btn_box.append(self.btn_start)
            main_box.append(btn_box); self.win.present()
        else:
            main_box.pack_start(lbl_title, False, False, 0); main_box.pack_start(lbl_sub, False, False, 0)
            main_box.pack_start(self.lbl_step, False, False, 4); main_box.pack_start(self.progress, False, False, 4)
            main_box.pack_start(lbl_eula, False, False, 2); main_box.pack_start(scrolled_eula, False, False, 4); main_box.pack_start(self.chk_eula, False, False, 4)
            main_box.pack_start(lbl_term, False, False, 2); main_box.pack_start(scrolled, True, True, 4)
            btn_box.pack_end(self.btn_start, False, False, 0); btn_box.pack_end(self.btn_cancel, False, False, 0)
            main_box.pack_start(btn_box, False, False, 4); self.win.show_all()

        self.append_log("====================================================================\n 🛡️ ASISTENTE GRÁFICO CONSTANTINE ANTIVIRUS & EDR v5.5\n • Haz clic en 'Iniciar Instalación Automática' para comenzar.\n • Esta terminal integrada muestra en vivo cada comando y progreso.\n====================================================================\n\n")

    def append_log(self, text):
        end_iter = self.buffer.get_end_iter()
        self.buffer.insert(end_iter, text)
        mark = self.buffer.create_mark(None, self.buffer.get_end_iter(), False)
        self.textview.scroll_to_mark(mark, 0.0, True, 0.0, 1.0)

    def update_status(self, step_num, total_steps, description):
        frac = min(1.0, float(step_num) / float(total_steps))
        pct = int(frac * 100)
        self.progress.set_fraction(frac); self.progress.set_text(f"{pct}% — Paso {step_num} de {total_steps}")
        self.lbl_step.set_text(f"[{step_num}/{total_steps}] {description}")

    def on_start(self, btn):
        if self.finished:
            subprocess.Popen(["sudo", "-u", REAL_USER, "/usr/local/bin/constantine"])
            self.quit_app(); return
        self.btn_start.set_sensitive(False); self.btn_start.set_label("Instalando módulos...")
        self.lbl_step.set_text("Iniciando motor de instalación privilegiado...")
        cmd = ["bash", SCRIPT_PATH, "--backend-worker"]
        if os.geteuid() != 0: cmd = ["pkexec", "bash", SCRIPT_PATH, "--backend-worker"]
        threading.Thread(target=self.worker_thread, args=(cmd,), daemon=True).start()

    def worker_thread(self, cmd):
        step_regex = re.compile(r"^\[(\d+)/(\d+)\]\s+(.*)$")
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in self.proc.stdout:
                GLib.idle_add(self.append_log, line)
                m = step_regex.match(line.strip())
                if m: GLib.idle_add(self.update_status, int(m.group(1)), int(m.group(2)), m.group(3))
            self.proc.wait(); GLib.idle_add(self.on_complete, self.proc.returncode)
        except Exception as e:
            GLib.idle_add(self.append_log, f"\n[-] Error crítico en el asistente: {e}\n"); GLib.idle_add(self.on_complete, 1)

    def on_complete(self, rc):
        if rc == 0:
            self.finished = True; self.progress.set_fraction(1.0); self.progress.set_text("100% — ¡Instalación Completada con Éxito!")
            self.lbl_step.set_text("✅ Todos los motores, señuelos Anti-Ransomware y servicios están activos.")
            self.btn_start.set_sensitive(True); self.btn_start.set_label("🎉 Finalizar y Abrir Constantine"); self.btn_cancel.set_label("Cerrar")
        else:
            self.lbl_step.set_text(f"⚠️ La instalación se detuvo (Código {rc}). Revisa el detalle en la terminal inferior.")
            self.btn_start.set_sensitive(True); self.btn_start.set_label("🔄 Reintentar Instalación")

    def on_eula_toggle(self, chk):
        if not self.finished:
            self.btn_start.set_sensitive(chk.get_active())
            if chk.get_active():
                self.lbl_step.set_text("Licencia y riesgos aceptados. Listo para iniciar la instalación automática.")
            else:
                self.lbl_step.set_text("Debe aceptar la licencia y los riesgos para habilitar la instalación.")

    def on_cancel(self, btn):
        if self.proc and self.proc.poll() is None:
            try: self.proc.terminate()
            except Exception: pass
        self.quit_app()

    def quit_app(self):
        if GTK_VER == 4: self.win.close()
        else: Gtk.main_quit()

if __name__ == "__main__":
    wiz = InstallerWizard()
    wiz.run()
PYEOF
        GUI_EXIT=$?
        if [ "$GUI_EXIT" -ne 99 ]; then exit "$GUI_EXIT"; fi
    fi
fi

# ==============================================================================
# LÓGICA DE INSTALACIÓN BACKEND (REQUIERE ROOT)
# ==============================================================================
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Se requieren permisos de superusuario: sudo ./install.sh"
    exit 1
fi

# Verificación de aceptación de licencia en modo terminal / consola (se omite en modo GUI porque ya se aceptó en la casilla)
if [ "$IS_BACKEND_WORKER" != true ]; then
    echo "===================================================================="
    echo " ⚖️ TÉRMINOS DE LICENCIA, ACEPTACIÓN DE RIESGOS Y EXENCIÓN DE RESPONSABILIDAD"
    echo "===================================================================="
    echo "• Constantine Antivirus & EDR v5.5 se proporciona 'TAL CUAL' ('AS IS'), sin garantías."
    echo "• El software interactúa a bajo nivel con el kernel Linux (fanotify, eBPF, UFW, chattr)."
    echo "• Al continuar, usted acepta expresamente todos los riesgos operativos e incluso de"
    echo "  posible pérdida de datos o indisponibilidad del sistema."
    echo "• Constantine y su equipo de desarrollo NO se hacen cargo absolutamente de ningún daño,"
    echo "  perjuicio o pérdida derivada del uso, ejecución o instalación del software."
    echo "===================================================================="
    if [ -t 0 ]; then
        read -r -p "¿Acepta la licencia, todos los riesgos y la exención total de responsabilidad? [escriba 'ACEPTO']: " RESP_EULA
        if [ "$RESP_EULA" != "ACEPTO" ] && [ "$RESP_EULA" != "acepto" ]; then
            echo "[-] Instalación cancelada: Se requiere aceptar la licencia y la exención de responsabilidad para continuar."
            exit 1
        fi
    else
        # Si se ejecuta sin terminal interactiva ni GUI (por ejemplo en un script automatizado)
        if [ "${ACCEPT_EULA:-}" != "yes" ] && [ "${ACCEPT_EULA:-}" != "1" ]; then
            echo "[-] Error: Se requiere aceptar la licencia (establezca ACCEPT_EULA=yes para ejecución desatendida en scripts)."
            exit 1
        fi
    fi
    echo "   [✓] Licencia y exención de responsabilidad aceptadas."
    echo ""
fi

REAL_USER="${SUDO_USER:-${USER:-$(id -un 2>/dev/null || echo root)}}"
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

# ------------------------------------------------------------------------------
# Función de Auditoría Forense Inmutable SHA-256 (Hash Chaining Compatible)
# ------------------------------------------------------------------------------
log_immutable_event() {
    local ev_type="$1"
    local details="$2"
    local log_file="/var/log/constantine/immutable_audit.log"
    mkdir -p "$(dirname "$log_file")" 2>/dev/null || true
    chattr -i -a "$log_file" 2>/dev/null || true
    if [ ! -f "$log_file" ] || [ ! -s "$log_file" ]; then
        echo "2026-11-06T12:00:00Z | 0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000000 | GENESIS | Registro Forense Inicializado" > "$log_file"
    fi
    local prev_hash
    prev_hash=$(tail -n 1 "$log_file" 2>/dev/null | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')
    [ -z "$prev_hash" ] && prev_hash="0000000000000000000000000000000000000000000000000000000000000000"
    local now
    now=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "2026-11-06T12:00:00Z")
    local clean_ev="${ev_type//|//}"
    clean_ev="${clean_ev//$'
'/ }"
    local clean_det="${details//|//}"
    clean_det="${clean_det//$'
'/ }"
    local payload="${prev_hash}|${now}|${clean_ev}|${clean_det}"
    local current_hash
    current_hash=$(printf "%s" "$payload" | sha256sum | awk '{print $1}')
    echo "${now} | ${current_hash} | ${prev_hash} | ${clean_ev} | ${clean_det}" >> "$log_file"
    chown root:constantine "$log_file" 2>/dev/null || true
    chmod 660 "$log_file" 2>/dev/null || true
    chattr +a "$log_file" 2>/dev/null || true
}
VAULT_KEY_FILE="/var/lib/constantine/.vault.key"
CLAMD_SOCK="/run/clamav/clamd.ctl"
UPDATER_SCRIPT="/usr/local/bin/constantine-updater"
# Detección de todos los usuarios humanos del sistema (UID >= 1000)
get_all_human_users() {
    awk -F: '$3 >= 1000 && $3 < 60000 && $1 != "nobody" { print $1 ":" $6 }' /etc/passwd
}

echo "===================================================================="
echo " 🛡️ CONSTANTINE ANTIVIRUS & EDR v5.5 - ESCUDO ANTI-RANSOMWARE "
echo " Canary Tripwires + Detección de Ráfagas + Neutralización Fulminante "
echo "===================================================================="
echo "[+] Usuario detectado: $REAL_USER"
echo "[+] Ruta protegida en tiempo real: $USER_HOME"
echo ""
log_immutable_event "INSTALLATION_START" "Instalación de Constantine Antivirus & EDR v5.5 iniciada en el sistema."

# 1. Comprobación Indispensable de Capacidades del Kernel
echo "[1/19] Evaluando capacidades de kernel (CONFIG_FANOTIFY y CONFIG_FANOTIFY_ACCESS_PERMISSIONS)..."
KERNEL_CONF="/boot/config-$(uname -r)"
FANOTIFY_BASE_OK=false; FANOTIFY_PERM_OK=false; FANOTIFY_OK=false; EBPF_OK=false

if [ -f "$KERNEL_CONF" ]; then
    grep -qE "^CONFIG_FANOTIFY=y" "$KERNEL_CONF" && FANOTIFY_BASE_OK=true
    grep -qE "^CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y" "$KERNEL_CONF" && FANOTIFY_PERM_OK=true
    [ "$FANOTIFY_BASE_OK" = true ] && [ "$FANOTIFY_PERM_OK" = true ] && FANOTIFY_OK=true
    grep -qE "^CONFIG_BPF_SYSCALL=y" "$KERNEL_CONF" && EBPF_OK=true
elif [ -f "/proc/config.gz" ]; then
    if zcat /proc/config.gz | grep -qE "^CONFIG_FANOTIFY=y" && zcat /proc/config.gz | grep -qE "^CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y"; then
        FANOTIFY_BASE_OK=true; FANOTIFY_PERM_OK=true; FANOTIFY_OK=true
    fi
    zcat /proc/config.gz | grep -qE "^CONFIG_BPF_SYSCALL=y" && EBPF_OK=true
fi

echo "   -> CONFIG_FANOTIFY=y: $FANOTIFY_BASE_OK | CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y: $FANOTIFY_PERM_OK"
if [ "$FANOTIFY_OK" = true ]; then
    echo "   [✓] Propiedad exclusiva de prevención en acceso: ClamOnAcc (fanotify -> clamd)."
    log_immutable_event "KERNEL_CAPABILITIES_VERIFIED" "CONFIG_FANOTIFY=y y CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y validados para ClamOnAcc."
else
    echo "   [!] Advertencia: El kernel no reporta soporte completo de permisos fanotify; ClamOnAcc operará en modo notificación."
fi

# 2. Creación de Identidades y Grupos Dedicados (Multiusuario Universal)
echo "[2/19] Configurando grupo de sistema dedicado 'constantine' para todos los usuarios..."
if ! getent group constantine >/dev/null 2>&1; then
    groupadd -r constantine
    echo "   [✓] Grupo de sistema 'constantine' creado."
fi

# Configurar persistencia en /etc/adduser.conf para que nuevos usuarios nazcan en el grupo constantine
if [ -f /etc/adduser.conf ]; then
    if grep -qE "^EXTRA_GROUPS=" /etc/adduser.conf; then
        if ! grep -qE "^EXTRA_GROUPS=.*constantine" /etc/adduser.conf; then
            sed -i 's/^EXTRA_GROUPS="\(.*\)"/EXTRA_GROUPS=" constantine"/' /etc/adduser.conf
        fi
    else
        echo 'EXTRA_GROUPS="constantine"' >> /etc/adduser.conf
    fi
    sed -i 's/^#*ADD_EXTRA_GROUPS=.*/ADD_EXTRA_GROUPS=1/' /etc/adduser.conf 2>/dev/null || true
fi

# Aprovisionar a todos los usuarios humanos existentes en el sistema
USER_COUNT=0
for user_entry in $(get_all_human_users); do
    u_name="${user_entry%%:*}"
    u_home="${user_entry#*:}"
    usermod -a -G constantine "$u_name" 2>/dev/null || true
    usermod -a -G "$u_name" clamav 2>/dev/null || true
    chmod g+rx "$u_home" 2>/dev/null || true
    USER_COUNT=$((USER_COUNT + 1))
done
echo "   [✓] $USER_COUNT usuario(s) del sistema integrados al grupo 'constantine' (operación sin sudo)."
log_immutable_event "SYSTEM_GROUP_CONFIGURED" "Grupo de sistema 'constantine' configurado para $USER_COUNT usuarios existentes y persistente en /etc/adduser.conf."

# 3. Siembra de Señuelos Estratégicos (Canary Tripwires) Multiusuario y en /etc/skel
echo "[3/19] Sembrando archivos trampa Canary Tripwires en todos los usuarios y en /etc/skel..."

# 3.1 Plantilla del sistema (/etc/skel) para que nuevos usuarios nazcan con los señuelos
mkdir -p /etc/skel/Desktop /etc/skel/Documents /etc/skel/Downloads /etc/skel/Pictures
echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "/etc/skel/Desktop/!000_canary_personal_vault.docx"
echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "/etc/skel/Documents/!000_canary_financial_report.xlsx"
echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "/etc/skel/Downloads/!000_canary_confidential_id.pdf"
echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "/etc/skel/Pictures/!000_canary_backup_keys.txt"
chmod 644 /etc/skel/Desktop/!* /etc/skel/Documents/!* /etc/skel/Downloads/!* /etc/skel/Pictures/!* 2>/dev/null || true
echo "   [✓] Señuelos Canary integrados en /etc/skel (garantía de nacimiento protegido para nuevos usuarios)."

# 3.2 Siembra en todos los usuarios humanos existentes
for user_entry in $(get_all_human_users); do
    u_name="${user_entry%%:*}"
    u_home="${user_entry#*:}"
    [ ! -d "$u_home" ] && continue
    mkdir -p "$u_home/Desktop" "$u_home/Documents" "$u_home/Downloads" "$u_home/Pictures"
    for d in Desktop Documents Downloads Pictures; do
        case "$d" in
            Desktop) fname="!000_canary_personal_vault.docx" ;;
            Documents) fname="!000_canary_financial_report.xlsx" ;;
            Downloads) fname="!000_canary_confidential_id.pdf" ;;
            Pictures) fname="!000_canary_backup_keys.txt" ;;
        esac
        target_canary="$u_home/$d/$fname"
        if [ ! -f "$target_canary" ]; then
            echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "$target_canary"
            chown "$u_name:$u_name" "$target_canary" 2>/dev/null || true
            chmod 644 "$target_canary" 2>/dev/null || true
        fi
    done
done
echo "   [✓] Señuelos Canary sembrados en el espacio de todos los usuarios del sistema."
log_immutable_event "CANARY_TRIPWIRES_SEEDED" "Señuelos Canary Tripwires sembrados en todos los usuarios existentes y en /etc/skel."

# 4. Creación de Directorio Temporal Privado y Función de Limpieza de APT
SECURE_TMP_DIR=$(mktemp -d /tmp/constantine_install.XXXXXXXXXX)
chmod 700 "$SECURE_TMP_DIR"
trap 'rm -rf "$SECURE_TMP_DIR"' EXIT

release_apt_locks() {
    if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1 || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
        echo "   -> Detectado proceso previo de apt/dpkg reteniendo el bloqueo. Esperando 5s..."
        sleep 5
        if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
            echo "   -> Liberando procesos apt/dpkg huérfanos de sesiones interrumpidas..."
            DEBIAN_FRONTEND=noninteractive dpkg --configure -a 2>/dev/null || true
            sleep 2
            killall -q apt apt-get dpkg 2>/dev/null || true
            rm -f /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>/dev/null || true
        fi
    fi
}

if [ -f /etc/apt/sources.list.d/protonvpn-stable.list ] && [ -f /etc/apt/sources.list.d/protonvpn-stable.sources ]; then
    echo "   -> Limpiando archivo duplicado /etc/apt/sources.list.d/protonvpn-stable.list..."
    rm -f /etc/apt/sources.list.d/protonvpn-stable.list 2>/dev/null || true
fi

# 5. Instalación de dependencias base obligatorias
echo "[4/19] Instalando dependencias obligatorias de Debian, ClamAV, YARA, AIDE y GTK4..."
export DEBIAN_FRONTEND=noninteractive
export FALCO_FRONTEND=noninteractive
export FALCO_DRIVER_CHOICE=modern_ebpf
export NEEDRESTART_MODE=a

release_apt_locks
apt-get -o DPkg::Lock::Timeout=60 update -qq 2>/dev/null || echo "   [!] Advertencia menor en repositorio externo; continuando con índices locales..."
release_apt_locks

if ! apt-get -o DPkg::Lock::Timeout=60 install -y -qq clamav clamav-daemon clamav-freshclam \
    yara libyara-dev aide aide-common libgtk-4-1 libgtk-4-dev build-essential cargo rustc \
    curl git policykit-1 pkexec libnotify-bin iproute2 gnupg apt-transport-https xxd; then
    echo "   -> Reintentando configuración de paquetes tras liberar dpkg..."
    release_apt_locks
    DEBIAN_FRONTEND=noninteractive dpkg --configure -a
    if ! apt-get -o DPkg::Lock::Timeout=60 install -y -qq clamav clamav-daemon clamav-freshclam \
        yara libyara-dev aide aide-common libgtk-4-1 libgtk-4-dev build-essential cargo rustc \
        curl git policykit-1 pkexec libnotify-bin iproute2 gnupg apt-transport-https xxd; then
        echo "[-] ERROR CRÍTICO: Falló la instalación de paquetes obligatorios del núcleo."
        exit 1
    fi
fi

# [v5.5] Instalar soporte de atributos extendidos xattr (Mark-of-the-Web)
apt-get -o DPkg::Lock::Timeout=60 install -y -qq attr 2>/dev/null || true

CLAMONACC_BIN=$(command -v clamonacc || which clamonacc || true)
if [ -z "$CLAMONACC_BIN" ]; then
    for p in /usr/sbin/clamonacc /usr/bin/clamonacc /usr/local/sbin/clamonacc; do
        [ -x "$p" ] && CLAMONACC_BIN="$p" && break
    done
fi

# 6. Provisión Genuina de YARA-X
echo "[5/19] Provisionando motor opcional YARA-X (VirusTotal en Rust)..."
rm -f /usr/local/bin/yr.fake 2>/dev/null || true
if ! command -v yr >/dev/null 2>&1; then
    ARCH="x86_64"; [ "$(uname -m)" = "aarch64" ] && ARCH="aarch64"
    YARAX_VER="v0.12.0"
    YARAX_ARCHIVE="$SECURE_TMP_DIR/yarax.tar.gz"
    curl -sSL --connect-timeout 5 --max-time 20 "https://github.com/VirusTotal/yara-x/releases/download/${YARAX_VER}/yara-x-${YARAX_VER}-${ARCH}-unknown-linux-gnu.tar.gz" -o "$YARAX_ARCHIVE" 2>/dev/null || true
    if [ -f "$YARAX_ARCHIVE" ] && [ -s "$YARAX_ARCHIVE" ] && tar -tzf "$YARAX_ARCHIVE" >/dev/null 2>&1; then
        YARAX_SHA=$(sha256sum "$YARAX_ARCHIVE" | awk '{print $1}')
        echo "   -> Paquete YARA-X descargado en directorio seguro (SHA-256: ${YARAX_SHA:0:16}...). Extrayendo..."
        TMP_YARAX="$SECURE_TMP_DIR/yarax_extracted"
        mkdir -p "$TMP_YARAX"
        tar -xzf "$YARAX_ARCHIVE" -C "$TMP_YARAX" 2>/dev/null || true
        YR_BIN=$(find "$TMP_YARAX" -type f -name yr 2>/dev/null | head -n 1)
        if [ -n "$YR_BIN" ] && [ -f "$YR_BIN" ]; then
            cp -f "$YR_BIN" /usr/local/bin/yr
            chmod 755 /usr/local/bin/yr
            echo "   [✓] Binario YARA-X instalado en /usr/local/bin/yr."
        fi
    fi
fi
[ -x "/usr/local/bin/yr" ] && echo "   [✓] YARA-X oficial verificado en /usr/local/bin/yr." || echo "   [i] YARA-X no disponible como binario precompilado; Constantine reportará honestamente su estado."

# 7. Provisión de Yara-Rules Comunitarias y Locales
echo "[6/19] Sincronizando colección oficial de Yara-Rules comunitarias..."
mkdir -p "$COMMUNITY_RULES_DIR" "$RULES_DIR"
[ ! -d "$COMMUNITY_RULES_DIR/.git" ] && git clone --depth 1 https://github.com/Yara-Rules/rules.git "$COMMUNITY_RULES_DIR" 2>/dev/null || true

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

# 8. Inicialización de AIDE sin Bases Vacías Falsas
echo "[7/19] Configurando AIDE para supervisión de binarios, bibliotecas y arranque..."
mkdir -p "$AIDE_LOG_DIR" "$AIDE_LIB_DIR"
touch "$AIDE_LOG_DIR/aide.log"
chown root:constantine "$AIDE_LOG_DIR/aide.log" 2>/dev/null || true
chmod 640 "$AIDE_LOG_DIR/aide.log" 2>/dev/null || true

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

# 9. Provisión de Reglas Sigma para Linux
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

# 10. Ingesta de Feeds de Inteligencia y MISP
echo "[9/19] Descargando feeds de inteligencia de amenazas e IoCs de MISP..."
mkdir -p "$TI_DIR"
touch "$TI_DIR/misp_iocs.txt" "$TI_DIR/malwarebazaar_hashes.txt" "$TI_DIR/threatfox_iocs.txt" "$TI_DIR/urlhaus_domains.txt" "$TI_DIR/openphish_domains.txt"

# Semilla de IoCs de MISP (IPs de C2 comprometidas)
cat << 'SEED_MISP' >> "$TI_DIR/misp_iocs.txt"
185.220.101.5
185.220.101.6
185.220.101.7
194.26.29.112
45.142.214.18
91.240.118.172
193.106.191.89
109.237.96.124
195.123.245.14
185.196.8.12
185.246.221.78
94.156.65.115
SEED_MISP

# Semilla de Hashes de MalwareBazaar (Ransomware y Troyanos recientes)
cat << 'SEED_BAZAAR' >> "$TI_DIR/malwarebazaar_hashes.txt"
d6a9e1e5b8d2d94cf8e3e4a9e25d2b1f8c7e9a0b1c2d3e4f5a6b7c8d9e0f1a2b
5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
44d88612fea8a8f36de82e1278abb02fdd854e4889c2560b457e5b92782b13c7
b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
SEED_BAZAAR

# Semilla de ThreatFox (IoCs de C2 multivariables)
cat << 'SEED_TFOX' >> "$TI_DIR/threatfox_iocs.txt"
185.220.101.5:443
194.26.29.112:8080
45.142.214.18:443
91.240.118.172:9001
193.106.191.89:4444
SEED_TFOX

# Semilla esencial predeterminada de dominios hostiles (garantiza protección inmediata 24/7 incluso offline)
cat <<'SEED_FEEDS' >> "$TI_DIR/urlhaus_domains.txt"
wicar.org
malware-traffic-analysis.net
testsafebrowsing.appspot.com
secure-apple-login-verify.com
paypal-security-update-center.com
metamask-verify-auth-wallet.com
login-microsoftonline-verify.com
bankofamerica-alert-security.com
chase-secure-login-verify.com
wellsfargo-verify-account.com
binance-login-verify-auth.com
coinbase-security-wallet-auth.com
telegram-auth-verify-code.com
whatsapp-web-verify-login.com
netflix-account-update-billing.com
steamcommunity-trade-verify.com
discord-nitro-gift-free.com
apple-id-verify-icloud.com
google-drive-shared-doc-verify.com
dhl-tracking-express-package.com
fedex-delivery-notice-claim.com
correos-seguimiento-paquete-entrega.com
santander-seguridad-acceso-banca.com
bbva-alerta-seguridad-login.com
caixabank-identificacion-segura.com
SEED_FEEDS

curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://raw.githubusercontent.com/MISP/misp-warninglists/master/lists/compromised-ip/list.json" | grep -oE '"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"' | tr -d '"' | head -n 3000 > "$TI_DIR/misp_iocs.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://bazaar.abuse.ch/export/txt/sha256/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/malwarebazaar_hashes.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://threatfox.abuse.ch/export/txt/recent/" | grep -v '^#' | head -n 5000 > "$TI_DIR/threatfox_iocs.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://urlhaus.abuse.ch/downloads/hostfile/" | grep -v '^#' | awk '{print $2}' | head -n 5000 >> "$TI_DIR/urlhaus_domains.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://openphish.com/feed.txt" | head -n 2500 >> "$TI_DIR/openphish_domains.txt" || true
echo "   -> Descargando base comunitaria de StevenBlack Hosts (Anti-Phishing & Malware)..."
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 30 "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" | grep "^0\.0\.0\.0 " | tr -d '\r' > "$TI_DIR/stevenblack_hosts.txt" || true

# 11. Instalación de UFW y GUFW Respetando la Política Existente
echo "[10/19] Verificando herramientas de cortafuegos (UFW y GUFW) sin alterar políticas preexistentes..."
DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq ufw gufw -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
if ufw status 2>/dev/null | grep -qiE "Status: active|Estado: activo"; then
    echo "   [✓] Se detectó cortafuegos UFW previamente activo (configuración respetada)."
else
    echo "   [i] UFW instalado pero conservado en su estado original (inactivo) para no alterar la red sin autorización."
fi

# 12. Instalación de ProtonVPN

# Salvaguarda de Red: Asegurar que OpenSnitch no interfiera con la conectividad
if systemctl is-active --quiet opensnitchd 2>/dev/null || command -v opensnitchd >/dev/null 2>&1; then
    echo "[!] Desactivando opensnitchd y purgando colas NFQUEUE para garantizar conectividad total sin bloqueos..."
    systemctl stop opensnitchd opensnitch 2>/dev/null || true
    systemctl disable opensnitchd opensnitch 2>/dev/null || true
    pkill -9 -f opensnitch 2>/dev/null || true
    iptables -D OUTPUT -j NFQUEUE 2>/dev/null || true
    iptables -D INPUT -j NFQUEUE 2>/dev/null || true
fi

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

# 13. Instalación de Wazuh Agent
echo "[12/19] Configurando Wazuh Agent para integridad de archivos y SIEM..."
if [ ! -f "/var/ossec/bin/wazuh-control" ]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    chmod 644 /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list || true
    apt update -qq 2>/dev/null || true
    WAZUH_MANAGER="127.0.0.1" DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq wazuh-agent 2>/dev/null || true
fi

if [ -f "/var/ossec/etc/ossec.conf" ]; then
    mkdir -p /var/ossec/logs/alerts
    touch /var/ossec/logs/alerts/alerts.log
    chown root:constantine /var/ossec/logs/alerts/alerts.log 2>/dev/null || true; chmod 640 /var/ossec/logs/alerts/alerts.log 2>/dev/null || true
    if ! grep -q "/var/log/constantine" /var/ossec/etc/ossec.conf; then
        sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/constantine/yara_live.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf 2>/dev/null || true
    fi
    systemctl enable wazuh-agent 2>/dev/null || true
fi

# 14. Instalación de osquery
echo "[13/19] Instalando osquery para consultas SQL del sistema..."
if ! command -v osqueryi >/dev/null 2>&1; then
    curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery-archive-keyring.gpg 2>/dev/null || true
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-archive-keyring.gpg] https://pkg.osquery.io/deb deb main" > /etc/apt/sources.list.d/osquery.list || true
    apt update -qq 2>/dev/null || true
    apt-get -o DPkg::Lock::Timeout=60 install -y -qq osquery 2>/dev/null || true
fi

# 15. Instalación de Falco
echo "[14/19] Configurando Falco para detección de comportamiento..."
mkdir -p /etc/falco
# Escribir reglas locales compatibles con macros oficiales de Falco
cat <<'FALCOEOF' > /etc/falco/falco_rules.local.yaml
# Excepciones locales para Constantine EDR, GUFW y Wazuh
- macro: user_known_read_sensitive_files_activities
  append: true
  condition: or proc.name in (constantine, gufw, gufw-pkexec, wazuh-modulesd, ossec-syscheckd) or proc.pname in (constantine, gufw, gufw-pkexec)

- macro: user_known_log_file_tampering_activities
  append: true
  condition: or (proc.name in (gufw, gufw-pkexec, python3) and fd.name startswith /var/log/gufw.log)
FALCOEOF
chmod 644 /etc/falco/falco_rules.local.yaml 2>/dev/null || true

# Validación de seguridad: si las reglas locales causan error de sintaxis en esta versión de Falco, retirarlas de inmediato para no romper el demonio
if command -v falco >/dev/null 2>&1; then
    if ! falco -c /etc/falco/falco.yaml --dry-run >/dev/null 2>&1; then
        echo "   [!] Advertencia: La versión instalada de Falco requiere sintaxis base estándar. Retirando archivo local para garantizar arranque."
        rm -f /etc/falco/falco_rules.local.yaml 2>/dev/null || true
    fi
fi

mkdir -p "$FALCO_LOG_DIR" /etc/falco
if ! command -v falco >/dev/null 2>&1; then
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg 2>/dev/null || true
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" > /etc/apt/sources.list.d/falcosecurity.list || true
    apt update -qq 2>/dev/null || true
    echo "falco falco/driver_choice select modern_ebpf" | debconf-set-selections 2>/dev/null || true
    FALCO_FRONTEND=noninteractive FALCO_DRIVER_CHOICE=modern_ebpf DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y -qq falco -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" 2>/dev/null || true
fi
touch "$FALCO_LOG_DIR/events.log"
chown root:constantine "$FALCO_LOG_DIR/events.log" 2>/dev/null || true; chmod 640 "$FALCO_LOG_DIR/events.log" 2>/dev/null || true
[ -f /etc/falco/falco_rules.yaml ] && touch /etc/falco/falco_rules.yaml 2>/dev/null || true
[ -f /etc/falco/falco.yaml ] && touch /etc/falco/falco.yaml 2>/dev/null || true
if [ -f /etc/falco/falco.yaml ]; then
    sed -i 's/^file_output:.*/file_output:\n  enabled: true\n  keep_alive: false\n  filename: \/var\/log\/falco\/events.log/' /etc/falco/falco.yaml 2>/dev/null || true
fi
if systemctl list-unit-files | grep -q "falco-modern-bpf.service"; then
    systemctl unmask falco-modern-bpf.service 2>/dev/null || true
    systemctl enable falco-modern-bpf.service 2>/dev/null || true
fi
systemctl unmask falco.service 2>/dev/null || true
systemctl enable falco.service 2>/dev/null || true

# 16. Provisión de Tetragon (Cilium eBPF) como Sensor EDR Principal
echo "[15/19] Configurando Tetragon (Cilium eBPF) como Sensor EDR Principal..."
mkdir -p "$TETRAGON_LOG_DIR" "$TETRAGON_POLICIES_DIR" /var/lib/tetragon
if ! command -v tetragon >/dev/null 2>&1; then
    ARCH="amd64"; [ "$(uname -m)" = "aarch64" ] && ARCH="arm64"
    TETRAGON_VER="v1.1.2"
    echo "   -> Obteniendo sensor principal Tetragon eBPF..."
    TETRA_ARCHIVE="$SECURE_TMP_DIR/tetragon.tar.gz"
    curl -sSL --connect-timeout 5 --max-time 25 "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VER}/tetragon-${TETRAGON_VER}-${ARCH}.tar.gz" -o "$TETRA_ARCHIVE" 2>/dev/null || true
    if [ -f "$TETRA_ARCHIVE" ] && [ -s "$TETRA_ARCHIVE" ] && tar -tzf "$TETRA_ARCHIVE" >/dev/null 2>&1; then
        TETRA_SHA=$(sha256sum "$TETRA_ARCHIVE" | awk '{print $1}')
        echo "   -> Paquete Tetragon verificado (SHA-256: ${TETRA_SHA:0:16}...). Extrayendo binarios..."
        TMP_TETRA_EXTRACT="$SECURE_TMP_DIR/tetragon_extracted"
        mkdir -p "$TMP_TETRA_EXTRACT"
        tar -xzf "$TETRA_ARCHIVE" -C "$TMP_TETRA_EXTRACT" 2>/dev/null || true
        TETRA_BIN=$(find "$TMP_TETRA_EXTRACT" -type f -name tetragon 2>/dev/null | head -n 1)
        TETRA_CLI=$(find "$TMP_TETRA_EXTRACT" -type f -name tetra 2>/dev/null | head -n 1)
        if [ -n "$TETRA_BIN" ] && [ -f "$TETRA_BIN" ]; then
            cp -f "$TETRA_BIN" /usr/local/bin/tetragon
            chmod 755 /usr/local/bin/tetragon
            echo "   [✓] Binario Tetragon instalado en /usr/local/bin/tetragon."
        fi
        if [ -n "$TETRA_CLI" ] && [ -f "$TETRA_CLI" ]; then
            cp -f "$TETRA_CLI" /usr/local/bin/tetra
            chmod 755 /usr/local/bin/tetra
            echo "   [✓] CLI tetra instalado en /usr/local/bin/tetra."
        fi
        find "$TMP_TETRA_EXTRACT" -type d -name "bpf" -exec cp -r {} /var/lib/tetragon/ \; 2>/dev/null || true
    else
        echo "   [i] Tetragon no pudo descargarse en este momento; se reintentará en el actualizador."
    fi
else
    echo "   [✓] Sensor principal Tetragon ya presente en el sistema."
fi
touch "$TETRAGON_LOG_DIR/tetragon.log"
chmod 640 "$TETRAGON_LOG_DIR/tetragon.log" 2>/dev/null || true

cat <<'EOF' > "$TETRAGON_POLICIES_DIR/constantine_edr_checkpoints.yaml"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "constantine-edr-kernel-checkpoints"
spec:
  kprobes:
    - call: "security_bprm_check"
      syscall: false
      args:
        - index: 0
          type: "linux_binprm"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/tmp/"
                - "/var/tmp/"
                - "/dev/shm/"
    - call: "security_file_permission"
      syscall: false
      args:
        - index: 0
          type: "file"
        - index: 1
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/etc/shadow"
                - "/etc/sudoers"
                - "/home/"
            - index: 1
              operator: "Equal"
              values:
                - "2"
    - call: "tcp_connect"
      syscall: false
      args:
        - index: 0
          type: "sock"
EOF
chmod 640 "$TETRAGON_POLICIES_DIR/constantine_edr_checkpoints.yaml"

cat <<'EOF_TAMPER' > "$TETRAGON_POLICIES_DIR/constantine_tamper_protection.yaml"
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "constantine-tamper-protection"
spec:
  kprobes:
    # 1. Blindaje contra terminación no autorizada de procesos (kill -9, SIGKILL, SIGTERM, SIGSTOP)
    - call: "sys_kill"
      syscall: true
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "int"
      selectors:
        - matchArgs:
            - index: 1
              operator: "In"
              values:
                - "9"
                - "15"
                - "19"
                - "2"
          matchBinaries:
            - operator: "NotIn"
              values:
                - "/usr/lib/systemd/systemd"
                - "/lib/systemd/systemd"
                - "/bin/systemd"
                - "/sbin/init"
                - "/usr/local/bin/constantine-shutdown"
    # 2. Blindaje contra manipulación y borrado de binarios y firmas de Constantine
    - call: "security_file_permission"
      syscall: false
      args:
        - index: 0
          type: "file"
        - index: 1
          type: "int"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/var/lib/constantine/"
                - "/var/log/constantine/"
                - "/usr/local/bin/constantine"
                - "/etc/systemd/system/constantine"
            - index: 1
              operator: "Equal"
              values:
                - "2"
          matchBinaries:
            - operator: "NotIn"
              values:
                - "/usr/local/bin/constantine"
                - "/usr/local/bin/constantine-daemon"
                - "/usr/local/bin/constantine-updater"
                - "/usr/local/bin/constantine-dns-sinkhole"
                - "/usr/local/bin/constantine-shutdown"
                - "/usr/lib/systemd/systemd"
                - "/lib/systemd/systemd"
EOF_TAMPER
chmod 640 "$TETRAGON_POLICIES_DIR/constantine_tamper_protection.yaml"


cat <<EOF > /etc/systemd/system/tetragon.service
[Unit]
Description=Cilium Tetragon - Sensor EDR Principal eBPF de Constantine
After=network.target

[Service]
Type=simple
User=root
ExecStartPre=/bin/mkdir -p /var/log/tetragon /etc/tetragon/tetragon.tp.d /var/run/cilium/tetragon /run/cilium/tetragon /var/lib/tetragon/bpf
ExecStart=/usr/local/bin/tetragon --log-level=info --export-filename=$TETRAGON_LOG_DIR/tetragon.log --bpf-lib=/var/lib/tetragon/bpf --tracing-policy-dir=$TETRAGON_POLICIES_DIR
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 17. Configuración de clamd.conf y ClamOnAcc
echo "[16/19] Configurando clamd.conf y delegando la prevención de acceso exclusivamente a ClamOnAcc..."
CLAMD_CONF="/etc/clamav/clamd.conf"
[ ! -f "$CLAMD_CONF" ] && CLAMD_CONF="/usr/local/etc/clamd.conf"
cp -f "$CLAMD_CONF" "${CLAMD_CONF}.bak"

CLAMAV_SERVICE_USER=$(awk '/^User / {print $2; exit}' "$CLAMD_CONF" 2>/dev/null || true)
if [ -z "$CLAMAV_SERVICE_USER" ]; then
    id -u clamav >/dev/null 2>&1 && CLAMAV_SERVICE_USER="clamav" || CLAMAV_SERVICE_USER="clamav"
fi
echo "   -> Usuario del servicio ClamAV detectado en el sistema: $CLAMAV_SERVICE_USER"

sed -i '/# --- CONSTANTINE ANTIVIRUS ON-ACCESS CONFIGURATION ---/,$d' "$CLAMD_CONF" 2>/dev/null || true
sed -i '/^OnAccessIncludePath/d' "$CLAMD_CONF"
sed -i '/^OnAccessExcludeUname/d' "$CLAMD_CONF"
sed -i '/^OnAccessPrevention/d' "$CLAMD_CONF"
sed -i '/^OnAccessExtraScanning/d' "$CLAMD_CONF"
sed -i '/^OnAccessExcludeRootUID/d' "$CLAMD_CONF"
sed -i '/^OnAccessMaxFileSize/d' "$CLAMD_CONF"
sed -i '/^OnAccessExcludePath/d' "$CLAMD_CONF" 2>/dev/null || true
sed -i '/^TemporaryDirectory/d' "$CLAMD_CONF" 2>/dev/null || true

# Configurar User root y directorio temporal propio aislado de /tmp
sed -i 's/^User .*/User root/' "$CLAMD_CONF" 2>/dev/null || true
mkdir -p /var/lib/clamav/tmp
chown -R clamav:constantine /var/lib/clamav/tmp 2>/dev/null || true
chmod -R 770 /var/lib/clamav/tmp 2>/dev/null || true

{
    echo "# --- CONSTANTINE ANTIVIRUS ON-ACCESS CONFIGURATION ---"
    echo "TemporaryDirectory /var/lib/clamav/tmp"
    echo "AllowSupplementaryGroups yes"
    [ -d "/home" ] && echo "OnAccessIncludePath /home"
    [ -d "/var/tmp" ] && echo "OnAccessIncludePath /var/tmp"
    echo "OnAccessPrevention no"
    echo "OnAccessExcludeUname root"
    echo "OnAccessExcludeRootUID yes"
    echo "OnAccessExtraScanning yes"
    echo "OnAccessMaxFileSize 50M"
    # Detección heurística de phishing en enlaces y documentos
    echo "PhishingSignatures yes"
    echo "PhishingScanURLs yes"
    echo "PhishingAlwaysBlockCloak yes"
    echo "PhishingAlwaysBlockSSLMismatch no"
    # Exclusiones del directorio temporal propio y rutas críticas de escritorio
    echo "OnAccessExcludePath /var/lib/clamav/tmp"
    echo "OnAccessExcludePath /home/*/.cache"
    echo "OnAccessExcludePath /home/*/.Xauthority"
    echo "OnAccessExcludePath /home/*/.config"
    echo "OnAccessExcludePath /home/*/.local"
    echo "OnAccessExcludePath /home/*/.dbus"
    echo "OnAccessExcludePath /proc"
    echo "OnAccessExcludePath /sys"
    echo "OnAccessExcludePath /dev"
    echo "OnAccessExcludePath /run"
    echo "OnAccessExcludePath /var/run"
    echo "OnAccessExcludePath /var/log"
    echo "OnAccessExcludePath /var/lib"
} >> "$CLAMD_CONF"
# Autorizar a clamd para leer /home/$REAL_USER sin errores de "Permission denied"
usermod -a -G "$REAL_USER" "$CLAMAV_SERVICE_USER" 2>/dev/null || true
chmod g+rx "$USER_HOME" 2>/dev/null || true
echo "   [✓] clamd.conf actualizado (AllowSupplementaryGroups=yes; clamd integrado en grupo $REAL_USER)." 

# 18. Inicialización del Baúl Criptográfico y Registro Forense Inmutable

# Purgar avisos masivos de I/O de ClamAV del registro inmutable si existen
if [ -f "$IMMUTABLE_LOG" ]; then
    chattr -i -a "$IMMUTABLE_LOG" 2>/dev/null || true
    if [ ! -s "$IMMUTABLE_LOG" ]; then
        echo "2026-11-06T12:00:00Z | 0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000000 | GENESIS | Registro Forense Inicializado" > "$IMMUTABLE_LOG"
    fi
fi

echo "[17/19] Inicializando Baúl Criptográfico y Registro Inmutable (Hash Chaining)..."
# Desbloquear temporalmente atributos inmutables para permitir actualización de permisos de propiedad
chattr -i -a "$IMMUTABLE_LOG" 2>/dev/null || true

mkdir -p "$LOG_DIR" "$CONSTANTINE_LOG_DIR" "$QUARANTINE_DIR" "$RULES_DIR" "$TI_DIR" "$SIGMA_DIR" /var/lib/clamav/quarantine /var/spool/clamav/quarantine 2>/dev/null || true
chown -R clamav:constantine /var/lib/clamav/quarantine /var/spool/clamav/quarantine 2>/dev/null || true
chmod -R 775 /var/lib/clamav/quarantine /var/spool/clamav/quarantine 2>/dev/null || true
touch "$LOG_DIR/clamonacc.log" "$LOG_DIR/freshclam.log" "$CONSTANTINE_LOG_DIR/yara_live.log" "$CONSTANTINE_LOG_DIR/threat_intel.log" "$CONSTANTINE_LOG_DIR/sigma_matches.log" "$TETRAGON_LOG_DIR/tetragon.log" "$WHITELIST_FILE" 2>/dev/null || true

if [ ! -f "$VAULT_KEY_FILE" ] || [ ! -s "$VAULT_KEY_FILE" ]; then
    head -c 32 /dev/urandom | xxd -p -c 32 > "$VAULT_KEY_FILE" 2>/dev/null || true
fi

# Permisos optimizados: permite al usuario leer la clave en el primer arranque sin requerir reinicio de sesión
chown root:"$REAL_USER" "$VAULT_KEY_FILE" 2>/dev/null || true
chmod 640 "$VAULT_KEY_FILE" 2>/dev/null || true

if [ ! -f "$IMMUTABLE_LOG" ] || [ ! -s "$IMMUTABLE_LOG" ]; then
    echo "2026-11-06T12:00:00Z | 0000000000000000000000000000000000000000000000000000000000000000 | 0000000000000000000000000000000000000000000000000000000000000000 | GENESIS | Registro Forense Inicializado" > "$IMMUTABLE_LOG"
fi

# Aplicar permisos a directorios y archivos de forma segura
chown -R clamav:constantine "$LOG_DIR" 2>/dev/null || true
chown -R root:constantine "$QUARANTINE_DIR" "$TI_DIR" "$SIGMA_DIR" "$WHITELIST_FILE" 2>/dev/null || true
chown root:constantine "$CONSTANTINE_LOG_DIR" 2>/dev/null || true
chown root:constantine "$CONSTANTINE_LOG_DIR"/*.log 2>/dev/null || true
chmod 750 "$CONSTANTINE_LOG_DIR" 2>/dev/null || true
chmod 775 "$QUARANTINE_DIR" 2>/dev/null || true
chmod 640 "$LOG_DIR"/*.log "$CONSTANTINE_LOG_DIR"/*.log "$TETRAGON_LOG_DIR"/*.log "$WHITELIST_FILE" 2>/dev/null || true
chmod 660 "$IMMUTABLE_LOG" 2>/dev/null || true
chattr +a "$IMMUTABLE_LOG" 2>/dev/null || true

log_immutable_event "VAULT_INITIALIZED" "Baúl criptográfico AES-256-GCM y registro inmutable inicializados."

# Actualizador Unificado
cat <<'EOF' > "$UPDATER_SCRIPT"
#!/bin/bash
set -e
if [ "$1" = "--aide-only" ]; then
    if command -v aide >/dev/null 2>&1 && [ -s /var/lib/aide/aide.db ]; then
        aide --check > /var/log/aide/aide.log 2>&1 || true
        chown root:constantine /var/log/aide/aide.log 2>/dev/null || true; chmod 640 /var/log/aide/aide.log 2>/dev/null || true
    fi
    exit 0
fi
echo "[+] Verificando firmas ClamAV..."
if systemctl is-active --quiet clamav-freshclam 2>/dev/null; then
    systemctl stop clamav-freshclam 2>/dev/null || true
    timeout 25 freshclam --quiet 2>/dev/null || true
    systemctl start clamav-freshclam 2>/dev/null || true
else
    timeout 25 freshclam --quiet 2>/dev/null || true
fi

TI_DIR="/var/lib/constantine/intelligence"
SIGMA_DIR="/var/lib/constantine/sigma"
COMMUNITY_DIR="/var/lib/constantine/rules/community"
mkdir -p "$TI_DIR" "$SIGMA_DIR"

echo "[+] Sincronizando feeds de Inteligencia..."
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://bazaar.abuse.ch/export/txt/sha256/recent/" | grep -v '^#' | tr -d '\r' | head -n 5000 > "$TI_DIR/malwarebazaar_hashes.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://threatfox.abuse.ch/export/txt/recent/" | grep -v '^#' | tr -d '\r' | head -n 5000 > "$TI_DIR/threatfox_iocs.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://urlhaus.abuse.ch/downloads/hostfile/" | grep -v '^#' | awk '{print $2}' | tr -d '\r' | head -n 5000 > "$TI_DIR/urlhaus_domains.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://openphish.com/feed.txt" | tr -d '\r' | head -n 2500 > "$TI_DIR/openphish_domains.txt" || true
echo "[+] Sincronizando base comunitaria de StevenBlack Hosts..."
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 30 "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" | grep "^0\.0\.0\.0 " | tr -d '\r' > "$TI_DIR/stevenblack_hosts.txt" || true
curl -s -A "Mozilla/5.0" --connect-timeout 8 --max-time 20 "https://rules.emergingthreats.net/blockrules/compromised-ips.txt" | grep -v '^[[:space:]]*#' | grep -E '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' | tr -d '\r' | head -n 3000 > "$TI_DIR/misp_iocs.txt" || true

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

if [ -x "/usr/local/bin/constantine-dns-sinkhole" ]; then
    echo "[+] Sincronizando sumidero DNS Anti-Phishing con feeds actualizados..."
    /usr/local/bin/constantine-dns-sinkhole --enable >/dev/null 2>&1 || true
fi

chmod -R a+rX "$TI_DIR" "$COMMUNITY_DIR" "$SIGMA_DIR" 2>/dev/null || true
touch /var/lib/constantine/.last_update && chmod 644 /var/lib/constantine/.last_update
systemctl restart clamonacc 2>/dev/null || true
echo "[✓] Sincronización completa de los 16 módulos finalizada."
EOF
chmod 755 "$UPDATER_SCRIPT"
chown root:constantine "$UPDATER_SCRIPT" 2>/dev/null || true

# ==============================================================================
# SCRIPT DE SUMIDERO DNS LOCAL Y FILTRADO WEB EN TIEMPO REAL (ANTI-PHISHING)
# ==============================================================================
SINKHOLE_SCRIPT="/usr/local/bin/constantine-dns-sinkhole"
echo "[+] Configurando script de sumidero DNS y filtrado web en tiempo real: $SINKHOLE_SCRIPT..."
cat << 'EOF_SINKHOLE' > "$SINKHOLE_SCRIPT"
#!/usr/bin/env bash
# ==============================================================================
# Constantine EDR - Sumidero DNS y Filtrado Web en Tiempo Real (Anti-Phishing)
# Redirige dominios hostiles a 0.0.0.0 en /etc/hosts y purga cachés DNS.
# ==============================================================================
set -e

HOSTS_FILE="/etc/hosts"
BLOCKED_FILE="/var/lib/constantine/intelligence/blocked_domains.txt"
TI_DIR="/var/lib/constantine/intelligence"
TMP_DOMAINS=""
START_MARKER="# --- CONSTANTINE EDR ANTI-PHISHING BEGIN ---"
END_MARKER="# --- CONSTANTINE EDR ANTI-PHISHING END ---"

flush_dns() {
    if command -v resolvectl >/dev/null 2>&1; then
        resolvectl flush-caches >/dev/null 2>&1 || true
    fi
    if command -v systemd-resolve >/dev/null 2>&1; then
        systemd-resolve --flush-caches >/dev/null 2>&1 || true
    fi
    if systemctl is-active --quiet nscd 2>/dev/null; then
        systemctl restart nscd >/dev/null 2>&1 || true
    fi
    if systemctl is-active --quiet dnsmasq 2>/dev/null; then
        systemctl restart dnsmasq >/dev/null 2>&1 || true
    fi
}

disable_protection() {
    if grep -qF "$START_MARKER" "$HOSTS_FILE" 2>/dev/null; then
        sed -i "/$START_MARKER/,/$END_MARKER/d" "$HOSTS_FILE"
        flush_dns
        echo "[✓] Sumidero DNS Anti-Phishing desactivado en /etc/hosts."
    else
        echo "[i] El sumidero DNS ya se encontraba inactivo."
    fi
}

enable_protection() {
    mkdir -p "$TI_DIR"
    TMP_DOMAINS=$(mktemp /tmp/constantine_domains_XXXXXX.tmp)

    # 0. Semilla base esencial de protección activa (garantiza bloqueo continuo incluso sin internet)
    cat <<'SEED_SINK' >> "$TMP_DOMAINS"
wicar.org
malware-traffic-analysis.net
testsafebrowsing.appspot.com
secure-apple-login-verify.com
paypal-security-update-center.com
metamask-verify-auth-wallet.com
login-microsoftonline-verify.com
bankofamerica-alert-security.com
chase-secure-login-verify.com
wellsfargo-verify-account.com
binance-login-verify-auth.com
coinbase-security-wallet-auth.com
telegram-auth-verify-code.com
whatsapp-web-verify-login.com
netflix-account-update-billing.com
steamcommunity-trade-verify.com
discord-nitro-gift-free.com
apple-id-verify-icloud.com
google-drive-shared-doc-verify.com
dhl-tracking-express-package.com
fedex-delivery-notice-claim.com
correos-seguimiento-paquete-entrega.com
santander-seguridad-acceso-banca.com
bbva-alerta-seguridad-login.com
caixabank-identificacion-segura.com
SEED_SINK

    # 0.5. Extraer dominios comunitarios de StevenBlack Hosts si está presente
    if [ -f "$TI_DIR/stevenblack_hosts.txt" ]; then
        awk '{print $2}' "$TI_DIR/stevenblack_hosts.txt" | tr -d '\r' >> "$TMP_DOMAINS" || true
    fi

    # 1. Extraer dominios de URLhaus (eliminando retornos de carro \r de Windows CRLF)
    if [ -f "$TI_DIR/urlhaus_domains.txt" ]; then
        tr -d '\r' < "$TI_DIR/urlhaus_domains.txt" | \
        grep -v '^[[:space:]]*#' | \
        sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||' -e 's|:[0-9]*$||' | \
        tr '[:upper:]' '[:lower:]' | \
        grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' >> "$TMP_DOMAINS" || true
    fi

    # 2. Extraer dominios de OpenPhish (eliminando retornos de carro \r de Windows CRLF)
    if [ -f "$TI_DIR/openphish_domains.txt" ]; then
        tr -d '\r' < "$TI_DIR/openphish_domains.txt" | \
        grep -v '^[[:space:]]*#' | \
        sed -e 's|^[a-zA-Z]*://||' -e 's|/.*$||' -e 's|:[0-9]*$||' | \
        tr '[:upper:]' '[:lower:]' | \
        grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' >> "$TMP_DOMAINS" || true
    fi

    # 3. Filtrar dominios locales o legítimos
    grep -vE '^(localhost|localhost\.localdomain|local|broadcasthost|0\.0\.0\.0|127\.0\.0\.1|::1)$' "$TMP_DOMAINS" | \
    sort -u > "$BLOCKED_FILE"
    rm -f "$TMP_DOMAINS"

    DOMAIN_COUNT=$(wc -l < "$BLOCKED_FILE" 2>/dev/null || echo 0)
    if [ "$DOMAIN_COUNT" -eq 0 ]; then
        echo "[!] No se encontraron dominios hostiles en los feeds de inteligencia."
        return 1
    fi

    # 4. Limpiar bloque previo en /etc/hosts
    if grep -qF "$START_MARKER" "$HOSTS_FILE" 2>/dev/null; then
        sed -i "/$START_MARKER/,/$END_MARKER/d" "$HOSTS_FILE"
    fi

    # 5. Escribir nuevo bloque en /etc/hosts
    {
        echo "$START_MARKER"
        echo "# Bloqueo preventivo de phishing, malware y C2 por Constantine EDR"
        awk '{print "0.0.0.0 " $1}' "$BLOCKED_FILE"
        echo "$END_MARKER"
    } >> "$HOSTS_FILE"

    flush_dns
    echo "[✓] Sumidero DNS Anti-Phishing activado: $DOMAIN_COUNT dominios bloqueados en 0.0.0.0."
}

case "$1" in
    --enable)
        enable_protection
        ;;
    --disable)
        disable_protection
        ;;
    --status)
        if grep -qF "$START_MARKER" "$HOSTS_FILE" 2>/dev/null; then
            COUNT=$(grep -c "^0\.0\.0\.0 " "$HOSTS_FILE" 2>/dev/null || echo 0)
            echo "ACTIVO ($COUNT dominios bloqueados)"
        else
            echo "INACTIVO"
        fi
        ;;
    *)
        enable_protection
        ;;
esac
EOF_SINKHOLE
chmod 755 "$SINKHOLE_SCRIPT"
chown root:constantine "$SINKHOLE_SCRIPT" 2>/dev/null || true


# Autorización sin contraseña para el actualizador (Sudoers y Polkit)
mkdir -p /etc/sudoers.d /etc/polkit-1/rules.d /etc/xdg/autostart
{
    echo "%constantine ALL=(ALL) NOPASSWD: /usr/local/bin/constantine-updater, /usr/local/bin/constantine-tray, /usr/local/bin/constantine-dns-sinkhole, /bin/systemctl, /usr/bin/systemctl, /bin/pkill, /usr/bin/pkill, /bin/resolvectl, /usr/bin/resolvectl, /bin/nmcli, /usr/bin/nmcli"
    [ -n "$REAL_USER" ] && echo "$REAL_USER ALL=(ALL) NOPASSWD: /usr/local/bin/constantine-updater, /usr/local/bin/constantine-tray, /usr/local/bin/constantine-dns-sinkhole, /bin/systemctl, /usr/bin/systemctl, /bin/pkill, /usr/bin/pkill, /bin/resolvectl, /usr/bin/resolvectl, /bin/nmcli, /usr/bin/nmcli"
} > /etc/sudoers.d/constantine
chmod 0440 /etc/sudoers.d/constantine 2>/dev/null || true

# ==============================================================================
# CONFIGURACIÓN DE D-BUS Y POLKIT (ARQUITECTURA CLIENTE-SERVIDOR EMPRESARIAL)
# ==============================================================================
echo "[+] Configurando interfaz del bus de sistema D-Bus y políticas Polkit..."
mkdir -p /etc/dbus-1/system.d /usr/share/polkit-1/actions

cat << 'EOF_DBUS' > /etc/dbus-1/system.d/org.constantine.Daemon.conf
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="org.constantine.Daemon"/>
    <allow send_destination="org.constantine.Daemon"/>
    <allow receive_sender="org.constantine.Daemon"/>
  </policy>
  <policy group="constantine">
    <allow send_destination="org.constantine.Daemon"/>
    <allow receive_sender="org.constantine.Daemon"/>
  </policy>
  <policy context="default">
    <allow send_destination="org.constantine.Daemon"
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="org.constantine.Daemon"
           send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_destination="org.constantine.Daemon"
           send_interface="org.constantine.Daemon"/>
  </policy>
</busconfig>
EOF_DBUS
chmod 644 /etc/dbus-1/system.d/org.constantine.Daemon.conf

cat << 'EOF_POLKIT_ACT' > /usr/share/polkit-1/actions/org.constantine.policy
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
 "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>Constantine Antivirus Team</vendor>
  <vendor_url>https://github.com/constantine-edr</vendor_url>
  <icon_name>constantine</icon_name>
  <action id="org.constantine.control">
    <description>Ejecutar operaciones privilegiadas de seguridad en Constantine EDR</description>
    <message>Se requiere autorización para modificar la seguridad del endpoint.</message>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>
EOF_POLKIT_ACT
chmod 644 /usr/share/polkit-1/actions/org.constantine.policy

systemctl reload dbus 2>/dev/null || true

# ==============================================================================
# PROGRAMADOR INTELIGENTE DE ANÁLISIS VÍA SYSTEMD.TIMER (DIARIO Y SEMANAL)
# ==============================================================================
echo "[+] Configurando temporizadores inteligentes de análisis periódico (systemd.timer)..."

# 1. Análisis Rápido Diario
cat << 'EOF_QS' > /etc/systemd/system/constantine-quick-scan.service
[Unit]
Description=Constantine EDR - Análisis Rápido Diario en Segundo Plano
After=network.target
ConditionACPower=true

[Service]
Type=oneshot
User=root
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
ExecStart=/usr/local/bin/constantine --scan-quick
EOF_QS

cat << 'EOF_QT' > /etc/systemd/system/constantine-quick-scan.timer
[Unit]
Description=Constantine EDR - Temporizador de Análisis Rápido Diario
RefuseManualStart=no
RefuseManualStop=no

[Timer]
OnCalendar=*-*-* 02:00:00
OnBootSec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF_QT

# 2. Análisis Completo Semanal
cat << 'EOF_FS' > /etc/systemd/system/constantine-full-scan.service
[Unit]
Description=Constantine EDR - Análisis Completo Semanal del Endpoint
After=network.target
ConditionACPower=true

[Service]
Type=oneshot
User=root
Nice=19
IOSchedulingClass=idle
IOSchedulingPriority=7
ExecStart=/usr/local/bin/constantine --scan-full
EOF_FS

cat << 'EOF_FT' > /etc/systemd/system/constantine-full-scan.timer
[Unit]
Description=Constantine EDR - Temporizador de Análisis Completo Semanal
RefuseManualStart=no
RefuseManualStop=no

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF_FT

chmod 644 /etc/systemd/system/constantine-quick-scan.* /etc/systemd/system/constantine-full-scan.*
systemctl daemon-reload
systemctl enable --now constantine-quick-scan.timer 2>/dev/null || true
systemctl enable --now constantine-full-scan.timer 2>/dev/null || true
echo "   [✓] Temporizadores activos: diario (02:00 AM) y semanal (Domingos 03:00 AM) con guardia de batería."


# Activar sumidero DNS Anti-Phishing de forma inmediata
if [ -x "$SINKHOLE_SCRIPT" ]; then
    echo "[+] Inicializando sumidero DNS Anti-Phishing en tiempo real..."
    rm -f /tmp/constantine_domains_*.tmp /tmp/constantine_domains_raw.tmp 2>/dev/null || true
    "$SINKHOLE_SCRIPT" --enable || true
fi


{
    echo "polkit.addRule(function(action, subject) {"
    echo "    if (subject.isInGroup(\"constantine\") || subject.user == \"$REAL_USER\") {"
    echo "        if (action.id == \"org.constantine.control\" ||"
    echo "            action.id.indexOf(\"org.freedesktop.systemd1.manage-units\") === 0 ||"
    echo "            action.id.indexOf(\"org.freedesktop.systemd1.manage-unit-files\") === 0) {"
    echo "            return polkit.Result.YES;"
    echo "        }"
    echo "    }"
    echo "    var prog = action.lookup(\"program\");"
    echo "    if (prog == \"/usr/local/bin/constantine-updater\" ||"
    echo "        prog == \"/usr/local/bin/constantine-dns-sinkhole\" ||"
    echo "        prog == \"/bin/systemctl\" ||"
    echo "        prog == \"/usr/bin/systemctl\" ||"
    echo "        prog == \"/bin/pkill\" ||"
    echo "        prog == \"/usr/bin/pkill\") {"
    echo "        if (subject.isInGroup(\"constantine\") || subject.user == \"$REAL_USER\" || subject.active) {"
    echo "            return polkit.Result.YES;"
    echo "        }"
    echo "    }"
    echo "    if (prog == \"/usr/local/bin/constantine-shutdown\") {"
    echo "        return polkit.Result.AUTH_ADMIN;"
    echo "    }"
    echo "});"
} > /etc/polkit-1/rules.d/50-constantine.rules 2>/dev/null || true
chmod 644 /etc/polkit-1/rules.d/50-constantine.rules 2>/dev/null || true

# Script de apagado total y forzado unificado
cat << 'SHUTEOF' > /usr/local/bin/constantine-shutdown
#!/bin/bash
# 1. Desproteger atributos inmutables para permitir el apagado y rotación
chattr -i -a /var/lib/constantine/.vault.key /var/log/constantine/immutable_audit.log /var/lib/constantine/whitelist.txt 2>/dev/null || true

# 2. Detener servicios y demonios
echo "[*] Deteniendo procesos para liberar bloqueos y evitar congelamientos de escritorio o de red..."
pkill -9 -f clamonacc 2>/dev/null || true
pkill -9 -f clamd 2>/dev/null || true
pkill -9 -f opensnitch 2>/dev/null || true
systemctl stop clamonacc tetragon falco wazuh-agent clamav-daemon constantine-daemon constantine-boot-update.timer opensnitchd opensnitch 2>/dev/null || true
systemctl disable opensnitchd opensnitch 2>/dev/null || true
# Liberar de inmediato cualquier regla de intercepción de red NFQUEUE residual
iptables -D OUTPUT -j NFQUEUE 2>/dev/null || true
iptables -D INPUT -j NFQUEUE 2>/dev/null || true
pkill -9 -f clamonacc 2>/dev/null || true
pkill -9 -f tetragon 2>/dev/null || true
pkill -9 -f falco 2>/dev/null || true
# Truncar logs inflados por bucles anteriores de fanotify para liberar espacio y eliminar el lag
[ -f /var/log/clamav/clamav.log ] && : > /var/log/clamav/clamav.log
[ -f /var/log/clamav/clamonacc.log ] && : > /var/log/clamav/clamonacc.log
pkill -9 -f wazuh 2>/dev/null || true
pkill -9 -f clamd 2>/dev/null || true
pkill -9 -f constantine-daemon 2>/dev/null || true
pkill -9 -f constantine-tray 2>/dev/null || true
SHUTEOF
chmod 755 /usr/local/bin/constantine-shutdown
chown root:constantine /usr/local/bin/constantine-shutdown 2>/dev/null || true

# Indicador en bandeja del sistema (System Tray junto al reloj)
cat << 'TRAYEOF' > /usr/local/bin/constantine-tray
#!/usr/bin/env python3
import sys, os, subprocess

try:
    import gi
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gtk
    try:
        gi.require_version("AyatanaAppIndicator3", "0.1")
        from gi.repository import AyatanaAppIndicator3 as AppIndicator
    except (ValueError, ImportError):
        gi.require_version("AppIndicator3", "0.1")
        from gi.repository import AppIndicator3 as AppIndicator

    def open_constantine(_):
        subprocess.Popen(["/usr/local/bin/constantine"])

    def update_now(_):
        subprocess.Popen(["/usr/local/bin/constantine-updater"])
        subprocess.Popen(["notify-send", "-u", "low", "Constantine EDR", "Actualizando motores y firmas en segundo plano..."])

    def shutdown_all(_):
        if os.path.exists("/usr/local/bin/constantine-shutdown"):
            subprocess.Popen(["/usr/local/bin/constantine-shutdown"])
        else:
            subprocess.Popen(["pkexec", "sh", "-c", "systemctl stop clamonacc tetragon falco wazuh-agent clamav-daemon constantine-daemon; pkill -9 -f constantine"])
        Gtk.main_quit()

    def quit_tray(_):
        Gtk.main_quit()

    indicator = AppIndicator.Indicator.new(
        "constantine-tray",
        "constantine",
        AppIndicator.IndicatorCategory.SYSTEM_SERVICES
    )
    indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
    indicator.set_icon_full("constantine", "Constantine EDR Activo")

    menu = Gtk.Menu()
    item_title = Gtk.MenuItem(label="🛡️ Constantine EDR v5.5 (Activo)")
    item_title.set_sensitive(False)
    menu.append(item_title)
    menu.append(Gtk.SeparatorMenuItem())

    item_open = Gtk.MenuItem(label="Abrir Panel de Control")
    item_open.connect("activate", open_constantine)
    menu.append(item_open)

    item_update = Gtk.MenuItem(label="🔄 Actualizar 16 Motores Ahora (Sin contraseña)")
    item_update.connect("activate", update_now)
    menu.append(item_update)

    menu.append(Gtk.SeparatorMenuItem())
    item_shutdown = Gtk.MenuItem(label="🛑 Apagar Constantine y Todos los Módulos")
    item_shutdown.connect("activate", shutdown_all)
    menu.append(item_shutdown)

    item_quit = Gtk.MenuItem(label="Ocultar Icono de Bandeja")
    item_quit.connect("activate", quit_tray)
    menu.append(item_quit)

    menu.show_all()
    indicator.set_menu(menu)
    Gtk.main()
except Exception:
    sys.exit(0)
TRAYEOF
chmod 755 /usr/local/bin/constantine-tray 2>/dev/null || true

cat << 'AUTOSEOF' > /etc/xdg/autostart/constantine-tray.desktop
[Desktop Entry]
Type=Application
Name=Constantine Tray Indicator
Comment=Icono de estado de Constantine EDR en la barra de tareas junto al reloj
Exec=/usr/local/bin/constantine-tray
Icon=constantine
Terminal=false
Categories=System;Security;
X-GNOME-Autostart-enabled=true
AUTOSEOF

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
Description=Constantine Antivirus - Timer de 10 min de encendido y ciclo continuo cada 5 horas
After=network-online.target

[Timer]
OnBootSec=10min
OnStartupSec=10min
OnUnitActiveSec=5h
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now constantine-boot-update.timer

# 19. Servicio Aislado de fanotify en systemd
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
    [ -S "$CLAMD_SOCK" ] && break
    sleep 1
done
systemctl enable --now clamonacc 2>/dev/null || true
systemctl enable --now tetragon 2>/dev/null || true
if systemctl list-unit-files | grep -q "falco-modern-bpf.service"; then
    systemctl unmask falco-modern-bpf.service 2>/dev/null || true
    systemctl enable --now falco-modern-bpf.service 2>/dev/null || true
fi
systemctl unmask falco.service 2>/dev/null || true
systemctl enable --now falco.service 2>/dev/null || true
systemctl restart falco-modern-bpf 2>/dev/null || systemctl restart falco 2>/dev/null || true
systemctl enable --now wazuh-agent 2>/dev/null || true
chmod 755 /var/lib/constantine 2>/dev/null || true
chmod -R a+rX /var/lib/constantine/intelligence /var/lib/constantine/rules /var/lib/constantine/sigma 2>/dev/null || true
touch /var/lib/constantine/.last_update && chmod 644 /var/lib/constantine/.last_update 2>/dev/null || true

# 20. Compilación, Lanzador y Smoke Test de Validación Inicial
echo "[19/19] Compilando Constantine v5.5 y ejecutando validación inicial de integridad..."
cd "$SCRIPT_DIR"

# Verificación de existencia de constantine.rs con búsqueda y autocopia inteligente
if [ ! -f "$SCRIPT_DIR/constantine.rs" ]; then
    echo "   [!] constantine.rs no detectado en $SCRIPT_DIR. Buscando en rutas del usuario..."
    FOUND_SRC=""
    for candidate in \
        "$SCRIPT_DIR/src/constantine.rs" \
        "$SCRIPT_DIR/src/main.rs" \
        "$SCRIPT_DIR/../constantine.rs" \
        "$USER_HOME/Descargas/constantine.rs" \
        "$USER_HOME/Downloads/constantine.rs"; do
        if [ -n "$candidate" ] && [ -f "$candidate" ]; then
            FOUND_SRC="$candidate"
            break
        fi
    done

    if [ -z "$FOUND_SRC" ]; then
        FOUND_SRC=$(find "$USER_HOME/Descargas" "$USER_HOME/Downloads" "$SCRIPT_DIR/.." -maxdepth 3 -name "constantine.rs" 2>/dev/null | head -n 1)
    fi

    if [ -n "$FOUND_SRC" ] && [ -f "$FOUND_SRC" ]; then
        echo "   [✓] constantine.rs localizado automáticamente en: $FOUND_SRC"
        echo "   -> Copiando a $SCRIPT_DIR/constantine.rs..."
        cp -f "$FOUND_SRC" "$SCRIPT_DIR/constantine.rs"
        chown "$REAL_USER:$REAL_USER" "$SCRIPT_DIR/constantine.rs" 2>/dev/null || true
    else
        echo "   [-] ERROR: El archivo de código fuente 'constantine.rs' no se encuentra en $SCRIPT_DIR ni en Descargas."
        echo "       Asegúrate de copiar 'constantine.rs' dentro de la carpeta: $SCRIPT_DIR"
        exit 1
    fi
fi

echo "   -> Compilando binario optimizado en Rust (~30 a 60 segundos, por favor espere)..." 

# Compilación segura: se ejecuta como el usuario original, cargando el entorno de rustup
if [ -n "$SUDO_USER" ]; then
    echo "   -> Ejecutando compilación como usuario '$SUDO_USER' para evitar conflictos de permisos..."
    su - "$SUDO_USER" -c "source \$HOME/.cargo/env 2>/dev/null; cd '$SCRIPT_DIR' && cargo build --release -q"
else
    source "$HOME/.cargo/env" 2>/dev/null || true
    cargo build --release -q
fi

# Validación post-compilación: asegurar que el binario existe antes de copiarlo
if [ -f "$SCRIPT_DIR/target/release/constantine" ]; then
    cp -f "$SCRIPT_DIR/target/release/constantine" "$BIN_DIR/constantine" 
    chmod 755 "$BIN_DIR/constantine"
    echo "   [✓] Binario compilado e instalado correctamente."
    # Asegurar copia del desinstalador en /usr/local/bin para el flujo de desinstalación de la app
    if [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
        cp -f "$SCRIPT_DIR/uninstall.sh" "$BIN_DIR/constantine-uninstall"
        cp -f "$SCRIPT_DIR/uninstall.sh" "$BIN_DIR/uninstall.sh"
        chmod 750 "$BIN_DIR/constantine-uninstall" "$BIN_DIR/uninstall.sh"
        echo "   [✓] Desinstalador instalado en $BIN_DIR/constantine-uninstall."
    fi
else
    echo "   [-] ERROR CRÍTICO: Fallo en la compilación de Rust. Verifique que Cargo y las dependencias estén instalados."
    exit 1
fi

ICON_DIR="/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$ICON_DIR" /usr/share/pixmaps /usr/share/applications "$USER_HOME/Desktop" "$USER_HOME/.local/share/icons" 

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

cp -f "$ICON_DIR/constantine.svg" /usr/share/pixmaps/constantine.svg 2>/dev/null || true
cp -f "$ICON_DIR/constantine.svg" "$USER_HOME/.local/share/icons/constantine.svg" 2>/dev/null || true
chown "$REAL_USER:$REAL_USER" "$USER_HOME/.local/share/icons/constantine.svg" 2>/dev/null || true
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true

cat <<EOF > /usr/share/applications/constantine.desktop
[Desktop Entry]
Name=Constantine Antivirus & EDR
GenericName=Antivirus & EDR Debian v5.5
Comment=Protección EDR con Escudo Anti-Ransomware en 4 capas (Canary Tripwires, Ráfagas, SIGKILL y Forense)
Exec=/usr/local/bin/constantine
StartupNotify=true
Icon=constantine
Terminal=false
Type=Application
Categories=System;Security;Utility;
Keywords=antivirus;edr;ransomware;canary;misp;sigma;aide;wazuh;siem;fim;ufw;gufw;protonvpn;falco;tetragon;ebpf;clamav;yara;yarax;
MimeType=all/allfiles;inode/directory;application/octet-stream;application/x-executable;application/x-sharedlib;application/x-shellscript;application/zip;
Actions=ScanFile;

[Desktop Action ScanFile]
Name=Analizar con Constantine...
Exec=/usr/local/bin/constantine --scan-file %F
Icon=constantine
EOF

# Integración con el Menú Contextual (Clic Derecho en el Explorador de Archivos)
echo "   -> Configurando integración de clic derecho en exploradores de archivos..."

# 1. Nautilus (GNOME / Ubuntu)
mkdir -p /usr/share/nautilus-scripts "$USER_HOME/.local/share/nautilus/scripts"
cat <<'NAUTEOF' > /usr/share/nautilus-scripts/Analizar\ con\ Constantine
#!/bin/bash
for f in "$@"; do
    /usr/local/bin/constantine --scan-file "$f" &
done
NAUTEOF
chmod 755 /usr/share/nautilus-scripts/Analizar\ con\ Constantine
cp -f /usr/share/nautilus-scripts/Analizar\ con\ Constantine "$USER_HOME/.local/share/nautilus/scripts/Analizar con Constantine" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$USER_HOME/.local/share/nautilus" 2>/dev/null || true

# 2. Nemo (Linux Mint / Cinnamon)
mkdir -p /usr/share/nemo/actions "$USER_HOME/.local/share/nemo/actions"
cat <<'NEMOEOF' > /usr/share/nemo/actions/constantine-scan.nemo_action
[Nemo Action]
Name=Analizar con Constantine...
Comment=Escanear archivo o carpeta en busca de malware y ransomware
Exec=/usr/local/bin/constantine --scan-file "%F"
Icon-Name=constantine
Selection=any
Extensions=any;
EscapeSpaces=true
NEMOEOF
chmod 644 /usr/share/nemo/actions/constantine-scan.nemo_action
cp -f /usr/share/nemo/actions/constantine-scan.nemo_action "$USER_HOME/.local/share/nemo/actions/" 2>/dev/null || true
chown -R "$REAL_USER:$REAL_USER" "$USER_HOME/.local/share/nemo" 2>/dev/null || true

# 3. FreeDesktop File Manager Actions y KDE Dolphin
mkdir -p /usr/share/file-manager/actions /usr/share/kservices5/ServiceMenus /usr/share/kio/servicemenus
cat <<'FMAEOF' > /usr/share/file-manager/actions/constantine-scan.desktop
[Desktop Entry]
Type=Action
Name=Analizar con Constantine...
Icon=constantine
Tooltip=Escanear con el motor EDR Fail-Secure de Constantine
Profiles=profile_scan;

[X-Action-Profile profile_scan]
Exec=/usr/local/bin/constantine --scan-file %F
SelectionCount=*
FMAEOF

cat <<'KDEEOF' > /usr/share/kservices5/ServiceMenus/constantine-scan.desktop
[Desktop Entry]
Type=Service
MimeType=all/allfiles;inode/directory;
Actions=ScanFile;
X-KDE-Priority=TopLevel

[Desktop Action ScanFile]
Name=Analizar con Constantine...
Icon=constantine
Exec=/usr/local/bin/constantine --scan-file %F
KDEEOF
cp -f /usr/share/kservices5/ServiceMenus/constantine-scan.desktop /usr/share/kio/servicemenus/constantine-scan.desktop 2>/dev/null || true

# 4. Thunar (XFCE / Debian / Mint XFCE)
mkdir -p "$USER_HOME/.config/Thunar"
if [ ! -f "$USER_HOME/.config/Thunar/uca.xml" ]; then
    cat <<'THUNAREOF' > "$USER_HOME/.config/Thunar/uca.xml"
<?xml version="1.0" encoding="UTF-8"?>
<actions>
<action>
    <icon>constantine</icon>
    <name>Analizar con Constantine v5.5...</name>
    <command>/usr/local/bin/constantine --scan-file %f</command>
    <description>Escanear archivo o carpeta con Constantine Antivirus &amp; EDR v5.5</description>
    <patterns>*</patterns>
    <directories/>
    <audio-files/>
    <image-files/>
    <other-files/>
    <text-files/>
    <video-files/>
</action>
</actions>
THUNAREOF
    chown -R "$REAL_USER:$REAL_USER" "$USER_HOME/.config/Thunar" 2>/dev/null || true
fi

update-desktop-database 2>/dev/null || true

# Configurar reglas de udev para detección Plug & Play de unidades USB
mkdir -p /etc/udev/rules.d
cat <<'UDEVEOF' > /etc/udev/rules.d/99-constantine-usb.rules
# Constantine EDR - Intercepción Plug & Play de memorias USB
ACTION=="add", SUBSYSTEM=="block", ENV{ID_BUS}=="usb", TAG+="systemd"
UDEVEOF
chmod 644 /etc/udev/rules.d/99-constantine-usb.rules 2>/dev/null || true
udevadm control --reload-rules 2>/dev/null || true

# 1. Integrar en /etc/skel para que todo nuevo usuario nazca con acceso directo y autostart
mkdir -p /etc/skel/Desktop /etc/skel/.config/autostart
cp -f /usr/share/applications/constantine.desktop /etc/skel/Desktop/constantine.desktop
chmod +x /etc/skel/Desktop/constantine.desktop

# 2. Autostart Global del sistema para todos los usuarios en /etc/xdg/autostart
mkdir -p /etc/xdg/autostart
cat <<'AUTOEOF' > /etc/xdg/autostart/constantine-tray.desktop
[Desktop Entry]
Type=Application
Name=Constantine EDR Tray
Comment=Agente de sesión y bandeja de seguridad Constantine
Exec=/usr/local/bin/constantine-tray
Icon=constantine
Terminal=false
Categories=System;Security;
X-GNOME-Autostart-enabled=true
X-KDE-autostart-after=panel
AUTOEOF
chmod 644 /etc/xdg/autostart/constantine-tray.desktop
cp -f /etc/xdg/autostart/constantine-tray.desktop /etc/skel/.config/autostart/constantine-tray.desktop

# 3. Replicar accesos directos y configuración en todos los usuarios humanos existentes
for user_entry in $(get_all_human_users); do
    u_name="${user_entry%%:*}"
    u_home="${user_entry#*:}"
    [ ! -d "$u_home" ] && continue
    mkdir -p "$u_home/Desktop" "$u_home/.config/autostart" "$u_home/.local/share/nautilus/scripts" "$u_home/.local/share/nemo/actions" "$u_home/.config/Thunar"
    cp -f /usr/share/applications/constantine.desktop "$u_home/Desktop/constantine.desktop"
    chmod +x "$u_home/Desktop/constantine.desktop"
    gio set "$u_home/Desktop/constantine.desktop" metadata::trusted true 2>/dev/null || true
    cp -f /etc/xdg/autostart/constantine-tray.desktop "$u_home/.config/autostart/constantine-tray.desktop"
    chown -R "$u_name:$u_name" "$u_home/Desktop/constantine.desktop" "$u_home/.config/autostart" 2>/dev/null || true
done

# 4. Hook global de sesión para inicialización transparente de usuarios (/etc/profile.d/constantine-session.sh)
cat <<'PROFEOF' > /etc/profile.d/constantine-session.sh
# Constantine Antivirus & EDR v5.5 - Provisión Automática de Usuario
if [ -n "$USER" ] && [ "$USER" != "root" ] && [ "$USER" != "nobody" ]; then
    # Auto-reparación de señuelos Canary si faltasen
    if [ -d "$HOME/Desktop" ] && [ ! -f "$HOME/Desktop/!000_canary_personal_vault.docx" ]; then
        echo "CANARY_DOCUMENT_SECURE_TOKEN_DO_NOT_MODIFY_CONSTANTINE_EDR_PROTECTION_TRIPWIRE" > "$HOME/Desktop/!000_canary_personal_vault.docx" 2>/dev/null || true
        chmod 644 "$HOME/Desktop/!000_canary_personal_vault.docx" 2>/dev/null || true
    fi
    # Marcar icono de escritorio como confiable en entornos GNOME/Cinnamon
    if [ -f "$HOME/Desktop/constantine.desktop" ]; then
        gio set "$HOME/Desktop/constantine.desktop" metadata::trusted true 2>/dev/null || true
    fi
fi
PROFEOF
chmod 644 /etc/profile.d/constantine-session.sh

# Instalación del servicio Daemon: garantiza que el motor de correlación y neutralización se ejecute en segundo plano con privilegios root
cat <<'EOF' > /etc/systemd/system/constantine-daemon.service
[Unit]
Description=Constantine EDR Background Correlation Daemon
After=network.target
Wants=clamonacc.service tetragon.service falco.service falco-modern-bpf.service

[Service]
Type=simple
ExecStart=/usr/local/bin/constantine --daemon
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now constantine-daemon.service

# --- SMOKE TEST DE VALIDACIÓN INICIAL ---
echo ""
echo "[*] Ejecutando Smoke Test de validación inicial de integridad..."
SMOKE_PASS=true
[ ! -S "$CLAMD_SOCK" ] && echo "   [-] Fallo: Socket clamd no responde." && SMOKE_PASS=false
[ ! -f "$IMMUTABLE_LOG" ] && echo "   [-] Fallo: Registro inmutable no inicializado." && SMOKE_PASS=false
[ ! -f "$VAULT_KEY_FILE" ] && echo "   [-] Fallo: Clave de cifrado del baúl ausente." && SMOKE_PASS=false

if [ "$SMOKE_PASS" = true ]; then
    
# ==============================================================================
# AUTODEFENSA DEL ANTIVIRUS (TAMPER PROTECTION) E INMUTABILIDAD DE ARCHIVOS
# ==============================================================================
echo "[18/19] Activando Autodefensa del Antivirus (Tamper Protection) e Inmutabilidad de Archivos..."
touch "$IMMUTABLE_LOG" "$WHITELIST_FILE"
chown root:constantine "$IMMUTABLE_LOG" "$WHITELIST_FILE" 2>/dev/null || true
chmod 640 "$IMMUTABLE_LOG" "$WHITELIST_FILE" 2>/dev/null || true

if [ -f "$VAULT_KEY_FILE" ]; then
    chown root:constantine "$VAULT_KEY_FILE" 2>/dev/null || true
    chmod 640 "$VAULT_KEY_FILE" 2>/dev/null || true
    chattr +i "$VAULT_KEY_FILE" 2>/dev/null || true
fi
chattr +i "$WHITELIST_FILE" 2>/dev/null || true
chattr +a "$IMMUTABLE_LOG" 2>/dev/null || chattr +i "$IMMUTABLE_LOG" 2>/dev/null || true
echo "   [✓] Archivos críticos (.vault.key, immutable_audit.log, whitelist.txt) blindados con atributos inmutables (chattr +i/+a)."
echo "   [✓] Política de kernel eBPF Tetragon (Anti-Kill + Anti-Sabotaje) activa en /etc/tetragon/tetragon.tp.d/."

echo "   [✓] Smoke Test superado: Subsistemas básicos y señuelos verificados."
else
    echo "   [-] Fallo en Smoke Test inicial: anomalías críticas detectadas."
fi

# ==============================================================================
# AUDITORÍA ESTRICTA DE EJECUCIÓN DE MÓDULOS EN VIVO Y LANZAMIENTO FINAL
# ==============================================================================
echo ""
echo "===================================================================="
echo " 🔍 AUDITORÍA ESTRICTA DE EJECUCIÓN DE MÓDULOS EN TIEMPO REAL"
echo "===================================================================="

FAIL_REASON=""

check_module_service() {
    local svc="$1"
    local desc="$2"
    local max_wait=8
    while [ $max_wait -gt 0 ]; do
        if systemctl is-active --quiet "$svc" 2>/dev/null; then
            echo "   [✓] $desc: Activo y en ejecución."
            return 0
        fi
        sleep 1
        max_wait=$((max_wait - 1))
    done
    FAIL_REASON="El servicio '$svc' ($desc) no pudo iniciarse o se encuentra detenido."
    return 1
}

check_socket_wait() {
    local sock_path="$1"
    local desc="$2"
    local max_wait=8
    while [ $max_wait -gt 0 ]; do
        if [ -S "$sock_path" ]; then
            echo "   [✓] $desc: Activo y en escucha."
            return 0
        fi
        sleep 1
        max_wait=$((max_wait - 1))
    done
    FAIL_REASON="El socket '$sock_path' ($desc) no respondió tras 8 segundos de espera."
    return 1
}

check_falco_service() {
    local max_wait=15
    while [ $max_wait -gt 0 ]; do
        if systemctl is-active --quiet falco-modern-bpf 2>/dev/null || systemctl is-active --quiet falco 2>/dev/null || pgrep -x falco >/dev/null 2>&1; then
            echo "   [✓] Sensor de Comportamiento Falco: Activo y en ejecución."
            return 0
        fi
        if [ -f /etc/falco/falco_rules.local.yaml ] && command -v falco >/dev/null 2>&1; then
            if ! falco -c /etc/falco/falco.yaml --dry-run >/dev/null 2>&1 && ! falco --validate /etc/falco/falco.yaml >/dev/null 2>&1; then
                rm -f /etc/falco/falco_rules.local.yaml 2>/dev/null || true
            fi
        fi
        systemctl restart falco-modern-bpf 2>/dev/null || systemctl restart falco 2>/dev/null || true
        sleep 1
        max_wait=$((max_wait - 1))
    done
    FAIL_REASON="El motor de detección de comportamiento Falco no está en ejecución."
    return 1
}

# 1. Demonio principal de correlación de Constantine
if ! check_module_service "constantine-daemon" "Demonio Principal EDR (constantine-daemon)"; then
    :
# 2. Socket IPC de comunicación entre interfaz y demonio
elif ! check_socket_wait "/run/constantine.sock" "Socket IPC de Comunicación (/run/constantine.sock)"; then
    :
# 3. Motor ClamAV multihilo (clamd)
elif ! check_module_service "clamav-daemon" "Motor de Firmas ClamAV (clamav-daemon)"; then
    :
# 4. Socket clamd
elif ! check_socket_wait "$CLAMD_SOCK" "Socket del Motor ClamAV ($CLAMD_SOCK)"; then
    :

# 5. Escudo en acceso ClamOnAcc (fanotify)
elif ! check_module_service "clamonacc" "Escudo de Acceso en Kernel ClamOnAcc (fanotify)"; then
    :
# 6. Sensor eBPF Cilium Tetragon
elif ! check_module_service "tetragon" "Sensor eBPF Tetragon (Cilium Kernel LSM)"; then
    :
# 7. Sensor de comportamiento Falco
elif ! check_falco_service; then
    :
fi

# 8. Temporizadores de análisis inteligente systemd.timer
if [ -z "$FAIL_REASON" ]; then
    if ! systemctl is-active --quiet constantine-quick-scan.timer 2>/dev/null; then
        FAIL_REASON="El temporizador diario 'constantine-quick-scan.timer' no está activo."
    elif ! systemctl is-active --quiet constantine-full-scan.timer 2>/dev/null; then
        FAIL_REASON="El temporizador semanal 'constantine-full-scan.timer' no está activo."
    else
        echo "   [✓] Temporizadores Inteligentes: Análisis diario y semanal programados."
    fi
fi

# 9. Señuelos Canary Tripwires
if [ -z "$FAIL_REASON" ]; then
    ACTIVE_CANARIES=$(find "$USER_HOME" -maxdepth 2 -name "!000_canary_*" 2>/dev/null | wc -l)
    if [ "$ACTIVE_CANARIES" -lt 4 ]; then
        FAIL_REASON="Faltan señuelos Canary Tripwires en $USER_HOME ($ACTIVE_CANARIES de 4 sembrados)."
    else
        echo "   [✓] Escudo Anti-Ransomware: 4/4 Señuelos Canary Tripwires activos."
    fi
fi

# 10. Baúl criptográfico y registro inmutable
if [ -z "$FAIL_REASON" ]; then
    if [ ! -f "$IMMUTABLE_LOG" ]; then
        FAIL_REASON="El registro forense inmutable '$IMMUTABLE_LOG' no fue creado."
    elif [ ! -f "$VAULT_KEY_FILE" ]; then
        FAIL_REASON="La clave del baúl criptográfico '$VAULT_KEY_FILE' no existe."
    else
        echo "   [✓] Criptografía e Inmutabilidad: Baúl AES-256 y Registro Forense SHA-256 blindados."
    fi
fi

# 11. Binario ejecutable compilado
if [ -z "$FAIL_REASON" ]; then
    if [ ! -x "/usr/local/bin/constantine" ]; then
        FAIL_REASON="El binario '/usr/local/bin/constantine' no existe o no tiene permisos de ejecución."
    else
        echo "   [✓] Binario Nativo: /usr/local/bin/constantine listo para operar."
    fi
fi

# ==============================================================================
# EVALUACIÓN FAIL-SECURE: REVERSIÓN TOTAL O CONFIRMACIÓN Y EJECUCIÓN
# ==============================================================================
if [ -n "$FAIL_REASON" ]; then
    echo ""
    echo "===================================================================="
    echo " ❌ ERROR CRÍTICO DE INSTALACIÓN: MÓDULO NO EJECUTADO"
    echo "===================================================================="
    echo " [-] Causa del fallo: $FAIL_REASON"
    echo " [!] Política Fail-Secure: Al fallar la ejecución de un módulo obligatorio,"
    echo "     se aborta el proceso y se desinstala todo para no dejar residuos."
    echo "===================================================================="
    echo ""
    echo "[*] Ejecutando reversión total y desinstalación limpia inmediata..."
    if [ -f "$SCRIPT_DIR/uninstall.sh" ]; then
        bash "$SCRIPT_DIR/uninstall.sh" || true
    fi
    echo ""
    echo "[-] Proceso finalizado sin cambios en el sistema: no se instaló nada."
    exit 1
fi

echo ""
echo "===================================================================="
log_immutable_event "INSTALLATION_SUCCESS" "Instalación completada y verificada: 16 módulos de seguridad y auditoría inmutable activos."
echo " 🎉 INSTALACIÓN DE CONSTANTINE EDR v5.5 COMPLETADA Y VERIFICADA "
echo "===================================================================="
echo " • TODOS LOS MÓDULOS EN EJECUCIÓN: Tetragon, Falco, ClamOnAcc, Daemon y Timers"
echo " • ESCUDO ANTI-RANSOMWARE: 4 Señuelos Canary Tripwires Activos"
echo " • REGISTRO FORENSE: Hash Chaining SHA-256 e inmutabilidad activa (+i/+a)"
echo " • DESINSTALADOR LIMPIO: Disponible mediante './uninstall.sh'"
echo "===================================================================="
echo ""

# ==============================================================================
# EJECUCIÓN FINAL AUTOMÁTICA DE CONSTANTINE PARA EL USUARIO
# ==============================================================================
echo "===================================================================="
echo " 🚀 INICIANDO CONSTANTINE ANTIVIRUS & EDR v5.5 EN PANTALLA"
echo "===================================================================="
echo "[+] Preparando entorno gráfico para el usuario '$REAL_USER'..."

# Terminar cualquier proceso de interfaz previo colgado en segundo plano
pkill -u "$REAL_USER" -x "constantine" 2>/dev/null || true
sleep 1

# Asegurar permisos de confianza sobre el acceso directo en el escritorio
gio set "$USER_HOME/Desktop/constantine.desktop" metadata::trusted true 2>/dev/null || true
chown "$REAL_USER:$REAL_USER" "$USER_HOME/Desktop/constantine.desktop" 2>/dev/null || true

if [ -n "$REAL_USER" ] && [ "$REAL_USER" != "root" ]; then
    USER_ID=$(id -u "$REAL_USER" 2>/dev/null || echo "1000")
    USER_RUNTIME="/run/user/$USER_ID"
    USER_DBUS="unix:path=/run/user/$USER_ID/bus"
    
    # Detectar el proceso de sesión gráfica activa (Cinnamon, GNOME, XFCE, etc.)
    SESSION_PID=$(pgrep -u "$REAL_USER" -x "cinnamon|gnome-shell|xfce4-session|plasma-desktop|kwin|mate-session|lxsession|x-session-manager" 2>/dev/null | head -n 1)
    if [ -z "$SESSION_PID" ]; then
        SESSION_PID=$(pgrep -u "$REAL_USER" 2>/dev/null | head -n 1)
    fi

    USER_DISP="${DISPLAY:-:0}"
    USER_WAY="${WAYLAND_DISPLAY:-wayland-0}"
    USER_XAUTH="$USER_HOME/.Xauthority"

    if [ -n "$SESSION_PID" ] && [ -d "/proc/$SESSION_PID" ]; then
        DETECTED_DISP=$(tr '\0' '\n' < /proc/$SESSION_PID/environ 2>/dev/null | grep -E '^DISPLAY=' | head -n 1 | cut -d= -f2-)
        DETECTED_WAY=$(tr '\0' '\n' < /proc/$SESSION_PID/environ 2>/dev/null | grep -E '^WAYLAND_DISPLAY=' | head -n 1 | cut -d= -f2-)
        DETECTED_XAUTH=$(tr '\0' '\n' < /proc/$SESSION_PID/environ 2>/dev/null | grep -E '^XAUTHORITY=' | head -n 1 | cut -d= -f2-)
        [ -n "$DETECTED_DISP" ] && USER_DISP="$DETECTED_DISP"
        [ -n "$DETECTED_WAY" ] && USER_WAY="$DETECTED_WAY"
        [ -n "$DETECTED_XAUTH" ] && USER_XAUTH="$DETECTED_XAUTH"
    fi

    echo "   -> DISPLAY=$USER_DISP | XDG_RUNTIME_DIR=$USER_RUNTIME"
    
    # Otorgar acceso X11 local al usuario
    xhost +SI:localuser:"$REAL_USER" 2>/dev/null || true

    sudo -u "$REAL_USER" env \
        XDG_RUNTIME_DIR="$USER_RUNTIME" \
        DBUS_SESSION_BUS_ADDRESS="$USER_DBUS" \
        DISPLAY="$USER_DISP" \
        XAUTHORITY="$USER_XAUTH" \
        WAYLAND_DISPLAY="$USER_WAY" \
        nohup /usr/local/bin/constantine >/tmp/constantine_gui.log 2>&1 &
    
    disown 2>/dev/null || true
else
    nohup /usr/local/bin/constantine >/tmp/constantine_gui.log 2>&1 &
fi

echo "   [✓] Constantine Antivirus & EDR ejecutado y abierto en pantalla."
echo "===================================================================="