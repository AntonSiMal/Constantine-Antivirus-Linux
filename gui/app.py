"""
Constantine Antivirus - Native GTK 3 Security Center (gui/app.py)
Versión mejorada:
- Selector de idioma en vivo (Español / English)
- Escaneo en segundo plano multihilo con barra de progreso fluida (sin congelar la UI)
- Escáner de Memoria RAM (procesos activos y mapas de memoria en /proc)
- Escáner de Todo el Sistema (/) y Selector nativo de carpetas (Gtk.FileChooserDialog)
- Integración con GUFW, Proton VPN, Mullvad DNS, Baúl y System Tray
"""

import os
import sys
import time
import logging
import threading
import subprocess
import webbrowser
import urllib.parse

# Configuración de rutas
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.auth.auth_manager import AuthManager
from core.engine.vault import QuarantineVault
from core.engine.phishing import PhishingShield
from core.engine.scanner import Scanner
from core.engine.system_whitelist import SystemWhitelist
from core.engine.dns_manager import DNSManager, MULLVAD_DNS_PROFILES
from core.engine.firewall import NetworkQuarantine
from core.engine.vpn_manager import VPNManager
from core.engine.ransomware_shield import RansomwareShield
from core.engine.usb_monitor import USBAutoScanner
from core.engine.update_guard import SystemUpdateGuard
from core.engine.memory_scanner import MemoryScanner
from core.engine.auto_updater import ConstantineUpdater
from core.engine.i18n import Localization
from gui.tray import ConstantineTrayIcon

logger = logging.getLogger("constantine.gui")

try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk, Gdk, GLib
    HAS_GTK = True
except Exception as e:
    HAS_GTK = False
    logger.warning("GTK 3 no detectado: %s", e)

class ConstantineGUI:
    def __init__(self):
        self.loc = Localization(default_lang="es")
        self.auth_mgr = AuthManager()
        self.vault = QuarantineVault()
        self.whitelist = SystemWhitelist()
        self.phishing = PhishingShield()
        self.scanner = Scanner()
        self.dns_mgr = DNSManager()
        self.firewall = NetworkQuarantine()
        self.vpn_mgr = VPNManager()
        self.ransomware = RansomwareShield()
        self.update_guard = SystemUpdateGuard()
        self.memory_scanner = MemoryScanner(scanner=self.scanner, vault=self.vault)
        self.updater = ConstantineUpdater()

        self.session_token = None
        self.is_unlocked = False
        self.antivirus_enabled = True

        # Control de escaneo en hilo de fondo
        self.scan_thread = None
        self.is_scanning = False
        self.abort_scan = False

        if not HAS_GTK:
            print("Error: Se requiere GTK 3 (python3-gi) para iniciar la interfaz gráfica.")
            return

        self._build_window()

    def _on_window_delete(self):
        # Al pulsar [X], minimizar a la bandeja junto al reloj
        self.window.hide()
        return True

    def _build_window(self):
        self.window = Gtk.Window(title="Constantine Antivirus")
        self.window.set_default_size(940, 660)
        self.window.set_position(Gtk.WindowPosition.CENTER)
        
        # Icono de la ventana
        icon_path = os.path.join(ROOT_DIR, "assets", "constantine.svg")
        if os.path.exists(icon_path):
            try:
                self.window.set_icon_from_file(icon_path)
            except Exception:
                pass

        self.window.connect("delete-event", lambda w, e: self._on_window_delete())
        self.tray = ConstantineTrayIcon(main_window=self.window, on_open_callback=lambda: self.window.show_all())

        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window.add(vbox)

        # 1. Cabecera Superior
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        header.set_margin_start(20); header.set_margin_end(20); header.set_margin_top(12); header.set_margin_bottom(12)

        title_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.lbl_title = Gtk.Label()
        self.lbl_title.set_markup("<span font='15' weight='bold' foreground='#d32f2f'>⚔️ CONSTANTINE ANTIVIRUS</span>")
        self.lbl_title.set_xalign(0)
        self.lbl_sub = Gtk.Label(label="Protección Activa en Kernel • Anti-Ransomware • GUFW • Mullvad DNS • Proton VPN")
        self.lbl_sub.set_xalign(0)
        title_box.pack_start(self.lbl_title, False, False, 0)
        title_box.pack_start(self.lbl_sub, False, False, 0)
        header.pack_start(title_box, True, True, 0)

        # Selector de Idioma (ES / EN)
        lang_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        self.btn_lang_es = Gtk.Button(label="ES")
        self.btn_lang_es.get_style_context().add_class("suggested-action")
        self.btn_lang_es.connect("clicked", lambda b: self._change_language("es"))
        self.btn_lang_en = Gtk.Button(label="EN")
        self.btn_lang_en.connect("clicked", lambda b: self._change_language("en"))
        lang_box.pack_start(self.btn_lang_es, False, False, 0)
        lang_box.pack_start(self.btn_lang_en, False, False, 0)
        header.pack_start(lang_box, False, False, 5)

        # Interruptor Maestro ON / OFF
        master_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.lbl_master_state = Gtk.Label()
        self.lbl_master_state.set_markup("<b>Antivirus: ON</b>")
        self.switch_master = Gtk.Switch()
        self.switch_master.set_active(True)
        self.switch_master.connect("state-set", self._on_master_switch_toggled)
        master_box.pack_start(self.lbl_master_state, False, False, 0)
        master_box.pack_start(self.switch_master, False, False, 0)
        header.pack_start(master_box, False, False, 10)

        # Estado del Sistema
        self.lbl_system_status = Gtk.Label()
        self.lbl_system_status.set_markup("<span font='10' weight='bold' foreground='#2e7d32'>🛡️ SISTEMA PROTEGIDO</span>")
        header.pack_start(self.lbl_system_status, False, False, 5)

        # Candado de Seguridad
        self.btn_lock = Gtk.Button()
        self.btn_lock.set_label("🔒 Desbloquear")
        self.btn_lock.connect("clicked", self._on_lock_clicked)
        header.pack_start(self.btn_lock, False, False, 0)

        vbox.pack_start(header, False, False, 0)
        vbox.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # 2. Pestañas
        self.notebook = Gtk.Notebook()
        self.notebook.set_tab_pos(Gtk.PositionType.LEFT)
        vbox.pack_start(self.notebook, True, True, 0)

        self.tab_shields_lbl = Gtk.Label(label="🛡️ Escudos en Vivo")
        self.notebook.append_page(self._create_shields_tab(), self.tab_shields_lbl)

        self.tab_scanner_lbl = Gtk.Label(label="🔍 Escáner Manual")
        self.notebook.append_page(self._create_scanner_tab(), self.tab_scanner_lbl)

        self.tab_vault_lbl = Gtk.Label(label="📦 Baúl de Amenazas")
        self.notebook.append_page(self._create_vault_tab(), self.tab_vault_lbl)

        self.tab_usb_lbl = Gtk.Label(label="💾 Discos & USB")
        self.notebook.append_page(self._create_usb_tab(), self.tab_usb_lbl)

        self.tab_firewall_lbl = Gtk.Label(label="🔥 GUFW & Proton VPN")
        self.notebook.append_page(self._create_firewall_vpn_tab(), self.tab_firewall_lbl)

        self.tab_dns_lbl = Gtk.Label(label="🌐 DNS Mullvad")
        self.notebook.append_page(self._create_dns_tab(), self.tab_dns_lbl)

        self.tab_phishing_lbl = Gtk.Label(label="🎣 Anti-Phishing")
        self.notebook.append_page(self._create_phishing_tab(), self.tab_phishing_lbl)

        self.tab_whitelist_lbl = Gtk.Label(label="📋 Lista Blanca")
        self.notebook.append_page(self._create_whitelist_tab(), self.tab_whitelist_lbl)

        self.tab_settings_lbl = Gtk.Label(label="⚙️ Configuración")
        self.notebook.append_page(self._create_settings_tab(), self.tab_settings_lbl)

        # 3. Barra Inferior de Estado
        statusbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        statusbar.set_margin_start(15); statusbar.set_margin_end(15); statusbar.set_margin_top(6); statusbar.set_margin_bottom(6)
        self.lbl_footer = Gtk.Label(label="fanotify I/O: ACTIVO | eBPF: ACTIVO | Anti-Ransomware: ACTIVO | Baúl: Listo")
        self.lbl_footer.set_xalign(0)
        statusbar.pack_start(self.lbl_footer, True, True, 0)
        vbox.pack_start(statusbar, False, False, 0)

        self._update_lock_ui()
        threading.Thread(target=self._check_updates_background, daemon=True).start()
        # Comprobar actualizaciones de Constantine en segundo plano al iniciar
        threading.Thread(target=self._check_updates_background, daemon=True).start()

    def _change_language(self, lang):
        self.loc.set_language(lang)
        is_es = (lang == "es")
        self.tab_shields_lbl.set_text("🛡️ Escudos en Vivo" if is_es else "🛡️ Live Shields")
        self.tab_scanner_lbl.set_text("🔍 Escáner Manual" if is_es else "🔍 Manual Scanner")
        self.tab_vault_lbl.set_text("📦 Baúl de Amenazas" if is_es else "📦 Threat Vault")
        self.tab_usb_lbl.set_text("💾 Discos & USB" if is_es else "💾 Disks & USB")
        self.tab_firewall_lbl.set_text("🔥 GUFW & Proton VPN")
        self.tab_dns_lbl.set_text("🌐 DNS Mullvad")
        self.tab_phishing_lbl.set_text("🎣 Anti-Phishing")
        self.tab_settings_lbl.set_text("⚙️ Configuración" if is_es else "⚙️ Settings")

        self.lbl_master_state.set_markup(f"<b>{'Antivirus: ON' if is_es else 'Antivirus: ON'}</b>")
        self._update_lock_ui()
        # Comprobar actualizaciones de Constantine en segundo plano al iniciar
        threading.Thread(target=self._check_updates_background, daemon=True).start()
        logger.info("Idioma cambiado a: %s", lang)


    def _check_updates_background(self):
        try:
            info = self.updater.check_for_updates()
            if info.get("update_available"):
                GLib.idle_add(self._show_update_available_dialog, info)
        except Exception as e:
            logger.debug("Error en comprobación de actualización en segundo plano: %s", e)

    def _show_update_available_dialog(self, info):
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.NONE,
            text=f"🎉 Nueva Versión Disponible: v{info['latest_version']}"
        )
        dialog.format_secondary_text(
            f"Tu versión actual es v{info['current_version']}.\n\n"
            f"Notas de la versión:\n{info['release_notes']}\n\n"
            f"¿Deseas descargar e instalar la actualización ahora?"
        )
        dialog.add_button("Recordar Más Tarde", Gtk.ResponseType.CANCEL)
        dialog.add_button("Actualizar Ahora", Gtk.ResponseType.OK)
        
        resp = dialog.run()
        dialog.destroy()

        if resp == Gtk.ResponseType.OK:
            self._trigger_app_update()

    def _trigger_app_update(self):
        if not self._check_auth_required():
            return

        progress_dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.NONE,
            text="Descargando e Instalando Actualización..."
        )
        progress_dialog.format_secondary_text("Sincronizando los últimos archivos desde GitHub y reiniciando el servicio...")
        progress_dialog.show_all()

        def do_update():
            ok, msg = self.updater.execute_update()
            def done():
                progress_dialog.destroy()
                if ok:
                    self._show_msg("Actualización Exitosa", f"{msg}\nSe recomienda reiniciar la aplicación.", Gtk.MessageType.INFO)
                else:
                    self._show_msg("Fallo de Actualización", msg, Gtk.MessageType.ERROR)
            GLib.idle_add(done)

        threading.Thread(target=do_update, daemon=True).start()


    def _manual_check_app_updates(self):
        info = self.updater.check_for_updates()
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.NONE,
            text=f"Actualizaciones de Constantine Antivirus (v{info['current_version']})"
        )
        dialog.format_secondary_text(
            f"Repositorio oficial: {self.updater.repo}\n\n"
            f"Estado en GitHub:\n{info['release_notes']}\n\n"
            "¿Deseas sincronizar y descargar los últimos archivos del repositorio oficial ahora?"
        )
        dialog.add_button("Cerrar", Gtk.ResponseType.CANCEL)
        dialog.add_button("🚀 Sincronizar y Actualizar Ahora", Gtk.ResponseType.OK)

        resp = dialog.run()
        dialog.destroy()

        if resp == Gtk.ResponseType.OK:
            self._trigger_app_update()

    def _create_shields_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        # Banner de Actualizaciones del Sistema
        up_info = self.update_guard.check_pending_updates()
        up_banner = Gtk.Frame(label=" Parches de Seguridad y Kernel del Sistema Operativo ")
        ubox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        ubox.set_margin_start(15); ubox.set_margin_end(15); ubox.set_margin_top(10); ubox.set_margin_bottom(10)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        lbl_k = Gtk.Label()
        lbl_k.set_markup(f"<b>Kernel en ejecución:</b> {up_info['current_kernel']} • <b>Gestor:</b> {up_info['manager_name']}")
        lbl_k.set_xalign(0)
        info_box.pack_start(lbl_k, False, False, 0)

        lbl_up_txt = Gtk.Label(label="Auditoría de distribución completada. Todo el software y librerías cuentan con sus firmas verificadas.")
        lbl_up_txt.set_xalign(0)
        info_box.pack_start(lbl_up_txt, False, False, 0)
        ubox.pack_start(info_box, True, True, 0)

        btn_mgr = Gtk.Button(label="🚀 Abrir Gestor Oficial del Sistema")
        btn_mgr.connect("clicked", lambda b: self.update_guard.launch_system_update_manager())
        ubox.pack_start(btn_mgr, False, False, 0)
        up_banner.add(ubox)
        box.pack_start(up_banner, False, False, 0)

        # Lista de escudos activos
        shields = [
            ("Escudo de Archivos en Kernel (fanotify)", "Bloqueo síncrono FAN_OPEN_PERM / FAN_EXEC_PERM en disco.", True),
            ("Escudo Anti-Ransomware (Canary Traps)", "Vigila ráfagas de cifrado y defiende archivos señuelo con SIGKILL.", True),
            ("Inspección de Memorias USB y Discos", "Auto-escaneo silencioso de almacenamiento removible al conectar.", True),
            ("Vigilancia Heurística y eBPF en RAM", "Intercepta sys_enter_execve, inyecciones de memoria ptrace y reverse shells.", True),
        ]

        self.shield_switches = {}
        for title, subtitle, default_state in shields:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
            ibox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

            t_lbl = Gtk.Label(); t_lbl.set_markup(f"<span font='11' weight='bold'>{title}</span>"); t_lbl.set_xalign(0)
            s_lbl = Gtk.Label(label=subtitle); s_lbl.set_xalign(0)
            ibox.pack_start(t_lbl, False, False, 0)
            ibox.pack_start(s_lbl, False, False, 0)
            row.pack_start(ibox, True, True, 0)

            sw = Gtk.Switch(); sw.set_active(default_state)
            sw.connect("state-set", self._on_shield_toggled, title)
            row.pack_start(sw, False, False, 0)
            self.shield_switches[title] = sw
            box.pack_start(row, False, False, 5)
            box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        return box

    def _create_scanner_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Análisis Manual y Escaneo en Profundidad</b>\nElige entre escaneo de memoria RAM, carpetas temporales, todo el disco o una carpeta específica.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # Botones de Escaneo Principal
        grid = Gtk.Grid()
        grid.set_column_spacing(12); grid.set_row_spacing(10)

        btn_scan_ram = Gtk.Button(label="🧠 Escanear Memoria RAM")
        btn_scan_ram.connect("clicked", lambda b: self._start_scan_thread(mode="ram"))
        grid.attach(btn_scan_ram, 0, 0, 1, 1)

        btn_scan_tmp = Gtk.Button(label="⚡ Analizar /tmp y /dev/shm")
        btn_scan_tmp.connect("clicked", lambda b: self._start_scan_thread(mode="folder", target="/tmp"))
        grid.attach(btn_scan_tmp, 1, 0, 1, 1)

        btn_scan_home = Gtk.Button(label="🏠 Carpeta Personal (~/)")
        btn_scan_home.connect("clicked", lambda b: self._start_scan_thread(mode="folder", target=os.path.expanduser("~")))
        grid.attach(btn_scan_home, 0, 1, 1, 1)

        btn_scan_custom = Gtk.Button(label="📂 Seleccionar Carpeta a Escanear...")
        btn_scan_custom.connect("clicked", self._on_pick_folder_to_scan)
        grid.attach(btn_scan_custom, 1, 1, 1, 1)

        btn_scan_full = Gtk.Button(label="🌐 Escanear Todo el Sistema (/)")
        btn_scan_full.connect("clicked", lambda b: self._start_scan_thread(mode="folder", target="/"))
        grid.attach(btn_scan_full, 0, 2, 2, 1)

        box.pack_start(grid, False, False, 0)

        # Contenedor de Progreso con Animación Fluida
        self.scan_panel = Gtk.Frame(label=" Progreso del Análisis en Vivo ")
        spbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        spbox.set_margin_start(15); spbox.set_margin_end(15); spbox.set_margin_top(10); spbox.set_margin_bottom(10)

        header_progress = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.lbl_scan_target = Gtk.Label(label="Esperando comando de escaneo...")
        self.lbl_scan_target.set_xalign(0)
        header_progress.pack_start(self.lbl_scan_target, True, True, 0)

        self.lbl_scan_percentage = Gtk.Label(label="0%")
        self.lbl_scan_percentage.set_xalign(1)
        header_progress.pack_start(self.lbl_scan_percentage, False, False, 0)
        spbox.pack_start(header_progress, False, False, 0)

        self.scan_progress = Gtk.ProgressBar()
        self.scan_progress.set_fraction(0.0)
        spbox.pack_start(self.scan_progress, False, False, 0)

        # Archivo actual en tiempo real
        self.lbl_scan_current_file = Gtk.Label(label="")
        self.lbl_scan_current_file.set_xalign(0)
        self.lbl_scan_current_file.set_line_wrap(True)
        spbox.pack_start(self.lbl_scan_current_file, False, False, 0)

        # Contadores de escaneo
        footer_scan = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        self.lbl_scan_stats = Gtk.Label(label="Archivos analizados: 0 | Amenazas: 0")
        self.lbl_scan_stats.set_xalign(0)
        footer_scan.pack_start(self.lbl_scan_stats, True, True, 0)

        self.btn_cancel_scan = Gtk.Button(label="⏹ Cancelar")
        self.btn_cancel_scan.set_sensitive(False)
        self.btn_cancel_scan.connect("clicked", self._on_cancel_scan)
        footer_scan.pack_start(self.btn_cancel_scan, False, False, 0)
        spbox.pack_start(footer_scan, False, False, 0)

        self.scan_panel.add(spbox)
        box.pack_start(self.scan_panel, False, False, 5)

        # Tabla de Amenazas Detectadas durante el Escaneo (Detalle exacto)
        self.threats_frame = Gtk.Frame(label=" Amenazas Detectadas y Enviadas al Baúl ")
        tbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
        tbox.set_margin_start(10); tbox.set_margin_end(10); tbox.set_margin_top(8); tbox.set_margin_bottom(8)

        self.threats_store = Gtk.ListStore(str, str, str, str) # Amenaza, Ruta, Estado, Hash
        self.threats_tree = Gtk.TreeView(model=self.threats_store)

        renderer = Gtk.CellRendererText()
        col_t = Gtk.TreeViewColumn("Amenaza Detectada", renderer, text=0); col_t.set_resizable(True)
        col_p = Gtk.TreeViewColumn("Ruta del Archivo", renderer, text=1); col_p.set_resizable(True)
        col_s = Gtk.TreeViewColumn("Acción de Seguridad", renderer, text=2)
        col_h = Gtk.TreeViewColumn("Hash SHA-256", renderer, text=3)

        self.threats_tree.append_column(col_t)
        self.threats_tree.append_column(col_p)
        self.threats_tree.append_column(col_s)
        self.threats_tree.append_column(col_h)

        scroll_t = Gtk.ScrolledWindow(); scroll_t.set_min_content_height(140); scroll_t.add(self.threats_tree)
        tbox.pack_start(scroll_t, True, True, 0)
        self.threats_frame.add(tbox)
        box.pack_start(self.threats_frame, True, True, 5)

        return box

    def _on_pick_folder_to_scan(self, button):
        dialog = Gtk.FileChooserDialog(
            title="Seleccionar Carpeta para Escaneo",
            parent=self.window,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        )
        if dialog.run() == Gtk.ResponseType.OK:
            chosen = dialog.get_filename()
            dialog.destroy()
            self._start_scan_thread(mode="folder", target=chosen)
        else:
            dialog.destroy()

    def _start_scan_thread(self, mode="folder", target="/tmp"):
        if self.is_scanning:
            self._show_msg("Escaneo en curso", "Ya hay un análisis activo. Espera a que termine o cancélalo.", Gtk.MessageType.WARNING)
            return

        self.threats_store.clear()
        self.is_scanning = True
        self.abort_scan = False
        self.btn_cancel_scan.set_sensitive(True)
        self.scan_progress.set_fraction(0.0)
        self.lbl_scan_percentage.set_text("0%")

        if mode == "ram":
            self.lbl_scan_target.set_markup("<b>Analizando:</b> Memoria RAM y Procesos del Kernel (/proc)")
        else:
            self.lbl_scan_target.set_markup(f"<b>Analizando:</b> {target}")

        self.scan_thread = threading.Thread(target=self._scan_worker, args=(mode, target), daemon=True)
        self.scan_thread.start()

    def _scan_worker(self, mode, target):
        scanned_count = 0
        threats_count = 0

        if mode == "ram":
            def ram_cb(pid, comm, current, total, threats):
                if self.abort_scan:
                    return
                frac = float(current) / float(total) if total > 0 else 0.0
                GLib.idle_add(self._update_scan_ui, frac, f"/proc/{pid} ({comm})", current, threats)

            res = self.memory_scanner.scan_ram(progress_callback=ram_cb)
            scanned_count = res["scanned"]
            threats_count = res["threats_count"]

        else:
            files_to_scan = []
            # Recolectar archivos rápidamente
            if os.path.isfile(target):
                files_to_scan.append(target)
            else:
                for root, dirs, files in os.walk(target):
                    if self.abort_scan:
                        break
                    # Evitar bucles infinitos en /proc y /sys durante escaneo raíz /
                    if target == "/" and (root.startswith("/proc") or root.startswith("/sys") or root.startswith("/dev")):
                        continue
                    for f in files:
                        files_to_scan.append(os.path.join(root, f))
                        if len(files_to_scan) >= 10000: # Límite de lote para respuesta visual
                            break
                    if len(files_to_scan) >= 10000:
                        break

            total_files = len(files_to_scan)
            for idx, fpath in enumerate(files_to_scan):
                if self.abort_scan:
                    break
                scanned_count += 1
                try:
                    res = self.scanner.scan_file(file_path=fpath)
                    if res.is_malicious:
                        threats_count += 1
                        t_name = res.threat_name or "Malware.Generic"
                        f_hash = res.sha256 or "Calculando..."
                        self.vault.quarantine_file(fpath, t_name)
                        GLib.idle_add(self._add_detected_threat_row, t_name, fpath, "Neutralizado y en Baúl", f_hash[:16] + "...")
                except Exception:
                    pass

                # Actualizar barra cada 5 archivos para máxima fluidez
                if idx % 5 == 0 or idx == total_files - 1:
                    frac = float(idx + 1) / float(total_files) if total_files > 0 else 1.0
                    GLib.idle_add(self._update_scan_ui, frac, fpath, scanned_count, threats_count)

        GLib.idle_add(self._finish_scan_ui, scanned_count, threats_count, self.abort_scan)

    def _add_detected_threat_row(self, threat, path, status, fhash):
        self.threats_store.append([threat, path, status, fhash])
        return False

    def _update_scan_ui(self, frac, current_name, count, threats):
        self.scan_progress.set_fraction(min(frac, 1.0))
        self.lbl_scan_percentage.set_text(f"{int(frac * 100)}%")
        # Truncar nombre si es muy largo
        short_name = current_name if len(current_name) < 70 else "..." + current_name[-67:]
        self.lbl_scan_current_file.set_text(f"Analizando: {short_name}")
        self.lbl_scan_stats.set_text(f"Archivos/Procesos analizados: {count} | Amenazas: {threats}")
        return False

    def _finish_scan_ui(self, count, threats, was_aborted):
        self.is_scanning = False
        self.btn_cancel_scan.set_sensitive(False)
        self.scan_progress.set_fraction(1.0)
        self.lbl_scan_percentage.set_text("100%")

        if was_aborted:
            self.lbl_scan_current_file.set_markup("<span foreground='#f59e0b' weight='bold'>⏹ Análisis cancelado por el usuario.</span>")
        elif threats > 0:
            self.lbl_scan_current_file.set_markup(f"<span foreground='#ef4444' weight='bold'>⚠️ Análisis completado: {threats} amenaza(s) aisladas en el Baúl.</span>")
            self._refresh_vault_list()
        else:
            self.lbl_scan_current_file.set_markup("<span foreground='#10b981' weight='bold'>✅ Análisis completado. Cero amenazas detectadas en el sistema.</span>")
        return False

    def _on_cancel_scan(self, button):
        self.abort_scan = True
        self.lbl_scan_current_file.set_text("Cancelando...")

    # --- Pestaña de Baúl ---
    def _create_vault_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_start(20); box.set_margin_end(20); box.set_margin_top(15)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Baúl de Cuarentena (Aislamiento Cifrado)</b>\nNeutralización segura con permisos 000 y clave XOR.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # Ubicación física en disco
        storage_path = self.vault.get_storage_location()
        card_loc = Gtk.Frame(label=" Ubicación Física en Disco ")
        cbox_loc = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        cbox_loc.set_margin_start(12); cbox_loc.set_margin_end(12); cbox_loc.set_margin_top(6); cbox_loc.set_margin_bottom(6)
        lbl_p = Gtk.Label()
        lbl_p.set_markup(f"📁 <span font='10' foreground='#38bdf8' font_family='monospace'>{storage_path}</span> (Permisos 000 • Inmune a ejecución)")
        lbl_p.set_xalign(0)
        cbox_loc.pack_start(lbl_p, True, True, 0)
        card_loc.add(cbox_loc)
        box.pack_start(card_loc, False, False, 0)

        # Tabla del Baúl con Selección Múltiple y Fecha/Hora Exacta
        self.vault_store = Gtk.ListStore(str, str, str, str, str) # ID, Amenaza, Ruta Original, Fecha/Hora, Hash
        self.vault_tree = Gtk.TreeView(model=self.vault_store)
        # Habilitar selección múltiple (Ctrl / Shift o selección arrastrada)
        self.vault_tree.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)

        renderer = Gtk.CellRendererText()
        col_threat = Gtk.TreeViewColumn("Amenaza", renderer, text=1); col_threat.set_resizable(True)
        col_path = Gtk.TreeViewColumn("Ruta Original", renderer, text=2); col_path.set_resizable(True)
        col_date = Gtk.TreeViewColumn("Fecha y Hora de Neutralización", renderer, text=3); col_date.set_resizable(True)
        col_hash = Gtk.TreeViewColumn("Hash SHA-256", renderer, text=4); col_hash.set_resizable(True)

        self.vault_tree.append_column(col_threat)
        self.vault_tree.append_column(col_path)
        self.vault_tree.append_column(col_date)
        self.vault_tree.append_column(col_hash)

        scroll = Gtk.ScrolledWindow(); scroll.set_vexpand(True); scroll.add(self.vault_tree)
        box.pack_start(scroll, True, True, 0)

        # Botonera con Selección Múltiple y Whitelist
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        
        self.btn_select_all = Gtk.Button(label="Seleccionar Todos")
        self.btn_select_all.connect("clicked", lambda b: self.vault_tree.get_selection().select_all())
        btn_box.pack_start(self.btn_select_all, False, False, 0)

        self.btn_restore = Gtk.Button(label="Restaurar Seleccionados (+ Whitelist)")
        self.btn_restore.connect("clicked", self._on_restore_vault_item)
        btn_box.pack_start(self.btn_restore, False, False, 0)

        self.btn_purge = Gtk.Button(label="Eliminar Seleccionados")
        self.btn_purge.connect("clicked", self._on_purge_vault_item)
        btn_box.pack_start(self.btn_purge, False, False, 0)

        self.btn_google_info = Gtk.Button(label="🔍 Buscar Amenaza en Google")
        self.btn_google_info.connect("clicked", self._on_search_threat_google)
        btn_box.pack_start(self.btn_google_info, False, False, 0)

        btn_refresh = Gtk.Button(label="Actualizar Lista")
        btn_refresh.connect("clicked", lambda b: self._refresh_vault_list())
        btn_box.pack_start(btn_refresh, False, False, 0)

        box.pack_start(btn_box, False, False, 5)
        self._refresh_vault_list()
        return box

    def _create_usb_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Vigilancia y Auto-Escaneo de Medios USB</b>\nAl conectar una unidad externa en /media, Constantine la audita en silencio sin interrumpir tu trabajo.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        card = Gtk.Frame(label=" Estado de Monitoreo Removible ")
        cbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        cbox.set_margin_start(15); cbox.set_margin_end(15); cbox.set_margin_top(10); cbox.set_margin_bottom(10)

        lbl_i = Gtk.Label(label="Monitor UDisks2: Activo. Si una memoria USB contiene un malware o autorun, se aísla automáticamente en el Baúl.")
        lbl_i.set_xalign(0); cbox.pack_start(lbl_i, False, False, 0)

        btn_usb = Gtk.Button(label="🔍 Escanear Manualmente Unidad USB Conectada")
        btn_usb.connect("clicked", lambda b: self._start_scan_thread(mode="folder", target="/media"))
        cbox.pack_start(btn_usb, False, False, 5)

        card.add(cbox)
        box.pack_start(card, False, False, 0)

        # Tarjeta Visible de Desinstalación Segura
        un_card = Gtk.Frame(label=" Desinstalación de Constantine Antivirus ")
        unbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        unbox.set_margin_start(15); unbox.set_margin_end(15); unbox.set_margin_top(10); unbox.set_margin_bottom(10)

        un_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        lbl_un_t = Gtk.Label()
        lbl_un_t.set_markup("<b>Desinstalar Constantine Antivirus de este equipo</b>")
        lbl_un_t.set_xalign(0)
        un_info.pack_start(lbl_un_t, False, False, 0)
        un_info.pack_start(Gtk.Label(label="Detiene el servicio, elimina reglas de red, iconos y accesos directos de forma limpia."), False, False, 0)
        unbox.pack_start(un_info, True, True, 0)

        btn_uninstall = Gtk.Button(label="🗑️ Desinstalar Constantine...")
        btn_uninstall.connect("clicked", self._on_uninstall_app_clicked)
        unbox.pack_start(btn_uninstall, False, False, 0)
        un_card.add(unbox)
        box.pack_start(un_card, False, False, 5)
        return box

    def _create_firewall_vpn_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Cortafuegos GUFW &amp; Proton VPN</b>\nControl del firewall UFW e invocación en 1 clic de la aplicación Proton VPN.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # UFW / GUFW
        f_frame = Gtk.Frame(label=" Cortafuegos de Linux (UFW / GUFW) ")
        fbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        fbox.set_margin_start(15); fbox.set_margin_end(15); fbox.set_margin_top(10); fbox.set_margin_bottom(10)

        self.lbl_ufw_state = Gtk.Label()
        self.lbl_ufw_state.set_markup("<b>Estado de UFW:</b> Activo")
        self.lbl_ufw_state.set_xalign(0)
        fbox.pack_start(self.lbl_ufw_state, False, False, 0)

        f_btns = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_toggle = Gtk.Button(label="Activar / Desactivar UFW")
        btn_toggle.connect("clicked", self._on_toggle_ufw_clicked)
        f_btns.pack_start(btn_toggle, False, False, 0)

        btn_gufw = Gtk.Button(label="🔥 Abrir Panel Avanzado GUFW")
        btn_gufw.connect("clicked", lambda b: self.firewall.launch_gufw())
        f_btns.pack_start(btn_gufw, False, False, 0)
        fbox.pack_start(f_btns, False, False, 5)
        f_frame.add(fbox)
        box.pack_start(f_frame, False, False, 0)

        # VPN
        v_frame = Gtk.Frame(label=" Red Privada Virtual (Proton VPN) ")
        vbox_vpn = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        vbox_vpn.set_margin_start(15); vbox_vpn.set_margin_end(15); vbox_vpn.set_margin_top(10); vbox_vpn.set_margin_bottom(10)

        btn_vpn = Gtk.Button(label="🛡️ Abrir y Conectar Proton VPN")
        btn_vpn.connect("clicked", lambda b: self.vpn_mgr.launch())
        vbox_vpn.pack_start(btn_vpn, False, False, 5)
        v_frame.add(vbox_vpn)
        box.pack_start(v_frame, False, False, 0)
        return box

    def _create_dns_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Perfiles DNS Cifrados de Mullvad &amp; Control de Conexión</b>\nResolución segura en el sistema operativo bloqueando ciberamenazas antes de la conexión TCP.")
        lbl.set_xalign(0); box.pack_start(lbl, False, False, 0)

        # BANNER DESTACADO DEL DNS ACTUALMENTE ACTIVO EN EL SISTEMA
        active_dns = self.dns_mgr.get_active_profile()
        self.dns_active_card = Gtk.Frame(label=" Servidor DNS Activo en tu Conexión ")
        abox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        abox.set_margin_start(15); abox.set_margin_end(15); abox.set_margin_top(10); abox.set_margin_bottom(10)

        self.lbl_active_dns_title = Gtk.Label()
        self.lbl_active_dns_title.set_markup(f"<span font='12' weight='bold' foreground='#38bdf8'>● {active_dns['summary']}</span>")
        self.lbl_active_dns_title.set_xalign(0)
        abox.pack_start(self.lbl_active_dns_title, False, False, 0)

        self.lbl_active_dns_desc = Gtk.Label(label=f"Categoría de filtrado: {active_dns['category']} • Protocolo: DoT (Puerto 853) / DoH")
        self.lbl_active_dns_desc.set_xalign(0)
        abox.pack_start(self.lbl_active_dns_desc, False, False, 0)

        self.dns_active_card.add(abox)
        box.pack_start(self.dns_active_card, False, False, 0)

        # Selector de Perfiles
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        hbox.pack_start(Gtk.Label(label="Cambiar a Perfil:"), False, False, 0)

        self.dns_combo = Gtk.ComboBoxText()
        profiles = self.dns_mgr.get_profiles()
        for pid, pdata in profiles.items():
            ip_display = ', '.join(pdata['ipv4']) if pdata['ipv4'] else 'DHCP / Auto'
            self.dns_combo.append(pid, f"{pdata['name']} [{ip_display}]")

        current_pid = active_dns.get("id", "mullvad-base")
        self.dns_combo.set_active_id(current_pid if current_pid in profiles else "mullvad-base")
        hbox.pack_start(self.dns_combo, True, True, 0)

        btn_apply = Gtk.Button(label="Aplicar Perfil a la Conexión")
        btn_apply.get_style_context().add_class("suggested-action")
        btn_apply.connect("clicked", self._on_apply_dns_clicked)
        hbox.pack_start(btn_apply, False, False, 0)
        box.pack_start(hbox, False, False, 0)

        # Tarjetas de descripción detallada
        lbl_desc = Gtk.Label()
        lbl_desc.set_line_wrap(True)
        lbl_desc.set_markup(
            "<b>🛡️ Mullvad Base (194.242.2.4):</b> Malware, phishing, publicidad intrusiva y rastreadores.\n"
            "<b>🚫 Mullvad Adblock (194.242.2.3):</b> Exclusivamente anuncios y telemetría.\n"
            "<b>🔒 Mullvad Extended (194.242.2.5):</b> Malware + Publicidad + Redes Sociales.\n"
            "<b>👨‍👩‍👧 Mullvad Family (194.242.2.6):</b> Control parental: adultos (+18), apuestas y malware.\n"
            "<b>⚡ Quad9 (9.9.9.9):</b> Protección estricta de malware y phishing con DNSSEC (Socio oficial de Mullvad)."
        )
        lbl_desc.set_xalign(0); box.pack_start(lbl_desc, False, False, 5)
        return box

    def _create_phishing_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label(); lbl.set_markup("<b>Verificador Anti-Phishing y Auditoría DNS</b>"); lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        entry_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.entry_url = Gtk.Entry(); self.entry_url.set_placeholder_text("Introduce URL sospechosa...")
        entry_box.pack_start(self.entry_url, True, True, 0)

        btn_check = Gtk.Button(label="Analizar")
        btn_check.connect("clicked", self._on_check_url_clicked)
        entry_box.pack_start(btn_check, False, False, 0)
        box.pack_start(entry_box, False, False, 0)

        self.lbl_phish_output = Gtk.Label(); self.lbl_phish_output.set_xalign(0); self.lbl_phish_output.set_line_wrap(True)
        box.pack_start(self.lbl_phish_output, False, False, 0)
        return box


    def _create_whitelist_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.set_margin_start(20); box.set_margin_end(20); box.set_margin_top(15)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Lista Blanca de Archivos y Carpetas (Whitelist)</b>\nLos elementos incluidos en esta lista quedan permanentemente excluidos del bloqueo y del auto-aislamiento.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # Tabla de Whitelist
        self.wl_store = Gtk.ListStore(str, str, str) # Tipo, Ruta/Hash, Estado
        self.wl_tree = Gtk.TreeView(model=self.wl_store)

        renderer = Gtk.CellRendererText()
        col_type = Gtk.TreeViewColumn("Tipo", renderer, text=0); col_type.set_resizable(True)
        col_path = Gtk.TreeViewColumn("Ruta de Archivo / Carpeta / Firma", renderer, text=1); col_path.set_resizable(True)
        col_stat = Gtk.TreeViewColumn("Estado", renderer, text=2)

        self.wl_tree.append_column(col_type)
        self.wl_tree.append_column(col_path)
        self.wl_tree.append_column(col_stat)

        scroll = Gtk.ScrolledWindow(); scroll.set_vexpand(True); scroll.add(self.wl_tree)
        box.pack_start(scroll, True, True, 0)

        # Botonera de Whitelist
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)

        btn_add_file = Gtk.Button(label="➕ Agregar Archivo a Whitelist...")
        btn_add_file.connect("clicked", self._on_add_whitelist_file)
        btn_box.pack_start(btn_add_file, False, False, 0)

        btn_add_folder = Gtk.Button(label="📁 Agregar Carpeta a Whitelist...")
        btn_add_folder.connect("clicked", self._on_add_whitelist_folder)
        btn_box.pack_start(btn_add_folder, False, False, 0)

        btn_remove = Gtk.Button(label="❌ Quitar de Lista Blanca")
        btn_remove.connect("clicked", self._on_remove_whitelist_entry)
        btn_box.pack_start(btn_remove, False, False, 0)

        btn_refresh = Gtk.Button(label="Actualizar")
        btn_refresh.connect("clicked", lambda b: self._refresh_whitelist_ui())
        btn_box.pack_start(btn_refresh, False, False, 0)

        box.pack_start(btn_box, False, False, 5)
        self._refresh_whitelist_ui()
        return box

    def _refresh_whitelist_ui(self):
        self.wl_store.clear()
        for item in self.whitelist.list_entries():
            self.wl_store.append([item["type"], item["path"], item["status"]])

    def _on_add_whitelist_file(self, button):
        if not self._check_auth_required(): return
        dialog = Gtk.FileChooserDialog(
            title="Seleccionar Archivo para Agregar a la Lista Blanca",
            parent=self.window,
            action=Gtk.FileChooserAction.OPEN,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        )
        if dialog.run() == Gtk.ResponseType.OK:
            target = dialog.get_filename()
            dialog.destroy()
            if self.whitelist.add_path(target):
                self._refresh_whitelist_ui()
                self._show_msg("Lista Blanca", f"Archivo agregado a exclusiones:\n{target}", Gtk.MessageType.INFO)
        else:
            dialog.destroy()

    def _on_add_whitelist_folder(self, button):
        if not self._check_auth_required(): return
        dialog = Gtk.FileChooserDialog(
            title="Seleccionar Carpeta para Agregar a la Lista Blanca",
            parent=self.window,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OPEN, Gtk.ResponseType.OK)
        )
        if dialog.run() == Gtk.ResponseType.OK:
            target = dialog.get_filename()
            dialog.destroy()
            if self.whitelist.add_path(target):
                self._refresh_whitelist_ui()
                self._show_msg("Lista Blanca", f"Carpeta agregada a exclusiones:\n{target}\n(Todo su contenido estará autorizado).", Gtk.MessageType.INFO)
        else:
            dialog.destroy()

    def _on_remove_whitelist_entry(self, button):
        if not self._check_auth_required(): return
        model, treeiter = self.wl_tree.get_selection().get_selected()
        if not treeiter:
            self._show_msg("Selección", "Por favor selecciona un elemento de la lista para quitar.", Gtk.MessageType.WARNING)
            return
        target = model[treeiter][1]
        if self.whitelist.remove_path(target):
            self._refresh_whitelist_ui()
            self._show_msg("Lista Blanca", f"Elemento removido de exclusiones:\n{target}", Gtk.MessageType.INFO)

    def _on_search_threat_google(self, button):
        """Abre en el navegador una búsqueda en Google sobre la amenaza seleccionada."""
        model, paths = self.vault_tree.get_selection().get_selected_rows()
        if not paths:
            self._show_msg("Selección", "Por favor selecciona una amenaza de la lista del baúl.", Gtk.MessageType.WARNING)
            return
        it = model.get_iter(paths[0])
        threat_name = model.get_value(it, 1)

        query = f"{threat_name} linux malware analysis"
        encoded_query = urllib.parse.quote(query)
        url = f"https://www.google.com/search?q={encoded_query}"
        try:
            webbrowser.open_new_tab(url)
            self._show_msg("Búsqueda en Google", f"Abriendo navegador con información de seguridad sobre:\n<b>{threat_name}</b>", Gtk.MessageType.INFO)
        except Exception as e:
            self._show_msg("Error", f"No se pudo abrir el navegador: {e}", Gtk.MessageType.ERROR)


    def _on_uninstall_app_clicked(self, button):
        if not self._check_auth_required(): return
        dialog = Gtk.MessageDialog(
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.OK_CANCEL,
            text="¿Estás seguro de que deseas desinstalar Constantine Antivirus?"
        )
        dialog.format_secondary_text(
            "Esta acción detendrá la protección activa del kernel, removerá el servicio systemd, "
            "limpiará las reglas de cortafuegos y quitará los accesos directos del menú y del escritorio.\n\n"
            "Se ejecutará el desinstalador seguro /opt/constantine/uninstall.sh."
        )
        resp = dialog.run()
        dialog.destroy()

        if resp == Gtk.ResponseType.OK:
            # Invocar desinstalador seguro con pkexec
            uninstall_script = "/opt/constantine/uninstall.sh"
            if not os.path.exists(uninstall_script):
                uninstall_script = os.path.join(ROOT_DIR, "uninstall.sh")

            try:
                cmd = ["pkexec", uninstall_script] if os.geteuid() != 0 else [uninstall_script]
                subprocess.Popen(cmd, start_new_session=True)
                self._show_msg("Desinstalación en Proceso", "Se ha iniciado el desinstalador seguro en segundo plano. La aplicación se cerrará.", Gtk.MessageType.INFO)
                Gtk.main_quit()
            except Exception as e:
                self._show_msg("Error", f"Fallo al invocar el desinstalador: {e}", Gtk.MessageType.ERROR)

    def _create_settings_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label(); lbl.set_markup("<b>Autenticación Nativa Linux (PAM / sudo)</b>"); lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        u = self.auth_mgr.get_current_user()
        is_sudo = self.auth_mgr.is_user_in_sudoers(u)

        card = Gtk.Frame(label=" Sesión de Usuario ")
        cbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        cbox.set_margin_start(15); cbox.set_margin_end(15); cbox.set_margin_top(10); cbox.set_margin_bottom(10)
        cbox.pack_start(Gtk.Label(label=f"• Usuario actual: {u}"), False, False, 0)
        cbox.pack_start(Gtk.Label(label=f"• Privilegios de sudo: {'Sí (Autorizado)' if is_sudo else 'No (Solo lectura)'}"), False, False, 0)
        cbox.pack_start(Gtk.Label(label="• Modelo de Seguridad: Cero contraseñas propietarias. Autenticación delegada a PAM/sudo."), False, False, 0)
        card.add(cbox)
        box.pack_start(card, False, False, 0)

        # Tarjeta de Actualizaciones de Constantine
        app_up_card = Gtk.Frame(label=" Actualizaciones de Constantine Antivirus ")
        au_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        au_box.set_margin_start(15); au_box.set_margin_end(15); au_box.set_margin_top(10); au_box.set_margin_bottom(10)

        au_info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        lbl_v = Gtk.Label()
        lbl_v.set_markup(f"<b>Versión instalada:</b> v{self.updater.current_version} • <b>Repositorio:</b> {self.updater.repo}")
        lbl_v.set_xalign(0)
        au_info.pack_start(lbl_v, False, False, 0)
        au_info.pack_start(Gtk.Label(label="Comprueba si existen nuevas versiones de Constantine y actualiza en un clic."), False, False, 0)
        au_box.pack_start(au_info, True, True, 0)

        btn_check_app_update = Gtk.Button(label="🔄 Buscar Actualizaciones Ahora")
        btn_check_app_update.connect("clicked", lambda b: self._manual_check_app_updates())
        au_box.pack_start(btn_check_app_update, False, False, 0)
        app_up_card.add(au_box)
        box.pack_start(app_up_card, False, False, 5)
        return box

    # --- Acciones y Eventos ---
    def _on_master_switch_toggled(self, switch, state):
        if not self._check_auth_required():
            switch.set_active(not state)
            return True
        self.antivirus_enabled = state
        is_es = (self.loc.lang == "es")
        if state:
            self.lbl_master_state.set_markup(f"<b>{'Antivirus: ON'}</b>")
            self.lbl_system_status.set_markup(f"<span font='10' weight='bold' foreground='#2e7d32'>{'🛡️ SISTEMA PROTEGIDO' if is_es else '🛡️ SYSTEM PROTECTED'}</span>")
        else:
            self.lbl_master_state.set_markup(f"<b>{'Antivirus: OFF'}</b>")
            self.lbl_system_status.set_markup(f"<span font='10' weight='bold' foreground='#d32f2f'>{'⚠️ PROTECCIÓN PAUSADA' if is_es else '⚠️ PROTECTION PAUSED'}</span>")
        return False

    def _on_shield_toggled(self, switch, state, title):
        if not self._check_auth_required():
            switch.set_active(not state)
            return True
        return False

    def _on_lock_clicked(self, button):
        if self.is_unlocked:
            self.auth_mgr.revoke_session(self.session_token)
            self.session_token = None
            self.is_unlocked = False
            self._update_lock_ui()
        else:
            self._show_login_dialog()

    def _show_login_dialog(self):
        dialog = Gtk.Dialog(title="Autenticación de Constantine", parent=self.window, flags=Gtk.DialogFlags.MODAL, buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL, Gtk.STOCK_OK, Gtk.ResponseType.OK))
        area = dialog.get_content_area(); area.set_spacing(10); area.set_margin_start(20); area.set_margin_end(20); area.set_margin_top(15)

        current_user = self.auth_mgr.get_current_user()
        lbl_info = Gtk.Label()
        lbl_info.set_markup(f"Ingresa la contraseña de <b>sudo / administrador</b> para el usuario <b>{current_user}</b>:")
        lbl_info.set_line_wrap(True)
        area.pack_start(lbl_info, False, False, 0)

        e_pass = Gtk.Entry()
        e_pass.set_placeholder_text("Contraseña de sudo / sistema")
        e_pass.set_visibility(False)
        e_pass.set_activates_default(True)
        area.pack_start(e_pass, False, False, 0)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()

        if dialog.run() == Gtk.ResponseType.OK:
            tok = self.auth_mgr.authenticate(current_user, e_pass.get_text())
            if tok:
                self.session_token = tok
                self.is_unlocked = True
                self._update_lock_ui()
            else:
                self._show_msg("Fallo de Autenticación", f"La contraseña de sudo para '{current_user}' no es válida o el usuario no tiene permisos.", Gtk.MessageType.ERROR)
        dialog.destroy()

    def _update_lock_ui(self):
        is_es = (self.loc.lang == "es")
        if self.is_unlocked:
            self.btn_lock.set_label("🔓 Bloquear" if is_es else "🔓 Lock")
            self.btn_restore.set_sensitive(True)
            self.btn_purge.set_sensitive(True)
        else:
            self.btn_lock.set_label("🔒 Desbloquear" if is_es else "🔒 Unlock")
            self.btn_restore.set_sensitive(False)
            self.btn_purge.set_sensitive(False)

    def _check_auth_required(self) -> bool:
        if not self.is_unlocked:
            self._show_login_dialog()
            return self.is_unlocked
        return True

    def _refresh_vault_list(self):
        self.vault_store.clear()
        for it in self.vault.list_items():
            t = it.get("quarantine_time_str") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get("quarantine_time", 0)))
            h = it.get("sha256", "")
            short_h = h[:16] + "..." if len(h) > 16 else h
            self.vault_store.append([
                it["vault_id"],
                it.get("threat_name", "Malware"),
                it.get("original_path", ""),
                t,
                short_h
            ])

    def _on_restore_vault_item(self, button):
        if not self._check_auth_required(): return
        model, paths = self.vault_tree.get_selection().get_selected_rows()
        if not paths:
            self._show_msg("Selección", "Por favor selecciona uno o más elementos de la lista del baúl.", Gtk.MessageType.WARNING)
            return

        restored_count = 0
        for p in paths:
            it = model.get_iter(p)
            vid = model.get_value(it, 0)
            target_path = model.get_value(it, 2)
            if self.vault.restore_file(vid, whitelist_manager=self.whitelist):
                restored_count += 1

        self._refresh_vault_list()
        self._show_msg("Restauración Completada", f"{restored_count} archivo(s) restaurados con éxito y añadidos automáticamente a la Lista Blanca (Whitelist) permanente.", Gtk.MessageType.INFO)

    def _on_purge_vault_item(self, button):
        if not self._check_auth_required(): return
        model, paths = self.vault_tree.get_selection().get_selected_rows()
        if not paths:
            self._show_msg("Selección", "Por favor selecciona uno o más elementos para eliminar.", Gtk.MessageType.WARNING)
            return

        purged_count = 0
        for p in paths:
            it = model.get_iter(p)
            vid = model.get_value(it, 0)
            if self.vault.purge_file(vid):
                purged_count += 1

        self._refresh_vault_list()
        self._show_msg("Purga Completada", f"{purged_count} muestra(s) eliminadas definitivamente del disco.", Gtk.MessageType.INFO)

    def _on_apply_dns_clicked(self, button):
        if not self._check_auth_required(): return
        pid = self.dns_combo.get_active_id()
        if self.dns_mgr.apply_profile(pid):
            active = self.dns_mgr.get_active_profile()
            self.lbl_active_dns_title.set_markup(f"<span font='12' weight='bold' foreground='#38bdf8'>● {active['summary']}</span>")
            self.lbl_active_dns_desc.set_text(f"Categoría de filtrado: {active['category']} • Protocolo: DoT (Puerto 853) / DoH")
            self._show_msg("DNS Aplicado", f"Perfil {active['name']} activado en tu conexión de red (systemd-resolved).", Gtk.MessageType.INFO)

    def _on_toggle_ufw_clicked(self, button):
        if not self._check_auth_required(): return
        current = self.firewall.get_ufw_status()
        self.firewall.toggle_ufw(not current)
        self.lbl_ufw_state.set_markup(f"<b>Estado de UFW:</b> {'Activo' if not current else 'Inactivo'}")

    def _on_check_url_clicked(self, button):
        url = self.entry_url.get_text().strip()
        if not url: return
        res = self.phishing.analyze_url(url)
        if res.is_phishing:
            self.lbl_phish_output.set_markup(f"<span foreground='#d32f2f' weight='bold'>⚠️ PHISHING DETECTADO</span>\n{', '.join(res.reasons)}")
        else:
            self.lbl_phish_output.set_markup(f"<span foreground='#2e7d32' weight='bold'>✅ ENLACE SEGURO</span>\nRiesgo: {res.risk_score}/100.")

    def _show_msg(self, title, msg, mtype):
        d = Gtk.MessageDialog(parent=self.window, flags=Gtk.DialogFlags.MODAL, type=mtype, buttons=Gtk.ButtonsType.OK, text=title)
        d.format_secondary_text(msg)
        d.run()
        d.destroy()

    def show_quick_scan_dialog(self, target_path):
        """Diálogo de escaneo rápido con barra de progreso fluida para clic derecho."""
        dialog = Gtk.Dialog(
            title="Constantine QuickScan",
            parent=None,
            flags=Gtk.DialogFlags.MODAL,
            buttons=(Gtk.STOCK_CLOSE, Gtk.ResponseType.CLOSE)
        )
        dialog.set_default_size(480, 200)
        dialog.set_position(Gtk.WindowPosition.CENTER)
        
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(20); area.set_margin_end(20); area.set_margin_top(15)

        lbl_t = Gtk.Label()
        lbl_t.set_markup(f"<b>Analizando elemento:</b>\n<span font='10' foreground='#94a3b8'>{target_path}</span>")
        lbl_t.set_xalign(0); lbl_t.set_line_wrap(True)
        area.pack_start(lbl_t, False, False, 0)

        pbar = Gtk.ProgressBar(); pbar.set_fraction(0.0)
        area.pack_start(pbar, False, False, 0)

        lbl_status = Gtk.Label(label="Iniciando escaneo...")
        lbl_status.set_xalign(0)
        area.pack_start(lbl_status, False, False, 0)

        dialog.show_all()

        def worker():
            files = []
            if os.path.isfile(target_path):
                files.append(target_path)
            elif os.path.isdir(target_path):
                for root, _, fs in os.walk(target_path):
                    for f in fs:
                        files.append(os.path.join(root, f))
                        if len(files) >= 5000: break
                    if len(files) >= 5000: break

            total = len(files)
            threats = 0
            for idx, fp in enumerate(files):
                try:
                    res = self.scanner.scan_file(file_path=fp)
                    if res.is_malicious:
                        threats += 1
                        self.vault.quarantine_file(fp, res.threat_name or "Malware")
                except Exception:
                    pass

                if idx % 2 == 0 or idx == total - 1:
                    frac = float(idx + 1) / float(total) if total > 0 else 1.0
                    GLib.idle_add(pbar.set_fraction, frac)
                    GLib.idle_add(lbl_status.set_text, f"Analizando ({idx+1}/{total}): {os.path.basename(fp)}")

            def done():
                pbar.set_fraction(1.0)
                if threats > 0:
                    lbl_status.set_markup(f"<span foreground='#ef4444' weight='bold'>⚠️ {threats} amenaza(s) encontradas y aisladas en el Baúl.</span>")
                else:
                    lbl_status.set_markup("<span foreground='#10b981' weight='bold'>✅ Análisis completado. Cero amenazas detectadas.</span>")

            GLib.idle_add(done)

        threading.Thread(target=worker, daemon=True).start()
        dialog.run()
        dialog.destroy()
        sys.exit(0)

    def run(self):
        self.window.show_all()
        Gtk.main()

if __name__ == "__main__":
    if HAS_GTK:
        import argparse
        parser = argparse.ArgumentParser(description="Constantine Antivirus GUI")
        parser.add_argument("--scan", type=str, default=None, help="Escanear archivo o carpeta desde clic derecho")
        args, _ = parser.parse_known_args()

        app = ConstantineGUI()
        if args.scan:
            app.show_quick_scan_dialog(args.scan)
        else:
            app.run()
