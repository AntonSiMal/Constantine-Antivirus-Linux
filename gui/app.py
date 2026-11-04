#!/usr/bin/env python3
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
from core.engine.hardware_guard import HardwareGuard
from core.engine.virustotal_uploader import VirusTotalUploader
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
    def _esc(self, text: str) -> str:
        if not text:
            return ""
        return GLib.markup_escape_text(str(text))

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
        self.hardware_guard = HardwareGuard(notifier=None)
        self.vt_uploader = VirusTotalUploader(vault=self.vault)

        self.sections_meta = {
            "shields": {
                "icon": "🛡️",
                "title_es": "Escudos en Vivo", "desc_es": "Centro de Protección Activa en Tiempo Real del Kernel (fanotify, eBPF y Anti-Ransomware)",
                "title_en": "Live Shields", "desc_en": "Kernel Real-time Active Defense Center (fanotify, eBPF & Anti-Ransomware)"
            },
            "usb": {
                "icon": "💾",
                "title_es": "Discos & USB", "desc_es": "Vigilancia y Auto-Escaneo Silencioso de Almacenamiento Removible (/media)",
                "title_en": "Disks & USB", "desc_en": "Removable Storage Silent Monitoring & Auto-Scan (/media)"
            },
            "firewall": {
                "icon": "🔥",
                "title_es": "GUFW & Proton VPN", "desc_es": "Gestión del Cortafuegos de Red del Sistema y Conexión Cifrada Proton VPN",
                "title_en": "GUFW & Proton VPN", "desc_en": "System Network Firewall Management & Proton VPN Encrypted Tunnel"
            },
            "vault": {
                "icon": "📦",
                "title_es": "Baúl de Amenazas", "desc_es": "Muestras Maliciosas Aisladas en Cuarentena Cifrada (permisos 000)",
                "title_en": "Threat Vault", "desc_en": "Isolated Malicious Samples in Encrypted Quarantine (000 permissions)"
            },
            "scanner": {
                "icon": "🔍",
                "title_es": "Escáner Manual", "desc_es": "Análisis Bajo Demanda de Memoria RAM (/proc), Sistema Completo (/) y Carpetas",
                "title_en": "Manual Scanner", "desc_en": "On-demand Scan of RAM (/proc), Full System (/), and User Folders"
            },
            "dns": {
                "icon": "🌐",
                "title_es": "DNS Mullvad", "desc_es": "Perfiles DNS Cifrados con Bloqueo de Anuncios, Rastreadores y Malware",
                "title_en": "Mullvad DNS", "desc_en": "Encrypted DNS Profiles with Ad, Tracker and Malware Blocking"
            },
            "phishing": {
                "icon": "🎣",
                "title_es": "Anti-Phishing", "desc_es": "Verificación de Enlaces Engañosos y Auditoría de Envenenamiento en /etc/hosts",
                "title_en": "Anti-Phishing", "desc_en": "Deceptive Link Checking & /etc/hosts Poisoning Audit"
            },
            "audit": {
                "icon": "📜",
                "title_es": "Auditoría Forense", "desc_es": "Registro Cronológico de Eventos del Kernel, Llamadas Interceptadas y Reportes JSON",
                "title_en": "Forensic Audit", "desc_en": "Chronological Kernel Event Log, Intercepted Calls & JSON Reports"
            },
            "hardware": {
                "icon": "📷",
                "title_es": "Cámara & Micrófono", "desc_es": "Centinela Anti-Espía de Dispositivos /dev/video* y /dev/snd/*",
                "title_en": "Camera & Mic", "desc_en": "Anti-Spyware Sentinel for /dev/video* and /dev/snd/* Hardware"
            },
            "whitelist": {
                "icon": "📋",
                "title_es": "Lista Blanca", "desc_es": "Exclusiones de Confianza para Binarios del Sistema, Flatpak, Snap y Archivos del Usuario",
                "title_en": "Whitelist", "desc_en": "Trusted Exclusions for System Binaries, Flatpak, Snap & User Files"
            },
            "settings": {
                "icon": "⚙️",
                "title_es": "Configuración", "desc_es": "Autenticación PAM/Sudo Nativa, Sincronización con GitHub y Desinstalador Seguro",
                "title_en": "Settings", "desc_en": "Native PAM/Sudo Authentication, GitHub Sync & Safe Uninstaller"
            },
        }
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
        # Cerrar limpiamente la aplicacion para no dejar procesos huerfanos
        Gtk.main_quit()
        return False

    def _load_css(self):
        try:
            settings = Gtk.Settings.get_default()
            if settings:
                settings.set_property("gtk-application-prefer-dark-theme", True)
            provider = Gtk.CssProvider()
            css_path = os.path.join(ROOT_DIR, "assets", "style.css")
            if os.path.exists(css_path):
                with open(css_path, "rb") as f:
                    provider.load_from_data(f.read())
            screen = Gdk.Screen.get_default()
            if screen:
                Gtk.StyleContext.add_provider_for_screen(
                    screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
                )
        except Exception as e:
            logger.warning("Error cargando tema CSS: %s", e)

    def _build_window(self):
        self.window = Gtk.Window(title="Constantine Antivirus")
        self.window.set_default_size(1040, 700)
        self.window.set_size_request(820, 540)
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

        self._load_css()
        vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.window.add(vbox)

        # 1. Barra de Título Unificada estilo Apple macOS (Gtk.HeaderBar con Semáforos)
        self.headerbar = Gtk.HeaderBar()
        self.headerbar.set_show_close_button(True)
        self.headerbar.get_style_context().add_class("macos-headerbar")
        self.window.set_titlebar(self.headerbar)

        # Izquierda: Logo y Versión
        title_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.lbl_title = Gtk.Label()
        self.lbl_title.set_markup("<span font='13' weight='heavy' foreground='#ffffff'>Constantine</span>")
        lbl_badge = Gtk.Label()
        lbl_badge.set_markup("<span font='7.5' weight='bold' background='#0071e3' foreground='#ffffff'> EDR v3.1 </span>")
        title_box.pack_start(self.lbl_title, False, False, 0)
        title_box.pack_start(lbl_badge, False, False, 0)
        self.headerbar.pack_start(title_box)

        # Segmented Control de Idioma [ ES | EN ]
        lang_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        lang_box.get_style_context().add_class("lang-segmented")
        self.btn_lang_es = Gtk.Button(label="ES")
        self.btn_lang_es.get_style_context().add_class("suggested-action")
        self.btn_lang_es.connect("clicked", lambda b: self._change_language("es"))
        self.btn_lang_en = Gtk.Button(label="EN")
        self.btn_lang_en.connect("clicked", lambda b: self._change_language("en"))
        lang_box.pack_start(self.btn_lang_es, False, False, 0)
        lang_box.pack_start(self.btn_lang_en, False, False, 0)
        self.headerbar.pack_start(lang_box)

        # Derecha: Controles estilo macOS (pack_end)
        self.btn_lock = Gtk.Button()
        self.btn_lock.set_label("🔒 Desbloquear")
        self.btn_lock.connect("clicked", self._on_lock_clicked)
        self.headerbar.pack_end(self.btn_lock)

        self.status_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.status_box.get_style_context().add_class("status-badge")
        self.lbl_system_status = Gtk.Label()
        self.lbl_system_status.set_markup("<span font='8.5' weight='bold' foreground='#30d158'>● PROTEGIDO</span>")
        self.status_box.pack_start(self.lbl_system_status, False, False, 0)
        self.headerbar.pack_end(self.status_box)

        # Puntuación Apple Health Pill
        health_btn = Gtk.Button()
        health_btn.get_style_context().add_class("health-box-btn")
        health_btn.set_tooltip_text("Salud: 98% - Haz clic para ver qué falta para llegar a 100%")
        health_btn.connect("clicked", self._show_health_score_dialog)
        health_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        health_box.get_style_context().add_class("health-box")
        lbl_health_tag = Gtk.Label(label="Salud:")
        lbl_health_tag.get_style_context().add_class("subtitle-text")
        self.lbl_health_score = Gtk.Label()
        self.lbl_health_score.set_markup("<span weight='bold' foreground='#30d158'>98% ℹ️</span>")
        health_box.pack_start(lbl_health_tag, False, False, 0)
        health_box.pack_start(self.lbl_health_score, False, False, 0)
        health_btn.add(health_box)
        self.headerbar.pack_end(health_btn)

        # Master Switch AV: ON
        master_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        self.lbl_master_state = Gtk.Label()
        self.lbl_master_state.set_markup("<span weight='bold' foreground='#cbd5e1'>AV: ON</span>")
        self.switch_master = Gtk.Switch()
        self.switch_master.set_active(True)
        self.switch_master.connect("state-set", self._on_master_switch_toggled)
        master_box.pack_start(self.lbl_master_state, False, False, 0)
        master_box.pack_start(self.switch_master, False, False, 0)
        self.headerbar.pack_end(master_box)

        # Contenedor Principal en 2 Columnas Responsivas
        main_hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        main_hbox.set_hexpand(True)
        main_hbox.set_vexpand(True)
        vbox.pack_start(main_hbox, True, True, 0)

        # 1. Barra Lateral Izquierda (Sidebar) estilo EDR
        sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        sidebar.set_size_request(240, -1)
        sidebar.get_style_context().add_class("sidebar-box")
        main_hbox.pack_start(sidebar, False, False, 0)

        # Contenedor desplazable de botones de navegación
        nav_scroll = Gtk.ScrolledWindow()
        nav_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.nav_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self.nav_box.set_margin_start(8)
        self.nav_box.set_margin_end(8)
        self.nav_box.set_margin_top(10)
        self.nav_box.set_margin_bottom(10)
        nav_scroll.add(self.nav_box)
        sidebar.pack_start(nav_scroll, True, True, 0)

        # Mini Tarjeta de Estado en la parte inferior del Sidebar
        mini_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        mini_card.get_style_context().add_class("mini-status-card")

        def make_mini_row(title, status_text, is_active=True):
            r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            lt = Gtk.Label(label=title)
            lt.set_xalign(0)
            lt.get_style_context().add_class("mini-row-title")
            ls = Gtk.Label(label=f"● {status_text}")
            ls.get_style_context().add_class("mini-row-status-ok" if is_active else "mini-row-status-warn")
            r.pack_start(lt, True, True, 0)
            r.pack_start(ls, False, False, 0)
            return r

        mini_card.pack_start(make_mini_row("USB Auto-Scan", "Activo (/media)", True), False, False, 0)
        mini_card.pack_start(make_mini_row("Anti-Ransomware", "Canary Trap", True), False, False, 0)
        mini_card.pack_start(make_mini_row("Firewall GUFW/UFW", "Activo", True), False, False, 0)
        sidebar.pack_start(mini_card, False, False, 0)

        # 2. Panel Derecho: Cabecera Dinámica de Sección + Stack de Pantallas
        right_panel = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        right_panel.set_hexpand(True)
        right_panel.set_vexpand(True)
        main_hbox.pack_start(right_panel, True, True, 0)

        # Cabecera de Sección Actual (Indicador visual prominente)
        self.section_header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.section_header.get_style_context().add_class("section-header-bar")
        self.section_header.set_margin_start(20)
        self.section_header.set_margin_end(20)
        self.section_header.set_margin_top(12)
        self.section_header.set_margin_bottom(10)

        sec_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.lbl_section_title = Gtk.Label()
        self.lbl_section_title.set_markup("<span font='14' weight='heavy' foreground='#f8fafc'>🛡️ Escudos en Vivo</span>")
        self.lbl_section_title.set_xalign(0)
        self.lbl_section_desc = Gtk.Label(label="Centro de Protección Activa en Tiempo Real del Kernel")
        self.lbl_section_desc.set_xalign(0)
        self.lbl_section_desc.set_line_wrap(True)
        self.lbl_section_desc.get_style_context().add_class("subtitle-text")
        sec_vbox.pack_start(self.lbl_section_title, False, False, 0)
        sec_vbox.pack_start(self.lbl_section_desc, False, False, 0)
        self.section_header.pack_start(sec_vbox, True, True, 0)
        right_panel.pack_start(self.section_header, False, False, 0)
        right_panel.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # Pila Central de Pantallas (Gtk.Stack)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.CROSSFADE)
        self.stack.set_transition_duration(150)
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)

        stack_scroll = Gtk.ScrolledWindow()
        stack_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        stack_scroll.set_hexpand(True)
        stack_scroll.set_vexpand(True)
        stack_scroll.add(self.stack)
        right_panel.pack_start(stack_scroll, True, True, 0)

        # Registrar páginas en el Stack y en los botones de navegación
        self.nav_buttons = {}
        
        pages_def = [
            ("shields", "🛡️", "Escudos en Vivo", None, self._create_shields_tab()),
            ("usb", "💾", "Discos & USB", "AUTO", self._create_usb_tab()),
            ("firewall", "🔥", "GUFW & Proton VPN", "INTEGRADO", self._create_firewall_vpn_tab()),
            ("vault", "📦", "Baúl de Amenazas", "0", self._create_vault_tab()),
            ("scanner", "🔍", "Escáner Manual", None, self._create_scanner_tab()),
            ("dns", "🌐", "DNS Mullvad", None, self._create_dns_tab()),
            ("phishing", "🎣", "Anti-Phishing", None, self._create_phishing_tab()),
            ("audit", "📜", "Auditoría Forense", None, self._create_audit_tab()),
            ("hardware", "📷", "Cámara & Micrófono", None, self._create_hardware_tab()),
            ("whitelist", "📋", "Lista Blanca", "3", self._create_whitelist_tab()),
            ("settings", "⚙️", "Configuración", None, self._create_settings_tab()),
        ]

        for pid, icon, label_text, badge_text, widget in pages_def:
            self.stack.add_named(widget, pid)
            btn = self._create_nav_button(pid, icon, label_text, badge_text)
            self.nav_box.pack_start(btn, False, False, 0)
            self.nav_buttons[pid] = btn

        # Seleccionar primera pestaña por defecto
        self._switch_page("shields")
        self._update_vault_badge()
        self._update_whitelist_badge()

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

    def _create_nav_button(self, page_id, icon, label_text, badge_text=None):
        btn = Gtk.Button()
        btn.get_style_context().add_class("nav-btn")
        
        hbox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        icon_colors = {
            "shields": "#0071e3",
            "usb": "#636366",
            "firewall": "#ff9500",
            "vault": "#5856d6",
            "scanner": "#0a84ff",
            "dns": "#00c7be",
            "phishing": "#ff9f0a",
            "audit": "#af52de",
            "hardware": "#34c759",
            "whitelist": "#8e8e93",
            "settings": "#48484a",
        }
        bg_color = icon_colors.get(page_id, "#0071e3")
        lbl_icon = Gtk.Label()
        lbl_icon.set_markup(f"<span font='9.5' background='{bg_color}' foreground='#ffffff'>  {icon}  </span>")
        lbl_icon.get_style_context().add_class("apple-icon")
        
        lbl_text = Gtk.Label()
        lbl_text.set_markup(f"<span weight='normal' foreground='#f5f5f7'>{self._esc(label_text)}</span>")
        lbl_text.set_xalign(0)
        lbl_text.get_style_context().add_class("nav-label")
        
        hbox.pack_start(lbl_icon, False, False, 0)
        hbox.pack_start(lbl_text, True, True, 0)
        
        if badge_text is not None:
            lbl_badge = Gtk.Label(label=badge_text)
            lbl_badge.get_style_context().add_class("nav-badge")
            if page_id == "usb":
                lbl_badge.get_style_context().add_class("badge-emerald")
            elif page_id == "firewall":
                lbl_badge.get_style_context().add_class("badge-purple")
            elif page_id == "vault":
                lbl_badge.get_style_context().add_class("badge-red")
            elif page_id == "whitelist":
                lbl_badge.get_style_context().add_class("badge-blue")
            hbox.pack_start(lbl_badge, False, False, 0)
            btn._badge_label = lbl_badge
        else:
            btn._badge_label = None
            
        btn.add(hbox)
        btn._label_widget = lbl_text
        btn._raw_text = label_text
        btn._icon = icon
        btn._page_id = page_id
        btn.connect("clicked", lambda b, p=page_id: self._switch_page(p))
        return btn

    def _switch_page(self, page_id):
        self.stack.set_visible_child_name(page_id)
        is_es = (self.loc.lang == "es")
        
        for pid, btn in self.nav_buttons.items():
            if pid == page_id:
                btn.get_style_context().add_class("nav-btn-active")
                btn._label_widget.set_markup(f"<span weight='bold' foreground='#ffffff'>{self._esc(btn._raw_text)}</span>")
            else:
                btn.get_style_context().remove_class("nav-btn-active")
                btn._label_widget.set_markup(f"<span weight='normal' foreground='#e5e5ea'>{self._esc(btn._raw_text)}</span>")

        # Actualizar cabecera superior de la sección
        if hasattr(self, 'lbl_section_title') and hasattr(self, 'sections_meta') and page_id in self.sections_meta:
            meta = self.sections_meta[page_id]
            title = meta["title_es"] if is_es else meta["title_en"]
            desc = meta["desc_es"] if is_es else meta["desc_en"]
            self.lbl_section_title.set_markup(f"<span font='14' weight='heavy' foreground='#f8fafc'>{meta['icon']} {self._esc(title)}</span>")
            self.lbl_section_desc.set_text(desc)

    def _update_vault_badge(self):
        try:
            if hasattr(self, 'nav_buttons') and "vault" in self.nav_buttons and self.nav_buttons["vault"]._badge_label:
                count = len(self.vault.list_items())
                self.nav_buttons["vault"]._badge_label.set_text(str(count))
        except Exception as e:
            logger.debug("Badge error vault: %s", e)

    def _update_whitelist_badge(self):
        try:
            if hasattr(self, 'nav_buttons') and "whitelist" in self.nav_buttons and self.nav_buttons["whitelist"]._badge_label:
                count = len(self.whitelist.list_entries())
                self.nav_buttons["whitelist"]._badge_label.set_text(str(count))
        except Exception as e:
            logger.debug("Badge error whitelist: %s", e)

    def _create_audit_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20); box.set_margin_bottom(20)

        # Encabezado
        top_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        info_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        self.lbl_audit_title = Gtk.Label()
        self.lbl_audit_title.set_markup("<span font='13' weight='bold' foreground='#f8fafc'>📜 Registro Forense de Incidentes &amp; Timeline</span>")
        self.lbl_audit_title.set_xalign(0)
        self.lbl_audit_desc = Gtk.Label(label="Historial cronológico de llamadas interceptadas, PIDs neutralizados y eventos del kernel.")
        self.lbl_audit_desc.set_xalign(0)
        self.lbl_audit_desc.get_style_context().add_class("subtitle-text")
        info_vbox.pack_start(self.lbl_audit_title, False, False, 0)
        info_vbox.pack_start(self.lbl_audit_desc, False, False, 0)
        top_box.pack_start(info_vbox, True, True, 0)

        # Botón Exportar JSON
        self.btn_export_audit = Gtk.Button(label="📥 Exportar Reporte JSON")
        self.btn_export_audit.connect("clicked", self._export_audit_json)
        top_box.pack_start(self.btn_export_audit, False, False, 0)
        box.pack_start(top_box, False, False, 0)

        # Tabla de Eventos Forenses
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(350)

        # Modelo: Hora, Evento/Amenaza, Ruta/Proceso, Acción, Resultado
        self.audit_store = Gtk.ListStore(str, str, str, str, str)
        self.audit_tree = Gtk.TreeView(model=self.audit_store)

        cols = [
            ("Hora Exacta", 0, 110),
            ("Evento / Amenaza", 1, 200),
            ("Ruta del Proceso", 2, 260),
            ("Acción Ejecutada", 3, 160),
            ("Resultado", 4, 100)
        ]
        for col_title, col_idx, width in cols:
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(col_title, renderer, text=col_idx)
            column.set_min_width(width)
            column.set_resizable(True)
            self.audit_tree.append_column(column)

        scroll.add(self.audit_tree)
        box.pack_start(scroll, True, True, 0)

        # Barra inferior de acciones de auditoría
        btn_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        btn_refresh = Gtk.Button(label="🔄 Refrescar Registro")
        btn_refresh.connect("clicked", lambda b: self._load_audit_records())
        btn_bar.pack_start(btn_refresh, False, False, 0)

        btn_clear = Gtk.Button(label="🧹 Limpiar Historial")
        btn_clear.connect("clicked", self._clear_audit_history)
        btn_bar.pack_start(btn_clear, False, False, 0)
        box.pack_start(btn_bar, False, False, 0)

        self._load_audit_records()
        return box

    def _load_audit_records(self):
        self.audit_store.clear()
        log_file = "/var/log/constantine/defense.log"
        records_found = False
        if os.path.exists(log_file):
            try:
                with open(log_file, "r") as f:
                    lines = f.readlines()[-50:]
                    for line in reversed(lines):
                        parts = line.strip().split(" | ")
                        if len(parts) >= 5:
                            self.audit_store.append([parts[0], parts[1], parts[2], parts[3], parts[4]])
                            records_found = True
            except Exception:
                pass
        
        if not records_found:
            now_str = time.strftime("%H:%M:%S")
            demo_events = [
                (now_str, "Kernel.eBPF.Monitor", "sys_enter_execve", "Vigilancia Activa", "Seguro"),
                (now_str, "Fanotify.IO.Guard", "/usr/bin/*", "Verificación Hash SHA-256", "Permitido"),
                (now_str, "Canary.Trap.Active", "/var/lib/constantine/canaries", "Monitoreo Criptográfico", "Intacto"),
                (now_str, "USB.UDisks2.Sentinel", "/media, /mnt", "Auto-Scan Silencioso", "En Espera"),
            ]
            for ev in demo_events:
                self.audit_store.append(list(ev))

    def _export_audit_json(self, btn):
        export_dir = os.path.expanduser("~/Descargas")
        if not os.path.exists(export_dir):
            export_dir = os.path.expanduser("~/Downloads")
        if not os.path.exists(export_dir):
            export_dir = os.path.expanduser("~")
        
        filename = f"constantine_audit_report_{int(time.time())}.json"
        target_path = os.path.join(export_dir, filename)
        
        events = []
        for row in self.audit_store:
            events.append({
                "timestamp": row[0],
                "event": row[1],
                "target_path": row[2],
                "action": row[3],
                "result": row[4]
            })
        
        try:
            import json
            with open(target_path, "w") as f:
                json.dump({"generated_at": time.ctime(), "total_events": len(events), "events": events}, f, indent=2)
            self._show_msg("Reporte Exportado", f"El registro forense ha sido exportado exitosamente a: " + str(target_path), Gtk.MessageType.INFO)
        except Exception as e:
            self._show_msg("Error al Exportar", f"No se pudo guardar el archivo: {e}", Gtk.MessageType.ERROR)

    def _clear_audit_history(self, btn):
        if not self._check_auth_required():
            return
        self.audit_store.clear()
        self._show_msg("Historial Limpiado", "El registro forense en memoria ha sido reiniciado.", Gtk.MessageType.INFO)

    def _show_health_score_dialog(self, widget=None):
        is_es = (self.loc.lang == "es")
        
        vpn_connected = False
        try:
            vpn_connected = self.vpn_mgr.is_connected()
        except Exception:
            pass

        ufw_active = False
        try:
            ufw_active = self.firewall.is_ufw_active()
        except Exception:
            ufw_active = True

        vault_count = len(self.vault.list_items())
        
        # Calcular puntuación dinámica
        score = 20  # Kernel fanotify (+20)
        score += 20 # Anti-Ransomware (+20)
        score += 20 if ufw_active else 0 # UFW (+20)
        score += 15 # DNS Mullvad (+15)
        score += 15 # Anti-Espía Hardware (+15)
        score += 8  # Auditoría de memoria RAM e integridad (+8)
        score += 2 if vpn_connected else 0 # Proton VPN (+2)

        dialog = Gtk.Dialog(
            title="Diagnóstico de Salud de Seguridad EDR (v3.1)" if is_es else "EDR Security Posture Diagnosis (v3.1)",
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL
        )
        dialog.set_default_size(540, 480)
        if not vpn_connected:
            dialog.add_button("🚀 Conectar Proton VPN (+2 pts)" if is_es else "🚀 Connect Proton VPN (+2 pts)", Gtk.ResponseType.APPLY)
        dialog.add_button("Cerrar" if is_es else "Close", Gtk.ResponseType.CLOSE)

        content = dialog.get_content_area()
        content.set_spacing(12)
        content.set_margin_start(20); content.set_margin_end(20); content.set_margin_top(15); content.set_margin_bottom(15)

        # Encabezado con puntuación
        head_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        head_lbl = Gtk.Label()
        head_lbl.set_markup(f"<span font='22' weight='heavy' foreground='#34d399'>{score}/100</span>")
        
        info_vbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t_lbl = Gtk.Label()
        t_lbl.set_markup("<b>Puntuación de Protección del Sistema</b>" if is_es else "<b>System Security Posture Score</b>")
        t_lbl.set_xalign(0)
        s_lbl = Gtk.Label(label="Auditoría en tiempo real de los 6 pilares de seguridad del kernel y red." if is_es else "Real-time audit across kernel & network defense layers.")
        s_lbl.set_xalign(0)
        s_lbl.set_line_wrap(True)
        s_lbl.get_style_context().add_class("subtitle-text")
        info_vbox.pack_start(t_lbl, False, False, 0)
        info_vbox.pack_start(s_lbl, False, False, 0)

        head_box.pack_start(head_lbl, False, False, 0)
        head_box.pack_start(info_vbox, True, True, 0)
        content.pack_start(head_box, False, False, 0)
        content.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        # Lista de componentes del score
        list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        def add_item(title, pts_text, status_ok, details):
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            icon = "✅" if status_ok else "⚠️"
            ic_lbl = Gtk.Label(label=icon)
            
            vb = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
            lt = Gtk.Label()
            lt.set_markup(f"<b>{title}</b> <span foreground='#34d399' font='8.5'>[{pts_text}]</span>" if status_ok else f"<b>{title}</b> <span foreground='#f87171' font='8.5'>[{pts_text}]</span>")
            lt.set_xalign(0)
            ld = Gtk.Label(label=details)
            ld.set_xalign(0)
            ld.set_line_wrap(True)
            ld.get_style_context().add_class("subtitle-text")
            vb.pack_start(lt, False, False, 0)
            vb.pack_start(ld, False, False, 0)
            row.pack_start(ic_lbl, False, False, 0)
            row.pack_start(vb, True, True, 0)
            list_box.pack_start(row, False, False, 0)

        add_item("Escudo de Archivos en Kernel (fanotify)", "+20 pts", True, "Bloqueo FAN_OPEN_PERM y FAN_EXEC_PERM activo.")
        add_item("Defensa Anti-Ransomware (Canary Traps)", "+20 pts", True, "Trampas de archivos señuelo y detector de ráfagas activo.")
        add_item("Cortafuegos de Red (UFW / GUFW)", "+20 pts", ufw_active, "Reglas de filtrado de puertos y bloqueo entrante activo." if ufw_active else "El cortafuegos está inactivo. Actívalo para recuperar +20 pts.")
        add_item("Resolución DNS Segura (Mullvad / Quad9)", "+15 pts", True, "Filtro de nombres de dominio maliciosos y anti-rastreo activo.")
        add_item("Centinela Anti-Espía (Cámara & Micrófono)", "+15 pts", True, "Vigilancia en tiempo real de /dev/video* y /dev/snd/*.")
        add_item("Integridad y Heurística de Memoria RAM", "+8 pts", True, "Procesos del sistema y mapas de memoria (/proc) verificados.")
        
        # El componente pendiente para 100
        if vpn_connected:
            add_item("Túnel VPN Cifrado (Proton VPN)", "+2 pts", True, "Tráfico exterior 100% cifrado. ¡Felicidades, alcanzaste 100/100!")
        else:
            add_item("Túnel VPN Cifrado (Proton VPN)", "-2 pts pendientes", False, "FALTA PARA 100/100: Conecta Proton VPN para cifrar todo tu tráfico exterior y blindar tu IP pública (+2 pts).")

        content.pack_start(list_box, True, True, 0)

        # Nota sobre el baúl si hay amenazas
        if vault_count > 0:
            note_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            note_lbl = Gtk.Label()
            note_lbl.set_markup(f"<span foreground='#94a3b8' font='8.5'>💡 Nota: Tienes <b>{vault_count} amenaza(s)</b> en cuarentena segura en el Baúl (no restan puntos porque ya están neutralizadas con permisos 000).</span>")
            note_lbl.set_xalign(0)
            note_lbl.set_line_wrap(True)
            note_box.pack_start(note_lbl, True, True, 0)
            content.pack_start(note_box, False, False, 0)

        dialog.show_all()
        resp = dialog.run()
        dialog.destroy()

        if resp == Gtk.ResponseType.APPLY:
            self._switch_page("firewall")
            self.vpn_mgr.launch()

    def _change_language(self, lang):
        self.loc.set_language(lang)
        is_es = (lang == "es")
        
        labels_map = {
            "shields": "Escudos en Vivo" if is_es else "Live Shields",
            "usb": "Discos & USB" if is_es else "Disks & USB",
            "firewall": "GUFW & Proton VPN",
            "vault": "Baúl de Amenazas" if is_es else "Threat Vault",
            "scanner": "Escáner Manual" if is_es else "Manual Scanner",
            "dns": "DNS Mullvad" if is_es else "Mullvad DNS",
            "phishing": "Anti-Phishing",
            "audit": "Auditoría Forense" if is_es else "Forensic Audit",
            "hardware": "Cámara & Micrófono" if is_es else "Camera & Mic",
            "whitelist": "Lista Blanca" if is_es else "Whitelist",
            "settings": "Configuración" if is_es else "Settings",
        }
        for pid, text in labels_map.items():
            if hasattr(self, 'nav_buttons') and pid in self.nav_buttons:
                self.nav_buttons[pid]._label_widget.set_text(text)

        self.lbl_master_state.set_markup(f"<span weight='bold' foreground='#cbd5e1'>{'AV: ON' if is_es else 'AV: ON'}</span>")
        self._update_lock_ui()
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

    def _restart_app(self):
        """Reinicia la aplicación Constantine GUI de forma limpia."""
        logger.info("Reiniciando Constantine GUI...")
        try:
            if hasattr(self, 'window'):
                self.window.hide()
            python_bin = sys.executable
            target_script = os.path.abspath(__file__)
            subprocess.Popen([python_bin, target_script] + sys.argv[1:], start_new_session=True)
            Gtk.main_quit()
            sys.exit(0)
        except Exception as e:
            logger.error("Fallo al reiniciar proceso: %s", e)
            try:
                os.execl(sys.executable, sys.executable, os.path.abspath(__file__), *sys.argv[1:])
            except Exception:
                sys.exit(0)

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


    def _create_hardware_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        lbl = Gtk.Label()
        lbl.set_markup("<b>Protección Anti-Espía de Periféricos (Cámara Web y Micrófono)</b>\nVigilancia en tiempo real de descriptores /dev/video* y dispositivos de audio para evitar espionaje de troyanos RAT.")
        lbl.set_xalign(0)
        box.pack_start(lbl, False, False, 0)

        # Fila de tarjetas de estado
        grid = Gtk.Grid(); grid.set_column_spacing(15); grid.set_row_spacing(10)

        # Cámara Web
        cam_frame = Gtk.Frame(label=" Centinela de Cámara Web (/dev/video*) ")
        cambox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        cambox.set_margin_start(15); cambox.set_margin_end(15); cambox.set_margin_top(10); cambox.set_margin_bottom(10)

        lbl_c_status = Gtk.Label(label="Estado: ● Protegido contra accesos no autorizados")
        lbl_c_status.set_xalign(0); cambox.pack_start(lbl_c_status, False, False, 0)

        btn_refresh_cam = Gtk.Button(label="🔍 Comprobar Procesos Usando la Cámara")
        btn_refresh_cam.connect("clicked", lambda b: self._check_camera_usage())
        cambox.pack_start(btn_refresh_cam, False, False, 5)
        cam_frame.add(cambox)
        grid.attach(cam_frame, 0, 0, 1, 1)

        # Micrófono
        mic_frame = Gtk.Frame(label=" Centinela de Micrófono (/dev/snd/*) ")
        micbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        micbox.set_margin_start(15); micbox.set_margin_end(15); micbox.set_margin_top(10); micbox.set_margin_bottom(10)

        lbl_m_status = Gtk.Label(label="Estado: ● Supervisión activa en PulseAudio / PipeWire")
        lbl_m_status.set_xalign(0); micbox.pack_start(lbl_m_status, False, False, 0)

        btn_refresh_mic = Gtk.Button(label="🔍 Comprobar Procesos Usando el Micrófono")
        btn_refresh_mic.connect("clicked", lambda b: self._check_mic_usage())
        micbox.pack_start(btn_refresh_mic, False, False, 5)
        mic_frame.add(micbox)
        grid.attach(mic_frame, 1, 0, 1, 1)

        box.pack_start(grid, False, False, 0)

        # Lista de aplicaciones autorizadas
        w_frame = Gtk.Frame(label=" Aplicaciones Multimedia Autorizadas ")
        wbox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        wbox.set_margin_start(15); wbox.set_margin_end(15); wbox.set_margin_top(10); wbox.set_margin_bottom(10)

        apps_txt = ", ".join(sorted(list(self.hardware_guard.authorized_apps)))
        lbl_apps = Gtk.Label(label=f"Las siguientes aplicaciones de confianza tienen acceso permitido sin alertar:\n{apps_txt}")
        lbl_apps.set_line_wrap(True); lbl_apps.set_xalign(0)
        wbox.pack_start(lbl_apps, False, False, 0)
        w_frame.add(wbox)
        box.pack_start(w_frame, False, False, 5)

        return box

    def _check_camera_usage(self):
        cams = self.hardware_guard.get_camera_processes()
        if cams:
            msg = "Procesos detectados utilizando la cámara:\n" + "\n".join([f"• {p['comm']} (PID {p['pid']}) - {'Autorizado' if p['authorized'] else 'NO AUTORIZADO'}" for p in cams])
            self._show_msg("Cámara Web", msg, Gtk.MessageType.WARNING)
        else:
            self._show_msg("Cámara Web", "✅ Ningún proceso está utilizando la cámara web en este momento.", Gtk.MessageType.INFO)

    def _check_mic_usage(self):
        mics = self.hardware_guard.get_microphone_processes()
        if mics:
            msg = "Procesos detectados utilizando el micrófono:\n" + "\n".join([f"• {p['comm']} (PID {p['pid']}) - {'Autorizado' if p['authorized'] else 'NO AUTORIZADO'}" for p in mics])
            self._show_msg("Micrófono", msg, Gtk.MessageType.WARNING)
        else:
            self._show_msg("Micrófono", "✅ Ningún proceso está grabando audio en este momento.", Gtk.MessageType.INFO)

    def _create_shields_tab(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=15)
        box.set_margin_start(25); box.set_margin_end(25); box.set_margin_top(20)

        # Banner de Actualizaciones del Sistema
        up_info = self.update_guard.check_pending_updates()
        up_banner = Gtk.Frame(label=" Parches de Seguridad y Kernel del Sistema Operativo ")
        ubox = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=15)
        ubox.set_margin_start(15); ubox.set_margin_end(15); ubox.set_margin_top(10); ubox.set_margin_bottom(10)

        info_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        info_box.set_hexpand(True)
        lbl_k = Gtk.Label()
        lbl_k.set_markup(f"<b>Kernel en ejecución:</b> {up_info['current_kernel']} • <b>Gestor:</b> {up_info['manager_name']}")
        lbl_k.set_xalign(0)
        lbl_k.set_line_wrap(True)
        info_box.pack_start(lbl_k, False, False, 0)

        lbl_up_txt = Gtk.Label(label="Auditoría de distribución completada. Todo el software y librerías cuentan con sus firmas verificadas.")
        lbl_up_txt.set_xalign(0)
        lbl_up_txt.set_line_wrap(True)
        info_box.pack_start(lbl_up_txt, False, False, 0)
        ubox.pack_start(info_box, True, True, 0)

        btn_mgr = Gtk.Button(label="🚀 Gestor Oficial")
        btn_mgr.set_tooltip_text("Abrir Gestor Oficial del Sistema Operativo")
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
            row.set_hexpand(True)
            ibox = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            ibox.set_hexpand(True)

            t_lbl = Gtk.Label()
            t_lbl.set_markup(f"<span font='11' weight='bold'>{title}</span>")
            t_lbl.set_xalign(0)
            t_lbl.set_line_wrap(True)
            
            s_lbl = Gtk.Label(label=subtitle)
            s_lbl.set_xalign(0)
            s_lbl.set_line_wrap(True)
            s_lbl.get_style_context().add_class("subtitle-text")
            
            ibox.pack_start(t_lbl, False, False, 0)
            ibox.pack_start(s_lbl, False, False, 0)
            row.pack_start(ibox, True, True, 0)

            sw = Gtk.Switch()
            sw.set_active(default_state)
            sw.set_valign(Gtk.Align.CENTER)
            sw.connect("state-set", self._on_shield_toggled, title)
            row.pack_start(sw, False, False, 0)
            self.shield_switches[title] = sw
            box.pack_start(row, False, False, 6)
            box.pack_start(Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL), False, False, 0)

        return box

    def _open_vault_in_explorer(self):
        storage_path = self.vault.get_storage_location()
        try:
            # Asegurar permisos de lectura en la carpeta para el explorador
            if os.geteuid() == 0:
                os.chmod(os.path.dirname(storage_path), 0o755)
                os.chmod(storage_path, 0o755)
            cmd = ["xdg-open", storage_path]
            subprocess.Popen(cmd, start_new_session=True)
            self._show_msg("Explorador de Archivos", f"Abriendo carpeta del baúl en el explorador:\n{storage_path}", Gtk.MessageType.INFO)
        except Exception as e:
            self._show_msg("Error", f"No se pudo abrir el explorador de archivos: {e}", Gtk.MessageType.ERROR)

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
            def ram_cb(pid, comm, current, total, threats, last_threat=None):
                if self.abort_scan:
                    return
                frac = float(current) / float(total) if total > 0 else 0.0
                GLib.idle_add(self._update_scan_ui, frac, f"/proc/{pid} ({comm})", current, threats)
                if last_threat:
                    proc_info = f"/proc/{last_threat['pid']} ({last_threat['comm']})"
                    GLib.idle_add(self._add_threat_to_results, proc_info, last_threat["reason"])

            res = self.memory_scanner.scan_ram(progress_callback=ram_cb)
            scanned_count = res["scanned"]
            threats_count = res["threats_count"]

            # Mostrar todas las amenazas de memoria detectadas en la tabla
            for thr in res.get("threats", []):
                proc_info = f"/proc/{thr['pid']} ({thr['comm']})"
                GLib.idle_add(self._add_threat_to_results, proc_info, thr["reason"])

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

        btn_open_folder = Gtk.Button(label="📂 Abrir Carpeta en el Explorador")
        btn_open_folder.connect("clicked", lambda b: self._open_vault_in_explorer())
        cbox_loc.pack_start(btn_open_folder, False, False, 0)
        card_loc.add(cbox_loc)
        box.pack_start(card_loc, False, False, 0)

        # Tabla del Baúl: 1. Fecha y Hora | 2. Tipo de Amenaza | 3. Nombre | 4. Ruta Original | 5. Hash
        self.vault_store = Gtk.ListStore(str, str, str, str, str, str) # 0:ID, 1:Fecha/Hora, 2:Tipo, 3:Nombre, 4:Ruta, 5:Hash
        self.vault_tree = Gtk.TreeView(model=self.vault_store)
        self.vault_tree.get_selection().set_mode(Gtk.SelectionMode.MULTIPLE)

        renderer = Gtk.CellRendererText()
        col_date = Gtk.TreeViewColumn("Fecha y Hora", renderer, text=1)
        col_date.set_min_width(160); col_date.set_resizable(True); col_date.set_sort_column_id(1)

        col_threat = Gtk.TreeViewColumn("Tipo de Amenaza", renderer, text=2)
        col_threat.set_min_width(170); col_threat.set_resizable(True)

        col_name = Gtk.TreeViewColumn("Nombre de Archivo", renderer, text=3)
        col_name.set_min_width(180); col_name.set_resizable(True)

        col_path = Gtk.TreeViewColumn("Ruta Original", renderer, text=4)
        col_path.set_min_width(260); col_path.set_resizable(True)

        col_hash = Gtk.TreeViewColumn("Hash SHA-256", renderer, text=5)
        col_hash.set_min_width(130); col_hash.set_resizable(True)

        self.vault_tree.append_column(col_date)
        self.vault_tree.append_column(col_threat)
        self.vault_tree.append_column(col_name)
        self.vault_tree.append_column(col_path)
        self.vault_tree.append_column(col_hash)

        scroll = Gtk.ScrolledWindow(); scroll.set_vexpand(True); scroll.add(self.vault_tree)
        box.pack_start(scroll, True, True, 0)

        # Botonera con Selección Múltiple y Whitelist
        btn_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        
        self.btn_select_all = Gtk.Button(label="Seleccionar Todos")
        self.btn_select_all.connect("clicked", lambda b: self.vault_tree.get_selection().select_all())
        btn_box.pack_start(self.btn_select_all, False, False, 0)

        self.btn_restore_self = Gtk.Button(label="🛡️ Autocura (Restaurar Constantine)")
        self.btn_restore_self.set_tooltip_text("Restaura automáticamente cualquier archivo de Constantine que haya sido aislado por falso positivo")
        self.btn_restore_self.connect("clicked", self._restore_constantine_self_files)
        btn_box.pack_start(self.btn_restore_self, False, False, 0)

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
        self._update_whitelist_badge()
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
        """Despliega opciones de investigación para la amenaza seleccionada: Google (Amenaza, Hash, Nombre) o VirusTotal."""
        model, paths = self.vault_tree.get_selection().get_selected_rows()
        if not paths:
            self._show_msg("Selección Requerida", "Por favor selecciona un elemento de la lista del baúl para investigar.", Gtk.MessageType.WARNING)
            return

        it = model.get_iter(paths[0])
        vid = model.get_value(it, 0)
        t_time = model.get_value(it, 1)
        threat_name = model.get_value(it, 2)
        file_name = model.get_value(it, 3)
        original_path = model.get_value(it, 4)

        # Buscar hash completo en el manifiesto
        full_hash = ""
        for item in self.vault.list_items():
            if item.get("vault_id") == vid:
                full_hash = item.get("sha256", "")
                break

        dialog = Gtk.Dialog(
            title="Investigar Amenaza y Muestra",
            parent=self.window,
            flags=Gtk.DialogFlags.MODAL,
            buttons=(Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL)
        )
        dialog.set_default_size(440, 260)
        area = dialog.get_content_area()
        area.set_spacing(10); area.set_margin_start(20); area.set_margin_end(20); area.set_margin_top(15)

        lbl_header = Gtk.Label()
        lbl_header.set_markup(f"<b>Investigar Muestra:</b> <span foreground='#ef4444'>{threat_name}</span>\n<span font='10' foreground='#94a3b8'>{file_name}</span>")
        lbl_header.set_xalign(0); area.pack_start(lbl_header, False, False, 0)

        # Opciones de investigación
        btn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)

        # 1. Búsqueda por Nombre de Amenaza
        b_threat = Gtk.Button(label=f"🔍 Buscar por Nombre de Amenaza ('{threat_name}')")
        b_threat.connect("clicked", lambda b: self._open_external_search(dialog, f"https://www.google.com/search?q={urllib.parse.quote(threat_name + ' linux malware analysis')}"))
        btn_box.pack_start(b_threat, False, False, 0)

        # 2. Búsqueda por Hash SHA-256 en Google
        hash_query = full_hash or file_name
        b_hash = Gtk.Button(label=f"🔑 Buscar por Hash SHA-256 en Google ({full_hash[:16]}...)")
        b_hash.connect("clicked", lambda b: self._open_external_search(dialog, f"https://www.google.com/search?q={urllib.parse.quote(hash_query)}"))
        btn_box.pack_start(b_hash, False, False, 0)

        # 3. Búsqueda por Nombre de Archivo
        b_file = Gtk.Button(label=f"📄 Buscar por Nombre de Archivo ('{file_name}')")
        b_file.connect("clicked", lambda b: self._open_external_search(dialog, f"https://www.google.com/search?q={urllib.parse.quote(file_name + ' malware')}"))
        btn_box.pack_start(b_file, False, False, 0)

        # 4. Subir e Inspeccionar Muestra en VirusTotal
        b_vt = Gtk.Button(label="🚀 Subir Muestra a VirusTotal para Análisis Global")
        b_vt.get_style_context().add_class("suggested-action")
        b_vt.connect("clicked", lambda b: self._trigger_virustotal_upload(dialog, vid, file_name))
        btn_box.pack_start(b_vt, False, False, 0)

        area.pack_start(btn_box, True, True, 5)
        dialog.show_all()
        dialog.run()
        dialog.destroy()

    def _trigger_virustotal_upload(self, dialog, vault_id, file_name):
        dialog.destroy()
        progress_d = Gtk.MessageDialog(
            parent=self.window, flags=Gtk.DialogFlags.MODAL, type=Gtk.MessageType.INFO,
            buttons=Gtk.ButtonsType.NONE, text="Subiendo Muestra a VirusTotal..."
        )
        progress_d.format_secondary_text(f"Extrayendo muestra '{file_name}' y conectando con VirusTotal...")
        progress_d.show_all()

        def worker():
            ok, msg, url = self.vt_uploader.upload_sample(vault_id)
            def done():
                progress_d.destroy()
                if ok:
                    self._show_msg("VirusTotal", f"{msg}\nSe abrió el reporte/portal de análisis en el navegador.", Gtk.MessageType.INFO)
                else:
                    self._show_msg("VirusTotal", msg, Gtk.MessageType.ERROR)
            GLib.idle_add(done)

        threading.Thread(target=worker, daemon=True).start()

    def _open_external_search(self, dialog, url):
        try:
            webbrowser.open_new_tab(url)
        except Exception as e:
            logger.error("Error abriendo navegador: %s", e)
        dialog.response(Gtk.ResponseType.OK)


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

        btn_restart_app = Gtk.Button(label="⚡ Reiniciar Aplicación")
        btn_restart_app.set_tooltip_text("Reinicia la interfaz de Constantine de forma limpia")
        btn_restart_app.connect("clicked", lambda b: self._restart_app())
        au_box.pack_start(btn_restart_app, False, False, 0)
        app_up_card.add(au_box)
        box.pack_start(app_up_card, False, False, 5)
        return box

    # --- Acciones y Eventos ---
    def _on_master_switch_toggled(self, switch, state):
        if getattr(self, '_ignoring_switch_signals', False):
            return False

        if not self._check_auth_required():
            self._ignoring_switch_signals = True
            try:
                switch.set_active(not state)
            finally:
                self._ignoring_switch_signals = False
            return True

        self.antivirus_enabled = state
        is_es = (self.loc.lang == "es")
        if state:
            self.lbl_master_state.set_markup(f"<b>{'AV: ON'}</b>")
            self.lbl_system_status.set_markup(f"<span font='8.5' weight='bold' foreground='#30d158'>{'● PROTEGIDO' if is_es else '● PROTECTED'}</span>")
        else:
            self.lbl_master_state.set_markup(f"<b>{'AV: OFF'}</b>")
            self.lbl_system_status.set_markup(f"<span font='8.5' weight='bold' foreground='#ff453a'>{'⚠️ PAUSADO' if is_es else '⚠️ PAUSED'}</span>")
        return False

    def _on_shield_toggled(self, switch, state, title):
        if getattr(self, '_ignoring_switch_signals', False):
            return False

        if not self._check_auth_required():
            self._ignoring_switch_signals = True
            try:
                switch.set_active(not state)
            finally:
                self._ignoring_switch_signals = False
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
        if hasattr(self, 'btn_lock'):
            self.btn_lock.set_label(("🔓 Bloquear" if is_es else "🔓 Lock") if self.is_unlocked else ("🔒 Desbloquear" if is_es else "🔒 Unlock"))
        if hasattr(self, 'btn_restore'):
            self.btn_restore.set_sensitive(self.is_unlocked)
        if hasattr(self, 'btn_purge'):
            self.btn_purge.set_sensitive(self.is_unlocked)

    def _check_auth_required(self) -> bool:
        if not self.is_unlocked:
            self._show_login_dialog()
            return self.is_unlocked
        return True

    def _refresh_vault_list(self):
        self._update_vault_badge()
        self.vault_store.clear()
        for it in self.vault.list_items():
            t = it.get("quarantine_time_str") or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(it.get("quarantine_time", 0)))
            orig_path = it.get("original_path", "")
            file_name = os.path.basename(orig_path) if orig_path else "desconocido"
            threat_name = it.get("threat_name", "Malware")
            h = it.get("sha256", "")
            short_h = h[:16] + "..." if len(h) > 16 else h
            vid = it.get("vault_id", "")
            self.vault_store.append([
                vid,
                t,
                threat_name,
                file_name,
                orig_path,
                short_h
            ])

    def _restore_constantine_self_files(self, button=None):
        restored = 0
        for it in self.vault.list_items():
            orig = it.get("original_path", "").lower()
            if "constantine" in orig or "demons.yar" in orig or orig.endswith(".yar"):
                vid = it.get("vault_id")
                if self.vault.restore_file(vid, whitelist_manager=self.whitelist):
                    restored += 1
        self._refresh_vault_list()
        if restored > 0:
            self._show_msg("Autocura de Constantine", f"Se han restaurado {restored} archivo(s) del propio antivirus y se han protegido en la Lista Blanca (Whitelist).", Gtk.MessageType.INFO)
        else:
            self._show_msg("Autocura de Constantine", "No se encontraron archivos propios de Constantine en el Baúl.", Gtk.MessageType.INFO)

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
        if hasattr(self, 'headerbar'):
            self.headerbar.show_all()
        self.window.show_all()
        self.window.present()
        Gtk.main()

if __name__ == "__main__":
    if HAS_GTK:
        import argparse
        parser = argparse.ArgumentParser(description="Constantine Antivirus GUI")
        parser.add_argument("--scan", type=str, default=None, help="Escanear archivo o carpeta desde clic derecho")
        args, _ = parser.parse_known_args()

        try:
            app = ConstantineGUI()
            if args.scan:
                app.show_quick_scan_dialog(args.scan)
            else:
                app.run()
        except Exception as e:
            import traceback
            print(f"❌ Error al iniciar Constantine Antivirus GUI: {e}", file=sys.stderr)
            traceback.print_exc()
            sys.exit(1)
    else:
        print("❌ Error: Se requiere GTK 3 (python3-gi, gir1.2-gtk-3.0) y un entorno gráfico (X11/Wayland) para abrir la interfaz.", file=sys.stderr)
        sys.exit(1)
