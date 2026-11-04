"""
Constantine Antivirus - System Tray Icon (gui/tray.py)
Icono residente en la bandeja del sistema junto al reloj (X11 & Wayland).
Compatible con:
- AyatanaAppIndicator3 / AppIndicator3 (Ubuntu, Linux Mint Cinnamon/MATE, Debian)
- Gtk.StatusIcon (Fallback X11/XFCE)
"""

import os
import sys
import logging

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

logger = logging.getLogger("constantine.tray")

try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk
    HAS_GTK = True
except Exception:
    HAS_GTK = False

# Intentar cargar soporte para AppIndicator (estándar moderno junto al reloj)
HAS_APPINDICATOR = False
try:
    gi.require_version('AyatanaAppIndicator3', '0.1')
    from gi.repository import AyatanaAppIndicator3 as appindicator
    HAS_APPINDICATOR = True
except Exception:
    try:
        gi.require_version('AppIndicator3', '0.1')
        from gi.repository import AppIndicator3 as appindicator
        HAS_APPINDICATOR = True
    except Exception:
        HAS_APPINDICATOR = False

class ConstantineTrayIcon:
    def __init__(self, main_window=None, on_open_callback=None, on_toggle_protection=None):
        self.main_window = main_window
        self.on_open_callback = on_open_callback
        self.on_toggle_protection = on_toggle_protection
        self.indicator = None
        self.status_icon = None

        self.icon_path = os.path.join(ROOT_DIR, "assets", "constantine.svg")
        if not os.path.exists(self.icon_path):
            self.icon_path = "/usr/share/pixmaps/constantine.svg"

        self._setup_tray()

    def _setup_tray(self):
        if not HAS_GTK:
            return

        menu = self._build_menu()

        if HAS_APPINDICATOR:
            try:
                self.indicator = appindicator.Indicator.new(
                    "constantine-antivirus",
                    self.icon_path if os.path.exists(self.icon_path) else "security-high",
                    appindicator.IndicatorCategory.APPLICATION_STATUS
                )
                self.indicator.set_status(appindicator.IndicatorStatus.ACTIVE)
                self.indicator.set_menu(menu)
                logger.info("Tray AppIndicator inicializado junto al reloj.")
                return
            except Exception as e:
                logger.debug("Error con AppIndicator, usando StatusIcon fallback: %s", e)

        # Fallback Gtk.StatusIcon
        try:
            self.status_icon = Gtk.StatusIcon()
            if os.path.exists(self.icon_path):
                self.status_icon.set_from_file(self.icon_path)
            else:
                self.status_icon.set_from_icon_name("security-high")
            self.status_icon.set_tooltip_text("Constantine Antivirus - Protección Activa")
            self.status_icon.connect("activate", self._on_tray_clicked)
            self.status_icon.connect("popup-menu", self._on_status_icon_popup, menu)
            self.status_icon.set_visible(True)
            logger.info("Gtk.StatusIcon inicializado en la bandeja del sistema.")
        except Exception as e:
            logger.warning("No se pudo crear StatusIcon en este entorno: %s", e)

    def _build_menu(self):
        menu = Gtk.Menu()

        # Título
        header = Gtk.MenuItem(label="⚔️ Constantine Antivirus")
        header.set_sensitive(False)
        menu.append(header)
        menu.append(Gtk.SeparatorMenuItem())

        # Abrir ventana principal
        item_open = Gtk.MenuItem(label="Abrir Centro de Seguridad")
        item_open.connect("activate", self._on_open_app)
        menu.append(item_open)

        # Estado
        self.item_status = Gtk.MenuItem(label="● Estado: Protegido (Kernel fanotify)")
        self.item_status.set_sensitive(False)
        menu.append(self.item_status)

        menu.append(Gtk.SeparatorMenuItem())

        # Atajos rápidos
        item_gufw = Gtk.MenuItem(label="🔥 Abrir Cortafuegos GUFW")
        item_gufw.connect("activate", self._on_launch_gufw)
        menu.append(item_gufw)

        item_vpn = Gtk.MenuItem(label="🛡️ Abrir Proton VPN")
        item_vpn.connect("activate", self._on_launch_vpn)
        menu.append(item_vpn)

        menu.append(Gtk.SeparatorMenuItem())

        # Salir
        item_exit = Gtk.MenuItem(label="Salir")
        item_exit.connect("activate", self._on_exit)
        menu.append(item_exit)

        menu.show_all()
        return menu

    def _on_tray_clicked(self, icon):
        self._on_open_app(None)

    def _on_status_icon_popup(self, icon, button, activate_time, menu):
        menu.popup(None, None, Gtk.StatusIcon.position_menu, icon, button, activate_time)

    def _on_open_app(self, widget):
        if self.on_open_callback:
            self.on_open_callback()
        elif self.main_window:
            self.main_window.show_all()
            self.main_window.present()

    def _on_launch_gufw(self, widget):
        from core.engine.firewall import NetworkQuarantine
        NetworkQuarantine().launch_gufw()

    def _on_launch_vpn(self, widget):
        from core.engine.vpn_manager import VPNManager
        VPNManager().launch()

    def _on_exit(self, widget):
        Gtk.main_quit()
