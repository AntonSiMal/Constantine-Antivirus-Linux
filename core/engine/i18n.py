"""
Constantine Antivirus - Internationalization & Localization (core/engine/i18n.py)
Gestor de idiomas (Español / Inglés) para la interfaz gráfica y notificaciones.
"""

STRINGS = {
    "es": {
        "app_title": "Constantine Antivirus - Centro de Seguridad Total",
        "app_sub": "Protección Activa en Kernel Linux • Anti-Ransomware • GUFW • Mullvad DNS • Proton VPN",
        "status_protected": "SISTEMA PROTEGIDO",
        "status_paused": "PROTECCIÓN PAUSADA",
        "antivirus_on": "Antivirus: ON",
        "antivirus_off": "Antivirus: OFF",
        "btn_unlock": "Desbloquear",
        "btn_lock": "Bloquear (Admin)",
        "tab_shields": "🛡️ Escudos en Vivo",
        "tab_usb": "💾 Discos & USB",
        "tab_firewall_vpn": "🔥 GUFW & Proton VPN",
        "tab_vault": "📦 Baúl de Amenazas",
        "tab_scanner": "🔍 Escáner Manual",
        "tab_dns": "🌐 DNS Mullvad",
        "tab_phishing": "🎣 Anti-Phishing",
        "tab_settings": "⚙️ Configuración",
        "stat_audited": "Archivos Auditados",
        "stat_threats": "Amenazas Neutralizadas",
        "stat_usb": "Vigilancia USB / Discos",
        "stat_ransomware": "Honeypots Anti-Ransom",
        "shield_kernel_title": "Escudo de Archivos en Kernel (fanotify)",
        "shield_kernel_desc": "Intercepta FAN_OPEN_PERM y FAN_OPEN_EXEC_PERM antes de su ejecución en disco.",
        "shield_ransom_title": "Escudo Anti-Ransomware Activo",
        "shield_ransom_desc": "Detecta ráfagas de cifrado y protege archivos señuelo neutralizando el proceso con SIGKILL.",
        "shield_usb_title": "Inspección Automática de Memorias USB y Discos",
        "shield_usb_desc": "Analiza medios en /media y bloquea archivos autorun maliciosos al conectar.",
        "shield_ebpf_title": "Vigilancia de Comportamiento eBPF",
        "shield_ebpf_desc": "Audita llamadas sys_enter_execve y evita inyecciones de memoria ptrace.",
        "btn_open_upmgr": "🚀 Abrir Gestor Oficial del Sistema",
        "btn_simulate_usb": "💾 Simular Inserción de Memoria USB",
        "btn_simulate_ransom": "Simular Ataque Ransomware",
        "btn_empty_vault": "Vaciar Todo el Baúl",
        "btn_restore": "Restaurar",
        "btn_purge": "Purgar",
        "btn_apply_dns": "Aplicar Perfil a la Conexión",
        "btn_test_dns": "Probar Latencia",
        "btn_analyze_url": "Analizar URL",
        "btn_audit_hosts": "Auditar /etc/hosts",
        "btn_launch_gufw": "🔥 Abrir Panel GUFW",
        "btn_launch_vpn": "🛡️ Lanzar Proton VPN",
        "btn_toggle_ufw": "Activar / Desactivar Firewall",
        "threat_blocked_toast": "Amenaza Bloqueada por Kernel",
        "vault_item_toast": "El archivo hostil fue neutralizado y enviado al Baúl."
    },
    "en": {
        "app_title": "Constantine Antivirus - Total Security Center",
        "app_sub": "Active Linux Kernel Defense • Anti-Ransomware • GUFW • Mullvad DNS • Proton VPN",
        "status_protected": "SYSTEM PROTECTED",
        "status_paused": "PROTECTION PAUSED",
        "antivirus_on": "Antivirus: ON",
        "antivirus_off": "Antivirus: OFF",
        "btn_unlock": "Unlock",
        "btn_lock": "Lock (Admin)",
        "tab_shields": "🛡️ Live Shields",
        "tab_usb": "💾 Disks & USB",
        "tab_firewall_vpn": "🔥 GUFW & Proton VPN",
        "tab_vault": "📦 Threat Vault",
        "tab_scanner": "🔍 Manual Scanner",
        "tab_dns": "🌐 Mullvad DNS",
        "tab_phishing": "🎣 Anti-Phishing",
        "tab_settings": "⚙️ Settings",
        "stat_audited": "Audited Files",
        "stat_threats": "Threats Neutralized",
        "stat_usb": "USB / Disk Monitor",
        "stat_ransomware": "Anti-Ransom Honeypots",
        "shield_kernel_title": "Kernel File Shield (fanotify)",
        "shield_kernel_desc": "Intercepts FAN_OPEN_PERM & FAN_OPEN_EXEC_PERM prior to disk execution.",
        "shield_ransom_title": "Active Anti-Ransomware Shield",
        "shield_ransom_desc": "Detects encryption bursts and defends canary files, killing rogue PIDs with SIGKILL.",
        "shield_usb_title": "Automatic USB & External Storage Inspection",
        "shield_usb_desc": "Scans mounted drives in /media and neutralizes malicious autorun files on insert.",
        "shield_ebpf_title": "eBPF Behavioral Surveillance",
        "shield_ebpf_desc": "Traces sys_enter_execve and prevents ptrace memory injection in RAM.",
        "btn_open_upmgr": "🚀 Open Official System Updater",
        "btn_simulate_usb": "💾 Simulate USB Drive Insertion",
        "btn_simulate_ransom": "Simulate Ransomware Attack",
        "btn_empty_vault": "Empty Threat Vault",
        "btn_restore": "Restore",
        "btn_purge": "Purge",
        "btn_apply_dns": "Apply Profile to Connection",
        "btn_test_dns": "Test Latency",
        "btn_analyze_url": "Analyze URL",
        "btn_audit_hosts": "Audit /etc/hosts",
        "btn_launch_gufw": "🔥 Open GUFW Panel",
        "btn_launch_vpn": "🛡️ Launch Proton VPN",
        "btn_toggle_ufw": "Enable / Disable Firewall",
        "threat_blocked_toast": "Threat Blocked by Kernel",
        "vault_item_toast": "Hostile file neutralized and isolated in Threat Vault."
    }
}

class Localization:
    def __init__(self, default_lang: str = "es"):
        self.lang = default_lang
        self.current_lang = default_lang

    def set_language(self, lang: str):
        if lang in STRINGS:
            self.lang = lang
            self.current_lang = lang

    def get(self, key: str) -> str:
        return STRINGS.get(self.lang, STRINGS["es"]).get(key, key)
