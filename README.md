# ⚔️ Constantine Antivirus (Linux Active Kernel Defense)

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%20%7C%20Ubuntu%20%7C%20Linux%20Mint-orange.svg)](https://www.debian.org)
[![Kernel: fanotify & eBPF](https://img.shields.io/badge/Kernel-fanotify%20%26%20eBPF-red.svg)](https://ebpf.io)

**Constantine Antivirus** es una suite de seguridad activa y preventiva para distribuciones Linux basadas en Debian (Ubuntu, Linux Mint, Debian) compatible con servidores gráficos **X11** y **Wayland**.

A diferencia de las herramientas tradicionales que solo ejecutan escaneos pasivos bajo demanda, Constantine emula los **minifiltros de E/S de Windows** mediante `fanotify` a nivel de kernel (`FAN_OPEN_PERM`, `FAN_EXEC_PERM`) y sondas **eBPF**, deteniendo amenazas antes de que el código toque la CPU.

---

## 🛡️ Características Principales

1. **Protección Activa en Kernel (fanotify):**
   - Intercepta síncronamente la apertura y ejecución de cualquier archivo (`FAN_OPEN_PERM`, `FAN_EXEC_PERM`).
   - Bloquea amenazas con `FAN_DENY` y las envía directamente al Baúl de Cuarentena.
2. **Escudo Anti-Ransomware Activo:**
   - Trampas señuelo (*Canary Honeypots*) en ubicaciones estratégicas.
   - Detección de ráfagas anómalas de cifrado y extensiones maliciosas (`.locked`, `.crypto`, `.lockbit`, `.enc`).
   - Neutralización instantánea del proceso agresor con señal `SIGKILL`.
3. **Auto-Escaneo de Memorias USB y Discos Duros:**
   - Detecta de inmediato el montaje de dispositivos en `/media/$USER/` o `/run/media/` mediante `udisks2`.
   - Engancha `fanotify` preventivo y neutraliza archivos `autorun.inf`, scripts ofuscados y droppers.
4. **Control de Cortafuegos (UFW) y Lanzador de GUFW:**
   - Interruptor directo para activar o desactivar UFW.
   - Botón integrado para abrir la interfaz gráfica avanzada **GUFW** (`pkexec gufw`).
5. **Integración con Proton VPN:**
   - Detección del cliente oficial de Proton VPN y llamada directa en 1 clic.
6. **Perfiles DNS Cifrados de Mullvad & Quad9:**
   - Configuración en 1 clic de perfiles DoT (853) / DoH en `systemd-resolved` (Base, Adblock, Extended, Family, All, Quad9).
7. **Baúl de Amenazas Cifrado (Quarantine Vault):**
   - Los archivos maliciosos se aíslan cifrados con XOR y permisos `000` en `/var/lib/constantine/vault`.
   - Restauración y purga definitiva protegidas por autenticación.
8. **Gestión Protegida con Usuario y Contraseña:**
   - Panel de control protegido por derivación PBKDF2-HMAC-SHA256 (100,000 rondas).
   - Credenciales iniciales: `admin` / `constantine2026!`.
9. **Interruptor Maestro (Encender / Apagar Antivirus):**
   - Control centralizado de todos los escudos desde la cabecera.
10. **Interfaz Gráfica Nativa (GTK 3):**
    - Diseñada para Linux Mint (Cinnamon, MATE, XFCE), Ubuntu y Debian.
11. **Threat Intelligence Libre:**
    - Feeds de MalwareBazaar (abuse.ch), URLhaus, OpenPhish y Signature-Base integrados.

---

## 📁 Estructura del Repositorio

```text
constantine/
├── core/
│   ├── auth/
│   │   └── auth_manager.py       # Credenciales PBKDF2-HMAC-SHA256
│   ├── engine/
│   │   ├── interceptor.py        # Interceptación síncrona fanotify
│   │   ├── scanner.py            # YARA + Hashes + Heurística
│   │   ├── vault.py              # Baúl de cuarentena cifrado
│   │   ├── ransomware_shield.py  # Honeypots y neutralización anti-ransomware
│   │   ├── usb_monitor.py        # Vigilancia y auto-escaneo USB/Discos
│   │   ├── dns_manager.py        # Perfiles DNS Mullvad & Quad9
│   │   ├── firewall.py           # UFW, corte ss -K y lanzador GUFW
│   │   ├── vpn_manager.py        # Integración con Proton VPN
│   │   ├── phishing.py           # Escudo anti-phishing y /etc/hosts
│   │   ├── ebpf_monitor.py       # Sondas eBPF (sys_enter_execve/ptrace)
│   │   ├── threat_intel.py       # Feeds de MalwareBazaar y URLhaus
│   │   └── notifier.py           # Alertas D-Bus en X11 y Wayland
│   └── rules/
│       └── demons.yar            # Reglas YARA para Linux
├── gui/
│   └── app.py                    # Aplicación de escritorio nativa GTK 3
├── service/
│   ├── constantine.service       # Demonio systemd
│   └── org.constantine.antivirus.policy # Directiva Polkit
├── scripts/
│   └── publish_to_github.sh      # Publicador automático a GitHub
├── tests/
│   └── test_constantine.py       # Pruebas unitarias
├── daemon.py                     # Servicio raíz en segundo plano
├── install.sh                    # Instalador automatizado en 1 comando
├── requirements.txt              # Dependencias Python
└── README.md
```

---

## 🚀 Instalación y Despliegue Rápido

```bash
git clone https://github.com/TU-USUARIO/constantine-antivirus.git
cd constantine-antivirus
chmod +x install.sh
sudo ./install.sh
```

Inicia la interfaz gráfica ejecutando:
```bash
python3 /opt/constantine/gui/app.py
```
*(O búscalo como "Constantine Antivirus" en tu menú de aplicaciones).*

---

## 📤 Publicar en GitHub

```bash
./scripts/publish_to_github.sh
```
O usando GitHub CLI:
```bash
gh repo create constantine-antivirus --public --source=. --remote=origin --push
```
